// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package migration_coordinator

import (
	"context"
	"fmt"
	"io"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/kata-containers/kata-containers/src/runtime/protocols/migration_coordinator"
)

// defaultChunkBytes is the SendSandboxState payload chunk size. The
// serialized SandboxState is small (~tens of KiB) but we keep this
// bounded so a future addition (e.g. embedded device state) does
// not blow past gRPC's default max message size.
const defaultChunkBytes = 64 * 1024

// Client is the source shim's handle to a destination shim's
// MigrationCoordinator. Each Client targets exactly one sandbox on
// one destination; create a new Client for each migration.
type Client struct {
	sandboxID string
	conn      *grpc.ClientConn

	// rpc is exported within the package so tests can drive the
	// raw stream interface for sandbox-id-mismatch scenarios that
	// the higher-level wrapper would never construct.
	rpc pb.MigrationCoordinatorClient
}

// Dial connects to the destination's MigrationCoordinator at the
// given unix socket path. The caller must Close the returned Client
// to release the connection. On error a nil Client is returned and
// no resources need releasing.
func Dial(ctx context.Context, sandboxID, socketPath string) (*Client, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("sandboxID is required")
	}
	if socketPath == "" {
		return nil, fmt.Errorf("socketPath is required")
	}

	// grpc.NewClient is the modern entry point (DialContext is
	// being phased out). For unix sockets we have to wire a
	// custom dialer because grpc-go does not understand the
	// "unix:" target scheme universally across versions; doing it
	// explicitly keeps behaviour predictable.
	conn, err := grpc.NewClient(
		"passthrough:///"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", addr)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("dial migration coordinator at %s: %w", socketPath, err)
	}

	// Probe with a Connect to surface dial failures eagerly,
	// otherwise the first RPC call would block on the first
	// attempt without surfacing the missing-socket error.
	conn.Connect()
	state := conn.GetState()
	if state.String() == "TRANSIENT_FAILURE" {
		_ = conn.Close()
		return nil, fmt.Errorf("dial migration coordinator at %s: connection in transient failure state", socketPath)
	}
	// Optionally wait for the connection to become Ready under
	// the caller's context, so a never-existing socket surfaces
	// as a deadline error rather than a delayed RPC failure.
	if !conn.WaitForStateChange(ctx, state) && ctx.Err() != nil {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	if conn.GetState().String() == "TRANSIENT_FAILURE" {
		_ = conn.Close()
		return nil, fmt.Errorf("dial migration coordinator at %s: transient failure", socketPath)
	}

	return &Client{
		sandboxID: sandboxID,
		conn:      conn,
		rpc:       pb.NewMigrationCoordinatorClient(conn),
	}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// PrepareIncoming asks the destination to prepare for an inbound
// migration. The returned response carries the URI the source's
// QMP migrate command should target and the capabilities the
// destination accepted (a subset of requested).
func (c *Client) PrepareIncoming(ctx context.Context, requestedCapabilities []string, hypervisorConfigSummary []byte) (*pb.PrepareIncomingResponse, error) {
	return c.rpc.PrepareIncoming(ctx, &pb.PrepareIncomingRequest{
		SandboxId:               c.sandboxID,
		RequestedCapabilities:   requestedCapabilities,
		HypervisorConfigSummary: hypervisorConfigSummary,
	})
}

// SendSandboxState streams the bytes from r to the destination,
// chunked at defaultChunkBytes. The final chunk carries final=true
// so the destination knows to invoke its StateApplier.
//
// The Reader is consumed in full and not closed by this method —
// the caller owns the source. Errors from the Reader are returned
// after closing the stream so the destination sees a transport
// error rather than a silently truncated payload.
//
// Uses io.ReadFull semantics so EOF detection is precise: a short
// read at end-of-stream returns io.ErrUnexpectedEOF with n>0, a
// clean end-of-stream returns io.EOF with n==0. Both are flagged
// to the server as the final chunk.
func (c *Client) SendSandboxState(ctx context.Context, r io.Reader) (*pb.SendSandboxStateResponse, error) {
	stream, err := c.rpc.SendSandboxState(ctx)
	if err != nil {
		return nil, fmt.Errorf("open SendSandboxState stream: %w", err)
	}

	buf := make([]byte, defaultChunkBytes)
	for {
		n, err := io.ReadFull(r, buf)
		isEOF := err == io.EOF || err == io.ErrUnexpectedEOF
		if err != nil && !isEOF {
			_, _ = stream.CloseAndRecv()
			return nil, fmt.Errorf("read SandboxState source: %w", err)
		}
		// Copy the bytes — protobuf marshal happens inside
		// Send, but defensive copying makes the contract
		// independent of grpc-go internals across versions.
		var payload []byte
		if n > 0 {
			payload = append([]byte(nil), buf[:n]...)
		}
		if sendErr := stream.Send(&pb.SandboxStateChunk{
			SandboxId:    c.sandboxID,
			PayloadChunk: payload,
			Final:        isEOF,
		}); sendErr != nil {
			return nil, fmt.Errorf("send chunk: %w", sendErr)
		}
		if isEOF {
			break
		}
	}
	return stream.CloseAndRecv()
}

// CompleteHandoff signals successful migration to the destination.
// On the source side this is called only after the source's QMP
// query-migrate reports status=completed.
func (c *Client) CompleteHandoff(ctx context.Context) (*pb.CompleteHandoffResponse, error) {
	return c.rpc.CompleteHandoff(ctx, &pb.CompleteHandoffRequest{
		SandboxId: c.sandboxID,
	})
}

// AbortHandoff signals abort to the destination. Reason is a
// free-form string for the destination's logs.
func (c *Client) AbortHandoff(ctx context.Context, reason string) error {
	_, err := c.rpc.AbortHandoff(ctx, &pb.AbortHandoffRequest{
		SandboxId: c.sandboxID,
		Reason:    reason,
	})
	return err
}
