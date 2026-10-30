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
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/kata-containers/kata-containers/src/runtime/protocols/migration_coordinator"
)

// parseDialTarget splits a target into (network, address) for
// net.Dial. Accepts unix socket paths (network=unix, address=path)
// and "tcp:host:port" or "tcp://host:port" addresses
// (network=tcp). The "tcp:host:port" form matches Kata's existing
// migration URI convention so the same string is usable end-to-end.
func parseDialTarget(target string) (network, address string) {
	switch {
	case strings.HasPrefix(target, "tcp://"):
		return "tcp", strings.TrimPrefix(target, "tcp://")
	case strings.HasPrefix(target, "tcp:"):
		return "tcp", strings.TrimPrefix(target, "tcp:")
	case strings.HasPrefix(target, "unix://"):
		return "unix", strings.TrimPrefix(target, "unix://")
	default:
		// Default to unix-socket path so existing callers with
		// raw paths continue to work.
		return "unix", target
	}
}

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

// Dial connects to the destination's MigrationCoordinator. The
// target is either a unix socket path or a "tcp:host:port" address
// (matching the form used elsewhere in Kata for migration URIs).
// The caller must Close the returned Client to release the
// connection. On error a nil Client is returned and no resources
// need releasing.
func Dial(ctx context.Context, sandboxID, target string) (*Client, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("sandboxID is required")
	}
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}

	network, addr := parseDialTarget(target)

	// grpc.NewClient is the modern entry point (DialContext is
	// being phased out). For unix sockets and TCP we wire a custom
	// dialer so grpc-go doesn't have to understand our target
	// format; the passthrough:/// scheme tells grpc to forward our
	// address verbatim to the dialer.
	conn, err := grpc.NewClient(
		"passthrough:///"+addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, a string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, a)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("dial migration coordinator at %s: %w", target, err)
	}

	// Probe with a Connect to surface dial failures eagerly,
	// otherwise the first RPC call would block on the first
	// attempt without surfacing the missing-socket error.
	// Wait for the connection to become Ready under the caller's context,
	// so a never-existing target surfaces as a deadline error rather than
	// a delayed RPC failure.
	if err := waitForReady(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dial migration coordinator at %s: %w", target, err)
	}

	return &Client{
		sandboxID: sandboxID,
		conn:      conn,
		rpc:       pb.NewMigrationCoordinatorClient(conn),
	}, nil
}

// connState is the slice of *grpc.ClientConn that waitForReady drives, so a
// test can stand in a connection that is already Ready, or one that fails.
type connState interface {
	Connect()
	GetState() connectivity.State
	WaitForStateChange(context.Context, connectivity.State) bool
}

// waitForReady connects and blocks until the connection is Ready, or returns
// why it cannot be: a transient failure, a shut-down connection, or the
// caller's context ending first.
//
// It loops on state changes rather than waiting for exactly one. A unix-socket
// dial to a listener that is already up can reach Ready between Connect and
// the first GetState; a single WaitForStateChange on an already-Ready state
// then blocks until the caller's deadline and reports a timeout for a
// connection that was fine. That is what made the migrate-out unit test fail
// intermittently on fast runners.
func waitForReady(ctx context.Context, conn connState) error {
	conn.Connect()
	for {
		state := conn.GetState()
		switch state {
		case connectivity.Ready:
			return nil
		case connectivity.TransientFailure:
			return fmt.Errorf("connection in transient failure state")
		case connectivity.Shutdown:
			return fmt.Errorf("connection shut down")
		case connectivity.Idle:
			// A channel can fall back to Idle after the first Connect
			// (grpc parks it there when a connect attempt ends without a
			// transport). Idle never changes on its own, so kick it again
			// rather than wait on it until the deadline.
			conn.Connect()
		}
		if !conn.WaitForStateChange(ctx, state) {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("connection stuck in state %s", state)
		}
	}
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
