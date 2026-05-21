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
	"os"
	"path/filepath"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kata-containers/kata-containers/src/runtime/protocols/migration_coordinator"
)

// StateApplier is invoked with the fully accumulated SandboxState
// payload after the final SendSandboxState chunk arrives. The
// applier is responsible for deserializing the payload and applying
// it to the destination's in-memory sandbox struct. Returning an
// error fails the RPC with codes.InvalidArgument so the source
// treats it as a state-content problem rather than a transport one.
//
// The signature is bytes-in, error-out (rather than a typed
// SandboxState) so this package does not depend on
// virtcontainers/persist/api — the caller in the shim layer owns
// that coupling.
type StateApplier func(ctx context.Context, payload []byte) error

// ServerOptions configures a per-sandbox Server instance. The
// Sandbox-ID-bearing fields are mandatory; the rest are optional
// hooks the shim layer wires for the real handoff. Tests pass stubs.
type ServerOptions struct {
	// SandboxID this server is bound to. Incoming RPCs whose
	// sandbox_id does not match are rejected with InvalidArgument.
	SandboxID string

	// SocketPath where the gRPC server binds. Defaults are derived
	// via SocketPath(SandboxID) when empty.
	SocketPath string

	// IncomingURI returned to the source from PrepareIncoming —
	// the URI its QMP migrate command should target. For the
	// skeleton phase this is a static value provided by the
	// caller; C.3 will read it from the destination QEMU's
	// query-migrate response after MigrateIncoming runs.
	IncomingURI string

	// StateApplier handles the accumulated SandboxState bytes on
	// the final SendSandboxState chunk. Nil is allowed for the
	// skeleton and tests — in that case state_applied is reported
	// as true and bytes are discarded.
	StateApplier StateApplier

	// OnComplete fires when CompleteHandoff is received from the
	// source. The shim wires this to its mode transition
	// (Incoming -> Owner). Returning an error fails the RPC with
	// codes.FailedPrecondition.
	OnComplete func() error

	// OnAbort fires when AbortHandoff is received. The reason is
	// the source's free-form explanation; the shim logs it and
	// initiates teardown. Nil is allowed for tests.
	OnAbort func(reason string)
}

// Server is one per-sandbox MigrationCoordinator gRPC instance,
// bound to a unix socket whose path is derived from the sandbox ID.
type Server struct {
	pb.UnimplementedMigrationCoordinatorServer

	opts ServerOptions

	listener   net.Listener
	grpcServer *grpc.Server

	// inFlightMu guards the accumulator state for in-progress
	// SendSandboxState streams. The protocol allows only one
	// stream at a time per server; concurrent streams race for the
	// same accumulator and the second one is rejected.
	inFlightMu sync.Mutex
	inFlight   bool
}

// NewServer constructs a Server with the supplied options. It
// creates the parent directory for the socket but does not yet bind
// — call Start to begin serving. Bind failure (e.g. socket already
// exists from a previous shim that crashed) is surfaced from Start,
// not NewServer, so caller-side cleanup logic stays in one place.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.SandboxID == "" {
		return nil, fmt.Errorf("ServerOptions.SandboxID is required")
	}
	if opts.SocketPath == "" {
		opts.SocketPath = SocketPath(opts.SandboxID)
	}
	if err := os.MkdirAll(filepath.Dir(opts.SocketPath), 0o755); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}
	s := &Server{opts: opts}
	listener, err := net.Listen("unix", opts.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("bind unix socket %s: %w", opts.SocketPath, err)
	}
	s.listener = listener
	s.grpcServer = grpc.NewServer()
	pb.RegisterMigrationCoordinatorServer(s.grpcServer, s)
	return s, nil
}

// Start begins serving in a background goroutine. Returns
// immediately. Errors from the serve loop are silent — Stop
// observes them when called.
func (s *Server) Start() error {
	go func() {
		// Serve returns nil when the listener is gracefully
		// closed via s.grpcServer.GracefulStop, and an error
		// only for unexpected failures (e.g. accept errors that
		// are not closed-listener). We swallow the result here
		// because the only meaningful action is for Stop to log
		// the failure when it has its own teardown context.
		_ = s.grpcServer.Serve(s.listener)
	}()
	return nil
}

// Stop gracefully shuts down the server, closes the listener, and
// removes the socket file. Idempotent.
func (s *Server) Stop() error {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	// Listener is closed by GracefulStop; removing the socket file
	// is best-effort because a crashed-and-restarted scenario will
	// already have unlinked it. Ignore the not-exist case.
	if err := os.Remove(s.opts.SocketPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// SandboxID returns the sandbox this server is bound to. Useful in
// tests for round-tripping the server's identity to a client.
func (s *Server) SandboxID() string { return s.opts.SandboxID }

// SocketPath returns the socket path the server is bound on.
func (s *Server) SocketPath() string { return s.opts.SocketPath }

// PrepareIncoming validates the source's request and returns the
// URI its QMP migrate command should target. Capability negotiation
// is a passthrough in the skeleton — every requested capability is
// accepted. C.3 will narrow this against the destination QEMU's
// query-migrate-capabilities response.
func (s *Server) PrepareIncoming(_ context.Context, req *pb.PrepareIncomingRequest) (*pb.PrepareIncomingResponse, error) {
	if req.SandboxId != s.opts.SandboxID {
		return nil, status.Errorf(codes.InvalidArgument,
			"sandbox_id mismatch: request %q != server %q",
			req.SandboxId, s.opts.SandboxID)
	}
	return &pb.PrepareIncomingResponse{
		IncomingUri:          s.opts.IncomingURI,
		AcceptedCapabilities: append([]string(nil), req.RequestedCapabilities...),
	}, nil
}

// SendSandboxState accumulates streamed chunks and invokes the
// configured StateApplier on the final chunk. Mid-stream sandbox_id
// mismatches abort the stream with InvalidArgument so the source
// never confuses the destination about which sandbox is in flight.
func (s *Server) SendSandboxState(stream pb.MigrationCoordinator_SendSandboxStateServer) error {
	// Only one stream per server at a time — concurrent streams
	// would race for the accumulator and corrupt the applied
	// state. This is a per-server lock, not per-sandbox-globally,
	// because there's exactly one server per sandbox by design.
	s.inFlightMu.Lock()
	if s.inFlight {
		s.inFlightMu.Unlock()
		return status.Error(codes.FailedPrecondition,
			"another SendSandboxState stream is already in flight for this sandbox")
	}
	s.inFlight = true
	s.inFlightMu.Unlock()
	defer func() {
		s.inFlightMu.Lock()
		s.inFlight = false
		s.inFlightMu.Unlock()
	}()

	var (
		accumulated []byte
		seenFinal   bool
	)
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if chunk.SandboxId != s.opts.SandboxID {
			return status.Errorf(codes.InvalidArgument,
				"sandbox_id mismatch mid-stream: chunk %q != server %q",
				chunk.SandboxId, s.opts.SandboxID)
		}
		accumulated = append(accumulated, chunk.PayloadChunk...)
		if chunk.Final {
			seenFinal = true
			break
		}
	}

	resp := &pb.SendSandboxStateResponse{
		BytesReceived: uint64(len(accumulated)),
	}
	if !seenFinal {
		// Source closed the stream without flagging the last
		// chunk. The accumulated bytes are not safe to apply —
		// either the source crashed mid-stream or implemented
		// the protocol wrong. Treat as a content error.
		return status.Error(codes.InvalidArgument,
			"stream closed without a final chunk; payload not applied")
	}

	if s.opts.StateApplier != nil {
		if err := s.opts.StateApplier(stream.Context(), accumulated); err != nil {
			return status.Errorf(codes.InvalidArgument,
				"state apply failed: %v", err)
		}
	}
	resp.StateApplied = true
	return stream.SendAndClose(resp)
}

// CompleteHandoff invokes the OnComplete hook and reports owner=true
// on success. In C.3 the hook will run the actual Incoming -> Owner
// mode transition.
func (s *Server) CompleteHandoff(_ context.Context, req *pb.CompleteHandoffRequest) (*pb.CompleteHandoffResponse, error) {
	if req.SandboxId != s.opts.SandboxID {
		return nil, status.Errorf(codes.InvalidArgument,
			"sandbox_id mismatch: request %q != server %q",
			req.SandboxId, s.opts.SandboxID)
	}
	if s.opts.OnComplete != nil {
		if err := s.opts.OnComplete(); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition,
				"OnComplete hook failed: %v", err)
		}
	}
	return &pb.CompleteHandoffResponse{Owner: true}, nil
}

// AbortHandoff invokes the OnAbort hook. Always returns success —
// abort is best-effort and the destination still tears down its
// QEMU even if the hook is missing or panics.
func (s *Server) AbortHandoff(_ context.Context, req *pb.AbortHandoffRequest) (*pb.AbortHandoffResponse, error) {
	if req.SandboxId != s.opts.SandboxID {
		return nil, status.Errorf(codes.InvalidArgument,
			"sandbox_id mismatch: request %q != server %q",
			req.SandboxId, s.opts.SandboxID)
	}
	if s.opts.OnAbort != nil {
		s.opts.OnAbort(req.Reason)
	}
	return &pb.AbortHandoffResponse{}, nil
}
