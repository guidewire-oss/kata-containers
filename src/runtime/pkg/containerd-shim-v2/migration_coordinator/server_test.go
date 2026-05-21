// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package migration_coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kata-containers/kata-containers/src/runtime/protocols/migration_coordinator"
)

// Small local fail-fast helpers. Only `assert` is vendored in this
// tree; these stand in for `require` so a setup failure (dial,
// listen, marshal) aborts the test instead of cascading into a wall
// of misleading errors.
func mustNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func mustTrue(t *testing.T, ok bool, msg string) {
	t.Helper()
	if !ok {
		t.Fatal(msg)
	}
}

// newTestServer constructs a server on a temp directory socket and
// starts it. The caller is responsible for stopping it (registered
// via t.Cleanup).
func newTestServer(t *testing.T, opts ServerOptions) *Server {
	t.Helper()
	if opts.SocketPath == "" {
		opts.SocketPath = filepath.Join(t.TempDir(), "migration.sock")
	}
	if opts.SandboxID == "" {
		opts.SandboxID = "test-sandbox-" + t.Name()
	}
	if opts.IncomingURI == "" {
		opts.IncomingURI = "tcp:127.0.0.1:0"
	}
	srv, err := NewServer(opts)
	mustNoError(t, err)
	mustNoError(t, srv.Start())
	t.Cleanup(func() { _ = srv.Stop() })
	return srv
}

// newTestClient dials the server. Tests that own both ends use this
// for a tight loop.
func newTestClient(t *testing.T, sandboxID, socketPath string) *Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := Dial(ctx, sandboxID, socketPath)
	mustNoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestNewServerBindsAndListens(t *testing.T) {
	srv := newTestServer(t, ServerOptions{})
	c := newTestClient(t, srv.SandboxID(), srv.SocketPath())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := c.PrepareIncoming(ctx, []string{"xbzrle"}, []byte("{}"))
	mustNoError(t, err)
	assert.Equal(t, "tcp:127.0.0.1:0", resp.IncomingUri)
}

func TestNewServerRejectsDoubleBind(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "double.sock")
	srv1 := newTestServer(t, ServerOptions{SocketPath: socket, SandboxID: "id"})
	defer srv1.Stop() //nolint:errcheck

	_, err := NewServer(ServerOptions{SocketPath: socket, SandboxID: "id"})
	if err == nil {
		_ = srv1.Stop()
		t.Fatal("expected error when binding the same socket twice")
	}
}

func TestPrepareIncomingRejectsSandboxIDMismatch(t *testing.T) {
	srv := newTestServer(t, ServerOptions{SandboxID: "correct-id"})
	c := newTestClient(t, "wrong-id", srv.SocketPath())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := c.PrepareIncoming(ctx, nil, nil)
	mustError(t, err)
	st, ok := status.FromError(err)
	mustTrue(t, ok, "error must be a gRPC status")
	assert.Equal(t, codes.InvalidArgument, st.Code(),
		"sandbox ID mismatch must be reported as InvalidArgument")
	assert.Contains(t, st.Message(), "sandbox_id",
		"error message should name the offending field")
}

func TestPrepareIncomingEchoesAcceptedCapabilities(t *testing.T) {
	srv := newTestServer(t, ServerOptions{})
	c := newTestClient(t, srv.SandboxID(), srv.SocketPath())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	requested := []string{"xbzrle", "compress", "postcopy-ram"}
	resp, err := c.PrepareIncoming(ctx, requested, nil)
	mustNoError(t, err)
	// Skeleton behaviour: every requested capability is accepted.
	// C.3 will filter against what the destination QEMU supports.
	assert.ElementsMatch(t, requested, resp.AcceptedCapabilities)
}

func TestSendSandboxStateAccumulatesAndApplies(t *testing.T) {
	var (
		mu      sync.Mutex
		applied []byte
	)
	srv := newTestServer(t, ServerOptions{
		StateApplier: func(_ context.Context, payload []byte) error {
			mu.Lock()
			defer mu.Unlock()
			applied = append([]byte(nil), payload...)
			return nil
		},
	})
	c := newTestClient(t, srv.SandboxID(), srv.SocketPath())

	payload, err := json.Marshal(map[string]any{
		"State":            "running",
		"SandboxContainer": "test-sandbox",
		"PersistVersion":   uint(1),
	})
	mustNoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := c.SendSandboxState(ctx, bytes.NewReader(payload))
	mustNoError(t, err)
	assert.Equal(t, uint64(len(payload)), resp.BytesReceived)
	assert.True(t, resp.StateApplied)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, payload, applied, "applier must see the exact bytes the source sent")
}

func TestSendSandboxStateChunksFromLargeReader(t *testing.T) {
	// 200 KiB of repeating bytes — larger than the default 64 KiB
	// chunk size, so we exercise the chunking loop.
	var (
		mu      sync.Mutex
		applied []byte
	)
	srv := newTestServer(t, ServerOptions{
		StateApplier: func(_ context.Context, payload []byte) error {
			mu.Lock()
			defer mu.Unlock()
			applied = append([]byte(nil), payload...)
			return nil
		},
	})
	c := newTestClient(t, srv.SandboxID(), srv.SocketPath())

	payload := bytes.Repeat([]byte("abcdefgh"), 200*1024/8)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.SendSandboxState(ctx, bytes.NewReader(payload))
	mustNoError(t, err)
	assert.Equal(t, uint64(len(payload)), resp.BytesReceived)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, len(payload), len(applied))
	assert.True(t, bytes.Equal(payload, applied), "reassembled payload must match the source bytes")
}

func TestSendSandboxStateRejectsSandboxIDMidstream(t *testing.T) {
	srv := newTestServer(t, ServerOptions{SandboxID: "correct-id"})
	c := newTestClient(t, "correct-id", srv.SocketPath())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := c.rpc.SendSandboxState(ctx)
	mustNoError(t, err)

	mustNoError(t, stream.Send(&pb.SandboxStateChunk{
		SandboxId:    "correct-id",
		PayloadChunk: []byte("first"),
		Final:        false,
	}))
	mustNoError(t, stream.Send(&pb.SandboxStateChunk{
		SandboxId:    "different-id",
		PayloadChunk: []byte("second"),
		Final:        true,
	}))
	_, err = stream.CloseAndRecv()
	mustError(t, err)
	st, ok := status.FromError(err)
	mustTrue(t, ok, "error must be a gRPC status")
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "sandbox_id")
}

func TestSendSandboxStateSurfacesApplierError(t *testing.T) {
	srv := newTestServer(t, ServerOptions{
		StateApplier: func(_ context.Context, _ []byte) error {
			return errors.New("simulated deserialize failure")
		},
	})
	c := newTestClient(t, srv.SandboxID(), srv.SocketPath())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := c.SendSandboxState(ctx, bytes.NewReader([]byte("not actually json")))
	mustError(t, err)
	st, ok := status.FromError(err)
	mustTrue(t, ok, "error must be a gRPC status")
	assert.Equal(t, codes.InvalidArgument, st.Code(),
		"applier failure should map to InvalidArgument so the source treats it as a state-content problem")
}

func TestCompleteHandoffHappyPath(t *testing.T) {
	var (
		mu      sync.Mutex
		invoked bool
	)
	srv := newTestServer(t, ServerOptions{
		OnComplete: func() error {
			mu.Lock()
			defer mu.Unlock()
			invoked = true
			return nil
		},
	})
	c := newTestClient(t, srv.SandboxID(), srv.SocketPath())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := c.CompleteHandoff(ctx)
	mustNoError(t, err)
	assert.True(t, resp.Owner)
	mu.Lock()
	defer mu.Unlock()
	assert.True(t, invoked, "OnComplete hook must run when CompleteHandoff RPC arrives")
}

func TestCompleteHandoffRejectsSandboxIDMismatch(t *testing.T) {
	srv := newTestServer(t, ServerOptions{SandboxID: "correct-id"})
	c := newTestClient(t, "wrong-id", srv.SocketPath())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := c.CompleteHandoff(ctx)
	mustError(t, err)
	st, ok := status.FromError(err)
	mustTrue(t, ok, "error must be a gRPC status")
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestAbortHandoffInvokesHook(t *testing.T) {
	var (
		mu        sync.Mutex
		gotReason string
	)
	srv := newTestServer(t, ServerOptions{
		OnAbort: func(reason string) {
			mu.Lock()
			defer mu.Unlock()
			gotReason = reason
		},
	})
	c := newTestClient(t, srv.SandboxID(), srv.SocketPath())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	mustNoError(t, c.AbortHandoff(ctx, "user-cancelled"))
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "user-cancelled", gotReason)
}

func TestDialFailsCleanlyForMissingSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	c, err := Dial(ctx, "any-id", filepath.Join(t.TempDir(), "does-not-exist.sock"))
	mustError(t, err)
	assert.Nil(t, c, "Dial must not return a partially-constructed client on error")
}
