// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/experimental"
	mc "github.com/kata-containers/kata-containers/src/runtime/pkg/containerd-shim-v2/migration_coordinator"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/vcmock"
)

// liveMigrationCtx returns a context with the live_migration
// experimental feature enabled — every migration entry point gates
// on this and otherwise returns early.
func liveMigrationCtx() context.Context {
	return experimental.ContextWithExp(context.Background(),
		[]string{"live_migration"})
}

func newMigrationTestService(t *testing.T, sandbox vc.VCSandbox, socketPath string) *service {
	t.Helper()
	return &service{
		id:                          "test-sandbox",
		ctx:                         context.Background(),
		rootCtx:                     context.Background(),
		sandbox:                     sandbox,
		containers:                  map[string]*container{},
		migrationMode:               ModeOwner,
		migrationSocketPathOverride: socketPath,
	}
}

// tempSocketPath returns a writable socket path inside the test's
// temp dir. The shim service's migrationSocketPathOverride field
// (wired by newMigrationTestService) makes BeginMigrateIncoming
// bind here instead of /run/kata-containers.
func tempSocketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "migrate.sock")
}

// startDestinationServer stands up a migration_coordinator.Server
// at the given path for tests that drive the source-side flow into
// an in-process destination. Hooks default to no-ops when nil.
func startDestinationServer(t *testing.T, socketPath, sandboxID string, applier mc.StateApplier, onComplete func() error) *mc.Server {
	t.Helper()
	srv, err := mc.NewServer(mc.ServerOptions{
		SandboxID:    sandboxID,
		SocketPath:   socketPath,
		IncomingURI:  "tcp:127.0.0.1:0",
		StateApplier: applier,
		OnComplete:   onComplete,
	})
	if err != nil {
		t.Fatalf("start destination server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("destination server start: %v", err)
	}
	return srv
}

func TestBeginMigrateIncomingRequiresFeatureFlag(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, tempSocketPath(t))

	err := s.BeginMigrateIncoming(context.Background(), "tcp:127.0.0.1:0")
	if !errors.Is(err, ErrLiveMigrationDisabled) {
		t.Fatalf("expected ErrLiveMigrationDisabled, got %v", err)
	}
	assert.Equal(t, ModeOwner, s.currentMigrationMode(),
		"refused entry must not transition the mode")
}

func TestBeginMigrateIncomingHappyPath(t *testing.T) {
	var (
		migrateIncomingCalls atomic.Int32
		gotURI               atomic.Value
	)
	mock := &vcmock.Sandbox{
		MockID: "sb",
		MigrateIncomingFunc: func(uri string) error {
			migrateIncomingCalls.Add(1)
			gotURI.Store(uri)
			return nil
		},
	}
	s := newMigrationTestService(t, mock, tempSocketPath(t))

	if err := s.BeginMigrateIncoming(liveMigrationCtx(), "tcp:0.0.0.0:0"); err != nil {
		t.Fatalf("BeginMigrateIncoming: %v", err)
	}
	t.Cleanup(func() { _ = s.stopMigrationServer() })

	assert.Equal(t, ModeIncoming, s.currentMigrationMode())
	assert.Equal(t, int32(1), migrateIncomingCalls.Load(),
		"hypervisor.MigrateIncoming must be invoked exactly once")
	assert.Equal(t, "tcp:0.0.0.0:0", gotURI.Load().(string),
		"the listen URI passed in must reach the hypervisor")
}

func TestBeginMigrateIncomingRollsBackOnHypervisorError(t *testing.T) {
	mock := &vcmock.Sandbox{
		MockID: "sb",
		MigrateIncomingFunc: func(string) error {
			return errors.New("destination QEMU refused -incoming")
		},
	}
	s := newMigrationTestService(t, mock, tempSocketPath(t))

	err := s.BeginMigrateIncoming(liveMigrationCtx(), "tcp:0.0.0.0:0")
	if err == nil {
		t.Fatal("expected error when MigrateIncoming fails")
	}
	assert.Equal(t, ModeFailed, s.currentMigrationMode(),
		"a destination QEMU failure must leave the shim in Failed so the orchestrator tears it down")
}

func TestBeginMigrateIncomingRefusesFromNonOwner(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, tempSocketPath(t))
	// Pretend a previous migration left us in MigratingOut.
	s.migrationMode = ModeMigratingOut

	err := s.BeginMigrateIncoming(liveMigrationCtx(), "tcp:0.0.0.0:0")
	if !errors.Is(err, ErrInvalidMigrationTransition) {
		t.Fatalf("expected ErrInvalidMigrationTransition, got %v", err)
	}
}

func TestBeginMigrateOutHappyPath(t *testing.T) {
	// Spin up an in-process destination (the migration coordinator
	// server) and have the source-side BeginMigrateOut sequence
	// dial into it. Covers the full source-to-destination wire.
	destSocket := tempSocketPath(t)

	var (
		applied     atomic.Bool
		onCompleted atomic.Bool
	)
	dest := startDestinationServer(t, destSocket, "test-sandbox",
		func(_ context.Context, _ []byte) error {
			applied.Store(true)
			return nil
		},
		func() error {
			onCompleted.Store(true)
			return nil
		},
	)
	t.Cleanup(func() { _ = dest.Stop() })

	var (
		migrateOutCalls atomic.Int32
		statusPollCount atomic.Int32
		gotIncomingURI  atomic.Value
	)
	mock := &vcmock.Sandbox{
		MockID: "test-sandbox",
		MigrateOutFunc: func(uri string, _ vc.MigrateOptions) error {
			migrateOutCalls.Add(1)
			gotIncomingURI.Store(uri)
			return nil
		},
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			// "active" twice then "completed" — exercises the
			// polling loop without making the test wait forever.
			n := statusPollCount.Add(1)
			if n < 3 {
				return vc.MigrationStatus{Phase: "active"}, nil
			}
			return vc.MigrationStatus{Phase: "completed"}, nil
		},
	}
	s := newMigrationTestService(t, mock, "")

	ctx, cancel := context.WithTimeout(liveMigrationCtx(), 5*time.Second)
	defer cancel()
	if err := s.BeginMigrateOut(ctx, destSocket, vc.MigrateOptions{
		Capabilities: map[string]bool{"xbzrle": true},
	}); err != nil {
		t.Fatalf("BeginMigrateOut: %v", err)
	}

	assert.Equal(t, ModeMigrated, s.currentMigrationMode(),
		"source must terminate in Migrated on success")
	assert.Equal(t, int32(1), migrateOutCalls.Load(),
		"hypervisor.MigrateOut must be invoked exactly once")
	assert.True(t, applied.Load(), "destination StateApplier must have run")
	assert.True(t, onCompleted.Load(), "destination OnComplete must have run")
	assert.True(t, statusPollCount.Load() >= 3,
		"status poll loop must have iterated at least until completion")
}

func TestBeginMigrateOutRollsBackOnDialFailure(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, "")

	ctx, cancel := context.WithTimeout(liveMigrationCtx(), 500*time.Millisecond)
	defer cancel()
	err := s.BeginMigrateOut(ctx, filepath.Join(t.TempDir(), "no-such.sock"),
		vc.MigrateOptions{})
	if err == nil {
		t.Fatal("expected dial failure")
	}
	assert.Equal(t, ModeOwner, s.currentMigrationMode(),
		"dial failure must roll back to Owner — no state changed yet on the destination")
}

func TestBeginMigrateOutFailsOnHypervisorMigrateError(t *testing.T) {
	destSocket := tempSocketPath(t)
	dest := startDestinationServer(t, destSocket, "test-sandbox", nil, nil)
	t.Cleanup(func() { _ = dest.Stop() })

	mock := &vcmock.Sandbox{
		MockID: "test-sandbox",
		MigrateOutFunc: func(string, vc.MigrateOptions) error {
			return errors.New("QMP migrate refused")
		},
	}
	s := newMigrationTestService(t, mock, "")

	ctx, cancel := context.WithTimeout(liveMigrationCtx(), 2*time.Second)
	defer cancel()
	err := s.BeginMigrateOut(ctx, destSocket, vc.MigrateOptions{})
	if err == nil {
		t.Fatal("expected error from hypervisor.MigrateOut")
	}
	assert.Equal(t, ModeFailed, s.currentMigrationMode(),
		"hypervisor migrate failure is terminal — must land in Failed for orchestrator cleanup")
}

func TestBeginMigrateOutFailsOnStatusFailed(t *testing.T) {
	destSocket := tempSocketPath(t)
	dest := startDestinationServer(t, destSocket, "test-sandbox", nil, nil)
	t.Cleanup(func() { _ = dest.Stop() })

	mock := &vcmock.Sandbox{
		MockID: "test-sandbox",
		MigrateOutFunc: func(string, vc.MigrateOptions) error { return nil },
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			return vc.MigrationStatus{Phase: "failed"}, nil
		},
	}
	s := newMigrationTestService(t, mock, "")

	ctx, cancel := context.WithTimeout(liveMigrationCtx(), 2*time.Second)
	defer cancel()
	err := s.BeginMigrateOut(ctx, destSocket, vc.MigrateOptions{})
	if err == nil {
		t.Fatal("expected error when status reports failed")
	}
	assert.Equal(t, ModeFailed, s.currentMigrationMode())
}

func TestApplyIncomingSandboxStateValidatesJSON(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, "")

	valid, _ := json.Marshal(map[string]any{
		"SandboxContainer": "sb",
		"State":            "running",
		"PersistVersion":   uint(1),
	})
	if err := s.applyIncomingSandboxState(context.Background(), valid); err != nil {
		t.Fatalf("valid state should be accepted: %v", err)
	}
	if err := s.applyIncomingSandboxState(context.Background(), []byte("not json")); err == nil {
		t.Fatal("garbage payload must be rejected so the source aborts cleanly")
	}
}

func TestOnMigrationCompleteTransitionsToOwner(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeIncoming

	if err := s.onMigrationComplete(); err != nil {
		t.Fatalf("onMigrationComplete: %v", err)
	}
	assert.Equal(t, ModeOwner, s.currentMigrationMode())
}

func TestOnMigrationAbortTransitionsToFailed(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeIncoming

	s.onMigrationAbort("source crashed")
	assert.Equal(t, ModeFailed, s.currentMigrationMode())
}

// Concurrency guard: the migration server stop path is invoked from
// multiple places (Shutdown, handoff completion). Verify stop is
// idempotent even across goroutines.
func TestStopMigrationServerIsIdempotent(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, tempSocketPath(t))
	if err := s.BeginMigrateIncoming(liveMigrationCtx(), "tcp:0.0.0.0:0"); err != nil {
		t.Fatalf("BeginMigrateIncoming: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.stopMigrationServer()
		}()
	}
	wg.Wait()
}
