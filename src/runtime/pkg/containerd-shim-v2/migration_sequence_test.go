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

	taskAPI "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/api/types/task"

	mc "github.com/kata-containers/kata-containers/src/runtime/pkg/containerd-shim-v2/migration_coordinator"
	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/experimental"
	persistapiAliasPkg "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/api"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/annotations"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/vcmock"
)

// persistapiAlias keeps the test-side type name short while still
// exercising the real persistapi.SandboxState — the production
// serializer encodes through that exact type.
type persistapiAlias = persistapiAliasPkg.SandboxState

// mustNoError fails the test immediately on a non-nil error.
// Stand-in for testify/require which is not vendored in this tree.
func mustNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

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

	err := s.BeginMigrateIncoming(context.Background(), "tcp:127.0.0.1:0", vc.MigrateOptions{})
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
		MigrateIncomingFunc: func(uri string, opts vc.MigrateOptions) error {
			migrateIncomingCalls.Add(1)
			gotURI.Store(uri)
			return nil
		},
	}
	s := newMigrationTestService(t, mock, tempSocketPath(t))

	if err := s.BeginMigrateIncoming(liveMigrationCtx(), "tcp:0.0.0.0:0", vc.MigrateOptions{}); err != nil {
		t.Fatalf("BeginMigrateIncoming: %v", err)
	}
	t.Cleanup(func() { _ = s.stopMigrationServer() })

	assert.Equal(t, ModeIncoming, s.currentMigrationMode())
	assert.Equal(t, int32(1), migrateIncomingCalls.Load(),
		"hypervisor.MigrateIncoming must be invoked exactly once")
	assert.Equal(t, "tcp:0.0.0.0:0", gotURI.Load().(string),
		"the listen URI passed in must reach the hypervisor")
}

// TestTransitionToOwnerDisarmsMigrationServer covers FR-056 part 1: reaching
// ModeOwner (a completed resume) must stop the destination coordinator so its
// source-inactivity watchdog can no longer abort the live guest. The
// coordinator-less hibernate restore drives no source RPCs, so without this
// disarm the watchdog fires ~SourceTimeout after a successful resume.
func TestTransitionToOwnerDisarmsMigrationServer(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, tempSocketPath(t))

	if err := s.BeginMigrateIncoming(liveMigrationCtx(), "tcp:0.0.0.0:0", vc.MigrateOptions{}); err != nil {
		t.Fatalf("BeginMigrateIncoming: %v", err)
	}
	t.Cleanup(func() { _ = s.stopMigrationServer() })

	s.migrationMu.Lock()
	armed := s.migrationServer != nil
	s.migrationMu.Unlock()
	assert.True(t, armed, "BeginMigrateIncoming must arm the coordinator")

	if err := s.transitionMigrationMode(ModeOwner); err != nil {
		t.Fatalf("transition to Owner: %v", err)
	}
	// The disarm is async (stopMigrationServer re-locks migrationMu and
	// Stop blocks on GracefulStop), so poll.
	assert.Eventually(t, func() bool {
		s.migrationMu.Lock()
		defer s.migrationMu.Unlock()
		return s.migrationServer == nil
	}, 2*time.Second, 10*time.Millisecond,
		"reaching ModeOwner must disarm (stop) the destination coordinator")
}

// TestIsIncomingActivePhase covers FR-056 part 2's phase classifier: only
// in-flight incoming-load phases count as progress; terminal/idle phases do
// not, so the watchdog can still abort a stuck or never-started incoming.
func TestIsIncomingActivePhase(t *testing.T) {
	for _, tc := range []struct {
		phase string
		want  bool
	}{
		{"setup", true},
		{"active", true},
		{"postcopy-active", true},
		{"device", true},
		{"colo", true},
		{"", false},
		{"none", false},
		{"completed", false},
		{"failed", false},
		{"cancelled", false},
		{"cancelling", false},
	} {
		assert.Equalf(t, tc.want, isIncomingActivePhase(tc.phase), "phase %q", tc.phase)
	}
}

func TestBeginMigrateIncomingRollsBackOnHypervisorError(t *testing.T) {
	mock := &vcmock.Sandbox{
		MockID: "sb",
		MigrateIncomingFunc: func(string, vc.MigrateOptions) error {
			return errors.New("destination QEMU refused -incoming")
		},
	}
	s := newMigrationTestService(t, mock, tempSocketPath(t))

	err := s.BeginMigrateIncoming(liveMigrationCtx(), "tcp:0.0.0.0:0", vc.MigrateOptions{})
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

	err := s.BeginMigrateIncoming(liveMigrationCtx(), "tcp:0.0.0.0:0", vc.MigrateOptions{})
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
	if err := s.BeginMigrateOut(ctx, destSocket, "", vc.MigrateOptions{
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
		"", vc.MigrateOptions{})
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
	err := s.BeginMigrateOut(ctx, destSocket, "", vc.MigrateOptions{})
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
		MockID:         "test-sandbox",
		MigrateOutFunc: func(string, vc.MigrateOptions) error { return nil },
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			return vc.MigrationStatus{Phase: "failed"}, nil
		},
	}
	s := newMigrationTestService(t, mock, "")

	ctx, cancel := context.WithTimeout(liveMigrationCtx(), 2*time.Second)
	defer cancel()
	err := s.BeginMigrateOut(ctx, destSocket, "", vc.MigrateOptions{})
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
	// Healthy resume: the guest is already running once the incoming load
	// finalized (the live-migration case, global-state recorded "running").
	mock.GetVMRunStateFunc = func() (string, error) { return "running", nil }
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeIncoming

	if err := s.onMigrationComplete(); err != nil {
		t.Fatalf("onMigrationComplete: %v", err)
	}
	assert.Equal(t, ModeOwner, s.currentMigrationMode())
}

// A migrate-to-file restore loads the guest paused; resumeIncomingMigratedVM
// must wait out "inmigrate", issue cont, and confirm the guest reaches
// "running" — a single cont that lands during "inmigrate" wouldn't stick.
func TestResumeIncomingMigratedVMResumesPausedGuest(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	var resumeCalls int
	mock.ResumeVMFunc = func() error { resumeCalls++; return nil }
	// inmigrate -> paused (settled) -> running (after cont).
	states := []string{"inmigrate", "paused", "running"}
	var i int
	mock.GetVMRunStateFunc = func() (string, error) {
		st := states[i]
		if i < len(states)-1 {
			i++
		}
		return st, nil
	}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeIncoming

	if err := s.resumeIncomingMigratedVM(context.Background()); err != nil {
		t.Fatalf("resumeIncomingMigratedVM: %v", err)
	}
	if resumeCalls == 0 {
		t.Fatal("expected cont (ResumeVM) to be issued for a paused restored guest")
	}
}

// When the hypervisor can't report run state (ErrMigrationNotSupported),
// fall back to a single ResumeVM — the prior behavior.
func TestResumeIncomingMigratedVMFallsBackWhenRunStateUnavailable(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	var resumeCalls int
	mock.ResumeVMFunc = func() error { resumeCalls++; return nil }
	mock.GetVMRunStateFunc = func() (string, error) { return "", vc.ErrMigrationNotSupported }
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeIncoming

	if err := s.resumeIncomingMigratedVM(context.Background()); err != nil {
		t.Fatalf("resumeIncomingMigratedVM: %v", err)
	}
	if resumeCalls != 1 {
		t.Fatalf("expected exactly one ResumeVM in fallback, got %d", resumeCalls)
	}
}

func TestOnMigrationAbortTransitionsToFailed(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeIncoming

	s.onMigrationAbort("source crashed")
	assert.Equal(t, ModeFailed, s.currentMigrationMode())
}

func TestStateReportsRunningDuringMigratingOut(t *testing.T) {
	// Verify the containerd-reaping mitigation: while in
	// MigratingOut the source's State() must report Status_RUNNING
	// regardless of the container's actual status, so containerd
	// doesn't reap the shim mid-handoff.
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, "")
	// Pre-stage a container with PAUSED status — something that
	// would normally surface to containerd as-is.
	c := &container{
		id:     "c1",
		status: task.Status_PAUSED,
	}
	s.containers["c1"] = c

	// Baseline: in Owner mode, State reports PAUSED as-is.
	ctx := context.Background()
	resp, err := s.State(ctx, &taskAPI.StateRequest{ID: "c1"})
	mustNoError(t, err)
	assert.Equal(t, task.Status_PAUSED, resp.Status,
		"Owner mode must surface the underlying status verbatim")

	// MigratingOut: State must lie and report RUNNING so
	// containerd does not reap us mid-handoff.
	s.migrationMode = ModeMigratingOut
	resp, err = s.State(ctx, &taskAPI.StateRequest{ID: "c1"})
	mustNoError(t, err)
	assert.Equal(t, task.Status_RUNNING, resp.Status,
		"MigratingOut must report Running to keep containerd from reaping the source")
}

func TestAbortMigrationFromOwnerIsNoop(t *testing.T) {
	var cancelCalls atomic.Int32
	mock := &vcmock.Sandbox{
		MockID: "sb",
		CancelMigrationFunc: func() error {
			cancelCalls.Add(1)
			return nil
		},
	}
	s := newMigrationTestService(t, mock, "")

	mustNoError(t, s.AbortMigration(context.Background(), "test"))
	assert.Equal(t, ModeOwner, s.currentMigrationMode())
	assert.Equal(t, int32(0), cancelCalls.Load(),
		"abort from Owner must not touch the hypervisor")
}

func TestAbortMigrationFromMigratingOutTransitionsAndCancels(t *testing.T) {
	var cancelCalls atomic.Int32
	mock := &vcmock.Sandbox{
		MockID: "sb",
		CancelMigrationFunc: func() error {
			cancelCalls.Add(1)
			return nil
		},
	}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeMigratingOut

	mustNoError(t, s.AbortMigration(context.Background(), "user-requested"))
	assert.Equal(t, ModeFailed, s.currentMigrationMode())
	assert.Equal(t, int32(1), cancelCalls.Load())
}

func TestAbortMigrationFromIncomingStopsServerAndTransitions(t *testing.T) {
	var cancelCalls atomic.Int32
	mock := &vcmock.Sandbox{
		MockID: "sb",
		CancelMigrationFunc: func() error {
			cancelCalls.Add(1)
			return nil
		},
	}
	s := newMigrationTestService(t, mock, tempSocketPath(t))
	mustNoError(t, s.BeginMigrateIncoming(liveMigrationCtx(), "tcp:0.0.0.0:0", vc.MigrateOptions{}))

	mustNoError(t, s.AbortMigration(context.Background(), "destination giving up"))
	assert.Equal(t, ModeFailed, s.currentMigrationMode())
	assert.Equal(t, int32(1), cancelCalls.Load())
	// stopMigrationServer cleared migrationServer; verify second
	// call is a no-op rather than a panic.
	mustNoError(t, s.stopMigrationServer())
}

func TestAbortMigrationIsIdempotent(t *testing.T) {
	var cancelCalls atomic.Int32
	mock := &vcmock.Sandbox{
		MockID: "sb",
		CancelMigrationFunc: func() error {
			cancelCalls.Add(1)
			return nil
		},
	}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeMigratingOut

	mustNoError(t, s.AbortMigration(context.Background(), "first"))
	mustNoError(t, s.AbortMigration(context.Background(), "second"))
	assert.Equal(t, ModeFailed, s.currentMigrationMode())
	assert.Equal(t, int32(1), cancelCalls.Load(),
		"second call should be a no-op — we're already terminal")
}

func TestSerializeSandboxStateUsesDump(t *testing.T) {
	// The source-side serializer must hand back whatever DumpState
	// returns, JSON-encoded. The mock returns a recognizable
	// payload and the test round-trips through the decoder.
	mock := &vcmock.Sandbox{
		MockID: "sb-with-state",
		DumpStateFunc: func() (persistapiAlias, error) {
			return persistapiAlias{
				SandboxContainer: "sb-with-state",
				State:            "running",
				PersistVersion:   42,
				CgroupPaths: map[string]string{
					"memory": "/sys/fs/cgroup/memory/kata/sb-with-state",
				},
			}, nil
		},
	}
	s := newMigrationTestService(t, mock, "")

	bytes, err := s.serializeSandboxState()
	if err != nil {
		t.Fatalf("serializeSandboxState: %v", err)
	}
	var got persistapiAlias
	if err := json.Unmarshal(bytes, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	assert.Equal(t, "sb-with-state", got.SandboxContainer)
	assert.Equal(t, "running", got.State)
	assert.Equal(t, uint(42), got.PersistVersion)
	assert.Equal(t, "/sys/fs/cgroup/memory/kata/sb-with-state",
		got.CgroupPaths["memory"])
}

func TestPollBackoffDoublesAndCaps(t *testing.T) {
	b := newPollBackoff(50*time.Millisecond, 400*time.Millisecond)
	got := []time.Duration{
		b.wait(), b.wait(), b.wait(), b.wait(), b.wait(),
	}
	want := []time.Duration{
		50 * time.Millisecond,
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		400 * time.Millisecond, // capped
	}
	assert.Equal(t, want, got, "backoff must double then cap")
}

func TestPollBackoffReset(t *testing.T) {
	b := newPollBackoff(50*time.Millisecond, 400*time.Millisecond)
	_ = b.wait()
	_ = b.wait()
	b.reset(50 * time.Millisecond)
	assert.Equal(t, 50*time.Millisecond, b.wait(),
		"reset must restart the cursor at the initial value")
}

// TestRewriteIncomingHost pins the host-selection precedence used
// when the source's QEMU is told where to dial for the actual
// memory transfer:
//
//  1. dataHostHint wins when non-empty — this is the orchestrator's
//     escape hatch for kata's "QEMU lives in pod netns" reality,
//     where the coordinator's host (a node IP) doesn't reach QEMU.
//  2. fall back to the host portion of dialTarget — preserves the
//     pre-hint behavior for legacy callers and for shim arrangements
//     where the coordinator and QEMU share a network namespace.
//
// Malformed inputs return the incoming URI unchanged rather than
// stalling the migration with an error.
func TestRewriteIncomingHost(t *testing.T) {
	cases := []struct {
		name       string
		incoming   string
		dialTarget string
		hint       string
		want       string
	}{
		{
			name:       "dataHostHint wins when supplied",
			incoming:   "tcp:0.0.0.0:4444",
			dialTarget: "tcp:10.0.0.1:42000",
			hint:       "10.0.5.42",
			want:       "tcp:10.0.5.42:4444",
		},
		{
			name:       "dataHostHint wins over dialTarget even when dialTarget is reachable",
			incoming:   "tcp:[::]:4444",
			dialTarget: "tcp:10.0.0.1:42000",
			hint:       "10.0.5.42",
			want:       "tcp:10.0.5.42:4444",
		},
		{
			name:       "falls back to dialTarget host when hint is empty",
			incoming:   "tcp:0.0.0.0:4444",
			dialTarget: "tcp:10.0.0.1:42000",
			hint:       "",
			want:       "tcp:10.0.0.1:4444",
		},
		{
			name:       "non-tcp incoming URI is returned unchanged",
			incoming:   "unix:/var/run/kata.sock",
			dialTarget: "tcp:10.0.0.1:42000",
			hint:       "10.0.5.42",
			want:       "unix:/var/run/kata.sock",
		},
		{
			name:       "missing port in incoming URI is returned unchanged",
			incoming:   "tcp:0.0.0.0",
			dialTarget: "tcp:10.0.0.1:42000",
			hint:       "10.0.5.42",
			want:       "tcp:0.0.0.0",
		},
		{
			name:       "non-tcp dialTarget with empty hint preserves incoming",
			incoming:   "tcp:0.0.0.0:4444",
			dialTarget: "unix:/var/run/coord.sock",
			hint:       "",
			want:       "tcp:0.0.0.0:4444",
		},
		{
			name:       "host:port dataHostHint fully overrides both host and port",
			incoming:   "tcp:0.0.0.0:4444",
			dialTarget: "tcp:10.0.0.1:42000",
			hint:       "10.0.0.5:55432",
			want:       "tcp:10.0.0.5:55432",
		},
		{
			name:       "bracketed IPv6 host:port dataHostHint is preserved",
			incoming:   "tcp:0.0.0.0:4444",
			dialTarget: "tcp:10.0.0.1:42000",
			hint:       "[::1]:55432",
			want:       "tcp:[::1]:55432",
		},
		{
			name:       "bare IPv6 host (unbracketed) is treated as host-only, port from incoming",
			incoming:   "tcp:0.0.0.0:4444",
			dialTarget: "tcp:10.0.0.1:42000",
			hint:       "::1",
			want:       "tcp:[::1]:4444",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rewriteIncomingHost(tc.incoming, tc.dialTarget, tc.hint)
			if got != tc.want {
				t.Errorf("rewriteIncomingHost(%q, %q, %q) = %q, want %q",
					tc.incoming, tc.dialTarget, tc.hint, got, tc.want)
			}
		})
	}
}

// Concurrency guard: the migration server stop path is invoked from
// multiple places (Shutdown, handoff completion). Verify stop is
// idempotent even across goroutines.
func TestStopMigrationServerIsIdempotent(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, tempSocketPath(t))
	if err := s.BeginMigrateIncoming(liveMigrationCtx(), "tcp:0.0.0.0:0", vc.MigrateOptions{}); err != nil {
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

// TestParseIncomingMigrateOptions covers the annotation → MigrateOptions
// mapping for the multifd knobs. Behaviour under malformed input is
// "ignore, log, continue" — the absence of multifd config must NEVER
// fail a sandbox create.
func TestParseIncomingMigrateOptions(t *testing.T) {
	t.Run("empty annotations gives empty opts", func(t *testing.T) {
		opts := parseIncomingMigrateOptions(map[string]string{})
		assert.Nil(t, opts.Capabilities)
		assert.Nil(t, opts.Parameters)
		assert.Nil(t, opts.StringParameters)
	})

	t.Run("multifd-channels enables multifd cap + sets channel count", func(t *testing.T) {
		opts := parseIncomingMigrateOptions(map[string]string{
			annotations.MigrationMultifdChannels: "8",
		})
		assert.True(t, opts.Capabilities["multifd"], "multifd cap must be enabled")
		assert.Equal(t, uint64(8), opts.Parameters["multifd-channels"])
	})

	t.Run("compression alone is honoured (QEMU rejects misconfig loudly)", func(t *testing.T) {
		opts := parseIncomingMigrateOptions(map[string]string{
			annotations.MigrationMultifdCompression: "zstd",
		})
		assert.Equal(t, "zstd", opts.StringParameters["multifd-compression"])
		assert.Nil(t, opts.Capabilities, "no channels => no multifd cap")
	})

	t.Run("zstd level parsed when present", func(t *testing.T) {
		opts := parseIncomingMigrateOptions(map[string]string{
			annotations.MigrationMultifdChannels:    "4",
			annotations.MigrationMultifdCompression: "zstd",
			annotations.MigrationMultifdZstdLevel:   "3",
		})
		assert.True(t, opts.Capabilities["multifd"])
		assert.Equal(t, uint64(4), opts.Parameters["multifd-channels"])
		assert.Equal(t, uint64(3), opts.Parameters["multifd-zstd-level"])
		assert.Equal(t, "zstd", opts.StringParameters["multifd-compression"])
	})

	t.Run("malformed channel count is ignored (degrades to off)", func(t *testing.T) {
		opts := parseIncomingMigrateOptions(map[string]string{
			annotations.MigrationMultifdChannels: "not-a-number",
		})
		assert.Nil(t, opts.Capabilities)
		assert.Nil(t, opts.Parameters)
	})

	t.Run("zero channels treated as absent (no multifd cap)", func(t *testing.T) {
		opts := parseIncomingMigrateOptions(map[string]string{
			annotations.MigrationMultifdChannels: "0",
		})
		assert.Nil(t, opts.Capabilities)
		assert.Nil(t, opts.Parameters)
	})
}

func TestBeginMigrateSaveRequiresFeatureFlag(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, "")

	_, err := s.BeginMigrateSave(context.Background(), "tcp:127.0.0.1:9999", vc.MigrateOptions{})
	if !errors.Is(err, ErrLiveMigrationDisabled) {
		t.Fatalf("expected ErrLiveMigrationDisabled, got %v", err)
	}
	assert.Equal(t, ModeOwner, s.currentMigrationMode(),
		"refused entry must not transition the mode")
}

func TestBeginMigrateSaveHappyPath(t *testing.T) {
	var (
		pauseCalls      atomic.Int32
		resumeCalls     atomic.Int32
		migrateOutCalls atomic.Int32
		statusPollCount atomic.Int32
		gotURI          atomic.Value
	)
	mock := &vcmock.Sandbox{
		MockID:      "sb",
		PauseVMFunc: func() error { pauseCalls.Add(1); return nil },
		ResumeVMFunc: func() error {
			resumeCalls.Add(1)
			return nil
		},
		MigrateOutFunc: func(uri string, _ vc.MigrateOptions) error {
			migrateOutCalls.Add(1)
			gotURI.Store(uri)
			return nil
		},
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			if statusPollCount.Add(1) < 3 {
				return vc.MigrationStatus{Phase: "active"}, nil
			}
			return vc.MigrationStatus{Phase: "completed"}, nil
		},
	}
	s := newMigrationTestService(t, mock, "")

	ctx, cancel := context.WithTimeout(liveMigrationCtx(), 5*time.Second)
	defer cancel()
	state, err := s.BeginMigrateSave(ctx, "tcp:127.0.0.1:9999", vc.MigrateOptions{})
	if err != nil {
		t.Fatalf("BeginMigrateSave: %v", err)
	}

	// Split-save contract: BeginMigrateSave leaves the sandbox in
	// ModeMigratingOut (paused, streamed out, agent conn still open) so the
	// caller can capture the workload rootfs before the ModeSaved teardown
	// unmounts it. The mode advances to Saved only on FinalizeMigrateSave.
	assert.Equal(t, ModeMigratingOut, s.currentMigrationMode(),
		"BeginMigrateSave must stay in MigratingOut so the rootfs stays mounted for capture")
	assert.Equal(t, int32(1), pauseCalls.Load(), "guest must be paused before the save")
	assert.Equal(t, int32(0), resumeCalls.Load(), "success must NOT resume — the VM stays paused for teardown")
	assert.Equal(t, int32(1), migrateOutCalls.Load())
	assert.Equal(t, "tcp:127.0.0.1:9999", gotURI.Load().(string),
		"the sink URI must reach the hypervisor unchanged")
	assert.NotEmpty(t, state, "serialized sandbox state must be returned for the restore path")

	// FinalizeMigrateSave advances to Saved — pod delete then runs the normal
	// teardown (no orphans). The agent connection is closed here, not in
	// BeginMigrateSave, so the rootfs capture window stays open until now.
	if err := s.FinalizeMigrateSave(ctx); err != nil {
		t.Fatalf("FinalizeMigrateSave: %v", err)
	}
	assert.Equal(t, ModeSaved, s.currentMigrationMode(),
		"FinalizeMigrateSave terminates the save in Saved — pod delete runs normal teardown, no orphans")
	assert.Equal(t, int32(0), resumeCalls.Load(), "finalize must not resume the guest")
}

func TestFinalizeMigrateSaveRejectsWithoutPriorSave(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, "")

	// No BeginMigrateSave first: the sandbox is in ModeOwner, which cannot jump
	// straight to Saved. The endpoint maps this to 409, not a teardown.
	err := s.FinalizeMigrateSave(context.Background())
	assert.ErrorIs(t, err, ErrInvalidMigrationTransition,
		"finalize without a prior save must be rejected, not silently torn down")
	assert.Equal(t, ModeOwner, s.currentMigrationMode(),
		"a rejected finalize must not change the mode")
}

func TestBeginMigrateSaveResumesOnMigrateError(t *testing.T) {
	var resumeCalls atomic.Int32
	mock := &vcmock.Sandbox{
		MockID:       "sb",
		ResumeVMFunc: func() error { resumeCalls.Add(1); return nil },
		MigrateOutFunc: func(string, vc.MigrateOptions) error {
			return errors.New("QMP migrate refused")
		},
	}
	s := newMigrationTestService(t, mock, "")

	ctx, cancel := context.WithTimeout(liveMigrationCtx(), 2*time.Second)
	defer cancel()
	_, err := s.BeginMigrateSave(ctx, "tcp:127.0.0.1:9999", vc.MigrateOptions{})
	if err == nil {
		t.Fatal("expected error from hypervisor.MigrateOut")
	}
	assert.Equal(t, int32(1), resumeCalls.Load(),
		"a failed save must resume the guest — the workload stays running")
	assert.Equal(t, ModeOwner, s.currentMigrationMode(),
		"a failed save returns to Owner: nothing was handed off, the sandbox is still authoritative")
}

func TestBeginMigrateSaveStaysOwnerOnPauseError(t *testing.T) {
	var migrateOutCalls atomic.Int32
	mock := &vcmock.Sandbox{
		MockID:      "sb",
		PauseVMFunc: func() error { return errors.New("QMP stop refused") },
		MigrateOutFunc: func(string, vc.MigrateOptions) error {
			migrateOutCalls.Add(1)
			return nil
		},
	}
	s := newMigrationTestService(t, mock, "")

	ctx, cancel := context.WithTimeout(liveMigrationCtx(), 2*time.Second)
	defer cancel()
	_, err := s.BeginMigrateSave(ctx, "tcp:127.0.0.1:9999", vc.MigrateOptions{})
	if err == nil {
		t.Fatal("expected error from PauseVM")
	}
	assert.Equal(t, int32(0), migrateOutCalls.Load(),
		"no state may be streamed when the guest could not be frozen")
	assert.Equal(t, ModeOwner, s.currentMigrationMode())
}

func TestModeSavedTransitionsAndTeardownSemantics(t *testing.T) {
	assert.True(t, canTransitionMigrationMode(ModeMigratingOut, ModeSaved),
		"a save terminates MigratingOut in Saved")
	assert.False(t, canTransitionMigrationMode(ModeSaved, ModeOwner),
		"Saved is terminal")
	// Saved gates ops like Migrated: reads + cleanup only — cleanup is what
	// lets pod delete drive the normal teardown that prevents orphans.
	assert.NoError(t, checkMigrationModeAllowsOp(ModeSaved, "state"))
	assert.Error(t, checkMigrationModeAllowsOp(ModeSaved, "exec"))
}

func TestAbortReasonSurfacesForObservability(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, "")
	if err := s.transitionMigrationMode(ModeIncoming); err != nil {
		t.Fatalf("enter incoming: %v", err)
	}

	s.onMigrationAbort("source timeout: no activity for 5m0s")

	assert.Equal(t, ModeFailed, s.currentMigrationMode())
	s.migrationMu.Lock()
	reason := s.migrationAbortReason
	s.migrationMu.Unlock()
	assert.Equal(t, "source timeout: no activity for 5m0s", reason,
		"the abort cause must be recorded so /migration/status never reports mode=failed with a null lastError")
}
