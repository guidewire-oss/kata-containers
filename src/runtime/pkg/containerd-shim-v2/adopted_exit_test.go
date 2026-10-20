// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	taskAPI "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/api/types/task"
	"github.com/stretchr/testify/assert"

	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/vcmock"
)

// A migration or warm-resume destination ADOPTS its workload containers: they
// arrive already running inside the migrated guest, so Start() short-circuits
// and startContainer() — the only place a normal container gets its exit
// watcher (go wait(...)) — never runs for them. Nothing then reports their
// exit: a teardown kill reaches the guest and the process dies, but containerd's
// StopContainer waits forever for a TaskExit, wedging the pod Terminating with
// its VM running. Observed on every migrated and resumed pod, 2026-10-19.
//
// A destination also keeps the pause (pod-sandbox) container under its own
// fresh ID, which the migrated guest does not know, so it has no guest process
// to wait on or signal at all.

const (
	adoptedDestID   = "dest-ctr-id"
	adoptedSourceID = "source-ctr-id"
)

type waitRecorder struct {
	mu    sync.Mutex
	calls []string // processIDs passed to WaitProcess
}

func (w *waitRecorder) wait(code int32) func(containerID, processID string) (int32, error) {
	return func(_, processID string) (int32, error) {
		w.mu.Lock()
		w.calls = append(w.calls, processID)
		w.mu.Unlock()
		return code, nil
	}
}

func (w *waitRecorder) snapshot() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.calls...)
}

// newAdoptedDestSvc builds an owner-mode destination service. sandboxAdopted
// makes the sandbox itself carry another sandbox's identity (a migration or
// resume destination); the container map holds one workload container whose
// guest identity is adoptedSourceID when adopted is true.
func newAdoptedDestSvc(t *testing.T, sandboxAdopted, adopted bool, rec *waitRecorder) (*service, *vcmock.Sandbox, *container) {
	t.Helper()
	mockCtr := &vcmock.Container{MockID: adoptedDestID}
	if adopted {
		mockCtr.MockInternalID = adoptedSourceID
	}
	sb := &vcmock.Sandbox{
		MockID:         testSandboxID,
		MockContainers: []*vcmock.Container{mockCtr},
	}
	if sandboxAdopted {
		sb.MockInternalID = "source-sandbox-id"
	}
	if rec != nil {
		sb.WaitProcessFunc = rec.wait(7)
	}
	s := &service{
		id:            testSandboxID,
		sandbox:       sb,
		containers:    make(map[string]*container),
		ec:            make(chan exit, bufferSize),
		ctx:           context.Background(),
		rootCtx:       context.Background(),
		migrationMode: ModeOwner,
	}
	c, err := newContainer(s, &taskAPI.CreateTaskRequest{ID: adoptedDestID}, vc.PodContainer, nil, true)
	assert.NoError(t, err)
	s.containers[adoptedDestID] = c
	return s, sb, c
}

// exitFor waits briefly for a container-level TaskExit for id on s.ec and
// returns its status, or ok=false if none arrived.
func exitFor(s *service, id string) (status uint32, ok bool) {
	deadline := time.After(2 * time.Second)
	for {
		select {
		case e := <-s.ec:
			if e.id == id && e.execid == "" {
				return uint32(e.status), true
			}
		case <-deadline:
			return 0, false
		}
	}
}

// FR-002: an adopted container's process is known to the guest by the SOURCE
// container's identity, exactly as IOStream already addresses it.
func TestWaitAddressesAdoptedContainerByGuestIdentity(t *testing.T) {
	rec := &waitRecorder{}
	s, _, c := newAdoptedDestSvc(t, true, true, rec)
	close(c.exitIOch)

	_, err := wait(context.Background(), s, c, "")
	assert.NoError(t, err)
	assert.Equal(t, []string{adoptedSourceID}, rec.snapshot(),
		"WaitProcess must use the guest identity of an adopted container, not its containerd id")
}

// FR-005: a container created on this shim is waited on by its own id, as before.
func TestWaitAddressesFreshContainerByOwnID(t *testing.T) {
	rec := &waitRecorder{}
	s, _, c := newAdoptedDestSvc(t, false, false, rec)
	close(c.exitIOch)

	_, err := wait(context.Background(), s, c, "")
	assert.NoError(t, err)
	assert.Equal(t, []string{adoptedDestID}, rec.snapshot())
}

// AC 3.1 / FR-001 / FR-003: wiring a migrated container's IO starts its exit
// watcher, exactly once even if the wiring endpoint is called again, and the
// guest's exit code is published.
func TestWiringAdoptedContainerWatchesExitOnce(t *testing.T) {
	rec := &waitRecorder{}
	s, _, _ := newAdoptedDestSvc(t, true, true, rec)
	// No stdio paths: the wiring closes exitIOch itself (the common case for a
	// migrated container whose CreateTask never landed on this host).

	s.startIOForMigratedContainers(context.Background())
	s.startIOForMigratedContainers(context.Background())

	status, ok := exitFor(s, adoptedDestID)
	assert.True(t, ok, "the adopted container's exit must be published")
	assert.Equal(t, uint32(7), status, "with the guest process's exit code")
	assert.Eventually(t, func() bool { return len(rec.snapshot()) >= 1 }, time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	assert.Len(t, rec.snapshot(), 1, "exit watcher must start at most once per container")
}

// FR-005: wiring never starts a watcher for a container this shim created
// itself — startContainer already runs one, and a second would double-reap.
func TestWiringFreshContainerStartsNoWatcher(t *testing.T) {
	rec := &waitRecorder{}
	s, _, _ := newAdoptedDestSvc(t, false, false, rec)

	s.startIOForMigratedContainers(context.Background())

	_, ok := exitFor(s, adoptedDestID)
	assert.False(t, ok)
	assert.Empty(t, rec.snapshot())
}

// AC 3.2: the destination's pause container is never given an exit watcher —
// the guest does not know its id, so WaitProcess would fail at once and wait()
// would tear down the live, just-migrated VM.
func TestWiringNeverWatchesThePodSandboxContainer(t *testing.T) {
	rec := &waitRecorder{}
	s, sb, _ := newAdoptedDestSvc(t, true, true, rec)
	var stopped atomic.Bool
	sb.StopFunc = func(bool) error { stopped.Store(true); return nil }
	pause, err := newContainer(s, &taskAPI.CreateTaskRequest{ID: testSandboxID}, vc.PodSandbox, nil, true)
	assert.NoError(t, err)
	s.containers[testSandboxID] = pause

	s.startIOForMigratedContainers(context.Background())
	time.Sleep(200 * time.Millisecond)

	for _, id := range rec.snapshot() {
		assert.NotEqual(t, testSandboxID, id, "pause container must not be waited on")
	}
	assert.False(t, stopped.Load(), "arrival must never stop the migrated VM")
}

// AC 1.1 / FR-004: on an adopted sandbox the teardown kill of the pause
// container completes the sandbox's exit locally and stops the VM — it never
// signals the guest under an id the guest does not know.
func TestKillAdoptedSandboxPauseCompletesExitLocally(t *testing.T) {
	s, sb, _ := newAdoptedDestSvc(t, true, true, nil)
	pause, err := newContainer(s, &taskAPI.CreateTaskRequest{ID: testSandboxID}, vc.PodSandbox, nil, true)
	assert.NoError(t, err)
	pause.status = task.Status_CREATED
	s.containers[testSandboxID] = pause

	signalled := false
	sb.SignalProcessFunc = func(string, string, syscall.Signal, bool) error { signalled = true; return nil }
	var mu sync.Mutex
	stopped, deleted := false, false
	sb.StopFunc = func(bool) error { mu.Lock(); stopped = true; mu.Unlock(); return nil }
	sb.DeleteFunc = func() error { mu.Lock(); deleted = true; mu.Unlock(); return nil }

	_, err = s.Kill(context.Background(), &taskAPI.KillRequest{ID: testSandboxID, Signal: uint32(syscall.SIGKILL)})
	assert.NoError(t, err)
	assert.False(t, signalled, "the guest does not know the destination pause id; it must not be signalled")
	assert.Equal(t, task.Status_STOPPED, pause.status)
	_, ok := exitFor(s, testSandboxID)
	assert.True(t, ok, "the pause container's exit must be published so StopPodSandbox completes")
	assert.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return stopped && deleted },
		2*time.Second, 10*time.Millisecond, "the VM must be stopped and the sandbox deleted")
	s.teardownWg.Wait()
}

// FR-005: a sandbox that never adopted another's identity keeps the normal
// path — the pause kill goes to the guest, and wait() does the teardown.
func TestKillFreshSandboxPauseStillSignalsGuest(t *testing.T) {
	s, sb, _ := newAdoptedDestSvc(t, false, false, nil)
	pause, err := newContainer(s, &taskAPI.CreateTaskRequest{ID: testSandboxID}, vc.PodSandbox, nil, true)
	assert.NoError(t, err)
	pause.status = task.Status_RUNNING
	s.containers[testSandboxID] = pause

	signalled := false
	sb.SignalProcessFunc = func(string, string, syscall.Signal, bool) error { signalled = true; return nil }
	var stopped atomic.Bool
	sb.StopFunc = func(bool) error { stopped.Store(true); return nil }

	_, err = s.Kill(context.Background(), &taskAPI.KillRequest{ID: testSandboxID, Signal: uint32(syscall.SIGKILL)})
	assert.NoError(t, err)
	assert.True(t, signalled)
	assert.Equal(t, task.Status_RUNNING, pause.status, "status is set by wait(), not by Kill, on the normal path")
	time.Sleep(100 * time.Millisecond)
	assert.False(t, stopped.Load(), "Kill must not stop a fresh sandbox; wait() does that after the guest pause exits")
}

// FR-005: an adopted WORKLOAD container's kill still reaches the guest — the
// guest knows it (by the source id), and wait() reports the exit.
func TestKillAdoptedWorkloadStillSignalsGuest(t *testing.T) {
	s, sb, c := newAdoptedDestSvc(t, true, true, nil)
	c.status = task.Status_CREATED
	signalled := false
	sb.SignalProcessFunc = func(string, string, syscall.Signal, bool) error { signalled = true; return nil }

	_, err := s.Kill(context.Background(), &taskAPI.KillRequest{ID: adoptedDestID, Signal: uint32(syscall.SIGTERM)})
	assert.NoError(t, err)
	assert.True(t, signalled)
}

// Ground rule 2 (MIGRATION-HARDENING-HANDOFF): no synthetic TaskExit outside confirmed post-handoff modes.
// completeAdoptedSandboxExit is a deliberate, documented exception gated to ModeOwner. A sandbox in
// ModeFailed can be a LIVE source whose migrate-out failed or a live resumed destination; a teardown kill
// there must take the existing agent-unreachable branch — container marked stopped, NO TaskExit, NO VM stop
// (#275: publishing there reaped and restarted a live source).
func TestKillAdoptedSandboxPauseInFailedModeStaysOnRule2Path(t *testing.T) {
	s, sb, _ := newAdoptedDestSvc(t, true, true, nil)
	s.migrationMode = ModeFailed
	sb.AgentReachableFunc = func() bool { return false }
	pause, err := newContainer(s, &taskAPI.CreateTaskRequest{ID: testSandboxID}, vc.PodSandbox, nil, true)
	assert.NoError(t, err)
	pause.status = task.Status_CREATED
	s.containers[testSandboxID] = pause
	var stopped atomic.Bool
	sb.StopFunc = func(bool) error { stopped.Store(true); return nil }

	_, err = s.Kill(context.Background(), &taskAPI.KillRequest{ID: testSandboxID, Signal: uint32(syscall.SIGKILL)})
	assert.NoError(t, err)
	assert.Equal(t, task.Status_STOPPED, pause.status, "still cleared for the kubelet (#268)")
	_, ok := exitFor(s, testSandboxID)
	assert.False(t, ok, "ModeFailed must never get a synthetic TaskExit (Ground rule 2, #275)")
	time.Sleep(100 * time.Millisecond)
	assert.False(t, stopped.Load(), "ModeFailed must not stop the VM from Kill")
}
