// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"sync"
	"syscall"
	"testing"
	"time"

	taskAPI "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/stretchr/testify/assert"
)

// A sandbox teardown whose guest cannot complete it (a dead agent, or an agent
// that answers its heartbeat while its operations hang) used to wait forever:
// every RPC queues behind s.mu while one agent call holds it. The watchdog
// stops the shim's own QEMU when teardown has not finished it within the
// threshold; the hung agent call then fails, s.mu is released, and the
// existing dead-QEMU teardown completes.

func TestTeardownWatchdogShouldStop(t *testing.T) {
	cases := []struct {
		name      string
		qemuAlive bool
		mode      SandboxMigrationMode
		want      bool
	}{
		{"teardown finished normally: QEMU already gone", false, ModeOwner, false},
		{"owner, QEMU still alive after the threshold", true, ModeOwner, true},
		{"migrated source, paused QEMU still alive", true, ModeMigrated, true},
		{"saved source, paused QEMU still alive", true, ModeSaved, true},
		{"failed, QEMU still alive", true, ModeFailed, true},
		{"outbound transfer in flight: never", true, ModeMigratingOut, false},
		{"inbound transfer in flight: never", true, ModeIncoming, false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, teardownWatchdogShouldStop(tc.qemuAlive, tc.mode), tc.name)
	}
}

type fakeVM struct {
	mu         sync.Mutex
	alive      bool
	exitOnTerm bool
	signals    []syscall.Signal
}

func (f *fakeVM) kill(_ int, sig syscall.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signals = append(f.signals, sig)
	if sig == syscall.SIGKILL || (sig == syscall.SIGTERM && f.exitOnTerm) {
		f.alive = false
	}
	return nil
}

func (f *fakeVM) isAlive(int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alive
}

func (f *fakeVM) sent() []syscall.Signal {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]syscall.Signal(nil), f.signals...)
}

func TestForceStopVMFlushesFirst(t *testing.T) {
	vm := &fakeVM{alive: true, exitOnTerm: true}
	outcome := forceStopVM(4242, time.Second, vm.kill, vm.isAlive)
	assert.Equal(t, "flushed", outcome)
	assert.Equal(t, []syscall.Signal{syscall.SIGTERM}, vm.sent(), "a QEMU that exits on SIGTERM needs no SIGKILL")
}

func TestForceStopVMKillsAfterTheFlushLimit(t *testing.T) {
	vm := &fakeVM{alive: true, exitOnTerm: false}
	start := time.Now()
	outcome := forceStopVM(4242, 150*time.Millisecond, vm.kill, vm.isAlive)
	assert.Equal(t, "timed-out", outcome)
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.Equal(t, []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}, vm.sent())
	assert.False(t, vm.isAlive(1))
}

func TestNoteTeardownKillStartsOncePerSandboxTeardown(t *testing.T) {
	s := &service{id: "sandbox-id"}
	kill := func(id, exec string, sig syscall.Signal) *taskAPI.KillRequest {
		return &taskAPI.KillRequest{ID: id, ExecID: exec, Signal: uint32(sig)}
	}
	assert.False(t, s.noteTeardownKill(kill("workload-id", "", syscall.SIGKILL)),
		"a workload container kill (e.g. a restart) is not a sandbox teardown")
	assert.False(t, s.noteTeardownKill(kill("sandbox-id", "exec-1", syscall.SIGKILL)), "an exec kill is not a teardown")
	assert.False(t, s.noteTeardownKill(kill("sandbox-id", "", syscall.SIGUSR1)), "only SIGKILL/SIGTERM tear down")
	assert.True(t, s.noteTeardownKill(kill("sandbox-id", "", syscall.SIGKILL)), "StopPodSandbox starts the watchdog")
	assert.False(t, s.noteTeardownKill(kill("sandbox-id", "", syscall.SIGKILL)), "kubelet retries must not start another")
}

func TestTeardownWatchdogStopsAStuckVMOnly(t *testing.T) {
	defer func(th, fl time.Duration, k func(int, syscall.Signal) error, a func(int) bool) {
		teardownStallThreshold, teardownFlushLimit, signalVM, vmAlive = th, fl, k, a
	}(teardownStallThreshold, teardownFlushLimit, signalVM, vmAlive)
	teardownStallThreshold, teardownFlushLimit = 20*time.Millisecond, 100*time.Millisecond

	stuck := &fakeVM{alive: true, exitOnTerm: true}
	signalVM, vmAlive = stuck.kill, stuck.isAlive
	(&service{id: "sb", hpid: 4242, migrationMode: ModeOwner}).teardownWatchdog()
	assert.Equal(t, []syscall.Signal{syscall.SIGTERM}, stuck.sent(), "a VM still alive after the threshold is stopped")

	gone := &fakeVM{alive: false}
	signalVM, vmAlive = gone.kill, gone.isAlive
	(&service{id: "sb", hpid: 4242, migrationMode: ModeOwner}).teardownWatchdog()
	assert.Empty(t, gone.sent(), "a teardown that finished normally is left alone")

	moving := &fakeVM{alive: true}
	signalVM, vmAlive = moving.kill, moving.isAlive
	(&service{id: "sb", hpid: 4242, migrationMode: ModeMigratingOut}).teardownWatchdog()
	assert.Empty(t, moving.sent(), "a transfer in flight is never stopped")

	none := &fakeVM{alive: true}
	signalVM, vmAlive = none.kill, none.isAlive
	(&service{id: "sb", hpid: 0, migrationMode: ModeOwner}).teardownWatchdog()
	assert.Empty(t, none.sent(), "no recorded QEMU pid: nothing to signal")
}

// Spec 060 Decision 8: the kubelet kills the workload containers first and sends
// StopPodSandbox minutes later (if at all) when the guest cannot answer, so the
// watchdog must also arm on the first teardown kill that cannot reach the agent.
func TestUnreachableAgentTeardownKillArmsTheWatchdog(t *testing.T) {
	s, _ := newTeardownSvc(t, ModeOwner, true /* agent unreachable */)
	_, err := s.Kill(context.Background(), &taskAPI.KillRequest{ID: testContainerID, Signal: uint32(syscall.SIGTERM)})
	assert.NoError(t, err)
	assert.True(t, s.teardownWatchdogArmed.Load(), "a workload kill that cannot reach the agent arms the watchdog")
}

func TestReachableAgentWorkloadKillDoesNotArmTheWatchdog(t *testing.T) {
	s, _ := newTeardownSvc(t, ModeOwner, false /* agent reachable */)
	_, _ = s.Kill(context.Background(), &taskAPI.KillRequest{ID: testContainerID, Signal: uint32(syscall.SIGTERM)})
	assert.False(t, s.teardownWatchdogArmed.Load(), "an ordinary kill (e.g. a restart) on a healthy guest never arms it")
}
