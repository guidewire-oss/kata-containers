// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"syscall"
	"time"

	taskAPI "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/sirupsen/logrus"
)

// Teardown watchdog: when the kubelet tears a sandbox down (StopPodSandbox
// reaches Kill for the pod-sandbox container) and the guest cannot complete it,
// for example a dead agent, or an agent that still answers its heartbeat while
// its operations hang, every RPC queues behind s.mu while one agent call holds
// it, and the pod stays Terminating forever. The watchdog stops this shim's own
// QEMU when teardown has not finished it within teardownStallThreshold: the
// hung agent call then fails, s.mu is released, and the existing dead-QEMU
// teardown completes. It is armed before s.mu is taken and never takes s.mu.
var (
	// teardownStallThreshold is how long teardown may run before a still-alive
	// QEMU is stopped.
	teardownStallThreshold = 60 * time.Second
	// teardownFlushLimit bounds the clean QEMU shutdown (SIGTERM makes QEMU
	// drain and flush its block devices) before SIGKILL.
	teardownFlushLimit = 5 * time.Second

	signalVM = syscall.Kill
	vmAlive  = func(pid int) bool { return pid > 0 && syscall.Kill(pid, 0) == nil }
)

// noteTeardownKill reports whether r is the kubelet's teardown kill of this
// shim's pod-sandbox container and the first one seen, i.e. whether it should
// start the watchdog. A workload container kill (a restart) or an exec kill is
// not a sandbox teardown.
func (s *service) noteTeardownKill(r *taskAPI.KillRequest) bool {
	if r == nil || r.ExecID != "" || r.ID == "" || r.ID != s.id {
		return false
	}
	if sig := syscall.Signal(r.Signal); sig != syscall.SIGKILL && sig != syscall.SIGTERM {
		return false
	}
	return s.teardownWatchdogArmed.CompareAndSwap(false, true)
}

// teardownWatchdogShouldStop decides, after the threshold, whether to stop the
// VM: only while QEMU is still alive, and never while a migration transfer is
// in flight in either direction.
func teardownWatchdogShouldStop(qemuAlive bool, mode SandboxMigrationMode) bool {
	if !qemuAlive {
		return false
	}
	return mode != ModeMigratingOut && mode != ModeIncoming
}

// forceStopVM sends SIGTERM to pid, waits up to flush for it to exit, then
// sends SIGKILL. Returns the flush outcome: flushed, timed-out or failed.
func forceStopVM(pid int, flush time.Duration, kill func(int, syscall.Signal) error, alive func(int) bool) string {
	if err := kill(pid, syscall.SIGTERM); err != nil {
		_ = kill(pid, syscall.SIGKILL)
		return "failed"
	}
	deadline := time.Now().Add(flush)
	for alive(pid) {
		if time.Now().After(deadline) {
			_ = kill(pid, syscall.SIGKILL)
			return "timed-out"
		}
		time.Sleep(50 * time.Millisecond)
	}
	return "flushed"
}

// teardownWatchdog waits out the threshold, then stops a QEMU that teardown
// did not finish. Runs once per shim, on its own goroutine.
func (s *service) teardownWatchdog() {
	time.Sleep(teardownStallThreshold)
	pid := int(s.hpid)
	mode := s.currentMigrationMode()
	alive := pid > 0 && vmAlive(pid)
	log := shimLog.WithFields(logrus.Fields{
		"sandbox": s.id, "qemuPid": pid, "mode": mode, "qemuAlive": alive, "threshold": teardownStallThreshold,
	})
	if pid <= 0 || !teardownWatchdogShouldStop(alive, mode) {
		log.Info("teardown watchdog: nothing to stop")
		return
	}
	log.Warn("teardown watchdog: teardown stalled with QEMU alive; stopping the VM (layer=runtime reason=teardown-stalled)")
	outcome := forceStopVM(pid, teardownFlushLimit, signalVM, vmAlive)
	log.WithField("flush", outcome).Warn("teardown watchdog: VM stopped; existing teardown completes against the dead VM")
}
