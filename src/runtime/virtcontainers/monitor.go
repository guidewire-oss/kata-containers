// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	"github.com/pkg/errors"
)

const (
	defaultCheckInterval = 5 * time.Second
	watcherChannelSize   = 128

	// kata-monitor-instr-v1: unique marker so we can prove the patched
	// binary is the one running (used by build-verify scripts via `strings`).
	monitorInstrMarker = "kata-monitor-instr-v1"

	// agentDeathFailStreakThreshold is how many CONSECUTIVE agent-ping
	// failures must accumulate before the monitor concludes the agent is
	// dead and escalates to Stop+Delete. A single miss is not proof the VM
	// is dead: the agent can be transiently unresponsive (vCPU/vsock
	// starvation while a freshly resumed/migrated guest re-pairs and
	// stabilizes, a long GC pause, RAM-transfer starvation at high migrate
	// bandwidth) while QEMU stays healthy. Each failing check blocks for the
	// agent CheckRequest timeout (~30s), so this is ~1.5min of SUSTAINED
	// unresponsiveness before a kill. Genuine agent death stays dead and is
	// still caught; a momentary miss recovers on the next check (which resets
	// the streak). watchHypervisor independently catches genuine QEMU death,
	// so the agent-death path only needs to catch "QEMU alive but agent
	// wedged" — credible only after several consecutive misses.
	agentDeathFailStreakThreshold = 3
)

var monitorLog = virtLog.WithField("subsystem", "virtcontainers/monitor")

// nolint: govet
type monitor struct {
	watchers []chan error
	sandbox  *Sandbox

	wg sync.WaitGroup
	sync.Mutex

	stopCh        chan bool
	checkInterval time.Duration

	running bool

	// agentEverOK is set the first time the in-guest agent answers a health
	// check on this monitor's lifetime. Distinct from lastAgentCheckOK
	// (which is pre-seeded to "now" at construction): agentEverOK starts
	// false and only flips on a real success. Used to hold off the
	// agent-death Stop+Delete for a migrated-IN sandbox until its agent has
	// actually re-paired at least once.
	agentEverOK atomic.Bool

	// instrumentation: track consecutive check failures + last success time
	lastAgentCheckOK      atomic.Int64 // unix seconds
	lastHypervisorCheckOK atomic.Int64 // unix seconds
	agentCheckFailStreak  atomic.Int64
	hyperCheckFailStreak  atomic.Int64
	totalAgentChecks      atomic.Int64
	totalHyperChecks      atomic.Int64
	totalAgentFailures    atomic.Int64
	totalHyperFailures    atomic.Int64
}

func newMonitor(s *Sandbox) *monitor {
	// there should only be one monitor for one sandbox,
	// so it's safe to let monitorLog as a global variable.
	monitorLog = monitorLog.WithField("sandbox", s.ID())
	m := &monitor{
		sandbox:       s,
		checkInterval: defaultCheckInterval,
		stopCh:        make(chan bool, 1),
	}
	now := time.Now().Unix()
	m.lastAgentCheckOK.Store(now)
	m.lastHypervisorCheckOK.Store(now)
	monitorLog.WithFields(map[string]interface{}{
		"marker":           monitorInstrMarker,
		"checkIntervalSec": int(m.checkInterval.Seconds()),
		"sandboxID":        s.ID(),
	}).Info("kata-monitor: created (instrumented)")
	return m
}

func (m *monitor) newWatcher(ctx context.Context) (chan error, error) {
	m.Lock()
	defer m.Unlock()

	watcher := make(chan error, watcherChannelSize)
	m.watchers = append(m.watchers, watcher)

	if !m.running {
		m.running = true
		m.wg.Add(1)

		// create and start agent watcher
		go func() {
			tick := time.NewTicker(m.checkInterval)
			for {
				select {
				case <-m.stopCh:
					tick.Stop()
					m.wg.Done()
					return
				case <-tick.C:
					m.watchHypervisor(ctx)
					m.watchAgent(ctx)
				}
			}
		}()
	}

	return watcher, nil
}

func (m *monitor) notify(ctx context.Context, err error) {
	// INSTR: dump everything we know about the failure context so a
	// post-mortem reader can answer "why did the shim kill QEMU?" without
	// having to repro the bug.
	now := time.Now().Unix()
	agentLastOK := m.lastAgentCheckOK.Load()
	hyperLastOK := m.lastHypervisorCheckOK.Load()
	fields := map[string]interface{}{
		"marker":                        monitorInstrMarker,
		"sandboxID":                     m.sandbox.ID(),
		"errType":                       fmt.Sprintf("%T", err),
		"errChain":                      fmt.Sprintf("%+v", err),
		"agentCheckFailStreak":          m.agentCheckFailStreak.Load(),
		"hyperCheckFailStreak":          m.hyperCheckFailStreak.Load(),
		"secSinceLastAgentCheckOK":      now - agentLastOK,
		"secSinceLastHypervisorCheckOK": now - hyperLastOK,
		"totalAgentChecks":              m.totalAgentChecks.Load(),
		"totalAgentFailures":            m.totalAgentFailures.Load(),
		"totalHyperChecks":              m.totalHyperChecks.Load(),
		"totalHyperFailures":            m.totalHyperFailures.Load(),
		"stack":                         string(debug.Stack()),
	}
	monitorLog.WithError(err).WithFields(fields).Error("INSTR: kata-monitor.notify: about to mark agent dead AND forward error to watchSandbox (which calls Stop+Delete)")

	m.sandbox.agent.markDead(ctx)

	m.Lock()
	defer m.Unlock()

	if !m.running {
		monitorLog.WithError(err).Warn("INSTR: kata-monitor.notify: monitor not running, dropping error")
		return
	}

	// a watcher is not supposed to close the channel
	// but just in case...
	defer func() {
		if x := recover(); x != nil {
			monitorLog.Warnf("watcher closed channel: %v", x)
		}
	}()

	for i, c := range m.watchers {
		monitorLog.WithError(err).WithField("watcherIdx", i).Warn("INSTR: kata-monitor.notify: writing error to watcher (this is what triggers watchSandbox Stop+Delete)")
		// throw away message can not write to channel
		// make it not stuck, the first error is useful.
		select {
		case c <- err:

		default:
			monitorLog.WithField("channel-size", watcherChannelSize).Warnf("watcher channel is full, throw notify message")
		}
	}
}

func (m *monitor) stop() {
	// wait outside of monitor lock for the watcher channel to exit.
	defer m.wg.Wait()
	monitorLog.Info("stopping monitor")

	m.Lock()
	defer m.Unlock()

	if !m.running {
		return
	}

	m.stopCh <- true
	defer func() {
		m.watchers = nil
		m.running = false
	}()

	// a watcher is not supposed to close the channel
	// but just in case...
	defer func() {
		if x := recover(); x != nil {
			monitorLog.Warnf("watcher closed channel: %v", x)
		}
	}()

	for _, c := range m.watchers {
		close(c)
	}
}

func (m *monitor) watchAgent(ctx context.Context) {
	m.totalAgentChecks.Add(1)
	start := time.Now()
	err := m.sandbox.agent.check(ctx)
	dur := time.Since(start)
	if err != nil {
		streak := m.agentCheckFailStreak.Add(1)
		m.totalAgentFailures.Add(1)
		monitorLog.WithError(err).WithFields(map[string]interface{}{
			"marker":     monitorInstrMarker,
			"errType":    fmt.Sprintf("%T", err),
			"durationMs": dur.Milliseconds(),
			"failStreak": streak,
			"totalCheck": m.totalAgentChecks.Load(),
			"totalFail":  m.totalAgentFailures.Load(),
		}).Warn("INSTR: kata-monitor.watchAgent: agent.check failed")
		// During a live migration the in-guest agent can be transiently
		// unresponsive — its CPU/vsock is starved by the RAM transfer
		// (acutely so at a high migrate max-bandwidth) while QEMU itself
		// stays healthy. An agent-ping miss here is NOT evidence the VM is
		// dead, and the hypervisor check (watchHypervisor) independently
		// guards genuine VM death. Stopping the sandbox on this miss would
		// destroy the very VM the migration is preserving, so suppress the
		// notify (Stop+Delete) path while a migration is in progress.
		if m.migrationActive(ctx) {
			monitorLog.WithError(err).WithFields(map[string]interface{}{
				"marker":     monitorInstrMarker,
				"failStreak": streak,
			}).Warn("kata-monitor.watchAgent: agent unresponsive during active migration — NOT stopping sandbox (hypervisor check still guards VM death)")
			return
		}
		// Outside migration, still don't kill on the first miss: a single
		// timed-out ping is not proof the VM is dead (transient vsock/vCPU
		// starvation while a just-resumed guest stabilizes, a GC pause, etc.).
		// Killing here has been observed to SIGKILL a healthy freshly-resumed
		// VM whose agent needed a moment — after which the pod's sandbox is
		// recreated in incoming mode and hangs. Require a sustained streak;
		// watchHypervisor still catches genuine QEMU death immediately.
		if streak < agentDeathFailStreakThreshold {
			monitorLog.WithError(err).WithFields(map[string]interface{}{
				"marker":     monitorInstrMarker,
				"failStreak": streak,
				"threshold":  agentDeathFailStreakThreshold,
			}).Warn("kata-monitor.watchAgent: agent unresponsive but under death threshold — deferring Stop+Delete (hypervisor check still guards VM death)")
			return
		}
		// TODO: define and export error types
		m.notify(ctx, errors.Wrapf(err, "failed to ping agent"))
		return
	}
	// success: reset streak, update last-OK timestamp
	if prev := m.agentCheckFailStreak.Swap(0); prev > 0 {
		monitorLog.WithFields(map[string]interface{}{
			"marker":     monitorInstrMarker,
			"prevStreak": prev,
			"durationMs": dur.Milliseconds(),
		}).Info("INSTR: kata-monitor.watchAgent: agent.check recovered after failure streak")
	}
	m.lastAgentCheckOK.Store(time.Now().Unix())
	m.agentEverOK.Store(true)
}

// migrationActive reports whether the sandbox is in the middle of a live
// migration, on either side. Used by watchAgent to suppress the agent-dead
// Stop+Delete path: during migration an agent-ping miss is expected (the
// agent's CPU/vsock is starved by the RAM transfer) and is not evidence the
// VM is dead.
func (m *monitor) migrationActive(ctx context.Context) bool {
	if m.sandbox == nil {
		return false
	}
	// Incoming (destination) side, pre-handoff: the agent is intentionally
	// not started until the handoff completes and the sandbox is flipped to
	// Running (see Sandbox.PairAgentAfterMigration), so its check fails until
	// then. Gate on state != Running so a fully migrated-in VM gets normal
	// agent-death detection again (IncomingMigrationURI itself is never
	// cleared, so it cannot be the sole condition).
	if m.sandbox.config != nil && m.sandbox.config.IncomingMigrationURI != "" {
		// Pre-handoff: the agent is intentionally not started until the
		// handoff completes and the sandbox is flipped to Running.
		if m.sandbox.state.State != types.StateRunning {
			return true
		}
		// Post-handoff but the agent has never answered a single health
		// check on this destination: the re-pair is still pending/failed.
		// PairAgentAfterMigration flips the sandbox to Running even when its
		// CheckAgent failed, so state==Running is NOT proof the agent is
		// reachable. Killing now destroys a migrated-in VM that may still
		// recover; genuine QEMU death is independently guarded by
		// watchHypervisor. Once the agent answers once (agentEverOK), normal
		// agent-death detection resumes, so a later genuine agent death is
		// still caught. Live migration's agent comes up promptly, so this
		// only defers the kill across the brief re-pair window for live;
		// for a restored VM whose agent never re-establishes its vsock it
		// stops the monitor from destroying it.
		if !m.agentEverOK.Load() {
			return true
		}
	}
	// Outgoing (source) side: query the live migration phase. Self-clears to
	// a non-active phase once the migration ends.
	st, err := m.sandbox.GetMigrationStatus(ctx)
	if err != nil {
		return false
	}
	return migrationPhaseActive(st.Phase)
}

// migrationPhaseActive reports whether a MigrationStatus.Phase indicates a
// migration that is still in flight. The terminal/idle phases ("", "none",
// "completed", "failed", "cancelled") are not active; everything else
// (setup, active, pre-switchover, device, postcopy-active, cancelling) is.
func migrationPhaseActive(phase string) bool {
	switch phase {
	case "", "none", "completed", "failed", "cancelled":
		return false
	default:
		return true
	}
}

func (m *monitor) watchHypervisor(ctx context.Context) error {
	m.totalHyperChecks.Add(1)
	start := time.Now()
	err := m.sandbox.hypervisor.Check()
	dur := time.Since(start)
	if err != nil {
		streak := m.hyperCheckFailStreak.Add(1)
		m.totalHyperFailures.Add(1)
		monitorLog.WithError(err).WithFields(map[string]interface{}{
			"marker":     monitorInstrMarker,
			"errType":    fmt.Sprintf("%T", err),
			"durationMs": dur.Milliseconds(),
			"failStreak": streak,
		}).Warn("INSTR: kata-monitor.watchHypervisor: hypervisor.Check failed")
		m.notify(ctx, errors.Wrapf(err, "failed to ping hypervisor process"))
		return err
	}
	if prev := m.hyperCheckFailStreak.Swap(0); prev > 0 {
		monitorLog.WithFields(map[string]interface{}{
			"marker":     monitorInstrMarker,
			"prevStreak": prev,
		}).Info("INSTR: kata-monitor.watchHypervisor: hypervisor.Check recovered")
	}
	m.lastHypervisorCheckOK.Store(time.Now().Unix())
	return nil
}
