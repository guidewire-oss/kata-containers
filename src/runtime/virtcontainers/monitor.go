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

	"github.com/pkg/errors"
)

const (
	defaultCheckInterval = 5 * time.Second
	watcherChannelSize   = 128

	// kata-monitor-instr-v1: unique marker so we can prove the patched
	// binary is the one running (used by build-verify scripts via `strings`).
	monitorInstrMarker = "kata-monitor-instr-v1"
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
		"marker":            monitorInstrMarker,
		"checkIntervalSec":  int(m.checkInterval.Seconds()),
		"sandboxID":         s.ID(),
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
		"marker":                       monitorInstrMarker,
		"sandboxID":                    m.sandbox.ID(),
		"errType":                      fmt.Sprintf("%T", err),
		"errChain":                     fmt.Sprintf("%+v", err),
		"agentCheckFailStreak":         m.agentCheckFailStreak.Load(),
		"hyperCheckFailStreak":         m.hyperCheckFailStreak.Load(),
		"secSinceLastAgentCheckOK":     now - agentLastOK,
		"secSinceLastHypervisorCheckOK": now - hyperLastOK,
		"totalAgentChecks":             m.totalAgentChecks.Load(),
		"totalAgentFailures":           m.totalAgentFailures.Load(),
		"totalHyperChecks":             m.totalHyperChecks.Load(),
		"totalHyperFailures":           m.totalHyperFailures.Load(),
		"stack":                        string(debug.Stack()),
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
		// TODO: define and export error types
		m.notify(ctx, errors.Wrapf(err, "failed to ping agent"))
		return
	}
	// success: reset streak, update last-OK timestamp
	if prev := m.agentCheckFailStreak.Swap(0); prev > 0 {
		monitorLog.WithFields(map[string]interface{}{
			"marker":      monitorInstrMarker,
			"prevStreak":  prev,
			"durationMs":  dur.Milliseconds(),
		}).Info("INSTR: kata-monitor.watchAgent: agent.check recovered after failure streak")
	}
	m.lastAgentCheckOK.Store(time.Now().Unix())
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
