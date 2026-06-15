// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"errors"
	"testing"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	"github.com/stretchr/testify/assert"
)

func TestMigrationPhaseActive(t *testing.T) {
	assert := assert.New(t)
	for _, phase := range []string{"", "none", "completed", "failed", "cancelled"} {
		assert.False(migrationPhaseActive(phase), "phase %q should be inactive", phase)
	}
	for _, phase := range []string{"setup", "active", "pre-switchover", "device", "postcopy-active", "cancelling"} {
		assert.True(migrationPhaseActive(phase), "phase %q should be active", phase)
	}
}

// An agent-ping miss during an incoming (destination) migration must not
// stop the sandbox until the handoff completes (state flips to Running).
// IncomingMigrationURI is never cleared, so it cannot be the sole gate —
// state==Running must re-enable normal agent-death detection.
func TestMigrationActiveIncomingGating(t *testing.T) {
	contConfig := newTestContainerConfigNoop("505")
	hConfig := newHypervisorConfig(nil, nil)
	assert := assert.New(t)

	s, err := testCreateSandbox(t, testSandboxID, MockHypervisor, hConfig, NetworkConfig{}, []ContainerConfig{contConfig}, nil)
	assert.NoError(err)
	defer cleanUp()

	m := newMonitor(s)
	ctx := context.Background()

	// No incoming URI and the mock hypervisor reports no migration:
	// nothing to suppress.
	s.config.IncomingMigrationURI = ""
	assert.False(m.migrationActive(ctx))

	// Incoming migration, pre-handoff (not yet Running): suppress.
	s.config.IncomingMigrationURI = "tcp:0.0.0.0:4444"
	s.state.State = types.StateReady
	assert.True(m.migrationActive(ctx))

	// Incoming migration handed off (Running) but the agent has not yet
	// answered a single health check on this destination — the agent re-pair
	// is still pending/failed. Keep suppressing the agent-death Stop+Delete:
	// PairAgentAfterMigration flips the sandbox to Running even when its
	// CheckAgent failed, so state==Running alone is not proof the agent is
	// reachable. Killing here would destroy a restored VM that may still
	// recover; watchHypervisor still guards genuine QEMU death.
	s.state.State = types.StateRunning
	m.agentEverOK.Store(false)
	assert.True(m.migrationActive(ctx))

	// Agent has answered at least once since this destination came up:
	// the re-pair succeeded, so normal agent-death detection resumes (a
	// later genuine agent death IS detected). Live migration reaches this
	// state promptly, so its steady-state detection is unchanged.
	m.agentEverOK.Store(true)
	assert.False(m.migrationActive(ctx))
}

// A single (or few) missed agent pings must NOT escalate to Stop+Delete:
// the monitor defers the kill until agentDeathFailStreakThreshold consecutive
// failures. This protects a freshly-resumed/migrated VM whose agent is briefly
// unresponsive while it re-pairs — killing on the first miss SIGKILLs a healthy
// guest. watchHypervisor still guards genuine QEMU death.
func TestWatchAgentDefersKillUntilStreakThreshold(t *testing.T) {
	contConfig := newTestContainerConfigNoop("505")
	hConfig := newHypervisorConfig(nil, nil)
	assert := assert.New(t)

	s, err := testCreateSandbox(t, testSandboxID, MockHypervisor, hConfig, NetworkConfig{}, []ContainerConfig{contConfig}, nil)
	assert.NoError(err)
	defer cleanUp()

	// Agent always fails its health check; not an incoming migration, so the
	// migrationActive suppression does not apply.
	s.agent = &mockAgent{checkErr: errors.New("CheckRequest timed out")}
	s.config.IncomingMigrationURI = ""

	m := newMonitor(s)
	// Register a watcher WITHOUT starting the periodic ticker, so the only
	// watchAgent calls are the deterministic ones below.
	ch := make(chan error, watcherChannelSize)
	m.watchers = append(m.watchers, ch)
	m.running = true
	ctx := context.Background()

	// The first threshold-1 consecutive misses must not notify.
	for i := 1; i < agentDeathFailStreakThreshold; i++ {
		m.watchAgent(ctx)
		select {
		case e := <-ch:
			t.Fatalf("watchAgent notified on failStreak=%d (%v) — must defer until threshold %d", i, e, agentDeathFailStreakThreshold)
		default:
		}
	}
	// The threshold-th consecutive miss escalates → notify writes the error.
	m.watchAgent(ctx)
	select {
	case e := <-ch:
		assert.Error(e)
	default:
		t.Fatalf("watchAgent did not notify at failStreak=%d (threshold %d)", agentDeathFailStreakThreshold, agentDeathFailStreakThreshold)
	}

	// A subsequent successful check resets the streak (a recovered agent is
	// not killed on the next isolated miss).
	s.agent = &mockAgent{checkErr: nil}
	m.watchAgent(ctx)
	assert.Equal(int64(0), m.agentCheckFailStreak.Load())
}

func TestMonitorSuccess(t *testing.T) {
	contID := "505"
	contConfig := newTestContainerConfigNoop(contID)
	hConfig := newHypervisorConfig(nil, nil)
	assert := assert.New(t)

	// create a sandbox
	s, err := testCreateSandbox(t, testSandboxID, MockHypervisor, hConfig, NetworkConfig{}, []ContainerConfig{contConfig}, nil)
	assert.NoError(err)
	defer cleanUp()

	m := newMonitor(s)

	ch, err := m.newWatcher(context.Background())
	assert.Nil(err, "newWatcher failed: %v", err)

	fakeErr := errors.New("foobar error")
	m.notify(context.Background(), fakeErr)
	resultErr := <-ch
	assert.True(resultErr == fakeErr, "monitor notification mismatch %v vs. %v", resultErr, fakeErr)

	m.stop()
}

func TestMonitorClosedChannel(t *testing.T) {
	contID := "505"
	contConfig := newTestContainerConfigNoop(contID)
	hConfig := newHypervisorConfig(nil, nil)
	assert := assert.New(t)

	// create a sandbox
	s, err := testCreateSandbox(t, testSandboxID, MockHypervisor, hConfig, NetworkConfig{}, []ContainerConfig{contConfig}, nil)
	assert.NoError(err)
	defer cleanUp()

	m := newMonitor(s)

	ch, err := m.newWatcher(context.Background())
	assert.Nil(err, "newWatcher failed: %v", err)

	close(ch)
	fakeErr := errors.New("foobar error")
	m.notify(context.Background(), fakeErr)

	m.stop()
}
