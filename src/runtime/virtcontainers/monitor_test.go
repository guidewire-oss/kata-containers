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

	// Incoming migration completed (sandbox flipped to Running): a migrated-in
	// VM gets normal agent-death detection again.
	s.state.State = types.StateRunning
	assert.False(m.migrationActive(ctx))
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
