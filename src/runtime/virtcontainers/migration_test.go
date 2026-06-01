// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMockHypervisorMigrationStubs locks in the contract that hypervisors
// without migration support return ErrMigrationNotSupported from all four
// methods. Orchestrator code can switch on this error without parsing
// strings or sniffing types.
func TestMockHypervisorMigrationStubs(t *testing.T) {
	assert := assert.New(t)
	m := &mockHypervisor{}
	ctx := context.Background()

	err := m.MigrateOut(ctx, "tcp:dest:4444", MigrateOptions{})
	assert.True(errors.Is(err, ErrMigrationNotSupported), "MigrateOut error: %v", err)

	err = m.MigrateIncoming(ctx, "tcp:0.0.0.0:4444", MigrateOptions{})
	assert.True(errors.Is(err, ErrMigrationNotSupported), "MigrateIncoming error: %v", err)

	_, err = m.GetMigrationStatus(ctx)
	assert.True(errors.Is(err, ErrMigrationNotSupported), "GetMigrationStatus error: %v", err)

	err = m.CancelMigration(ctx)
	assert.True(errors.Is(err, ErrMigrationNotSupported), "CancelMigration error: %v", err)
}

// (qemu.go QMP-wrapper happy-path tests would require either a real
// QEMU process or a refactor to inject the QMP interface as a mock.
// Deferred to the Phase B integration test phase; the govmm helpers
// they wrap are covered in qmp_test.go.)

// TestMigrateOptionsZero ensures the zero-valued MigrateOptions is safe
// to use — orchestrators that don't care about tuning just pass {}.
func TestMigrateOptionsZero(t *testing.T) {
	var opts MigrateOptions
	assert.Nil(t, opts.Capabilities, "Capabilities should default to nil")
	assert.Nil(t, opts.Parameters, "Parameters should default to nil")
}

// TestMigrationStatusZero ensures the zero-valued MigrationStatus reads
// as "no migration" — Phase is empty string which the qemu mapper
// normalizes to "none".
func TestMigrationStatusZero(t *testing.T) {
	var s MigrationStatus
	assert.Equal(t, "", s.Phase)
	assert.Equal(t, uint64(0), s.BytesTransferred)
	assert.Equal(t, uint64(0), s.TotalBytes)
	assert.Equal(t, uint64(0), s.DirtyRate)
	assert.Equal(t, uint64(0), s.BandwidthBPS)
	assert.Equal(t, uint64(0), s.RemainingMS)
}
