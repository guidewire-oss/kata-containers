// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"testing"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/experimental"
	"github.com/stretchr/testify/assert"
)

func TestLiveMigrationFeatureRegistered(t *testing.T) {
	assert := assert.New(t)
	f := experimental.Get("live_migration")
	assert.NotNil(f, "live_migration feature should be registered")
	if f != nil {
		assert.Equal("live_migration", f.Name)
		assert.NotEmpty(f.Description)
		assert.NotEmpty(f.ExpRelease)
	}
}

func TestIsLiveMigrationEnabled(t *testing.T) {
	assert := assert.New(t)

	assert.False(IsLiveMigrationEnabled(context.Background()),
		"should be false with no experimental features set on the context")

	ctx := experimental.ContextWithExp(context.Background(), []string{"live_migration"})
	assert.True(IsLiveMigrationEnabled(ctx),
		"should be true when live_migration is in the experimental list")

	ctx = experimental.ContextWithExp(context.Background(), []string{"some_other_feature"})
	assert.False(IsLiveMigrationEnabled(ctx),
		"should be false when only unrelated features are set")

	ctx = experimental.ContextWithExp(context.Background(),
		[]string{"feature_a", "live_migration", "feature_b"})
	assert.True(IsLiveMigrationEnabled(ctx),
		"should be true when live_migration is one of several features")
}

func TestSandboxMigrationModeValues(t *testing.T) {
	assert := assert.New(t)
	// Lock in the wire-format strings used in logs and the future
	// MigrationCoordinator RPC. Changing these is a compatibility break.
	assert.Equal("owner", string(ModeOwner))
	assert.Equal("migrating-out", string(ModeMigratingOut))
	assert.Equal("incoming", string(ModeIncoming))
	assert.Equal("migrated", string(ModeMigrated))
	assert.Equal("failed", string(ModeFailed))
}

func TestSandboxMigrationModeString(t *testing.T) {
	// String() is exercised by log frameworks that don't honor
	// fmt.Stringer for typed string aliases — verify the explicit
	// method returns the underlying value.
	assert.Equal(t, "owner", ModeOwner.String())
	assert.Equal(t, "incoming", ModeIncoming.String())
}
