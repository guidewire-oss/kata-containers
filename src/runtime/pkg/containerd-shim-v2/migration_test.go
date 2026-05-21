// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"errors"
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

// TestCanTransitionMigrationMode exhaustively covers every (from, to)
// pair from the state diagram in
// docs/design/live-migration-shim-lifecycle.md so an accidental
// table-edit cannot silently widen the protocol.
func TestCanTransitionMigrationMode(t *testing.T) {
	allModes := []SandboxMigrationMode{
		ModeOwner, ModeMigratingOut, ModeIncoming, ModeMigrated, ModeFailed,
	}
	// allowed[from][to] = true means the transition is legal.
	allowed := map[SandboxMigrationMode]map[SandboxMigrationMode]bool{
		ModeOwner: {
			ModeMigratingOut: true,
			ModeIncoming:     true,
		},
		ModeMigratingOut: {
			ModeMigrated: true,
			ModeFailed:   true,
			ModeOwner:    true, // orchestrator abort before any state transfer
		},
		ModeIncoming: {
			ModeOwner:  true, // handoff complete
			ModeFailed: true,
		},
		ModeFailed: {
			ModeOwner: true, // orchestrator explicit abort
		},
		ModeMigrated: {}, // terminal
	}

	for _, from := range allModes {
		for _, to := range allModes {
			want := allowed[from][to]
			got := canTransitionMigrationMode(from, to)
			if got != want {
				t.Errorf("canTransitionMigrationMode(%s, %s) = %v, want %v",
					from, to, got, want)
			}
		}
	}
}

// TestCanTransitionMigrationModeUnknown verifies that bogus modes
// fed in (e.g. from a corrupted on-disk SandboxState in the future)
// are rejected rather than crashing.
func TestCanTransitionMigrationModeUnknown(t *testing.T) {
	bogus := SandboxMigrationMode("not-a-real-mode")
	assert := assert.New(t)
	assert.False(canTransitionMigrationMode(bogus, ModeOwner),
		"unknown 'from' mode must not be transitionable")
	assert.False(canTransitionMigrationMode(ModeOwner, bogus),
		"unknown 'to' mode must not be a valid target")
	assert.False(canTransitionMigrationMode(ModeOwner, ModeOwner),
		"self-transitions are not legal — caller is expressing confused intent")
}

// TestOpClassFor pins the op-name → class mapping so the per-mode
// gating decisions are stable.
func TestOpClassFor(t *testing.T) {
	cases := []struct {
		op   string
		want opClass
	}{
		// Read ops — observe state without changing it.
		{"stats", opClassRead},
		{"state", opClassRead},
		{"pids", opClassRead},
		{"wait", opClassRead},
		{"connect", opClassRead},
		// Cleanup ops — orchestrator/containerd-driven teardown.
		{"delete", opClassCleanup},
		{"kill", opClassCleanup},
		{"shutdown", opClassCleanup},
		// Write ops — mutate sandbox or container state.
		{"create", opClassWrite},
		{"start", opClassWrite},
		{"exec", opClassWrite},
		{"resizepty", opClassWrite},
		{"pause", opClassWrite},
		{"resume", opClassWrite},
		{"update", opClassWrite},
		{"closeio", opClassWrite},
		{"checkpoint", opClassWrite},
		// Unknown ops default to write — the safe choice if we ever
		// forget to classify a new entry point.
		{"some-future-op", opClassWrite},
		{"", opClassWrite},
	}
	for _, tc := range cases {
		if got := opClassFor(tc.op); got != tc.want {
			t.Errorf("opClassFor(%q) = %v, want %v", tc.op, got, tc.want)
		}
	}
}

// TestCheckMigrationModeAllowsOp covers every (mode, opName) pair
// against the allowed-ops table in
// docs/design/live-migration-shim-lifecycle.md.
func TestCheckMigrationModeAllowsOp(t *testing.T) {
	// One op per class is sufficient — opClassFor is already exhaustively
	// covered above, and the gate only cares about the class.
	type expect struct {
		err error // nil = allowed
	}
	cases := []struct {
		mode SandboxMigrationMode
		read expect
		wr   expect
		cln  expect
	}{
		{ModeOwner, expect{nil}, expect{nil}, expect{nil}},
		{ModeMigratingOut, expect{nil}, expect{ErrSandboxMigrating}, expect{ErrSandboxMigrating}},
		{ModeIncoming, expect{ErrSandboxNotReady}, expect{ErrSandboxNotReady}, expect{nil}},
		{ModeMigrated, expect{ErrSandboxMigrated}, expect{ErrSandboxMigrated}, expect{nil}},
		{ModeFailed, expect{ErrSandboxFailedMigration}, expect{ErrSandboxFailedMigration}, expect{nil}},
	}
	for _, tc := range cases {
		check := func(label, op string, want error) {
			got := checkMigrationModeAllowsOp(tc.mode, op)
			if !errors.Is(got, want) {
				t.Errorf("mode=%s op=%s (%s): got err=%v, want %v",
					tc.mode, op, label, got, want)
			}
		}
		check("read", "stats", tc.read.err)
		check("write", "start", tc.wr.err)
		check("cleanup", "delete", tc.cln.err)
	}
}

// TestServiceTransitionMigrationMode exercises the lock-safe wrapper
// on *service. We construct a minimal service literal — the only
// fields referenced are migrationMode and mu.
func TestServiceTransitionMigrationMode(t *testing.T) {
	assert := assert.New(t)
	s := &service{migrationMode: ModeOwner}

	// Owner is the starting state.
	assert.Equal(ModeOwner, s.currentMigrationMode())

	// Legal transition succeeds and the mode is observable.
	if err := s.transitionMigrationMode(ModeMigratingOut); err != nil {
		t.Fatalf("Owner -> MigratingOut should be legal, got %v", err)
	}
	assert.Equal(ModeMigratingOut, s.currentMigrationMode())

	// Illegal transition is rejected and the mode is unchanged.
	err := s.transitionMigrationMode(ModeIncoming)
	if !errors.Is(err, ErrInvalidMigrationTransition) {
		t.Fatalf("MigratingOut -> Incoming should fail with ErrInvalidMigrationTransition, got %v", err)
	}
	assert.Contains(err.Error(), "migrating-out",
		"error should name the 'from' mode for operators reading logs")
	assert.Contains(err.Error(), "incoming",
		"error should name the 'to' mode for operators reading logs")
	assert.Equal(ModeMigratingOut, s.currentMigrationMode(),
		"failed transition must not leave the service in a half-transitioned state")
}

// TestServiceCheckOpAllowed verifies the service-level wrapper picks
// up the current mode under the lock.
func TestServiceCheckOpAllowed(t *testing.T) {
	assert := assert.New(t)
	s := &service{migrationMode: ModeOwner}

	assert.NoError(s.checkOpAllowed("start"), "Owner allows everything")
	assert.NoError(s.checkOpAllowed("stats"))
	assert.NoError(s.checkOpAllowed("delete"))

	s.migrationMode = ModeMigratingOut
	assert.NoError(s.checkOpAllowed("stats"), "reads continue during MigratingOut")
	assert.ErrorIs(s.checkOpAllowed("start"), ErrSandboxMigrating)
	assert.ErrorIs(s.checkOpAllowed("delete"), ErrSandboxMigrating)

	s.migrationMode = ModeIncoming
	assert.ErrorIs(s.checkOpAllowed("stats"), ErrSandboxNotReady,
		"Incoming gates every op including reads — orchestrator owns the lifecycle")

	s.migrationMode = ModeMigrated
	assert.ErrorIs(s.checkOpAllowed("start"), ErrSandboxMigrated)
	assert.NoError(s.checkOpAllowed("delete"), "Migrated awaits cleanup signal")

	s.migrationMode = ModeFailed
	assert.ErrorIs(s.checkOpAllowed("start"), ErrSandboxFailedMigration)
	assert.NoError(s.checkOpAllowed("delete"), "Failed allows cleanup")
}

// TestEmptyModeIsOwner pins the choice that the Go zero value of
// SandboxMigrationMode (i.e. "") behaves as ModeOwner. This matches
// Go's zero-value convention and keeps test files that construct
// *service literals without going through New() working unchanged.
// Genuinely garbled strings (typos, corrupted persisted state) still
// fail closed via the default branch — see TestUnknownModeIsClosed.
func TestEmptyModeIsOwner(t *testing.T) {
	assert := assert.New(t)
	empty := SandboxMigrationMode("")
	assert.NoError(checkMigrationModeAllowsOp(empty, "start"),
		"zero-value mode must behave as Owner: writes allowed")
	assert.NoError(checkMigrationModeAllowsOp(empty, "stats"),
		"zero-value mode must behave as Owner: reads allowed")
	assert.NoError(checkMigrationModeAllowsOp(empty, "delete"),
		"zero-value mode must behave as Owner: cleanup allowed")
}

// TestUnknownModeIsClosed verifies that a non-empty but unrecognized
// mode value (the corruption case) still fails closed.
func TestUnknownModeIsClosed(t *testing.T) {
	assert := assert.New(t)
	bogus := SandboxMigrationMode("not-a-real-mode")
	err := checkMigrationModeAllowsOp(bogus, "start")
	assert.Error(err, "unknown non-empty mode must not be permissive")
	assert.Contains(err.Error(), "unknown migration mode",
		"error should help operators identify the corruption")
}
