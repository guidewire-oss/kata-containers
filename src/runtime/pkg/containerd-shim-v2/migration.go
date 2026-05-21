// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"fmt"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/experimental"
)

// SandboxMigrationMode represents the lifecycle mode of a sandbox with
// respect to live migration. See
// docs/design/live-migration-shim-lifecycle.md for the full state
// machine and per-mode operation gating.
type SandboxMigrationMode string

// String reports the mode for logging.
func (m SandboxMigrationMode) String() string { return string(m) }

const (
	// ModeOwner is the normal state — the shim owns the sandbox and
	// processes all CRI operations. The default mode for any newly
	// created sandbox.
	ModeOwner SandboxMigrationMode = "owner"

	// ModeMigratingOut is set on the source shim while a migration is
	// in flight. Write CRI operations are rejected; read ops (Status,
	// Stats, Logs) continue to work.
	ModeMigratingOut SandboxMigrationMode = "migrating-out"

	// ModeIncoming is set on the destination shim from creation until
	// the handoff completes. CRI operations are rejected until the
	// transition to ModeOwner.
	ModeIncoming SandboxMigrationMode = "incoming"

	// ModeMigrated is the terminal state of the source shim after a
	// successful handoff. The shim awaits cleanup from the
	// orchestrator; no CRI operations succeed.
	ModeMigrated SandboxMigrationMode = "migrated"

	// ModeFailed is the terminal state of either shim after an
	// unrecoverable migration error. Only cleanup operations are
	// allowed.
	ModeFailed SandboxMigrationMode = "failed"
)

// LiveMigrationFeature is the experimental.Feature handle for live
// migration support at the shim layer. Operators opt in via
// experimental = ["live_migration"] in configuration.toml. When the
// feature is disabled the shim behaves exactly as it did before live
// migration support landed: mode is permanently ModeOwner, the
// MigrationCoordinator gRPC is not bound, and no migration RPCs are
// accepted.
var LiveMigrationFeature = experimental.Feature{
	Name:        "live_migration",
	Description: "Enable shim-level coordination of live migration. See docs/design/live-migration-shim-lifecycle.md.",
	ExpRelease:  "3.x",
}

func init() {
	if err := experimental.Register(LiveMigrationFeature); err != nil {
		// Registration only fails on duplicate names or invalid
		// metadata, both of which are programmer errors caught in
		// package init across all builds.
		panic(fmt.Sprintf("failed to register live_migration experimental feature: %v", err))
	}
}

// IsLiveMigrationEnabled reports whether the live_migration
// experimental feature is enabled in the supplied context. The
// experimental feature list is propagated via
// experimental.ContextWithExp during runtime configuration loading.
func IsLiveMigrationEnabled(ctx context.Context) bool {
	for _, name := range experimental.ExpFromContext(ctx) {
		if name == LiveMigrationFeature.Name {
			return true
		}
	}
	return false
}
