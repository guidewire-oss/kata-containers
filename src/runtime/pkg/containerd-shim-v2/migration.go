// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"errors"
	"fmt"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/experimental"
)

// Migration-mode gate errors. Each names the situation the caller is
// in, not the operation that was attempted — operators reading shim
// logs care about why the sandbox is unavailable.
var (
	// ErrSandboxMigrating is returned by CRI write and cleanup ops
	// when the source shim is mid-migration. Reads still succeed.
	ErrSandboxMigrating = errors.New("sandbox is migrating: write and cleanup operations are blocked until migration completes or is aborted")

	// ErrSandboxNotReady is returned by every CRI op on a destination
	// shim before the handoff completes.
	ErrSandboxNotReady = errors.New("sandbox is receiving an incoming migration and is not yet ready")

	// ErrSandboxMigrated is returned by ops on the source shim after
	// a successful handoff. Only cleanup ops succeed past this point.
	ErrSandboxMigrated = errors.New("sandbox has been migrated to another host: this shim is awaiting cleanup")

	// ErrSandboxFailedMigration is the terminal-failure analogue of
	// ErrSandboxMigrated. Cleanup ops succeed; everything else is
	// rejected.
	ErrSandboxFailedMigration = errors.New("sandbox is in a failed migration state: only cleanup operations are allowed")

	// ErrInvalidMigrationTransition wraps every rejected mode
	// transition. The wrapper preserves the original sentinel so
	// callers can errors.Is() match without parsing strings.
	ErrInvalidMigrationTransition = errors.New("invalid migration mode transition")
)

// opClass groups CRI entry points by how the migration state machine
// should treat them. Per-op fine grain is not needed — the design
// table in docs/design/live-migration-shim-lifecycle.md gates by
// class.
type opClass int

const (
	// opClassWrite mutates sandbox or container state. Default for
	// unknown ops — the safer choice if a new entry point is ever
	// added without updating opClassFor.
	opClassWrite opClass = iota

	// opClassRead observes state without changing it. Allowed during
	// MigratingOut so monitoring stays usable.
	opClassRead

	// opClassCleanup is orchestrator/containerd-driven teardown.
	// Allowed in terminal states (Migrated, Failed) so the shim can
	// actually be reaped.
	opClassCleanup
)

// opClassFor maps the short op name passed to checkOpAllowed to its
// class. The names match the lowercase form used at each CRI entry
// point in service.go; keep the two in sync.
func opClassFor(opName string) opClass {
	switch opName {
	case "stats", "state", "pids", "wait", "connect":
		return opClassRead
	case "delete", "kill", "shutdown":
		return opClassCleanup
	default:
		return opClassWrite
	}
}

// allowedTransitions encodes the state-machine edges from the diagram
// in docs/design/live-migration-shim-lifecycle.md. Inserting an edge
// here is a protocol change — update the design doc first.
var allowedTransitions = map[SandboxMigrationMode]map[SandboxMigrationMode]struct{}{
	ModeOwner: {
		ModeMigratingOut: {},
		ModeIncoming:     {},
	},
	ModeMigratingOut: {
		ModeMigrated: {},
		ModeFailed:   {},
		// Orchestrator-driven abort before any state transfer has
		// happened. CancelMigration on the hypervisor and the shim
		// goes back to Owner.
		ModeOwner: {},
	},
	ModeIncoming: {
		ModeOwner:  {}, // handoff complete
		ModeFailed: {},
	},
	ModeFailed: {
		// Orchestrator's explicit abort path — CancelMigration on
		// the hypervisor has cleared QMP state, shim returns to
		// owning the sandbox.
		ModeOwner: {},
	},
	ModeMigrated: {}, // terminal
}

// canTransitionMigrationMode reports whether the given transition is
// legal. Self-transitions are not legal — the caller is expressing
// confused intent (the mode is already what they want).
func canTransitionMigrationMode(from, to SandboxMigrationMode) bool {
	if from == to {
		return false
	}
	nexts, ok := allowedTransitions[from]
	if !ok {
		return false
	}
	_, allowed := nexts[to]
	return allowed
}

// checkMigrationModeAllowsOp returns nil if the named op may proceed
// under the given mode, or the appropriate sentinel error otherwise.
// The empty string is treated as ModeOwner — it's the Go zero value
// of an unset migration field and semantically means "not in any
// migration". Genuinely unknown strings (a typo, or a corrupted
// persisted value) fall through the default branch and fail closed.
func checkMigrationModeAllowsOp(mode SandboxMigrationMode, opName string) error {
	class := opClassFor(opName)
	switch mode {
	case ModeOwner, "":
		return nil
	case ModeMigratingOut:
		if class == opClassRead {
			return nil
		}
		return ErrSandboxMigrating
	case ModeIncoming:
		// Incoming gates every op including reads and cleanup —
		// the orchestrator owns the lifecycle until handoff. If
		// the handoff fails, the shim first transitions to Failed
		// (which allows cleanup) before containerd ever sees a
		// Delete on this sandbox.
		return ErrSandboxNotReady
	case ModeMigrated:
		if class == opClassCleanup {
			return nil
		}
		return ErrSandboxMigrated
	case ModeFailed:
		if class == opClassCleanup {
			return nil
		}
		return ErrSandboxFailedMigration
	default:
		// Defensive default — an empty or unknown mode indicates
		// a programmer error (forgot to initialize) or a corrupted
		// persisted state. Either way: block.
		return fmt.Errorf("sandbox is in unknown migration mode %q", mode)
	}
}

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

// currentMigrationMode returns the sandbox's current migration mode
// under s.mu. Safe to call without holding the lock; callers that
// already hold s.mu should read migrationMode directly to avoid
// re-locking.
func (s *service) currentMigrationMode() SandboxMigrationMode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.migrationMode
}

// transitionMigrationMode performs a guarded mode transition under
// s.mu. On rejection the mode is unchanged and the returned error
// wraps ErrInvalidMigrationTransition with the attempted edge for
// log readers.
func (s *service) transitionMigrationMode(to SandboxMigrationMode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !canTransitionMigrationMode(s.migrationMode, to) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidMigrationTransition, s.migrationMode, to)
	}
	s.migrationMode = to
	return nil
}

// checkOpAllowed gates the named CRI op against the current mode.
// Returns nil if the op may proceed, or the appropriate sentinel
// error otherwise. Callers MUST invoke this before acquiring s.mu so
// the gate's own lock acquisition does not deadlock.
func (s *service) checkOpAllowed(opName string) error {
	return checkMigrationModeAllowsOp(s.currentMigrationMode(), opName)
}
