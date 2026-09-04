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
		// Snapshot save (BeginMigrateSave) terminates here instead of
		// Migrated so teardown semantics differ (see ModeSaved).
		ModeSaved:  {},
		ModeFailed: {},
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
	ModeSaved:    {}, // terminal — teardown proceeds via normal pod delete
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
		// Incoming allows reads, cleanup, and the specific CRI
		// writes that containerd issues to bring the destination
		// Pod sandbox + workload containers to Running before
		// the migration handoff completes:
		//
		//   - "create" of the workload container after sandbox
		//     creation. Sandbox.CreateContainer detects Incoming
		//     and registers bookkeeping only; no agent.create RPC
		//     until the agent comes online via onMigrationComplete.
		//
		//   - "start" of any container. service.Start detects
		//     Incoming and short-circuits to a TaskStart event so
		//     containerd's task state machine advances.
		//
		// All other writes (kill, update, pause, resume, etc.)
		// would race with the migration handoff or hit the
		// not-yet-reachable agent — reject them.
		switch opName {
		case "create", "start":
			return nil
		}
		if class == opClassRead || class == opClassCleanup {
			return nil
		}
		return ErrSandboxNotReady
	case ModeMigrated:
		// Reads are allowed so containerd's cleanup probe
		// (state → kill → delete) can drain the sandbox.
		// Without this, kubelet spins forever on the
		// post-migration source bundle and the stale entry
		// never gets garbage-collected.
		if class == opClassRead || class == opClassCleanup {
			return nil
		}
		return ErrSandboxMigrated
	case ModeSaved:
		// Same gating as Migrated: the VM state has left the
		// building (to a snapshot sink), so only reads and the
		// cleanup ops that drive normal pod teardown make sense.
		if class == opClassRead || class == opClassCleanup {
			return nil
		}
		return ErrSandboxMigrated
	case ModeFailed:
		// Same rationale as ModeMigrated: cleanup needs to be
		// able to read state first. If reads are blocked,
		// retried migrations find the still-on-disk failed
		// bundle and route their handoff to the wrong shim.
		if class == opClassRead || class == opClassCleanup {
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

	// ModeSaved is the terminal state after a successful snapshot save
	// (/migration/save): the VM state lives in the caller's sink and
	// the paused local VM is dead-by-design. Unlike ModeMigrated —
	// where a destination owns the live VM and the source shim defers
	// teardown — a saved sandbox MUST tear down normally on pod
	// delete (wait.go's non-owner skip excludes this mode), otherwise
	// the paused QEMU + virtiofsd + shim survive as orphans holding
	// the dual-identity vhost-fs.sock the restore pod needs.
	ModeSaved SandboxMigrationMode = "saved"
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
// under s.migrationMu. The mode has its own dedicated mutex so
// reads do not block on s.mu — Create() holds s.mu for the entire
// lifetime of its inner goroutine, and that goroutine drives the
// destination-shim BeginMigrateIncoming -> transitionMigrationMode
// path which would otherwise deadlock on s.mu.
// isMigrationAdoptedContainer reports whether id names a container this
// sandbox adopted from a migration source — i.e. one whose process is already
// running inside the guest that arrived in the memory image.
//
// A container is adopted exactly when it carries an InternalID that differs
// from its containerd ID: adoptMigrationContainerID sets InternalID to the
// source's ID, while a freshly created container has InternalID == ID. This is
// the same test ShareDeferredWorkloadRootfs uses to pick adopted containers.
//
// Start() needs this because its short-circuit keys on the sandbox's migration
// MODE, which is transient. The destination pod is created fresh, so the
// kubelet issues Start for EVERY container in spec order. Whichever containers
// it reaches while the shim is still ModeIncoming are short-circuited safely;
// once the handoff completes and the mode flips to ModeOwner, any remaining
// container takes the normal path — agent.startContainer fails, because the
// process is already running in the guest, and Container.start()'s error
// handler force-stops it. That KILLS a live process.
//
// Observed on a two-container pod: the workload (started first, still
// ModeIncoming) survived every hop, while the sidecar (started after the flip)
// died, leaving postgres refused on both loopback and the pod IP while the
// kubelet still reported the container Ready.
func (s *service) isMigrationAdoptedContainer(id string) bool {
	if s.sandbox == nil || id == "" {
		return false
	}
	for _, c := range s.sandbox.GetAllContainers() {
		if c.ID() != id {
			continue
		}
		internal := c.InternalID()
		return internal != "" && internal != c.ID()
	}
	return false
}

func (s *service) currentMigrationMode() SandboxMigrationMode {
	s.migrationMu.Lock()
	defer s.migrationMu.Unlock()
	return s.migrationMode
}

// transitionMigrationMode performs a guarded mode transition under
// s.migrationMu. Independent of s.mu — see currentMigrationMode
// for the deadlock rationale. On rejection the mode is unchanged
// and the returned error wraps ErrInvalidMigrationTransition with
// the attempted edge for log readers.
func (s *service) transitionMigrationMode(to SandboxMigrationMode) error {
	s.migrationMu.Lock()
	defer s.migrationMu.Unlock()
	from := s.migrationMode
	if !canTransitionMigrationMode(from, to) {
		// Log rejected transitions at Info — frequent enough that
		// Warn would be noisy, but useful for post-mortem diagnosis
		// of "why did mode X reject Y?"
		shimLog.WithFields(map[string]interface{}{
			"from": string(from),
			"to":   string(to),
		}).Info("transitionMigrationMode: rejected")
		return fmt.Errorf("%w: %s -> %s", ErrInvalidMigrationTransition, from, to)
	}
	s.migrationMode = to
	// Once a sandbox reaches a terminal saved/migrated/failed mode its local
	// guest is paused (a snapshot save pauses vCPUs), gone (migrated out), or
	// wedged (failed) — the in-guest agent can no longer answer. Mark it
	// unreachable so teardown skips agent RPCs that would otherwise block
	// `delete` (agent.waitProcess never returns on a paused guest) and leave
	// the pod stuck Terminating (spec 022 FR-054). ModeOwner is the reachable
	// state, so clear it there (defensive — it's also the zero value).
	if s.sandbox != nil {
		switch to {
		case ModeSaved, ModeMigrated, ModeFailed:
			s.sandbox.SetAgentUnreachable(true)
		case ModeOwner:
			s.sandbox.SetAgentUnreachable(false)
		}
		// ModeSaved and ModeMigrated: the local guest is gone — checkpointed to a
		// snapshot sink (saved) or handed off to a destination (migrated) — so
		// close its agent connection to abort any in-flight, no-timeout agent RPC.
		// Two of those otherwise pin the shim's service mutex and wedge the source
		// pod in Terminating: the per-container waitProcess goroutine (never returns
		// on a departed guest) and the kubelet/cadvisor Stats poll (statsContainer
		// runs while s.mu is held). MarkAgentSaved also sets agentSaved, so the
		// stats path returns empty instead of dialing the dead agent again. Done for
		// both source-terminal modes; deliberately NOT for ModeFailed, because a
		// live resumed dest can legitimately sit in ModeFailed while still serving,
		// and severing its agent there breaks its networking, IO, and logs.
		// ModeMigrated is only ever reached by a source (MigratingOut -> Migrated),
		// so a destination is never affected (spec 022 FR-054).
		if to == ModeSaved || to == ModeMigrated {
			if err := s.sandbox.MarkAgentSaved(s.rootCtx); err != nil {
				shimLog.WithError(err).Warn("transitionMigrationMode: MarkAgentSaved (close agent conn) failed")
			}
		}
	}
	// Reaching ModeOwner means this sandbox has completed (or rolled back)
	// its migration — the destination-side coordinator's source-inactivity
	// watchdog has no further purpose and MUST be disarmed. Without this the
	// coordinator-less hibernate restore (which drives no source RPCs) trips
	// the watchdog ~SourceTimeout after a SUCCESSFUL resume and tears down
	// the live, serving guest. Async because stopMigrationServer re-locks
	// migrationMu (held here) and Server.Stop blocks on GracefulStop — which,
	// when Owner is set from within the coordinator's own Complete RPC (the
	// live path), would otherwise deadlock. Idempotent and a safe no-op on the
	// source side where no incoming coordinator exists.
	if to == ModeOwner {
		go func() {
			if err := s.stopMigrationServer(); err != nil {
				shimLog.WithError(err).Warn("transitionMigrationMode: stopMigrationServer (disarm watchdog) failed")
			}
		}()
	}
	// Log accepted transitions at Warn so they're permanently visible
	// in the journal. Mode transitions are infrequent and load-bearing
	// — every one of them deserves to be findable after the fact when
	// we're trying to reconstruct what happened during a migration.
	shimLog.WithFields(map[string]interface{}{
		"from": string(from),
		"to":   string(to),
	}).Warn("transitionMigrationMode: applied")
	return nil
}

// checkOpAllowed gates the named CRI op against the current mode.
// Returns nil if the op may proceed, or the appropriate sentinel
// error otherwise. Callers MUST invoke this before acquiring s.mu so
// the gate's own lock acquisition does not deadlock.
func (s *service) checkOpAllowed(opName string) error {
	return checkMigrationModeAllowsOp(s.currentMigrationMode(), opName)
}
