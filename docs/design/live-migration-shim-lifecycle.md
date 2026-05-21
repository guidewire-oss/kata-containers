# Live migration — shim sandbox lifecycle modes

## Status

Proposal — Phase 2 of an incremental live migration effort, building
on the hypervisor abstraction methods landed in
`docs/design/live-migration.md` (`MigrateOut`, `MigrateIncoming`,
`GetMigrationStatus`, `CancelMigration`).

This document covers the shim-level changes needed to coordinate a
live migration between two `containerd-shim-kata-v2` instances —
one on the source host, one on the destination — so that the
sandbox can move with its containers, IO, and state intact.

## Motivation

A Kata pod's hypervisor-only migration (Phase 1) is necessary but
not sufficient. The pod is owned by a per-pod
`containerd-shim-kata-v2` process on the source host. After the
hypervisor moves the guest VM, the source shim still believes it
owns the sandbox, and there's no destination shim that knows about
the pod at all. Container IO streams (kubelet's `attach`, `logs`,
`exec`) flow through the source shim; the kata-agent inside the
guest is paired with the source shim's vsock channel; containerd
on the destination host has no idea this sandbox exists.

Phase C makes the shim **aware** of migration and adds the
coordination needed to **hand off** sandbox ownership cleanly. It
does not yet solve the IO stream handoff or the agent vsock CID
reconnect — those are tracked in Phase D
(`docs/design/live-migration-io-vsock.md`, forthcoming).

## Non-goals (deferred to later phases)

- **Container IO stream handoff.** Phase D. Source shim's
  open `attach`/`exec` streams need to either drop cleanly or
  proxy to the destination during cutover.
- **Vsock CID handoff.** Phase D. The kata-agent's vsock channel
  uses host-scoped CIDs that change when the VM moves between
  hosts.
- **Containerd integration.** Phase D / E. Containerd's CRI
  assumes one shim per sandbox; the handoff window where both
  shims touch the sandbox needs either containerd cooperation or
  a workaround.
- **Cloud Hypervisor.** Different migration protocol; out of scope
  here.
- **Confidential Containers.** Cross-TEE migration is unsolved
  upstream; out of scope.

## Conceptual model

A Kata sandbox has exactly one owning shim at any moment. During a
migration there is a brief overlap window when both source and
destination shims exist; the protocol described here keeps that
window short and well-defined.

```
   ┌─────────────────────────────────────────────────────────────────┐
   │                       Steady state                              │
   │                                                                 │
   │   host A                                       host B           │
   │   ┌──────────────┐                                              │
   │   │  shim (Owner)│ ── owns ──> sandbox / QEMU / containers      │
   │   └──────────────┘                                              │
   └─────────────────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────────────────┐
   │                       During migration                          │
   │                                                                 │
   │   host A                                       host B           │
   │   ┌──────────────────┐         ┌────────────────────────────┐   │
   │   │ shim (Source)    │ ──RPC──>│ shim (Incoming)            │   │
   │   │ owns source QEMU │         │ owns destination QEMU      │   │
   │   │ sends state      │         │ receives state             │   │
   │   └──────────────────┘         └────────────────────────────┘   │
   │           │                              ▲                      │
   │           └────────── QMP migrate ───────┘                      │
   │                  (Phase 1 mechanism)                            │
   └─────────────────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────────────────┐
   │                       Post-cutover                              │
   │                                                                 │
   │   host A                              host B                    │
   │   ┌──────────────────┐                ┌────────────────────┐    │
   │   │ shim (Migrated)  │                │ shim (Owner)       │    │
   │   │ cleanup pending  │                │ resumes guest      │    │
   │   └──────────────────┘                └────────────────────┘    │
   └─────────────────────────────────────────────────────────────────┘
```

## Sandbox modes

The shim's `service` struct gains a `mode` field. Mode determines
which operations are allowed on the sandbox at any time.

| Mode | Set when | Allowed ops | Notes |
|---|---|---|---|
| `Owner` | Normal state. Default after `CreateSandbox`. | All standard CRI ops (Start, Exec, Pause, Resume, Stop). | The mode that exists today. |
| `MigratingOut` | Source shim, after orchestrator calls the migrate-start API. | Read-only CRI ops (Status, Stats, Logs). Write ops return `ErrSandboxMigrating`. | Hypervisor is actively transferring memory; container state is frozen at orchestrator's request. |
| `Incoming` | Destination shim, immediately after `CreateSandbox` invoked with a migrate-incoming hint. | No CRI ops succeed until the handoff completes. Returns `ErrSandboxNotReady`. | QEMU starts in `-incoming` mode; agent vsock isn't yet usable. |
| `Migrated` | Source shim, after a successful migration handoff. | No ops. Shim awaits cleanup signal from orchestrator. | Hypervisor process is in `migrated` state; shim is essentially a tombstone. |
| `Failed` | Either shim, on unrecoverable migration error. | Cleanup ops only. | Transitions back to `Owner` only via orchestrator explicit "abort migration" call (Phase 1 `CancelMigration` clears the QMP state; shim transitions back). |

Transitions:

```
                    ┌───────────────────────────┐
                    │                           │
                    ▼                           │
       ┌──────────► Owner ────────┐             │
       │            │             │ source      │
abort  │            │ source      │             │
       │            ▼             ▼             │
       │     MigratingOut    Failed ────────────┘
       │            │             ▲
       │            │ success     │ destination
       │            ▼             │ error
       │       Migrated           │
       │                          │
       │                          │
       │            ┌─────────────┘
       │            │
       │            │
       └─── Owner ◄─┴── Incoming ──── created on destination
                          │
                          │ handoff done
                          ▼
                        Owner
```

A sandbox is never in two modes simultaneously. The destination
shim's sandbox is `Incoming` until the source signals handoff
complete, at which point it transitions to `Owner`. The source's
sandbox is `MigratingOut` until either success (→ `Migrated`) or
failure (→ `Failed`).

## Handoff RPC

A new gRPC service exposed by the shim **only when**
`experimental.live_migration` is true in `configuration.toml`.
This service is the in-band channel through which source and
destination shims coordinate. Not exposed to containerd; only
shim-to-shim.

```protobuf
service MigrationCoordinator {
  // Called by the source shim against the destination shim once the
  // destination is up and the hypervisor is in -incoming mode.
  // The destination acks readiness with the URI QEMU is listening
  // on (so the source can fill it into the QMP migrate command).
  rpc PrepareIncoming(PrepareIncomingRequest) returns (PrepareIncomingResponse);

  // Streams SandboxState from source to destination. The destination
  // applies it before the cutover so post-cutover read paths return
  // sane data immediately.
  rpc SendSandboxState(stream SandboxStateChunk) returns (SendSandboxStateResponse);

  // Called by the source shim once QMP reports phase=completed.
  // The destination flips Incoming -> Owner.
  rpc CompleteHandoff(CompleteHandoffRequest) returns (CompleteHandoffResponse);

  // Abort. Called by either side. Destination tears down its QEMU;
  // source's hypervisor.CancelMigration() is invoked separately.
  rpc AbortHandoff(AbortHandoffRequest) returns (AbortHandoffResponse);
}

message PrepareIncomingRequest {
  string sandbox_id = 1;
  HypervisorConfigSummary hypervisor_config = 2;
  // Capabilities the source wants enabled; destination acks with a
  // possibly-narrower set if a capability is unsupported on dest.
  repeated string requested_capabilities = 3;
}

message PrepareIncomingResponse {
  // URI that the source's QMP migrate command should target.
  string incoming_uri = 1;
  repeated string accepted_capabilities = 2;
}

message SandboxStateChunk {
  string sandbox_id = 1;
  bytes payload_chunk = 2; // streaming chunks of JSON SandboxState
  bool final = 3;
}
```

(Full protobuf in a follow-up PR; this is the conceptual contract.)

### Shim discovery — how does source find destination?

Two patterns considered:

1. **Orchestrator-mediated**: orchestrator creates the destination
   shim via containerd CRI as if creating a new sandbox, passes an
   annotation that tells it "you're the destination for sandbox X
   on host Y at address Z". Destination shim binds its
   `MigrationCoordinator` to a unix socket whose path is derivable
   from the sandbox ID. Source shim looks up the destination's
   address via Kubernetes (the orchestrator writes a configmap or
   CR like `SandboxMigration{Source, Destination, Phase}`).
2. **Sidecar broker**: a per-host daemonset broker that mediates
   shim-to-shim RPCs. More moving parts.

**Going with pattern 1** for simplicity. Orchestrator owns the
discovery; shims only know about the peer they were told about.
Phase E (orchestration controller in ccs-vamos) owns the
discovery glue.

### State transfer mechanism

`SandboxState` from `pkg/persist/api/sandbox.go` is already JSON-
serializable. The handoff streams that JSON over the
`SendSandboxState` RPC in chunks (~64 KiB each) so we don't have
to materialize the full state in a single gRPC message.

Most fields are small (cgroup paths, network info, agent state,
device list). The hypervisor state inside is the largest dynamic
piece but it's already bounded.

QEMU memory pages do **not** flow through this RPC — they go via
the QMP `migrate tcp:dest:port` channel directly between source
QEMU and destination QEMU. The shim RPC only carries the
*metadata* needed to make the destination shim a faithful
replacement for the source shim.

## Coordination with Phase 1 hypervisor methods

The handoff sequence:

```
1. Orchestrator creates destination shim with MigrationIncoming annotation.
2. Destination shim:
   a. Sets sandbox mode = Incoming
   b. Calls hypervisor.MigrateIncoming(ctx, "tcp:0.0.0.0:0")
   c. Reads the bound port from query-migrate or sockstat
   d. Binds MigrationCoordinator gRPC on a unix socket
3. Orchestrator tells source shim to begin: "destination is at <addr>".
4. Source shim:
   a. Sets sandbox mode = MigratingOut
   b. Dials MigrationCoordinator on destination
   c. PrepareIncoming → receives incoming_uri
   d. SendSandboxState → streams SandboxState JSON
   e. Calls hypervisor.MigrateOut(ctx, incoming_uri, opts)
   f. Polls hypervisor.GetMigrationStatus until phase=completed
   g. CompleteHandoff(destination)
   h. Sets sandbox mode = Migrated
5. Destination shim, on CompleteHandoff:
   a. Verifies QMP query-migrate shows status=completed on its side
   b. Applies SandboxState to its in-memory sandbox struct
   c. Sets sandbox mode = Owner
   d. Resumes processing CRI requests
6. Orchestrator stops the source shim normally.
```

The hypervisor methods from Phase B are called by the shim — not by
the orchestrator. The shim is the only entity that knows about both
the hypervisor and the sandbox metadata.

## Failure modes

### Destination QEMU fails to start

`hypervisor.MigrateIncoming` returns an error. Destination shim
transitions to `Failed` and the orchestrator should tear it down.
Source remains in `Owner`, never transitioned.

### Source QMP migrate command fails immediately

Before any state transfer. Source shim transitions back to `Owner`;
orchestrator aborts the destination shim.

### Migration is in progress, network fails

QEMU detects the broken migration channel. `GetMigrationStatus`
returns `phase=failed`. Source shim:
- Logs the error
- Calls `hypervisor.CancelMigration()` (defensive — QEMU may have
  already)
- Transitions to `Failed`
- Notifies orchestrator via Kubernetes Event so the
  `KataSandboxMigration` CR can update its status

Source guest is still running normally — no data loss, just a
failed migration attempt.

### Source shim dies during MigratingOut

QEMU process is orphaned (containerd will SIGKILL on shim death
under containerd's default settings). Destination shim's QEMU
still in `-incoming` mode, never receives the rest of the state.
A separate timeout (default: 5 min, configurable) at the
destination's `MigrationCoordinator` aborts after no activity and
cleans up.

### Destination shim dies after CompleteHandoff but before cleanup

The source's QEMU is in `migrated` state — it can't resume.
This is the worst case: containers are lost. Mitigation:
the source shim doesn't transition to `Migrated` (its terminal
state) until the destination acks `CompleteHandoff` AND its QEMU
is confirmed running. We also keep the source's QMP socket alive
until the destination signals "fully resumed" to allow a rollback
via `migrate-cancel` if the destination collapses early in
post-handoff cleanup.

### Containerd reaps source shim too aggressively

Containerd's default behavior is to kill the shim once the
sandbox is stopped from its perspective. If the source shim
reports the sandbox as stopped before the destination shim is
fully `Owner`, containerd will SIGKILL the source — possibly
mid-state-transfer. Mitigation: the source shim keeps reporting
the sandbox as `Running` to containerd throughout
`MigratingOut`. Only after `CompleteHandoff` returns successfully
does the source report it as stopped.

This carries a risk: if the source shim crashes after reporting
`Running` to containerd but before completing the handoff,
containerd will retry various ops on a dead sandbox. The shim's
existing crash-recovery code handles that for non-migration
cases and should continue to work here.

## Configuration

A new section in `configuration.toml`:

```toml
[experimental]
# Enable live migration support. When false, the migration RPC
# is not bound, sandbox mode is permanently Owner, and all
# Hypervisor migration methods return ErrMigrationNotSupported
# at the shim layer regardless of the underlying hypervisor's
# capability. Default false; flip to true only after verifying
# the feature works in your environment.
live_migration = false
```

The flag exists to give operators a kill switch and to make the
feature opt-in during the experimental period. Setting it to false
must result in **zero behavior change** compared to a Kata version
without this work.

## Backwards compatibility

- **API**: No breaking changes to containerd CRI surface. The shim
  still implements the same TaskService and SandboxService.
- **On-disk format**: `SandboxState` is unchanged — we serialize
  what's already there. If future work adds fields, those fields
  must be optional during the experimental period.
- **Behavior with `experimental.live_migration=false`**: identical
  to current Kata. Mode is permanently `Owner`. The
  `MigrationCoordinator` gRPC server is not started. Hypervisor
  migration methods (Phase B) are still callable but the shim
  doesn't invoke them.

## Testing strategy

Outside-in across three layers:

1. **State machine unit tests** in `pkg/containerd-shim-v2/migration_test.go`.
   Drive mode transitions in isolation, verify allowed ops and
   error returns per mode.
2. **Handoff RPC tests** with two in-process shims and a mocked
   hypervisor. Verify the gRPC sequence (PrepareIncoming →
   SendSandboxState → CompleteHandoff) produces the expected
   final state on the destination shim.
3. **Integration test** in `tests/functional/` — two real shims
   on two test nodes with two real QEMUs. Drive a migration
   end-to-end without an orchestrator (the test acts as one).
   Verify the destination guest is running with the source's
   state. This test is the gate before declaring Phase C done.

## Implementation order

The work is large enough that we split into milestones with
review checkpoints:

1. **C.0** — Land the configuration flag and the placeholder
   mode field on the sandbox. No new behavior; mode is always
   `Owner` until C.1. ~200 LOC, 1 PR.
2. **C.1** — State machine: introduce the mode enum, transitions,
   and the per-mode op gating in `pkg/containerd-shim-v2/`.
   Existing tests must continue to pass. ~500 LOC.
3. **C.2** — `MigrationCoordinator` gRPC service skeleton +
   `PrepareIncoming` + `SendSandboxState`. Destination shim can
   receive state but doesn't yet transition modes; source can
   send state but doesn't yet invoke QMP migrate. Tests for the
   RPC plumbing. ~800 LOC.
4. **C.3** — Wire it together: source invokes
   `hypervisor.MigrateOut`, polls status, calls
   `CompleteHandoff`. Destination transitions `Incoming → Owner`
   on successful handoff. State machine unit tests now cover the
   full flow. ~600 LOC.
5. **C.4** — Failure-mode hardening: timeouts, abort paths,
   destination-death-during-handoff recovery, source-crash
   detection. The work that turns a "works in tests" PoC into
   something we'd run in front of real workloads. ~700 LOC.
6. **C.5** — Integration test in `tests/functional/`. Two real
   shims, real QEMUs, end-to-end. Gate for Phase C close-out.

Each milestone is a separately reviewable, separately mergeable
change on the fork's `dev` branch. The `experimental.live_migration`
flag stays off through C.4 and only flips on for the C.5
integration test (and only on the test infrastructure).

## Open questions

- **Mode persistence**: Should the sandbox mode survive a shim
  restart, or is it always reconstructed? Today's shim recovers
  `SandboxState` from disk on restart; mode should probably be
  persisted too. Implementation note: serialize mode as part of
  `SandboxState` extension fields.
- **Concurrent migrations**: A node could host multiple sandboxes
  migrating simultaneously. The state machine is per-sandbox so
  there's no shared resource concern at the shim layer — but
  network bandwidth and QEMU's concurrency caps may need
  per-node throttling. Defer to Phase F.
- **Containerd CRI semantics during the overlap window**: When
  source-shim is `MigratingOut` and destination-shim is
  `Incoming`, both shims have an entry in containerd's task
  database with the same sandbox ID. Containerd doesn't
  natively support two shims for one sandbox. Workarounds:
  - Different "sandbox IDs" at the containerd layer; orchestrator
    holds the mapping. Complex.
  - Source shim continues to claim ownership in containerd's view
    until cutover; destination's containerd entry is created
    only at `CompleteHandoff` time, by the orchestrator.
  - Negotiate with containerd upstream for a sandbox-handoff
    primitive. Long-term right answer; out of scope here.
  Going with option 2 for the initial implementation.

## Out of scope, again, explicitly

- IO stream handoff (`attach`, `exec`, `logs` open during migration).
- Agent vsock CID handoff.
- Sub-second cutover guarantees. Initial target: cutover ≤ 10s
  p95. Tighter SLAs in Phase F.
- Post-copy migration. The capability flag is plumbed via
  `MigrateOptions` (Phase B) but no special handling for
  switchover; orchestrators that need post-copy can drive QMP
  `migrate-start-postcopy` directly out-of-band for now.
- Network identity continuity (pod IP stability across hosts).
  Owned by the orchestrator / CNI layer, not the shim.
