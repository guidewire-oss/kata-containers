# Live migration — hypervisor abstraction methods

## Status

Proposal — Phase 1 of an incremental live migration effort. This
document covers the smallest building block: extending the
`Hypervisor` interface with the primitives needed to drive a QEMU
live migration from outside the hypervisor package. Subsequent phases
(shim sandbox lifecycle, agent vsock reconnect, container IO stream
handoff) build on top.

## Motivation

Today Kata's `Hypervisor` interface exposes lifecycle methods
(`CreateVM`, `StartVM`, `StopVM`, `PauseVM`, `ResumeVM`, `SaveVM`) but
not live migration. A higher-level controller that wants to live-
migrate a sandbox between two hosts must drive QMP directly or
re-implement the QMP plumbing — both leak hypervisor-internal
concerns out of the abstraction.

This proposal adds four methods to the `Hypervisor` interface that
mirror QEMU's migration QMP commands behind a hypervisor-agnostic
shape. The QMP wire code already exists in `pkg/govmm/qemu`; we add
two small helpers there and expose the surface to virtcontainers.

For non-QEMU implementers (Cloud Hypervisor, Firecracker, Dragonball,
remote hypervisor, mock) the methods return a typed
`ErrMigrationNotSupported`. Those hypervisors either have their own
migration mechanisms (Cloud Hypervisor uses a different protocol) or
none at all; supporting them is out of scope for this phase.

This is **not** a complete live migration. The full feature requires
shim-level sandbox lifecycle changes (Owner / Source / Destination
modes) and container IO stream handoff, which are tracked separately.
This phase delivers the hypervisor-level building block in isolation
so it can be reviewed, tested, and merged without depending on the
larger work.

## Non-goals

- Shim-level sandbox lifecycle changes (separate phase).
- Container IO stream handoff between source/destination shims
  (separate phase).
- Cloud Hypervisor live migration (different protocol; out of scope
  here).
- Confidential Containers (CoCo) variants. Guest memory is bound to
  the source host's TEE attestation; cross-TEE migration is an
  unsolved research problem upstream. Implementers for CoCo runtime
  classes return `ErrMigrationNotSupported`.
- Network plumbing (Cilium Egress Gateway, IP-following-pod). Pure
  hypervisor-level migration assumes the orchestrator handles network
  identity continuity.

## Interface additions

In `src/runtime/virtcontainers/hypervisor.go`:

```go
// MigrateOptions tunes the QMP migrate-set-capabilities and
// migrate-set-parameters calls that precede a migration. All fields
// are optional; zero values map to QEMU defaults.
type MigrateOptions struct {
    // Capabilities is a name -> enabled map applied via
    // migrate-set-capabilities. Common values: "auto-converge",
    // "postcopy-ram", "compress", "xbzrle".
    Capabilities map[string]bool

    // Parameters is a name -> value map applied via
    // migrate-set-parameters. Common values: "max-bandwidth" (bytes/sec),
    // "downtime-limit" (ms), "cpu-throttle-initial" (percent).
    Parameters map[string]uint64
}

// MigrationStatus is the digestible projection of QEMU's
// query-migrate response. Fields not relevant to orchestration
// (e.g. xbzrle cache stats) are omitted; the underlying govmm type
// remains available for callers that need them.
type MigrationStatus struct {
    // Phase is one of: "none", "setup", "active", "postcopy-active",
    // "completed", "failed", "cancelled", "cancelling".
    Phase string

    // BytesTransferred and TotalBytes are zero before "active" phase.
    BytesTransferred uint64
    TotalBytes       uint64

    // DirtyRate is bytes/sec of guest RAM page dirtying. Drives the
    // auto-converge decision.
    DirtyRate uint64

    // BandwidthBPS is observed migration bandwidth.
    BandwidthBPS uint64

    // RemainingMS is QEMU's estimate of completion time in
    // milliseconds (zero before "active").
    RemainingMS uint64
}

// MigrateOut initiates an outgoing migration to the destination
// specified by uri (e.g. "tcp:dest-host:4444"). Returns when QEMU has
// accepted the migrate command; actual transfer progress is observable
// via GetMigrationStatus. Returns an error if the hypervisor doesn't
// support migration or if QEMU rejects the migrate request.
MigrateOut(ctx context.Context, uri string, opts MigrateOptions) error

// MigrateIncoming starts a QEMU instance in receive-migration mode
// listening on uri. Called on the destination host. Must be invoked
// before MigrateOut on the source.
MigrateIncoming(ctx context.Context, uri string) error

// GetMigrationStatus queries QEMU for the current migration state.
// Safe to call repeatedly; orchestrators typically poll every 1-2s
// during an active migration.
GetMigrationStatus(ctx context.Context) (MigrationStatus, error)

// CancelMigration aborts an in-flight migration. The guest continues
// running on the source. No-op if no migration is in progress.
CancelMigration(ctx context.Context) error
```

The companion error type:

```go
// ErrMigrationNotSupported is returned by hypervisors that do not
// implement live migration via this interface.
var ErrMigrationNotSupported = errors.New("live migration not supported by this hypervisor")
```

## Semantics and edge cases

### Calling order

A successful migration sequence:

1. **Destination host**: `MigrateIncoming(ctx, "tcp:0.0.0.0:4444")`.
   QEMU starts in `-incoming` mode, listening but not running.
2. **Source host**: `MigrateOut(ctx, "tcp:dest:4444", opts)`. QEMU
   begins streaming guest state. Returns immediately.
3. **Source host**: orchestrator polls `GetMigrationStatus` until
   phase is `completed` (success) or `failed`/`cancelled`.
4. On success, **destination host's** QEMU resumes guest execution;
   source's QEMU is in `migrated` state and should be stopped via
   `StopVM`.

Out-of-order calls (e.g. `MigrateOut` without a destination set up)
return whatever error QEMU reports — typically a connection failure.

### Configuration timing

`opts.Capabilities` and `opts.Parameters` are applied via
`migrate-set-capabilities` and `migrate-set-parameters` **before** the
`migrate` command, in `MigrateOut`. Calling `MigrateOut` again on the
same source without first cancelling is undefined behavior at the QMP
layer (QEMU rejects). The interface does not enforce ordering — that's
the orchestrator's responsibility.

### Cancellation

`CancelMigration` sends `migrate-cancel`. QEMU may take a short while
to fully cancel; subsequent `GetMigrationStatus` calls will show
`cancelling` then `cancelled`. The guest continues running on the
source throughout.

### Post-copy

`opts.Capabilities["postcopy-ram"] = true` enables post-copy support.
To actually switch from pre-copy to post-copy mid-migration the
orchestrator calls `migrate-start-postcopy` — this isn't yet exposed
via the interface; orchestrators that need it can drive QMP directly
for now or this proposal extends with a `StartPostcopy(ctx)` method
in a follow-up.

## Implementation

### `pkg/govmm/qemu`

Two new helpers:

```go
// ExecuteMigrationCancel cancels an in-flight migration.
func (q *QMP) ExecuteMigrationCancel(ctx context.Context) error {
    return q.executeCommand(ctx, "migrate-cancel", nil, nil)
}

// ExecuteMigrationSetParameters applies migrate-set-parameters.
func (q *QMP) ExecuteMigrationSetParameters(ctx context.Context, params map[string]interface{}) error {
    return q.executeCommand(ctx, "migrate-set-parameters", params, nil)
}
```

The existing `ExecSetMigrationCaps`, `ExecSetMigrateArguments`,
`ExecuteQueryMigration`, and `ExecuteMigrationIncoming` cover the rest.

### `virtcontainers/qemu.go`

```go
func (q *qemu) MigrateOut(ctx context.Context, uri string, opts MigrateOptions) error {
    if err := q.qmpSetup(); err != nil {
        return err
    }
    if len(opts.Capabilities) > 0 {
        caps := make([]map[string]interface{}, 0, len(opts.Capabilities))
        for name, on := range opts.Capabilities {
            caps = append(caps, map[string]interface{}{"capability": name, "state": on})
        }
        if err := q.qmpMonitorCh.qmp.ExecSetMigrationCaps(ctx, caps); err != nil {
            return fmt.Errorf("migrate-set-capabilities: %w", err)
        }
    }
    if len(opts.Parameters) > 0 {
        params := make(map[string]interface{}, len(opts.Parameters))
        for k, v := range opts.Parameters {
            params[k] = v
        }
        if err := q.qmpMonitorCh.qmp.ExecuteMigrationSetParameters(ctx, params); err != nil {
            return fmt.Errorf("migrate-set-parameters: %w", err)
        }
    }
    return q.qmpMonitorCh.qmp.ExecSetMigrateArguments(ctx, uri)
}
```

And analogous `MigrateIncoming`, `GetMigrationStatus`,
`CancelMigration` wrappers around the existing govmm helpers.

`GetMigrationStatus` maps govmm's `MigrationStatus` (which has
xbzrle cache and other internals) onto the slimmer
`virtcontainers.MigrationStatus`.

### Other implementers

`mock_hypervisor.go`, `clh.go`, `remote.go`, and any other type
satisfying `Hypervisor` get four small stubs returning
`ErrMigrationNotSupported`. The mock optionally records the call
arguments for tests that want to assert orchestrator behavior.

## Testing

Outside-in:

1. **Unit tests** in `qemu_migration_test.go` with a mocked QMP
   socket. Verifies that calling each new method results in the
   correct sequence of QMP commands on the wire.
2. **govmm unit tests** for the two new helpers
   (`ExecuteMigrationCancel`, `ExecuteMigrationSetParameters`).
3. **Integration test** — separate follow-up, runs a real QEMU pair
   on a test host and exercises a migration end-to-end. Out of scope
   for this PR; tracked separately.

## Backwards compatibility

The interface gains four methods. Any external implementer of
`Hypervisor` will fail to compile until they add stubs. Inside this
repo all four built-in implementers get stubs in the same change.

No on-disk format changes, no config changes, no behavior changes for
existing flows. Feature is purely additive.

## Open questions

- Should `MigrateOptions` use govmm's `MigrationCapability` enum
  rather than `map[string]bool`? The map is more flexible but loses
  type safety. The enum doesn't yet exist in govmm; introducing it
  would be a separate cleanup.
- Should there be a `StartPostcopy(ctx context.Context) error` method
  now, or wait until an orchestrator actually needs it? Leaning wait.
- Naming: `MigrateOut` vs `Migrate`. `MigrateOut` reads better paired
  with `MigrateIncoming`; `Migrate` is shorter but ambiguous about
  direction. Going with `MigrateOut`.
