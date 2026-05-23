# Sandbox identity during live migration

## Problem

A kata sandbox is identified throughout the runtime by a single string
(`Sandbox.id`, `q.id`, etc.) which originates from containerd's CRI
`RunPodSandboxRequest`. That ID is woven into:

- on-disk paths (`/run/kata-containers/shared/sandboxes/<id>/`, `/run/vc/vm/<id>/`,
  `/run/vc/sbs/<id>/`)
- virtiofsd's `--shared-dir` argument and the inode paths it persists in its
  migration state
- QMP and vhost-user socket file names under `<VMStorePath>/<id>/`
- kata's own persisted state keys (`/run/vc/sbs/<id>/`)
- logging fields, resource controller groups, and debug socket paths

During a live migration the destination pod is a new Kubernetes object with
a new containerd sandbox ID, so all of the above paths and persisted state
keys differ from the source. As soon as a migrated state stream encodes
anything anchored at the source's ID, the destination cannot resolve it.

The first observed failure is virtiofsd:

```text
virtiofsd: Migration failed: Failed to load state:
  Inode 2: Opening /<source-sandbox-id>: No such file or directory
qemu-system-x86_64: Error loading back-end state of virtio-user-fs device
  /machine/peripheral-anon/device[1]/virtio-backend (tag: "kataShared"):
  Back-end failed to process its internal state
```

Patching virtiofsd's path layout in isolation would address that single
error but leaves every other ID-anchored migration state field as a
latent bug.

## Goal

After a successful live migration the destination kata sandbox presents
the **same internal identity** as the source — same on-disk paths, same
persisted state keys, same anything that the source might have encoded
into migrated state. From containerd's perspective the destination
remains a new pod with a new CRI sandbox ID; the two identities live in
separate filesystem trees and never collide.

Stated as an invariant: any path or state key that kata itself owns and
that could appear in a migration stream uses the *source's* sandbox ID
on the destination. Anything containerd or kubelet owns (the OCI bundle
directory, the CRI sandbox ID, the pod UID in kubelet's view) continues
to use the destination's ID.

## Design

### Dual identity on the Sandbox

`Sandbox` exposes two getters:

```go
// ContainerdID returns the CRI sandbox ID assigned by containerd. Used
// for OCI bundle paths, kubelet/CRI bookkeeping, and anything cross-
// referenced with containerd's own data layout.
func (s *Sandbox) ContainerdID() string

// InternalID returns the identity kata uses for its own on-disk paths
// and persisted state. Equal to ContainerdID() for a freshly created
// sandbox. Overridden to the source sandbox ID when the sandbox was
// created as the destination of a live migration, so migrated state
// encoded with the source's paths resolves correctly on this host.
func (s *Sandbox) InternalID() string
```

Both are backed by fields on the Sandbox struct:

```go
type Sandbox struct {
    id                 string  // CRI sandbox ID — what containerd assigned
    internalID         string  // defaults to id; overridden in migrate-incoming
    // ...
}
```

`id` stays the existing field so all CRI-facing code paths and any code
that interacts with containerd's bookkeeping continue to compile and
behave unchanged. `internalID` is new and is consulted by every kata-
owned path or state-key generator.

### The classification rule

For every existing reference to `q.id` / `s.id` / `sandbox.ID()`, the
rule is mechanical:

| Reference in this kind of context | Replace with |
| --- | --- |
| Logging, tracing fields, metrics labels | `ContainerdID()` (unchanged behavior) |
| CRI request handling, containerd events | `ContainerdID()` |
| OCI bundle paths (`/run/containerd/...`) | `ContainerdID()` |
| `/run/kata-containers/shared/sandboxes/<X>/...` | `InternalID()` |
| `/run/vc/vm/<X>/...` | `InternalID()` |
| `/run/vc/sbs/<X>/...` | `InternalID()` |
| QMP / vhost-fs / vsock socket file names | `InternalID()` |
| virtiofsd `--shared-dir` argument | `InternalID()` |
| Persisted state keys (anything written under `RunStorePath`) | `InternalID()` |
| Resource controller cgroup names | `InternalID()` — present in QEMU's view of itself, would round-trip through migration |

Most kata-owned path generation flows through four helpers in
`virtcontainers/kata_agent.go`:

```go
func kataHostSharedDir() string                  // base, unchanged
func getSandboxPath(id string) string            // <base>/<id>
func getSharedPath(id string) string             // <base>/<id>/shared
func getMountPath(id string) string              // <base>/<id>/mounts
func getPrivatePath(id string) string            // <base>/<id>/private
```

The mechanical change at each callsite is to pass `s.InternalID()` (or
the equivalent for whatever object exposes the sandbox) instead of
`s.id`. The helpers themselves don't need to change.

Path-generating callsites outside those helpers (mostly inline
`filepath.Join(VMStorePath, q.id, ...)` in `qemu.go`, `clh.go`,
`stratovirt.go`, and `sandbox.go`) get the same treatment.

### Source-of-truth for the override

The destination kata-shim learns the source's sandbox ID from a Pod
annotation set by the orchestrator at destination-pod creation time:

```text
io.katacontainers.config.runtime.migration_source_sandbox_id = <source-sandbox-id>
```

This annotation lives in the same family as the existing
`migration_incoming_uri` annotation (declared in
`virtcontainers/pkg/annotations/annotations.go`). The shim parses it in
`Create()` and stores it on the sandbox config. The `Sandbox`
constructor honors it:

```go
if cfg.MigrationSourceSandboxID != "" {
    s.internalID = cfg.MigrationSourceSandboxID
} else {
    s.internalID = s.id
}
```

When the annotation is absent (the normal, non-migration case),
`internalID == id` and behavior is identical to today.

### Persistence and restart

The `internalID` is part of the sandbox's persisted state. If the
destination shim is restarted (or the kata-runtime is restarted on the
destination host) before the migrated sandbox is torn down, the saved
state must reload with the same `internalID` so all subsequent path
generation continues to use the source's identity.

This means:

1. `MigrationSourceSandboxID` is added to `persistapi.SandboxState` and
   round-tripped on save/load.
2. The reload path in `sandbox.go` sets `s.internalID` from the
   persisted value rather than re-reading the annotation (which may not
   be available at restart).
3. The persisted state file itself is written under
   `<RunStorePath>/<InternalID()>/...` so the post-migration shim finds
   the same state file across restarts.

A consequence worth noting: the destination's state file lives under the
*source's* sandbox ID on disk. A `ls /run/vc/sbs/` on the destination
node shows a directory named with the source's ID, not the
destination's. This is correct (it's where the persisted internal
identity lives) but is a surprise for anyone debugging by directory
name. The state file should include both IDs in its serialized form so
inspection isn't ambiguous.

### Annotation parsing in the shim

`pkg/containerd-shim-v2/create.go` already parses
`migration_incoming_uri` and stores it on
`HypervisorConfig.IncomingMigrationURI`. We add a sibling field for the
source ID:

```go
type HypervisorConfig struct {
    // ...
    IncomingMigrationURI       string
    MigrationSourceSandboxID   string  // NEW
}
```

The shim's annotation reader pulls
`io.katacontainers.config.runtime.migration_source_sandbox_id` into
this field. The Sandbox constructor consults it (see "Source-of-truth"
above).

The annotation is added to the per-runtime allow-list in
`virtcontainers/pkg/annotations/annotations.go` so containerd will
forward it to the shim.

### Orchestrator side

The vamos controller's `buildKataMigrationDestinationPod` already
stamps `migration_incoming_uri`. It needs to also stamp
`migration_source_sandbox_id`, pulled from the source kata-shim's
`/pod` endpoint (which we use already to learn the source's sandbox
ID for the handoff).

The controller change is one line in the annotation map, plus
populating it from the source-shim response that's already in scope.

## Implementation order

The change is large only in volume of call sites touched, not in
conceptual difficulty. To keep the blast radius bounded, ship it in
stages, each independently buildable and testable:

1. **Add the field and the two accessors.** Default `internalID = id`
   in every constructor; no behavior change yet. Includes the
   annotation plumbing, persistence round-trip, and the new
   `HypervisorConfig` field. Unit tests assert the default (
   `internalID == id`) and the override (annotation populates
   `internalID`).
2. **Migrate path-generating helpers in `kata_agent.go`** to take
   `sandbox.InternalID()`. The helpers themselves don't change; their
   callers do. Touches ~20 lines.
3. **Migrate inline `filepath.Join(VMStorePath, q.id, ...)` in
   `qemu.go`** to `filepath.Join(VMStorePath, q.InternalID(), ...)`.
   `q.InternalID()` is a new method on `qemu` that returns the sandbox
   it embeds. Touches ~10 lines in `qemu.go`. Repeat the same in
   `clh.go`, `stratovirt.go`, `firecracker.go` (smaller — these
   hypervisors don't support migration today, so the change is a
   correctness baseline rather than a fix).
4. **Migrate persisted-state key generators** under
   `virtcontainers/persist/` to use `InternalID()` for the storage key.
   This is where the test plan needs care: a sandbox saved with
   `internalID = source-id` and reloaded must come up with
   `internalID = source-id`, not the on-disk ID.
5. **Migrate `fs_share_linux.go`** — the one that virtiofsd actually
   consumes, the original motivation for this change.
6. **Migrate everything else** — resource controllers, sockets, swap
   files, dumps. Each is one-line. The full grep audit is in the
   appendix.
7. **End-to-end test on the cluster** with the existing
   `scripts/diagnose-kata-migration.sh`. virtiofsd no longer reports
   path mismatch; migration reaches resume.

Stages 1, 2, and 3 land together as one PR — they're meaningless in
isolation but together exercise the dual-identity path for hypervisor
files. Stages 4–6 land as separate PRs so a regression bisect points at
the specific layer.

## Test plan

Unit tests live alongside the code they test. The cross-cutting tests:

- `Sandbox.InternalID()` returns `id` when no migration annotation is
  set, and returns the annotation value when it is.
- `Sandbox` reloaded from persisted state preserves `internalID`
  across the round-trip.
- `getSandboxPath(s.InternalID())` returns a path under
  `<base>/<source-id>/` for a migrate-incoming sandbox and under
  `<base>/<dest-id>/` for a normal sandbox.
- A `qemu` instance constructed for a migrate-incoming sandbox emits
  a QEMU command line whose `-pidfile`, `-chardev path=` and
  `-qmp unix:fd=...` socket paths are anchored at the source ID.

The integration-level signal comes from the existing kata test fixture
plus the cluster-level diagnose script. Once dual-identity is wired
through, a migration that previously failed at
`virtiofsd: Inode 2: Opening /<source-id>` should instead succeed past
the device-state-load phase.

## Risks

- **Containerd reaches into a kata-owned path.** If any containerd-
  facing code path constructs a kata-owned filesystem path using its
  own sandbox ID (containerd's, not kata's), it will look in the wrong
  place after migration. The mitigation is to keep that boundary
  audited: containerd hands kata an ID, kata uses `ContainerdID()`
  only when reflecting back to containerd, never for its own paths.
  The full grep audit is the enforcement mechanism.
- **A persisted state field outside the audit references the source
  ID.** Possible but bounded — anything that survives to the migration
  stream is on the QEMU side, and QEMU's own state references are
  through the host paths we're already addressing. The unit tests
  exercise the persist round-trip explicitly to catch this class.
- **Logs become harder to grep across the source + destination
  hosts.** Today a single sandbox ID greps cleanly across both nodes;
  after this change, the destination's `ContainerdID()` appears in
  containerd's logs while `InternalID()` appears in kata's path
  logging. Mitigated by always emitting both in any new log line that
  the migration code path adds, and by a one-line log at sandbox
  startup that records both IDs side by side.
- **The destination's `/run/vc/sbs/<source-id>/` directory looks like
  a leftover state file from another sandbox.** An operator who
  manually cleans up "stale" sandbox state could delete a live
  destination's state. Mitigated by writing a `kata-migration.json`
  marker into the directory at create time that documents the
  relationship, and by documenting this behavior in the operator
  runbook.

## Appendix: call-site audit

134 references to `q.id`, `s.id`, `sandbox.id`, `sandbox.ID()`, and
`GetID()` across `virtcontainers/` and `pkg/containerd-shim-v2/`
(non-test files).

Concentration:

| File | Count | Notes |
| --- | --- | --- |
| `virtcontainers/qemu.go` | 33 | path generation, QMP socket, pidfile, dump path |
| `virtcontainers/sandbox.go` | 29 | resource controllers, swap, persist keys, logging |
| `virtcontainers/clh.go` | ~10 | analogous to qemu.go for cloud-hypervisor |
| `virtcontainers/stratovirt.go` | ~10 | analogous to qemu.go for stratovirt |
| `virtcontainers/fs_share_linux.go` | 2 | the file that motivated this change |
| Everywhere else | scattered | logging, container loop bookkeeping, agent calls |

The full per-file audit gets done during stages 2–6; this section gets
updated in the same PR as the stage that finishes the audit.
