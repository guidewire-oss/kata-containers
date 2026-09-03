// Copyright (c) 2016 Intel Corporation
// Copyright (c) 2020 Adobe Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	v1 "github.com/containerd/cgroups/stats/v1"
	v2 "github.com/containerd/cgroups/v2/stats"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	cri "github.com/containerd/containerd/pkg/cri/annotations"
	crio "github.com/cri-o/cri-o/pkg/annotations"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/device/api"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/device/config"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/device/drivers"
	deviceManager "github.com/kata-containers/kata-containers/src/runtime/pkg/device/manager"
	volume "github.com/kata-containers/kata-containers/src/runtime/pkg/direct-volume"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils/katatrace"
	resCtrl "github.com/kata-containers/kata-containers/src/runtime/pkg/resourcecontrol"
	exp "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/experimental"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist"
	persistapi "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/api"
	pbTypes "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/annotations"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/compatoci"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/cpuset"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/rootless"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/utils"

	"google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"
)

// sandboxTracingTags defines tags for the trace span
var sandboxTracingTags = map[string]string{
	"source":    "runtime",
	"package":   "virtcontainers",
	"subsystem": "sandbox",
}

const (
	// VmStartTimeout represents the time in seconds a sandbox can wait before
	// to consider the VM starting operation failed.
	VmStartTimeout = 10

	// DirMode is the permission bits used for creating a directory
	DirMode = os.FileMode(0750) | os.ModeDir

	mkswapPath = "/sbin/mkswap"
	rwm        = "rwm"

	// When the Kata overhead threads (I/O, VMM, etc) are not
	// placed in the sandbox resource controller (A cgroup on Linux),
	// they are moved to a specific, unconstrained resource controller.
	// On Linux, assuming the cgroup mount point is at /sys/fs/cgroup/,
	// on a cgroup v1 system, the Kata overhead memory cgroup will be at
	// /sys/fs/cgroup/memory/kata_overhead/$CGPATH where $CGPATH is
	// defined by the orchestrator.
	resCtrlKataOverheadID = "/kata_overhead/"

	sandboxMountsDir = "sandbox-mounts"

	// Restricted permission for shared directory managed by virtiofs
	sharedDirMode = os.FileMode(0700) | os.ModeDir

	// hotplug factor indicates how much memory can be hotplugged relative to the amount of
	// RAM provided to the guest. This is a conservative heuristic based on needing 64 bytes per
	// 4KiB page of hotplugged memory.
	//
	// As an example: 12 GiB hotplugged -> 3 Mi pages -> 192 MiBytes overhead (3Mi x 64B).
	// This is approximately what should be free in a relatively unloaded 256 MiB guest (75% of available memory). So, 256 Mi x 48 => 12 Gi
	acpiMemoryHotplugFactor = 48
)

var (
	errSandboxNotRunning = errors.New("Sandbox not running")
)

// HypervisorPidKey is the context key for hypervisor pid
type HypervisorPidKey struct{}

// SandboxStatus describes a sandbox status.
type SandboxStatus struct {
	Annotations      map[string]string
	ID               string
	Hypervisor       HypervisorType
	ContainersStatus []ContainerStatus
	State            types.SandboxState
	HypervisorConfig HypervisorConfig
	EmptyDirMode     string
}

// SandboxStats describes a sandbox's stats
type SandboxStats struct {
	CgroupStats CgroupStats
	Cpus        int
}

type SandboxResourceSizing struct {
	// The number of CPUs required for the sandbox workload(s)
	WorkloadCPUs float32
	// The base number of CPUs for the VM that are assigned as overhead
	BaseCPUs float32
	// The amount of memory required for the sandbox workload(s)
	WorkloadMemMB uint32
	// The base amount of memory required for that VM that is assigned as overhead
	BaseMemMB uint32
}

// SandboxConfig is a Sandbox configuration.
type SandboxConfig struct {
	// Annotations keys must be unique strings and must be name-spaced
	Annotations map[string]string

	// Custom SELinux security policy to the container process inside the VM
	GuestSeLinuxLabel string

	HypervisorType HypervisorType

	ID string

	Hostname string

	// SandboxBindMounts - list of paths to mount into guest
	SandboxBindMounts []string

	// Experimental features enabled
	Experimental []exp.Feature

	// Containers describe the list of containers within a Sandbox.
	// This list can be empty and populated by adding containers
	// to the Sandbox a posteriori.
	// TODO: this should be a map to avoid duplicated containers
	Containers []ContainerConfig

	Volumes []types.Volume

	NetworkConfig NetworkConfig

	AgentConfig KataAgentConfig

	HypervisorConfig HypervisorConfig

	ShmSize uint64

	SandboxResources SandboxResourceSizing

	VfioMode config.VFIOModeType

	// StaticResourceMgmt indicates if the shim should rely on statically sizing the sandbox (VM)
	StaticResourceMgmt bool

	// SharePidNs sets all containers to share the same sandbox level pid namespace.
	SharePidNs bool
	// SystemdCgroup enables systemd cgroup support
	SystemdCgroup bool
	// SandboxCgroupOnly enables cgroup only at podlevel in the host
	SandboxCgroupOnly bool

	// DisableGuestSeccomp disable seccomp within the guest
	DisableGuestSeccomp bool

	// EmptyDirMode specifies how Kubernetes emptyDir volumes are handled.
	// Valid values are "shared-fs" (default) or "block-encrypted".
	EmptyDirMode string

	// EnableVCPUsPinning controls whether each vCPU thread should be scheduled to a fixed CPU
	EnableVCPUsPinning bool

	// Create container timeout which, if provided, indicates the create container timeout
	// needed for the workload(s)
	CreateContainerTimeout uint64

	// ForceGuestPull enforces guest pull independent of snapshotter annotations.
	ForceGuestPull bool

	// KubeletRootDir is the kubelet root directory (e.g. /var/lib/kubelet or
	// /var/lib/k0s/kubelet for k0s). If empty, the runtime uses the default
	// /var/lib/kubelet for matching ConfigMap/Secret volume paths.
	KubeletRootDir string

	// IncomingMigrationURI marks the sandbox as the destination of
	// an inbound live migration. Set by the shim from the
	// io.katacontainers.config.runtime.migration_incoming_uri OCI
	// annotation. When non-empty, the hypervisor boots with
	// "-incoming defer" so QEMU is paused waiting for the source's
	// memory; the post-VM-start setup (agent connection, container
	// creation) is skipped until the handoff completes. Empty for
	// every normal sandbox.
	IncomingMigrationURI string
}

// valid checks that the sandbox configuration is valid.
func (sandboxConfig *SandboxConfig) valid() bool {
	if sandboxConfig.ID == "" {
		return false
	}

	if _, err := NewHypervisor(sandboxConfig.HypervisorType); err != nil {
		sandboxConfig.HypervisorType = QemuHypervisor
	}

	// validate experimental features
	for _, f := range sandboxConfig.Experimental {
		if exp.Get(f.Name) == nil {
			return false
		}
	}
	return true
}

// Sandbox is composed of a set of containers and a runtime environment.
// A Sandbox can be created, deleted, started, paused, stopped, listed, entered, and restored.
type Sandbox struct {
	ctx        context.Context
	devManager api.DeviceManager
	factory    Factory
	hypervisor Hypervisor
	agent      agent
	store      persistapi.PersistDriver
	fsShare    FilesystemSharer

	swapDevices    []*config.BlockDrive
	volumes        []types.Volume
	ephemeralDisks []EphemeralDisk

	monitor         *monitor
	config          *SandboxConfig
	annotationsLock *sync.RWMutex
	wg              *sync.WaitGroup
	cw              *consoleWatcher

	sandboxController  resCtrl.ResourceController
	overheadController resCtrl.ResourceController

	containers map[string]*Container

	// id is the CRI sandbox ID assigned by containerd. Used for all
	// containerd-facing bookkeeping (OCI bundle path, CRI events,
	// logging that needs to correlate with containerd's view).
	id string

	// internalID is the identity kata uses for its own on-disk paths
	// and persisted state keys. Equal to id for a freshly created
	// sandbox. When a sandbox is created as the destination of a
	// live migration (HypervisorConfig.MigrationSourceSandboxID is
	// set), internalID overrides to the source's sandbox ID so any
	// kata-owned path or state key encoded into the migration stream
	// resolves on this host without per-component workarounds. See
	// docs/design/live-migration-sandbox-identity.md.
	internalID string

	network Network

	state types.SandboxState

	sync.Mutex

	swapSizeBytes int64
	shmSize       uint64
	swapDeviceNum uint

	sharePidNs        bool
	seccompSupported  bool
	disableVMShutdown bool
	isVCPUsPinningOn  bool

	// hotplugNetworkConfigApplied prevents network config API being called
	// multiple times for hot-plugged network device when Sandbox has multiple
	// containers.
	hotplugNetworkConfigApplied bool

	// migrationSourceContainers maps OCI container-name to the
	// source's CRI container ID. Populated by the shim from the
	// /migration/topology payload, read by CreateContainer to set
	// each adopted Container's InternalID to the source-side ID so
	// agent RPCs land on the right entry in the agent's container
	// table after the migrated guest resumes.
	migrationSourceContainers map[string]string

	// migrationSourceMounts maps OCI container-name to the per-
	// container OCI bind mounts the source had bound into its
	// shared sandbox dir (resolv.conf, hosts, hostname, configmaps,
	// etc.). The destination uses these source HostPaths to re-
	// stage equivalent files at the same paths inside its shared
	// dir so the migrated guest's mount table — which still points
	// at the source paths — can serve them via virtio-fs. Populated
	// alongside migrationSourceContainers from the topology payload.
	migrationSourceMounts map[string][]MigrationSourceMount

	// agentUnreachable marks the in-guest agent as unreachable for the
	// remainder of this sandbox's life: the VM's vCPUs are paused (a
	// snapshot save pauses them before MigrateOut) or its state has left
	// for another node, so any agent RPC would block forever waiting on a
	// frozen guest. Container teardown consults this to SKIP agent calls
	// (kill / waitProcess / stopContainer / virtiofs-share unmount) and go
	// straight to host-side cleanup + VM SIGKILL. Without it a `delete` of a
	// saved/paused sandbox hangs in agent.waitProcess and the pod is stuck
	// Terminating. Set when the shim enters a terminal saved/migrated mode.
	agentUnreachable bool

	// agentSaved is set when this sandbox's local guest is gone for good — either
	// checkpointed to a snapshot for hibernation (ModeSaved) or handed off to a
	// destination by live migration (ModeMigrated). In both, the local agent can
	// never answer again, so teardown's Stats path returns empty instead of
	// dialing it (a held-mutex statsContainer would otherwise pin s.mu and wedge
	// the pod Terminating). Deliberately NOT set for ModeFailed: a live resumed
	// dest can sit in ModeFailed while still serving and must keep reporting
	// metrics. ModeMigrated is source-only, so no live dest is ever affected.
	agentSaved bool

	// agentReach caches the last AgentReachable probe result for a short
	// TTL. The shim's Kill handler probes reachability while holding its
	// service mutex; kubelet retries StopContainer in a tight loop against
	// a wedged pod, so without the cache every retry pays the full probe
	// timeout under the lock — the residual teardown convoy. Guarded by
	// its own mutex (never nested inside the probe itself).
	agentReachMu     sync.Mutex
	agentReachVal    bool
	agentReachExpiry time.Time

	// agentSettleStart anchors the post-resume agent-settle measurement
	// (spec 022 FR-062a): set when PairAgentAfterMigration starts — which
	// runs immediately after the resumed guest is verified running — so
	// the settle instrumentation in renumberGuestNetworkAsync can report
	// how long after resume the in-guest agent first answered vsock.
	agentSettleStart time.Time
}

// SetAgentUnreachable marks (or clears) the in-guest agent as unreachable so
// teardown skips agent RPCs that would block on a paused/departed guest. The
// shim sets this when a sandbox enters a saved or migrated terminal mode.
func (s *Sandbox) SetAgentUnreachable(v bool) { s.agentUnreachable = v }

// MarkAgentSaved records that the local guest is gone for good — checkpointed
// (ModeSaved) or migrated away (ModeMigrated) — and closes the agent client
// connection. Closing aborts any in-flight, no-timeout agent RPC — notably the
// per-container wait goroutine's waitProcess and a held-mutex statsContainer,
// either of which otherwise stays parked forever on the departed guest and
// wedges the source pod in Terminating. The shim calls this only on the
// source-terminal transitions (ModeSaved / ModeMigrated), so a live resumed
// dest is never affected.
func (s *Sandbox) MarkAgentSaved(ctx context.Context) error {
	s.agentSaved = true
	if s.agent == nil {
		return nil
	}
	return s.agent.disconnect(ctx)
}

// MigrationSourceMount is one OCI bind mount the source had in its
// shared sandbox dir at original CreateContainer time. Carried in
// the migration topology payload so the destination can re-stage
// equivalent files at the same paths post-handoff.
type MigrationSourceMount struct {
	Destination string // guest path, e.g. "/etc/resolv.conf"
	HostPath    string // source's shared-dir absolute path (with random suffix)
	ReadOnly    bool
}

// ID returns the sandbox identifier string. For containerd-facing
// bookkeeping callers, ID() and ContainerdID() are equivalent.
func (s *Sandbox) ID() string {
	return s.id
}

// ContainerdID returns the CRI sandbox ID assigned by containerd.
// Use this for OCI bundle paths, CRI events, and anything that has
// to correlate with containerd's view of this pod.
func (s *Sandbox) ContainerdID() string {
	return s.id
}

// InternalID returns the identity kata uses for its own on-disk paths
// and persisted state. For a freshly created sandbox InternalID()
// equals ContainerdID(). When the sandbox was created as the
// destination of a live migration (HypervisorConfig
// .MigrationSourceSandboxID is set), InternalID() returns the source
// sandbox's ID so any kata-owned path or state key encoded into the
// migration stream resolves on this host. See
// docs/design/live-migration-sandbox-identity.md.
func (s *Sandbox) InternalID() string {
	if s.internalID != "" {
		return s.internalID
	}
	return s.id
}

// writeMigrationMarker writes a best-effort JSON file at
// <RunStoragePath>/<InternalID>/kata-migration.json documenting the
// sandbox's ID relationship so host tooling can distinguish an
// adopted-identity dir from an orphan without correlating persist
// files and process trees.
//
// Written at sandbox creation time when MigrationSourceSandboxID is
// set (destination adoption path). For a non-migration sandbox,
// InternalID == ContainerdID and no marker is written (or equivalently,
// role:"origin" with equal IDs — the absence of the file is the
// "origin" signal). Failure to write is logged and never fails
// sandbox creation.
//
// Per the reviewer POV in MIGRATION-HARDENING-HANDOFF.md: the source
// writes to its own ContainerdID-keyed path; the destination writes
// to the InternalID-keyed path. This avoids same-node collision when
// a dual-identity successor shares the InternalID dir.
func (s *Sandbox) writeMigrationMarker() {
	if s.internalID == "" || s.internalID == s.id {
		return // not a migration destination
	}
	markerDir := filepath.Join(s.store.RunStoragePath(), s.internalID)
	if err := writeMigrationMarkerAt(markerDir, s.id, s.internalID); err != nil {
		s.Logger().WithError(err).Warn("writeMigrationMarker failed")
		return
	}
	// Warn (not Debug) so the node journal proves the marker fired — its
	// absence on live nodes was previously undiagnosable (FR-063c).
	s.Logger().WithFields(logrus.Fields{
		"markerDir":    markerDir,
		"containerdID": s.id,
		"internalID":   s.internalID,
	}).Warn("writeMigrationMarker: adoption marker written")
}

// migrationMarker is the on-disk schema of kata-migration.json.
// Chain holds the ContainerdIDs of every prior adoption of this
// InternalID dir (oldest first) — same-node chain hops each re-adopt the
// same InternalID, and post-mortem diagnosis of hop >= 2 ID confusion
// needs the history, not just the latest pair.
type migrationMarker struct {
	ContainerdID string   `json:"containerdID"`
	InternalID   string   `json:"internalID"`
	Role         string   `json:"role"`
	Hop          int      `json:"hop"`
	Chain        []string `json:"chain,omitempty"`
}

// writeMigrationMarkerAt writes (or advances) the identity marker in
// markerDir. An existing parseable marker is treated as the previous hop:
// its ContainerdID is appended to the chain and the hop counter advances.
// An unparseable marker is overwritten fresh (best-effort tooling aid, not
// a source of truth — persist.json remains authoritative).
func writeMigrationMarkerAt(markerDir, containerdID, internalID string) error {
	if err := os.MkdirAll(markerDir, 0o750); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	markerPath := filepath.Join(markerDir, "kata-migration.json")

	marker := migrationMarker{
		ContainerdID: containerdID,
		InternalID:   internalID,
		Role:         "destination",
		Hop:          1,
	}
	if prev, err := os.ReadFile(markerPath); err == nil {
		var old migrationMarker
		if json.Unmarshal(prev, &old) == nil && old.ContainerdID != "" {
			marker.Hop = old.Hop + 1
			marker.Chain = append(old.Chain, old.ContainerdID)
		}
	}

	payload, err := json.Marshal(&marker)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(markerPath, payload, 0o644); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// SetMigrationSourceContainers stores the {container-name → source-id}
// mapping the shim received from /migration/topology AND retroactively
// adopts the source IDs onto any workload containers that already
// exist in s.containers. Calling with a nil or empty map clears any
// prior mapping (and leaves existing containers untouched — there's
// no useful "unadopt" semantics).
//
// The retroactive walk is load-bearing because of the orchestration
// ordering: kubelet's CRI CreateContainer for each workload fires
// BEFORE the controller's /migration/topology call lands. Without
// the re-walk, Sandbox.CreateContainer's adoption check sees an
// empty mapping, skips adoption, and the workload's InternalID
// stays at the dest's fresh CRI ID — the agent then rejects every
// subsequent RPC ("exec", "stop", "signal") with "Invalid container id".
func (s *Sandbox) SetMigrationSourceContainers(m map[string]string) {
	if len(m) == 0 {
		s.Logger().Warn("SetMigrationSourceContainers: cleared (empty mapping)")
		s.migrationSourceContainers = nil
		return
	}
	out := make(map[string]string, len(m))
	names := make([]string, 0, len(m))
	for k, v := range m {
		out[k] = v
		names = append(names, k)
	}
	s.migrationSourceContainers = out

	adopted := 0
	skipped := 0
	for _, c := range s.containers {
		if c.internalID != "" {
			skipped++
			continue
		}
		if s.adoptMigrationContainerID(c) {
			adopted++
		}
	}
	// Note: the rootfs bind is intentionally NOT done here. It used
	// to be, but firing ShareRootFilesystem from inside the topology
	// HTTP handler (this is called from handleMigrationTopology)
	// consistently caused the dest QEMU's next QMP call to die with
	// "exiting QMP loop, command cancelled". The bind adds files
	// under the shared-dir that virtiofsd is serving; doing it
	// microseconds before HotplugMemoryDevices disrupts the
	// vhost-user-fs channel. The fix mirrors the renumber-guest
	// pattern: the orchestrator calls a dedicated synchronous
	// endpoint (POST /migration/share-workload-rootfs) AFTER
	// handoff completes, away from the topology hot path. See
	// handleMigrationShareWorkloadRootfs.
	s.Logger().WithFields(logrus.Fields{
		"size":               len(out),
		"names":              names,
		"existingContainers": len(s.containers),
		"adoptedNow":         adopted,
		"alreadyAdopted":     skipped,
	}).Warn("SetMigrationSourceContainers: stored and adopted (rootfs share deferred to /migration/share-workload-rootfs)")
}

// SetMigrationSourceMounts stores the per-container OCI bind mounts
// the source had bound into its shared sandbox dir. The destination
// needs these source HostPaths to re-stage equivalent files at the
// same paths inside its own shared dir — otherwise the migrated guest
// sees EIO on every /etc/resolv.conf, /etc/hosts, /etc/hostname read
// (and any configmap/secret bind mount) because virtio-fs has nothing
// to serve at those paths on the destination node.
//
// Called from handleMigrationTopology after SetMigrationSourceContainers.
// The actual bind step runs later from BindMigrationSourceMounts,
// invoked alongside ShareDeferredWorkloadRootfs — both must run AFTER
// CompleteHandoff so they don't disrupt virtiofsd's vhost-user channel
// while QEMU is still mid-handoff (same reason rootfs share is deferred).
//
// Idempotent. Empty/nil input clears the field. Defensive copy so the
// caller's map is not retained.
func (s *Sandbox) SetMigrationSourceMounts(mounts map[string][]MigrationSourceMount) {
	if len(mounts) == 0 {
		s.migrationSourceMounts = nil
		return
	}
	out := make(map[string][]MigrationSourceMount, len(mounts))
	totalMounts := 0
	for name, ms := range mounts {
		if len(ms) == 0 {
			continue
		}
		cp := make([]MigrationSourceMount, len(ms))
		copy(cp, ms)
		out[name] = cp
		totalMounts += len(cp)
	}
	s.migrationSourceMounts = out
	s.Logger().WithFields(logrus.Fields{
		"containerCount": len(out),
		"totalMounts":    totalMounts,
	}).Warn("SetMigrationSourceMounts: stored (bind deferred to /migration/share-workload-rootfs)")
}

// precreateBindTarget creates the mount target so a subsequent bindMount has
// something to bind onto, matching the KIND of the source.
//
// A bind mount's target must be the same kind as its source: a file for a
// file, a directory for a directory. Creating a file unconditionally is why
// directory mounts never bound — bindMount(dir -> file) fails ENOTDIR, the
// caller skipped the mount, and the migrated guest kept a mount entry
// pointing at nothing, so every read beneath it returned EIO.
//
// The aux mounts this path was written for (resolv.conf, hosts, hostname) are
// files, which is why it went unnoticed. Every Kubernetes volume — emptyDir,
// PVC, configMap and projected directories — is a directory, and all of them
// were silently skipped.
//
// Existing targets are left alone: the caller treats an already-mounted
// target as satisfied, and re-creating one would be destructive.
func precreateBindTarget(source, target string) error {
	if _, err := os.Stat(target); err == nil || !os.IsNotExist(err) {
		return nil
	}
	// Self-contained: a file target needs its parent to exist, and relying on
	// the caller for that is the kind of implicit contract this function was
	// extracted to remove. MkdirAll is idempotent, so the caller doing it too
	// costs nothing.
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	st, err := os.Stat(source)
	if err != nil {
		// The source is missing; the caller's bind will fail and report it
		// with more context than this helper has. Default to a file so
		// behaviour is unchanged from before directories were handled.
		if f, ferr := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o644); ferr == nil {
			return f.Close()
		} else {
			return ferr
		}
	}
	if st.IsDir() {
		return os.MkdirAll(target, 0o755)
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

// BindMigrationSourceMounts re-creates the per-container OCI bind
// mounts (resolv.conf, hosts, hostname, configmaps, etc.) at the
// source's HostPaths inside the destination's shared sandbox dir.
//
// For each adopted container c, we look up its source-side mounts by
// container-name (the OCI annotation). For each (Destination,
// HostPath), we find the matching local file on this node by scanning
// c.config.Mounts for an entry with the same Destination — that gives
// us c's spec.Mounts[i].Source, the host path containerd assigned for
// THIS pod's local resolv.conf/hosts/hostname/etc. We then bind that
// local file to the source's HostPath inside the shared dir.
//
// The shared dir on the dest is keyed by the source sandbox ID (via
// dual-identity #72), so the source's HostPath is already a valid
// path on the dest's filesystem; we just need a file at that path.
//
// Idempotent: skips entries already mounted (probed via
// /proc/self/mountinfo). Best-effort per-container — failures are
// logged but the rest of the loop continues.
//
// Returns (boundCount, skippedCount). Called from the same endpoint
// (POST /migration/share-workload-rootfs) that fires
// ShareDeferredWorkloadRootfs, immediately after the rootfs binds —
// both are out of the QMP-sensitive topology window.
func (s *Sandbox) BindMigrationSourceMounts(ctx context.Context) (int, int) {
	s.Logger().WithFields(logrus.Fields{
		"containerCount":        len(s.migrationSourceMounts),
		"sandboxContainerCount": len(s.containers),
		"sandboxInternalID":     s.InternalID(),
		"namesWithSourceMounts": sortedKeys(toStringKeyMap(s.migrationSourceMounts)),
	}).Warn("BindMigrationSourceMounts: ENTRY")
	if len(s.migrationSourceMounts) == 0 {
		s.Logger().Warn("BindMigrationSourceMounts: nothing to bind (no source mounts received)")
		return 0, 0
	}
	bound := 0
	skipped := 0
	for _, c := range s.containers {
		if c == nil || c.config == nil {
			s.Logger().Warn("BindMigrationSourceMounts: skipping container with nil config")
			continue
		}
		name := c.config.Annotations["io.kubernetes.cri.container-name"]
		if name == "" {
			s.Logger().WithField("containerdID", c.id).
				Warn("BindMigrationSourceMounts: container has no container-name annotation; skipping")
			continue
		}
		srcMounts := s.migrationSourceMounts[name]
		if len(srcMounts) == 0 {
			continue
		}
		// Build dest-side Destination → Source lookup from the
		// container's OCI spec. The Source here is the local file
		// path containerd assigned for THIS pod's resolv.conf/hosts/
		// hostname/etc — populated at CreateContainer time even when
		// Start short-circuited because of migration-incoming mode.
		destByDest := make(map[string]Mount, len(c.config.Mounts))
		destDestinations := make([]string, 0, len(c.config.Mounts))
		for _, m := range c.config.Mounts {
			destByDest[m.Destination] = m
			destDestinations = append(destDestinations, m.Destination)
		}
		s.Logger().WithFields(logrus.Fields{
			"containerName":        name,
			"containerdID":         c.id,
			"internalID":           c.internalID,
			"sourceMountCount":     len(srcMounts),
			"destSpecMountCount":   len(c.config.Mounts),
			"destSpecDestinations": destDestinations,
		}).Warn("BindMigrationSourceMounts: container ENTRY")
		for _, sm := range srcMounts {
			clog := s.Logger().WithFields(logrus.Fields{
				"containerName": name,
				"containerdID":  c.id,
				"internalID":    c.internalID,
				"destination":   sm.Destination,
				"srcHostPath":   sm.HostPath,
				"readOnly":      sm.ReadOnly,
			})
			if sm.HostPath == "" {
				clog.Warn("BindMigrationSourceMounts: source HostPath empty; skipping")
				skipped++
				continue
			}
			// Re-anchor the aux bind target under THIS sandbox's shared dir.
			// sm.HostPath carries the sandbox-dir prefix of whichever sandbox
			// first staged the file (the original cold source, propagated
			// across hops); but virtiofsd on this destination serves
			// getMountPath(s.InternalID()), so on a chain hop (hop >= 2) the
			// dest's InternalID differs from that prefix. Rewrite the prefix to
			// this sandbox's own shared dir, keeping the /mounts/<rest> suffix
			// the migrated guest's mount table references — exactly as
			// ShareDeferredWorkloadRootfs does for the rootfs. Without this the
			// aux files land under a stale sandbox dir, outside the served
			// shared dir, and the guest EIOs on /etc/{resolv.conf,hosts,hostname}.
			if idx := strings.LastIndex(sm.HostPath, "/mounts/"); idx >= 0 {
				rebased := filepath.Join(getMountPath(s.InternalID()), sm.HostPath[idx+len("/mounts/"):])
				if rebased != sm.HostPath {
					clog = clog.WithField("rebasedHostPath", rebased)
					sm.HostPath = rebased
				}
			}
			localMount, ok := destByDest[sm.Destination]
			if !ok || localMount.Source == "" {
				clog.WithField("destSpecDestinations", destDestinations).
					Warn("BindMigrationSourceMounts: no matching destination in dest spec.Mounts; skipping")
				skipped++
				continue
			}
			// Stat the dest's local source file BEFORE binding so a
			// later failure is grep-able to "missing on dest" vs
			// "bind syscall failed".
			localSrcInfo := "unknown"
			if st, err := os.Stat(localMount.Source); err != nil {
				localSrcInfo = fmt.Sprintf("stat-error=%v", err)
			} else {
				localSrcInfo = fmt.Sprintf("isDir=%v mode=%o size=%d", st.IsDir(), st.Mode().Perm(), st.Size())
			}
			// Check whether the target already has a mount — if yes,
			// we're idempotent and skip (counts as bound, not skipped,
			// because the user's intent is satisfied).
			alreadyMounted := false
			if mountedAt, err := isMountPoint(sm.HostPath); err == nil && mountedAt {
				alreadyMounted = true
			}
			clog.WithFields(logrus.Fields{
				"localSource":    localMount.Source,
				"localSrcInfo":   localSrcInfo,
				"alreadyMounted": alreadyMounted,
			}).Warn("BindMigrationSourceMounts: about to bind")
			if alreadyMounted {
				clog.Warn("BindMigrationSourceMounts: target already mounted; skipping rebind")
				// Record on the adopted container so it carries the aux mount
				// to the next hop (chain migration); empty c.mounts otherwise
				// means the next source enumerates 0 bind mounts.
				c.recordMigrationBindMount(Mount{Destination: sm.Destination, HostPath: sm.HostPath, ReadOnly: sm.ReadOnly})
				bound++
				continue
			}
			// Pre-create the target. bindMount needs the destination to
			// already exist, and it must be the SAME KIND as the source:
			// a file for a file, a directory for a directory. Creating a
			// file unconditionally is why directory mounts never bound —
			// bindMount(dir -> file) fails ENOTDIR, this loop logged
			// "bind failed; skipping", and the migrated guest was left
			// with a mount entry pointing at nothing, so every read under
			// that path returned EIO.
			//
			// The aux mounts this was written for (resolv.conf, hosts,
			// hostname) are files, which is why it went unnoticed. Every
			// Kubernetes volume — emptyDir, PVC, configMap and projected
			// dirs — is a directory, and all of them were silently skipped.
			// The parent dir is the shared sandbox dir, which already exists.
			if err := os.MkdirAll(filepath.Dir(sm.HostPath), 0o755); err != nil {
				clog.WithError(err).Warn("BindMigrationSourceMounts: mkdir parent failed; skipping")
				skipped++
				continue
			}
			if err := precreateBindTarget(localMount.Source, sm.HostPath); err != nil {
				clog.WithError(err).Warn("BindMigrationSourceMounts: pre-create target failed; skipping")
				skipped++
				continue
			}
			if err := bindMount(ctx, localMount.Source, sm.HostPath, sm.ReadOnly, "private"); err != nil {
				clog.WithError(err).WithField("localSource", localMount.Source).
					Warn("BindMigrationSourceMounts: bind failed; skipping")
				skipped++
				continue
			}
			// Post-bind verification: re-check /proc/self/mountinfo for
			// the expected entry. Same triage rationale as the rootfs
			// share — the symptom "endpoint reports bound:N but no
			// mount lands on host" tells us syscall succeeded but the
			// mount was either immediately removed or landed in a
			// different mount namespace from where we expect.
			postBindOK := false
			if mountedAt, err := isMountPoint(sm.HostPath); err == nil && mountedAt {
				postBindOK = true
			}
			clog.WithFields(logrus.Fields{
				"localSource": localMount.Source,
				"postBindOK":  postBindOK,
			}).Warn("BindMigrationSourceMounts: bound local file at source HostPath")
			// Record on the adopted container so it carries this aux mount to
			// the NEXT hop. Without it the adopted container's c.mounts stays
			// empty and the next source enumerates 0 bind mounts, leaving the
			// migrated guest with unreadable /etc/{resolv.conf,hosts,hostname}.
			c.recordMigrationBindMount(Mount{Destination: sm.Destination, HostPath: sm.HostPath, ReadOnly: sm.ReadOnly})
			bound++
		}
		s.Logger().WithFields(logrus.Fields{
			"containerName": name,
			"containerdID":  c.id,
		}).Warn("BindMigrationSourceMounts: container EXIT")
	}
	s.Logger().WithFields(logrus.Fields{
		"bound":   bound,
		"skipped": skipped,
	}).Warn("BindMigrationSourceMounts: EXIT")
	return bound, skipped
}

// isMountPoint reports whether path is currently a mount point by
// scanning /proc/self/mountinfo. Returns (false, nil) when path is
// not mounted; non-nil error only if the procfs read itself fails.
// Used by BindMigrationSourceMounts for idempotency + post-bind verify.
func isMountPoint(path string) (bool, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	// mountinfo format: each line has fields separated by spaces; the
	// 5th field (1-indexed) is the mount point. We do a substring
	// search bounded by tabs/spaces to avoid path-prefix false positives.
	target := " " + path + " "
	return bytes.Contains(data, []byte(target)), nil
}

// toStringKeyMap returns the keys of a generic map as a string-keyed
// shim so sortedKeys can stringify them in a log field. Only used for
// log readability.
func toStringKeyMap(m map[string][]MigrationSourceMount) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = fmt.Sprintf("%d-mounts", len(v))
	}
	return out
}

// ShareDeferredWorkloadRootfs binds the workload-container rootfs(es)
// into the shared sandbox dir for any migration-adopted container
// that has not yet been shared (rootfsShared==false, internalID!=id).
// Idempotent and safe to call repeatedly. Returns (sharedCount,
// failedCount) — counts how many containers transitioned from
// not-shared to shared on this call.
//
// Called by the dest shim's POST /migration/share-workload-rootfs
// endpoint, after CompleteHandoff. Splitting the share out of the
// topology handler avoids disrupting virtiofsd's vhost-user channel
// while QEMU is mid-hot-add — see SetMigrationSourceContainers for
// the failure mode this works around.
//
// Logs at Warn level around every step so a single run's journal
// tells us exactly what happened: source rootfs path, bind dest
// path, ShareRootFilesystem return, and POST-BIND verification by
// re-reading /proc/self/mountinfo for the expected entry. The
// previous symptom — "endpoint reports shared:1 but no mount lands
// on host" — needs the verify step to triage whether the issue is
// (a) bind not firing, (b) bind firing but immediately removed, or
// (c) bind landing in a different mount namespace from PID 1.
func (s *Sandbox) ShareDeferredWorkloadRootfs(ctx context.Context) (int, int) {
	if s.fsShare == nil {
		s.Logger().Warn("ShareDeferredWorkloadRootfs: fsShare nil; no-op")
		return 0, 0
	}
	shared := 0
	failed := 0
	for _, c := range s.containers {
		if c.rootfsShared {
			s.Logger().WithFields(logrus.Fields{
				"containerdID": c.id,
				"internalID":   c.internalID,
			}).Warn("ShareDeferredWorkloadRootfs: already shared; skipping")
			continue
		}
		// Skip non-adopted containers: those are either fresh (no
		// migration) and got their share via c.create(), or are the
		// pod-sandbox bundle which doesn't have a workload rootfs.
		if c.internalID == "" || c.internalID == c.id {
			s.Logger().WithFields(logrus.Fields{
				"containerdID": c.id,
				"internalID":   c.internalID,
				"reason":       "not adopted",
			}).Warn("ShareDeferredWorkloadRootfs: skipping non-adopted container")
			continue
		}

		// Pre-bind diagnostic: source path, target path, source
		// stat. If source doesn't exist or stat fails, bindMount
		// will silently fail under us. We want to know that up
		// front.
		srcPath := c.rootFs.Target
		bindDestExpected := filepath.Join(getMountPath(s.InternalID()), c.InternalID(), c.rootfsSuffix)
		srcStat, srcStatErr := os.Stat(srcPath)
		srcInfo := "unknown"
		if srcStatErr != nil {
			srcInfo = fmt.Sprintf("stat-error=%v", srcStatErr)
		} else {
			srcInfo = fmt.Sprintf("isDir=%v mode=%o", srcStat.IsDir(), srcStat.Mode().Perm())
		}
		s.Logger().WithFields(logrus.Fields{
			"containerdID":     c.id,
			"internalID":       c.internalID,
			"rootFsSource":     srcPath,
			"rootFsType":       c.rootFs.Type,
			"rootFsMounted":    c.rootFs.Mounted,
			"rootFsOptions":    c.rootFs.Options,
			"bindDestExpected": bindDestExpected,
			"srcInfo":          srcInfo,
		}).Warn("ShareDeferredWorkloadRootfs: about to call ShareRootFilesystem")

		if _, err := s.fsShare.ShareRootFilesystem(ctx, c); err != nil {
			failed++
			s.Logger().WithError(err).WithFields(logrus.Fields{
				"containerdID": c.id,
				"internalID":   c.internalID,
				"bindDest":     bindDestExpected,
			}).Error("ShareDeferredWorkloadRootfs: ShareRootFilesystem failed")
			continue
		}

		// Post-bind verification: read /proc/self/mountinfo and
		// grep for the bindDest path. If the bind landed, we see
		// an entry; if not, the call returned nil but no mount
		// happened — which has been the actual failure mode.
		mountedOK := false
		if data, rErr := os.ReadFile("/proc/self/mountinfo"); rErr == nil {
			if strings.Contains(string(data), bindDestExpected) {
				mountedOK = true
			}
		}
		s.Logger().WithFields(logrus.Fields{
			"containerdID": c.id,
			"internalID":   c.internalID,
			"bindDest":     bindDestExpected,
			"mountedOK":    mountedOK,
		}).Warn("ShareDeferredWorkloadRootfs: post-bind /proc/self/mountinfo check")

		c.rootfsShared = true
		shared++
	}
	return shared, failed
}

// adoptMigrationContainerID overrides c.internalID with the source
// container's ID when this sandbox is a live-migration destination
// AND the new container's OCI annotations identify it by a
// container-name the source mapping knows. Returns true when the
// adoption applied, false otherwise. Idempotent and safe to call on
// non-migration sandboxes — the empty mapping short-circuits.
//
// Logs every outcome at Warn so a single deploy → migrate → exec
// produces a complete breadcrumb trail in the journal: empty
// mapping, missing name, no-match, success.
func (s *Sandbox) adoptMigrationContainerID(c *Container) bool {
	if c == nil || c.config == nil {
		s.Logger().Warn("adoptMigrationContainerID: nil container/config — skipping")
		return false
	}
	if len(s.migrationSourceContainers) == 0 {
		s.Logger().WithField("containerdID", c.id).
			Warn("adoptMigrationContainerID: no source mapping in sandbox; container keeps fresh ID")
		return false
	}
	name := c.config.Annotations["io.kubernetes.cri.container-name"]
	if name == "" {
		s.Logger().WithFields(logrus.Fields{
			"containerdID":   c.id,
			"annotationKeys": sortedKeys(c.config.Annotations),
		}).Warn("adoptMigrationContainerID: container has no container-name annotation; keeping fresh ID")
		return false
	}
	srcID := s.migrationSourceContainers[name]
	if srcID == "" {
		s.Logger().WithFields(logrus.Fields{
			"containerdID": c.id,
			"name":         name,
			"knownNames":   sortedKeys(s.migrationSourceContainers),
		}).Warn("adoptMigrationContainerID: container-name not in source mapping; keeping fresh ID")
		return false
	}
	c.internalID = srcID
	s.Logger().WithFields(logrus.Fields{
		"containerdID": c.id,
		"internalID":   srcID,
		"name":         name,
	}).Warn("adoptMigrationContainerID: adopted source container ID")
	return true
}

// sortedKeys returns the sorted keys of a string map. Used by the
// migration-adoption logger so a missing-name diagnostic shows which
// annotation keys ARE present, in stable order.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Logger returns a logrus logger appropriate for logging Sandbox messages
func (s *Sandbox) Logger() *logrus.Entry {
	return virtLog.WithFields(logrus.Fields{
		"subsystem": "sandbox",
		"sandbox":   s.id,
	})
}

// Annotations returns any annotation that a user could have stored through the sandbox.
func (s *Sandbox) Annotations(key string) (string, error) {
	s.annotationsLock.RLock()
	defer s.annotationsLock.RUnlock()

	value, exist := s.config.Annotations[key]
	if !exist {
		return "", fmt.Errorf("Annotations key %s does not exist", key)
	}

	return value, nil
}

// SetAnnotations sets or adds an annotations
func (s *Sandbox) SetAnnotations(annotations map[string]string) error {
	s.annotationsLock.Lock()
	defer s.annotationsLock.Unlock()

	for k, v := range annotations {
		s.config.Annotations[k] = v
	}
	return nil
}

// GetAnnotations returns sandbox's annotations
func (s *Sandbox) GetAnnotations() map[string]string {
	s.annotationsLock.RLock()
	defer s.annotationsLock.RUnlock()

	return s.config.Annotations
}

// GetNetNs returns the network namespace of the current sandbox.
func (s *Sandbox) GetNetNs() string {
	return s.network.NetworkID()
}

// GetHypervisorPid returns the hypervisor's pid.
func (s *Sandbox) GetHypervisorPid() (int, error) {
	pids := s.hypervisor.GetPids()
	if len(pids) == 0 || pids[0] == 0 {
		return -1, fmt.Errorf("Invalid hypervisor PID: %+v", pids)
	}

	return pids[0], nil
}

// GetVirtioFsPid returns the virtiofsd daemon's PID, or 0 if no
// virtiofsd has been started for this sandbox. Used by diagnostic
// callers (e.g. the shim's migration status endpoint) that need to
// distinguish "QEMU died" from "virtiofsd died" without a coredump.
func (s *Sandbox) GetVirtioFsPid() int {
	pidPtr := s.hypervisor.GetVirtioFsPid()
	if pidPtr == nil {
		return 0
	}
	return *pidPtr
}

// RescanNetwork re-scans the network namespace for endpoints if none have
// been discovered yet. This is idempotent: if endpoints already exist it
// returns immediately. It enables Docker 26+ support where networking is
// configured after task creation but before Start.
//
// Docker 26+ configures networking (veth pair, IP addresses) between
// Create and Start. The interfaces may not be present immediately, so
// this method polls until they appear or a timeout is reached.
//
// When new endpoints are found, the guest agent is informed about the
// interfaces and routes so that networking becomes functional inside the VM.
func (s *Sandbox) RescanNetwork(ctx context.Context) error {
	if s.config.NetworkConfig.DisableNewNetwork {
		return nil
	}
	if len(s.network.Endpoints()) > 0 {
		return nil
	}

	const maxWait = 5 * time.Second
	const pollInterval = 50 * time.Millisecond
	deadline := time.NewTimer(maxWait)
	defer deadline.Stop()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	s.Logger().Debug("waiting for network interfaces in namespace")

	for {
		if _, err := s.network.AddEndpoints(ctx, s, nil, true); err != nil {
			return err
		}
		if len(s.network.Endpoints()) > 0 {
			return s.configureGuestNetwork(ctx)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			s.Logger().Warn("no network interfaces found after timeout — networking may be configured by prestart hooks")
			return nil
		case <-ticker.C:
		}
	}
}

// configureGuestNetwork informs the guest agent about discovered network
// endpoints so that interfaces and routes become functional inside the VM.
func (s *Sandbox) configureGuestNetwork(ctx context.Context) error {
	endpoints := s.network.Endpoints()
	s.Logger().WithField("endpoints", len(endpoints)).Info("configuring hotplugged network in guest")

	// Note: ARP neighbors (3rd return value) are not propagated here
	// because the agent interface only exposes per-entry updates. The
	// full setupNetworks path in kataAgent handles them; this path is
	// only reached for late-discovered endpoints where neighbor entries
	// are populated dynamically by the kernel.
	interfaces, routes, _, err := generateVCNetworkStructures(ctx, endpoints)
	if err != nil {
		return fmt.Errorf("generating network structures: %w", err)
	}
	for _, ifc := range interfaces {
		if _, err := s.agent.updateInterface(ctx, ifc); err != nil {
			return fmt.Errorf("updating interface %s in guest: %w", ifc.Name, err)
		}
	}
	if len(routes) > 0 {
		if _, err := s.agent.updateRoutes(ctx, routes); err != nil {
			return fmt.Errorf("updating routes in guest: %w", err)
		}
	}
	return nil
}

// GetAllContainers returns all containers.
func (s *Sandbox) GetAllContainers() []VCContainer {
	ifa := make([]VCContainer, len(s.containers))

	i := 0
	for _, v := range s.containers {
		ifa[i] = v
		i++
	}

	return ifa
}

// GetContainer returns the container named by the containerID.
func (s *Sandbox) GetContainer(containerID string) VCContainer {
	if c, ok := s.containers[containerID]; ok {
		return c
	}
	return nil
}

// Release closes the agent connection.
func (s *Sandbox) Release(ctx context.Context) error {
	s.Logger().Info("release sandbox")
	if s.monitor != nil {
		s.monitor.stop()
	}
	s.fsShare.StopFileEventWatcher(ctx)
	s.hypervisor.Disconnect(ctx)
	return s.agent.disconnect(ctx)
}

// Status gets the status of the sandbox
func (s *Sandbox) Status() SandboxStatus {
	var contStatusList []ContainerStatus
	for _, c := range s.containers {
		rootfs := c.config.RootFs.Source
		if c.config.RootFs.Mounted {
			rootfs = c.config.RootFs.Target
		}

		contStatusList = append(contStatusList, ContainerStatus{
			ID:          c.id,
			State:       c.state,
			PID:         c.process.Pid,
			StartTime:   c.process.StartTime,
			RootFs:      rootfs,
			Annotations: c.config.Annotations,
		})
	}

	return SandboxStatus{
		ID:               s.id,
		State:            s.state,
		Hypervisor:       s.config.HypervisorType,
		HypervisorConfig: s.config.HypervisorConfig,
		ContainersStatus: contStatusList,
		Annotations:      s.config.Annotations,
		EmptyDirMode:     s.config.EmptyDirMode,
	}
}

// Monitor returns a error channel for watcher to watch at
func (s *Sandbox) Monitor(ctx context.Context) (chan error, error) {
	if s.state.State != types.StateRunning {
		return nil, errSandboxNotRunning
	}

	s.Lock()
	if s.monitor == nil {
		s.monitor = newMonitor(s)
	}
	s.Unlock()

	return s.monitor.newWatcher(ctx)
}

// WaitProcess waits on a container process and return its exit code
func (s *Sandbox) WaitProcess(ctx context.Context, containerID, processID string) (int32, error) {
	if s.state.State != types.StateRunning {
		return 0, errSandboxNotRunning
	}

	c, err := s.findContainer(containerID)
	if err != nil {
		return 0, err
	}

	return c.wait(ctx, processID)
}

// SignalProcess sends a signal to a process of a container when all is false.
// When all is true, it sends the signal to all processes of a container.
func (s *Sandbox) SignalProcess(ctx context.Context, containerID, processID string, signal syscall.Signal, all bool) error {
	if s.state.State != types.StateRunning {
		return errSandboxNotRunning
	}

	c, err := s.findContainer(containerID)
	if err != nil {
		return err
	}

	return c.signalProcess(ctx, processID, signal, all)
}

// WinsizeProcess resizes the tty window of a process
func (s *Sandbox) WinsizeProcess(ctx context.Context, containerID, processID string, height, width uint32) error {
	if s.state.State != types.StateRunning {
		return errSandboxNotRunning
	}

	c, err := s.findContainer(containerID)
	if err != nil {
		return err
	}

	return c.winsizeProcess(ctx, processID, height, width)
}

// IOStream returns stdin writer, stdout reader and stderr reader of a process
func (s *Sandbox) IOStream(containerID, processID string) (io.WriteCloser, io.Reader, io.Reader, error) {
	if s.state.State != types.StateRunning {
		return nil, nil, nil, errSandboxNotRunning
	}

	c, err := s.findContainer(containerID)
	if err != nil {
		return nil, nil, nil, err
	}

	return c.ioStream(processID)
}

// IsGuestPullEnforced returns true if guest pull is forced through the sandbox configuration.
func (s *Sandbox) IsGuestPullForced() bool {
	if s.config == nil {
		return false
	}
	return s.config.ForceGuestPull
}

func createAssets(ctx context.Context, sandboxConfig *SandboxConfig) error {
	span, _ := katatrace.Trace(ctx, nil, "createAssets", sandboxTracingTags, map[string]string{"sandbox_id": sandboxConfig.ID})
	defer span.End()

	for _, name := range types.AssetTypes() {
		annotation, _, err := name.Annotations()
		if err != nil {
			return err
		}
		// For remote hypervisor donot check for Absolute Path incase of ImagePath, as it denotes the name of the image.
		if sandboxConfig.HypervisorType == RemoteHypervisor && annotation == annotations.ImagePath {
			value := sandboxConfig.Annotations[annotation]
			if value != "" {
				sandboxConfig.HypervisorConfig.ImagePath = value
			}
		} else {
			a, err := types.NewAsset(sandboxConfig.Annotations, name)
			if err != nil {
				return err
			}

			if err := sandboxConfig.HypervisorConfig.AddCustomAsset(a); err != nil {
				return err
			}
		}
	}

	_, imageErr := sandboxConfig.HypervisorConfig.assetPath(types.ImageAsset)
	_, initrdErr := sandboxConfig.HypervisorConfig.assetPath(types.InitrdAsset)

	if imageErr != nil && initrdErr != nil {
		return fmt.Errorf("%s and %s cannot be both set", types.ImageAsset, types.InitrdAsset)
	}

	return nil
}

func (s *Sandbox) getAndStoreGuestDetails(ctx context.Context) error {
	guestDetailRes, err := s.agent.getGuestDetails(ctx, &grpc.GuestDetailsRequest{
		MemBlockSize:    true,
		MemHotplugProbe: true,
	})
	if err != nil {
		return err
	}

	if guestDetailRes != nil {
		s.state.GuestMemoryBlockSizeMB = uint32(guestDetailRes.MemBlockSizeBytes >> 20)
		if guestDetailRes.AgentDetails != nil {
			s.seccompSupported = guestDetailRes.AgentDetails.SupportsSeccomp
		}
		s.state.GuestMemoryHotplugProbe = guestDetailRes.SupportMemHotplugProbe
	}

	return nil
}

// createSandbox creates a sandbox from a sandbox description, the containers list, the hypervisor
// and the agent passed through the Config structure.
// It will create and store the sandbox structure, and then ask the hypervisor
// to physically create that sandbox i.e. starts a VM for that sandbox to eventually
// be started.
func createSandbox(ctx context.Context, sandboxConfig SandboxConfig, factory Factory) (*Sandbox, error) {
	span, ctx := katatrace.Trace(ctx, nil, "createSandbox", sandboxTracingTags, map[string]string{"sandbox_id": sandboxConfig.ID})
	defer span.End()

	if err := createAssets(ctx, &sandboxConfig); err != nil {
		return nil, err
	}

	s, err := newSandbox(ctx, sandboxConfig, factory)
	if err != nil {
		return nil, err
	}

	if len(s.config.Experimental) != 0 {
		s.Logger().WithField("features", s.config.Experimental).Infof("Enable experimental features")
	}

	// Sandbox state has been loaded from storage.
	// If the Stae is not empty, this is a re-creation, i.e.
	// we don't need to talk to the guest's agent, but only
	// want to create the sandbox and its containers in memory.
	if s.state.State != "" {
		return s, nil
	}

	// The code below only gets called when initially creating a sandbox, not when restoring or
	// re-creating it. The above check for the sandbox state enforces that.

	if err := s.fsShare.Prepare(ctx); err != nil {
		return nil, err
	}

	if err := s.agent.createSandbox(ctx, s); err != nil {
		return nil, err
	}

	// Set sandbox state
	if err := s.setSandboxState(types.StateReady); err != nil {
		return nil, err
	}

	return s, nil
}

func newSandbox(ctx context.Context, sandboxConfig SandboxConfig, factory Factory) (sb *Sandbox, retErr error) {
	span, ctx := katatrace.Trace(ctx, nil, "newSandbox", sandboxTracingTags, map[string]string{"sandbox_id": sandboxConfig.ID})
	defer span.End()

	if !sandboxConfig.valid() {
		return nil, fmt.Errorf("Invalid sandbox configuration")
	}

	// create agent instance
	agent := getNewAgentFunc(ctx)()

	hypervisor, err := NewHypervisor(sandboxConfig.HypervisorType)
	if err != nil {
		return nil, err
	}

	network, err := NewNetwork(&sandboxConfig.NetworkConfig)
	if err != nil {
		return nil, err
	}

	// internalID overrides id for kata-owned paths and persisted state
	// keys on the destination side of a live migration so the source's
	// encoded paths resolve. Empty means "behave like containerd's ID",
	// which is the only correct behavior outside migrate-incoming.
	internalID := sandboxConfig.HypervisorConfig.MigrationSourceSandboxID

	s := &Sandbox{
		id:              sandboxConfig.ID,
		internalID:      internalID,
		factory:         factory,
		hypervisor:      hypervisor,
		agent:           agent,
		config:          &sandboxConfig,
		volumes:         sandboxConfig.Volumes,
		containers:      map[string]*Container{},
		state:           types.SandboxState{BlockIndexMap: make(map[int]struct{})},
		annotationsLock: &sync.RWMutex{},
		wg:              &sync.WaitGroup{},
		shmSize:         sandboxConfig.ShmSize,
		sharePidNs:      sandboxConfig.SharePidNs,
		network:         network,
		ctx:             ctx,
		swapDeviceNum:   0,
		swapSizeBytes:   0,
		swapDevices:     []*config.BlockDrive{},
	}

	fsShare, err := NewFilesystemShare(s)
	if err != nil {
		return nil, err
	}
	s.fsShare = fsShare

	if s.store, err = persist.GetDriver(); err != nil || s.store == nil {
		return nil, fmt.Errorf("failed to get fs persist driver: %v", err)
	}
	defer func() {
		if retErr != nil {
			s.Logger().WithError(retErr).Error("Create new sandbox failed")
			s.store.Destroy(s.id)
		}
	}()

	sandboxConfig.HypervisorConfig.VMStorePath = s.store.RunVMStoragePath()
	sandboxConfig.HypervisorConfig.RunStorePath = s.store.RunStoragePath()

	// W4: Write a best-effort identity marker so host tooling can
	// distinguish an adopted-identity dir from an orphan without
	// correlating persist files and process trees. Written when
	// MigrationSourceSandboxID is set (destination adoption path).
	// Failure to write is logged and never fails sandbox creation.
	s.writeMigrationMarker()

	spec := s.GetPatchedOCISpec()
	if spec != nil && spec.Process.SelinuxLabel != "" {
		sandboxConfig.HypervisorConfig.SELinuxProcessLabel = spec.Process.SelinuxLabel
	}

	s.devManager = deviceManager.NewDeviceManager(sandboxConfig.HypervisorConfig.BlockDeviceDriver,
		sandboxConfig.HypervisorConfig.EnableVhostUserStore,
		sandboxConfig.HypervisorConfig.VhostUserStorePath, sandboxConfig.HypervisorConfig.VhostUserDeviceReconnect, nil)

	// Create the sandbox resource controllers.
	if err := s.createResourceController(); err != nil {
		return nil, err
	}

	// Ignore the error. Restore can fail for a new sandbox
	if err := s.Restore(); err != nil {
		s.Logger().WithError(err).Debug("restore sandbox failed")
	}

	if err := validateHypervisorConfig(&sandboxConfig.HypervisorConfig); err != nil {
		return nil, err
	}

	// Start the event loop if not already started when fs sharing is not used
	if sandboxConfig.HypervisorConfig.SharedFS == config.NoSharedFS {
		// Start the StartFileEventWatcher method as a goroutine
		// to monitor the file events.
		go func() {
			if err := s.fsShare.StartFileEventWatcher(ctx); err != nil {
				s.Logger().WithError(err).Error("Failed to start file event watcher")
				return
			}
		}()

		// Stop the file event watcher on error
		defer func() {
			if retErr != nil {
				s.Logger().WithError(retErr).Error("Stopping File Event Watcher")
				s.fsShare.StopFileEventWatcher(ctx)
			}
		}()

	}

	setHypervisorConfigAnnotations(&sandboxConfig)

	coldPlugVFIO, err := s.coldOrHotPlugVFIO(&sandboxConfig)
	if err != nil {
		return nil, err
	}

	// Plumb the inbound-migration URI down to the hypervisor so
	// QEMU can boot with -incoming defer when this sandbox is a
	// migration destination.
	sandboxConfig.HypervisorConfig.IncomingMigrationURI = sandboxConfig.IncomingMigrationURI

	// store doesn't require hypervisor to be stored immediately
	// Pass InternalID() so all hypervisor-side path generation
	// (q.id, q.config-derived paths, virtiofsd --shared-dir, etc.)
	// uses the source's identity on a migrate-incoming sandbox.
	// Non-migration sandboxes are unaffected (InternalID == id).
	if err = s.hypervisor.CreateVM(ctx, s.InternalID(), s.network, &sandboxConfig.HypervisorConfig); err != nil {
		return nil, err
	}

	if s.disableVMShutdown, err = s.agent.init(ctx, s, sandboxConfig.AgentConfig); err != nil {
		return nil, err
	}

	if !coldPlugVFIO {
		return s, nil
	}

	for _, dev := range sandboxConfig.HypervisorConfig.VFIODevices {
		s.Logger().Info("cold-plug device: ", dev)
		_, err := s.AddDevice(ctx, dev)
		if err != nil {
			s.Logger().WithError(err).Debug("Cannot cold-plug add device")
			return nil, err
		}
	}
	return s, nil
}

func setHypervisorConfigAnnotations(sandboxConfig *SandboxConfig) {
	if len(sandboxConfig.Containers) > 0 {
		// These values are required by remote hypervisor
		for _, a := range []string{cri.SandboxName, crio.SandboxName} {
			if value, ok := sandboxConfig.Containers[0].Annotations[a]; ok {
				sandboxConfig.HypervisorConfig.SandboxName = value
			}
		}

		for _, a := range []string{cri.SandboxNamespace, crio.Namespace} {
			if value, ok := sandboxConfig.Containers[0].Annotations[a]; ok {
				sandboxConfig.HypervisorConfig.SandboxNamespace = value
			}
		}
	}
}

func (s *Sandbox) coldOrHotPlugVFIO(sandboxConfig *SandboxConfig) (bool, error) {
	// If we have a confidential guest we need to cold-plug the PCIe VFIO devices
	// until we have TDISP/IDE PCIe support.
	coldPlugVFIO := (sandboxConfig.HypervisorConfig.ColdPlugVFIO != config.NoPort)
	// Aggregate all the containner devices for hot-plug and use them to dedcue
	// the correct amount of ports to reserve for the hypervisor.
	hotPlugVFIO := (sandboxConfig.HypervisorConfig.HotPlugVFIO != config.NoPort)

	//modeIsGK := (sandboxConfig.VfioMode == config.VFIOModeGuestKernel)
	// modeIsVFIO is needed at the container level not the sandbox level.
	// modeIsVFIO := (sandboxConfig.VfioMode == config.VFIOModeVFIO)

	var vfioDevices []config.DeviceInfo
	// vhost-user-block device is a PCIe device in Virt, keep track of it
	// for correct number of PCIe root ports.
	var vhostUserBlkDevices []config.DeviceInfo

	for cnt, container := range sandboxConfig.Containers {
		for dev, device := range container.DeviceInfos {
			if deviceManager.IsVhostUserBlk(device) {
				vhostUserBlkDevices = append(vhostUserBlkDevices, device)
				continue
			}
			isVFIODevice := deviceManager.IsVFIODevice(device.ContainerPath)
			if hotPlugVFIO && isVFIODevice {
				device.ColdPlug = false
				device.Port = sandboxConfig.HypervisorConfig.HotPlugVFIO
				vfioDevices = append(vfioDevices, device)
				sandboxConfig.Containers[cnt].DeviceInfos[dev].Port = sandboxConfig.HypervisorConfig.HotPlugVFIO
				continue
			}
			if coldPlugVFIO && isVFIODevice {
				device.ColdPlug = true
				device.Port = sandboxConfig.HypervisorConfig.ColdPlugVFIO
				vfioDevices = append(vfioDevices, device)
				sandboxConfig.Containers[cnt].DeviceInfos[dev].Port = sandboxConfig.HypervisorConfig.ColdPlugVFIO
				continue
			}
		}
	}

	sandboxConfig.HypervisorConfig.VFIODevices = vfioDevices
	sandboxConfig.HypervisorConfig.VhostUserBlkDevices = vhostUserBlkDevices

	return coldPlugVFIO, nil
}

func (s *Sandbox) createResourceController() error {
	var err error
	cgroupPath := ""

	// Do not change current cgroup configuration.
	// Create a spec without constraints
	resources := specs.LinuxResources{}

	if s.config == nil {
		return fmt.Errorf("Could not create %s resource controller manager: empty sandbox configuration", s.sandboxController)
	}

	spec := s.GetPatchedOCISpec()
	if spec != nil && spec.Linux != nil {
		cgroupPath = spec.Linux.CgroupsPath

		// Kata relies on the resource controller (cgroups on Linux) parent created and configured by the
		// container engine by default. The exception is for devices whitelist as well as sandbox-level CPUSet.
		// For the sandbox controllers we create and manage, rename the base of the controller ID to
		// include "kata_"
		if !resCtrl.IsSystemdCgroup(cgroupPath) { // don't add prefix when cgroups are managed by systemd
			cgroupPath, err = resCtrl.RenameCgroupPath(cgroupPath)
			if err != nil {
				return err
			}
		}

		if spec.Linux.Resources != nil {
			resources.Devices = spec.Linux.Resources.Devices

			intptr := func(i int64) *int64 { return &i }
			// Determine if device /dev/null and /dev/urandom exist, and add if they don't
			nullDeviceExist := false
			urandomDeviceExist := false
			ptmxDeviceExist := false
			for _, device := range resources.Devices {
				if device.Type == "c" && device.Major == intptr(1) && device.Minor == intptr(3) {
					nullDeviceExist = true
				}

				if device.Type == "c" && device.Major == intptr(1) && device.Minor == intptr(9) {
					urandomDeviceExist = true
				}

				if device.Type == "c" && device.Major == intptr(5) && device.Minor == intptr(2) {
					ptmxDeviceExist = true
				}
			}

			if !nullDeviceExist {
				// "/dev/null"
				resources.Devices = append(resources.Devices, []specs.LinuxDeviceCgroup{
					{Type: "c", Major: intptr(1), Minor: intptr(3), Access: rwm, Allow: true},
				}...)
			}
			if !urandomDeviceExist {
				// "/dev/urandom"
				resources.Devices = append(resources.Devices, []specs.LinuxDeviceCgroup{
					{Type: "c", Major: intptr(1), Minor: intptr(9), Access: rwm, Allow: true},
				}...)
			}

			// If the hypervisor debug console is enabled and
			// sandbox_cgroup_only are configured, then the vmm needs access to
			// /dev/ptmx.  Add this to the device allowlist if it is not
			// already present in the config.
			if s.config.HypervisorConfig.Debug && s.config.SandboxCgroupOnly && !ptmxDeviceExist {
				// "/dev/ptmx"
				resources.Devices = append(resources.Devices, []specs.LinuxDeviceCgroup{
					{Type: "c", Major: intptr(5), Minor: intptr(2), Access: rwm, Allow: true},
				}...)

			}

			if spec.Linux.Resources.CPU != nil {
				resources.CPU = &specs.LinuxCPU{
					Cpus: spec.Linux.Resources.CPU.Cpus,
				}
			}
		}

		//TODO: in Docker or Podman use case, it is reasonable to set a constraint. Need to add a flag
		// to allow users to configure Kata to constrain CPUs and Memory in this alternative
		// scenario. See https://github.com/kata-containers/runtime/issues/2811
	}

	if s.devManager != nil {
		for _, d := range s.devManager.GetAllDevices() {
			dev, err := resCtrl.DeviceToLinuxDevice(d.GetHostPath())
			if err != nil {
				s.Logger().WithError(err).WithField("device", d.GetHostPath()).Warn("Could not add device to sandbox resources")
				continue
			}
			resources.Devices = append(resources.Devices, dev)
		}
	}

	// Create the sandbox resource controller (cgroups on Linux).
	// Depending on the SandboxCgroupOnly value, this cgroup
	// will either hold all the pod threads (SandboxCgroupOnly is true)
	// or only the virtual CPU ones (SandboxCgroupOnly is false).
	s.sandboxController, err = resCtrl.NewSandboxResourceController(
		cgroupPath,
		&resources,
		s.config.SandboxCgroupOnly,
		s.config.HypervisorType != RemoteHypervisor,
	)
	if err != nil {
		return fmt.Errorf("Could not create the sandbox resource controller %v", err)
	}

	// Now that the sandbox resource controller is created, we can set the state controller paths.
	s.state.SandboxCgroupPath = s.sandboxController.ID()
	s.state.OverheadCgroupPath = ""

	if s.config.SandboxCgroupOnly {
		s.overheadController = nil
	} else {
		// The shim configuration is requesting that we do not put all threads
		// into the sandbox resource controller.
		// We're creating an overhead controller, with no constraints. Everything but
		// the vCPU threads will eventually make it there.
		overheadController, err := resCtrl.NewResourceController(fmt.Sprintf("%s%s", resCtrlKataOverheadID, s.InternalID()), &specs.LinuxResources{})
		// TODO: support systemd cgroups overhead cgroup
		// https://github.com/kata-containers/kata-containers/issues/2963
		if err != nil {
			return err
		}
		s.overheadController = overheadController
		s.state.OverheadCgroupPath = s.overheadController.ID()
	}

	return nil
}

// storeSandbox stores a sandbox config.
func (s *Sandbox) storeSandbox(ctx context.Context) error {
	span, _ := katatrace.Trace(ctx, s.Logger(), "storeSandbox", sandboxTracingTags, map[string]string{"sandbox_id": s.id})
	defer span.End()

	// flush data to storage
	if err := s.Save(); err != nil {
		return err
	}
	return nil
}

func rwLockSandbox(sandboxID string) (func() error, error) {
	store, err := persist.GetDriver()
	if err != nil {
		return nil, fmt.Errorf("failed to get fs persist driver: %v", err)
	}

	return store.Lock(sandboxID, true)
}

// findContainer returns a container from the containers list held by the
// sandbox structure, based on a container ID.
func (s *Sandbox) findContainer(containerID string) (*Container, error) {
	if s == nil {
		return nil, types.ErrNeedSandbox
	}

	if containerID == "" {
		return nil, types.ErrNeedContainerID
	}

	if c, ok := s.containers[containerID]; ok {
		return c, nil
	}

	return nil, errors.Wrapf(types.ErrNoSuchContainer, "Could not find the container %q from the sandbox %q containers list",
		containerID, s.id)
}

// removeContainer removes a container from the containers list held by the
// sandbox structure, based on a container ID.
func (s *Sandbox) removeContainer(containerID string) error {
	if s == nil {
		return types.ErrNeedSandbox
	}

	if containerID == "" {
		return types.ErrNeedContainerID
	}

	if _, ok := s.containers[containerID]; !ok {
		return errors.Wrapf(types.ErrNoSuchContainer, "Could not remove the container %q from the sandbox %q containers list",
			containerID, s.id)
	}

	delete(s.containers, containerID)

	return nil
}

// Delete deletes an already created sandbox.
// The VM in which the sandbox is running will be shut down.
func (s *Sandbox) Delete(ctx context.Context) error {
	if s.state.State != types.StateReady &&
		s.state.State != types.StatePaused &&
		s.state.State != types.StateStopped {
		return fmt.Errorf("Sandbox not ready, paused or stopped, impossible to delete")
	}

	for _, c := range s.containers {
		if err := c.delete(ctx); err != nil {
			s.Logger().WithError(err).WithField("container`", c.id).Debug("failed to delete container")
		}
	}

	if !rootless.IsRootless() {
		if err := s.resourceControllerDelete(); err != nil {
			s.Logger().WithError(err).Errorf("failed to cleanup the %s resource controllers", s.sandboxController)
		}
	}

	if s.monitor != nil {
		s.monitor.stop()
	}

	if err := s.hypervisor.Cleanup(ctx); err != nil {
		s.Logger().WithError(err).Error("failed to Cleanup hypervisor")
	}

	if err := s.fsShare.Cleanup(ctx); err != nil {
		s.Logger().WithError(err).Error("failed to cleanup share files")
	}

	if err := s.cleanupEphemeralDisks(); err != nil {
		s.Logger().WithError(err).Error("failed to cleanup ephemeral disks")
	}

	return s.store.Destroy(s.id)
}

// cleanupEphemeralDisks removes ephemeral disk images and their mount info.
func (s *Sandbox) cleanupEphemeralDisks() error {
	if s.config.EmptyDirMode != EmptyDirModeVirtioBlkEncrypted {
		return nil
	}

	for _, disk := range s.ephemeralDisks {
		if err := os.Remove(disk.DiskPath); err != nil && !os.IsNotExist(err) {
			s.Logger().WithError(err).Errorf("Failed to remove disk file: %s", disk.DiskPath)
		}
		if err := volume.Remove(disk.SourcePath); err != nil && !os.IsNotExist(err) {
			s.Logger().WithError(err).Errorf("Failed to remove volume: %s", disk.SourcePath)
		}
	}

	return nil
}

func (s *Sandbox) createNetwork(ctx context.Context) error {
	if s.config.NetworkConfig.DisableNewNetwork ||
		s.config.NetworkConfig.NetworkID == "" {
		return nil
	}

	// docker container needs the hypervisor process ID to find out the container netns,
	// which means that the hypervisor has to support network device hotplug so that docker
	// can use the prestart hooks to set up container netns.
	caps := s.hypervisor.Capabilities(ctx)
	if !caps.IsNetworkDeviceHotplugSupported() {
		spec := s.GetPatchedOCISpec()
		if utils.IsDockerContainer(spec) {
			return errors.New("docker container needs network device hotplug but the configured hypervisor does not support it")
		}
	}

	span, ctx := katatrace.Trace(ctx, s.Logger(), "createNetwork", sandboxTracingTags, map[string]string{"sandbox_id": s.id})
	defer span.End()
	katatrace.AddTags(span, "network", s.network, "NetworkConfig", s.config.NetworkConfig)

	// In case there is a factory, network interfaces are hotplugged
	// after the vm is started.
	if s.factory != nil {
		return nil
	}

	// Add all the networking endpoints.
	if _, err := s.network.AddEndpoints(ctx, s, nil, false); err != nil {
		return err
	}

	return nil
}

func (s *Sandbox) postCreatedNetwork(ctx context.Context) error {
	if s.factory != nil {
		return nil
	}

	if s.network.Endpoints() == nil {
		return nil
	}

	for _, endpoint := range s.network.Endpoints() {
		netPair := endpoint.NetworkPair()
		if netPair == nil {
			continue
		}
		if netPair.VhostFds != nil {
			for _, VhostFd := range netPair.VhostFds {
				VhostFd.Close()
			}
		}
	}

	return nil
}

func (s *Sandbox) removeNetwork(ctx context.Context) error {
	span, ctx := katatrace.Trace(ctx, s.Logger(), "removeNetwork", sandboxTracingTags, map[string]string{"sandbox_id": s.id})
	defer span.End()

	return s.network.RemoveEndpoints(ctx, s, nil, false)
}

func (s *Sandbox) generateNetInfo(inf *pbTypes.Interface) (NetworkInfo, error) {
	hw, err := net.ParseMAC(inf.HwAddr)
	if err != nil {
		return NetworkInfo{}, err
	}

	var addrs []netlink.Addr
	for _, addr := range inf.IPAddresses {
		netlinkAddrStr := fmt.Sprintf("%s/%s", addr.Address, addr.Mask)
		netlinkAddr, err := netlink.ParseAddr(netlinkAddrStr)
		if err != nil {
			return NetworkInfo{}, fmt.Errorf("could not parse %q: %v", netlinkAddrStr, err)
		}

		addrs = append(addrs, *netlinkAddr)
	}

	return NetworkInfo{
		Iface: NetlinkIface{
			LinkAttrs: netlink.LinkAttrs{
				Name:         inf.Name,
				HardwareAddr: hw,
				MTU:          int(inf.Mtu),
			},
			Type: inf.Type,
		},
		Addrs: addrs,
	}, nil
}

// AddInterface adds new nic to the sandbox.
func (s *Sandbox) AddInterface(ctx context.Context, inf *pbTypes.Interface) (*pbTypes.Interface, error) {
	netInfo, err := s.generateNetInfo(inf)
	if err != nil {
		return nil, err
	}

	endpoints, err := s.network.AddEndpoints(ctx, s, []NetworkInfo{netInfo}, true)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			eps := s.network.Endpoints()
			// The newly added endpoint is last.
			added_ep := eps[len(eps)-1]
			if errDetach := s.network.RemoveEndpoints(ctx, s, []Endpoint{added_ep}, true); err != nil {
				s.Logger().WithField("endpoint-type", added_ep.Type()).WithError(errDetach).Error("rollback hot attaching endpoint failed")
			}
		}
	}()

	// Add network for vm
	inf.DevicePath = endpoints[0].PciPath().String()
	result, err := s.agent.updateInterface(ctx, inf)
	if err != nil {
		return nil, err
	}

	// Update the sandbox storage
	if err = s.Save(); err != nil {
		return nil, err
	}

	return result, nil
}

// RemoveInterface removes a nic of the sandbox.
func (s *Sandbox) RemoveInterface(ctx context.Context, inf *pbTypes.Interface) (*pbTypes.Interface, error) {
	for _, endpoint := range s.network.Endpoints() {
		if endpoint.HardwareAddr() == inf.HwAddr {
			s.Logger().WithField("endpoint-type", endpoint.Type()).Info("Hot detaching endpoint")
			if err := s.network.RemoveEndpoints(ctx, s, []Endpoint{endpoint}, true); err != nil {
				return inf, err
			}

			if err := s.Save(); err != nil {
				return inf, err
			}

			break
		}
	}
	return nil, nil
}

// ListInterfaces lists all nics and their configurations in the sandbox.
func (s *Sandbox) ListInterfaces(ctx context.Context) ([]*pbTypes.Interface, error) {
	return s.agent.listInterfaces(ctx)
}

// UpdateRoutes updates the sandbox route table (e.g. for portmapping support).
func (s *Sandbox) UpdateRoutes(ctx context.Context, routes []*pbTypes.Route) ([]*pbTypes.Route, error) {
	return s.agent.updateRoutes(ctx, routes)
}

// ListRoutes lists all routes and their configurations in the sandbox.
func (s *Sandbox) ListRoutes(ctx context.Context) ([]*pbTypes.Route, error) {
	return s.agent.listRoutes(ctx)
}

const (
	// unix socket type of console
	consoleProtoUnix = "unix"

	// pty type of console.
	consoleProtoPty = "pty"
)

// console watcher is designed to monitor guest console output.
type consoleWatcher struct {
	conn       net.Conn
	ptyConsole *os.File
	proto      string
	consoleURL string
}

func newConsoleWatcher(ctx context.Context, s *Sandbox) (*consoleWatcher, error) {
	var (
		err error
		cw  consoleWatcher
	)

	cw.proto, cw.consoleURL, err = s.hypervisor.GetVMConsole(ctx, s.InternalID())
	if err != nil {
		return nil, err
	}

	return &cw, nil
}

// start the console watcher
func (cw *consoleWatcher) start(s *Sandbox) (err error) {
	if cw.consoleWatched() {
		return fmt.Errorf("console watcher has already watched for sandbox %s", s.id)
	}

	var scanner *bufio.Scanner

	switch cw.proto {
	case consoleProtoUnix:
		cw.conn, err = net.Dial("unix", cw.consoleURL)
		if err != nil {
			return err
		}
		scanner = bufio.NewScanner(cw.conn)
	case consoleProtoPty:
		// read-only
		cw.ptyConsole, _ = os.Open(cw.consoleURL)
		scanner = bufio.NewScanner(cw.ptyConsole)
	default:
		return fmt.Errorf("unknown console proto %s", cw.proto)
	}

	go func() {
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				s.Logger().WithFields(logrus.Fields{
					"console-protocol": cw.proto,
					"console-url":      cw.consoleURL,
					"sandbox":          s.id,
					"vmconsole":        text,
				}).Debug("reading guest console")
			}
		}

		if err := scanner.Err(); err != nil {
			s.Logger().WithError(err).WithFields(logrus.Fields{
				"console-protocol": cw.proto,
				"console-url":      cw.consoleURL,
				"sandbox":          s.id,
			}).Error("Failed to read guest console logs")
		} else { // The error is `nil` in case of io.EOF
			s.Logger().Info("console watcher quits")
		}
	}()

	return nil
}

// Check if the console watcher has already watched the vm console.
func (cw *consoleWatcher) consoleWatched() bool {
	return cw.conn != nil || cw.ptyConsole != nil
}

// stop the console watcher.
func (cw *consoleWatcher) stop() {
	if cw.conn != nil {
		cw.conn.Close()
		cw.conn = nil
	}

	if cw.ptyConsole != nil {
		cw.ptyConsole.Close()
		cw.ptyConsole = nil
	}
}

func (s *Sandbox) addSwap(ctx context.Context, swapID string, size int64) (*config.BlockDrive, error) {
	swapFile := filepath.Join(getSandboxPath(s.InternalID()), swapID)

	swapFD, err := os.OpenFile(swapFile, os.O_CREATE, 0600)
	if err != nil {
		err = fmt.Errorf("creat swapfile %s fail %s", swapFile, err.Error())
		s.Logger().WithError(err).Error("addSwap")
		return nil, err
	}
	swapFD.Close()
	defer func() {
		if err != nil {
			os.Remove(swapFile)
		}
	}()

	// Check the size
	pagesize := os.Getpagesize()
	// mkswap refuses areas smaller than 10 pages.
	size = int64(math.Max(float64(size), float64(pagesize*10)))
	// Swapfile need a page to store the metadata
	size += int64(pagesize)

	err = os.Truncate(swapFile, size)
	if err != nil {
		err = fmt.Errorf("truncate swapfile %s fail %s", swapFile, err.Error())
		s.Logger().WithError(err).Error("addSwap")
		return nil, err
	}

	var outbuf, errbuf bytes.Buffer
	cmd := exec.CommandContext(ctx, mkswapPath, swapFile)
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf
	err = cmd.Run()
	if err != nil {
		err = fmt.Errorf("mkswap swapfile %s fail %s stdout %s stderr %s", swapFile, err.Error(), outbuf.String(), errbuf.String())
		s.Logger().WithError(err).Error("addSwap")
		return nil, err
	}

	blockDevice := &config.BlockDrive{
		File:   swapFile,
		Format: "raw",
		ID:     swapID,
		Swap:   true,
	}
	_, err = s.hypervisor.HotplugAddDevice(ctx, blockDevice, BlockDev)
	if err != nil {
		err = fmt.Errorf("add swapfile %s device to VM fail %s", swapFile, err.Error())
		s.Logger().WithError(err).Error("addSwap")
		return nil, err
	}
	defer func() {
		if err != nil {
			_, e := s.hypervisor.HotplugRemoveDevice(ctx, blockDevice, BlockDev)
			if e != nil {
				s.Logger().Errorf("remove swapfile %s to VM fail %s", swapFile, e.Error())
			}
		}
	}()

	err = s.agent.addSwap(ctx, blockDevice.PCIPath)
	if err != nil {
		err = fmt.Errorf("agent add swapfile %s PCIPath %+v to VM fail %s", swapFile, blockDevice.PCIPath, err.Error())
		s.Logger().WithError(err).Error("addSwap")
		return nil, err
	}

	s.Logger().Infof("add swapfile %s size %d PCIPath %+v to VM success", swapFile, size, blockDevice.PCIPath)

	return blockDevice, nil
}

func (s *Sandbox) removeSwap(ctx context.Context, blockDevice *config.BlockDrive) error {
	err := os.Remove(blockDevice.File)
	if err != nil {
		err = fmt.Errorf("remove swapfile %s fail %s", blockDevice.File, err.Error())
		s.Logger().WithError(err).Error("removeSwap")
	} else {
		s.Logger().Infof("remove swapfile %s success", blockDevice.File)
	}
	return err
}

func (s *Sandbox) setupSwap(ctx context.Context, sizeBytes int64) error {
	if sizeBytes > s.swapSizeBytes {
		dev, err := s.addSwap(ctx, fmt.Sprintf("swap%d", s.swapDeviceNum), sizeBytes-s.swapSizeBytes)
		if err != nil {
			return err
		}

		s.swapDeviceNum += 1
		s.swapSizeBytes = sizeBytes
		s.swapDevices = append(s.swapDevices, dev)
	}

	return nil
}

func (s *Sandbox) cleanSwap(ctx context.Context) {
	for _, dev := range s.swapDevices {
		err := s.removeSwap(ctx, dev)
		if err != nil {
			s.Logger().Warnf("remove swap device %+v got error %s", dev, err)
		}
	}
}

func (s *Sandbox) runPrestartHooks(ctx context.Context, prestartHookFunc func(context.Context) error) error {
	hid, _ := s.GetHypervisorPid()
	// Ignore errors here as hypervisor might not have been started yet, likely in FC case.
	if hid > 0 {
		s.Logger().Infof("sandbox %s hypervisor pid is %v", s.id, hid)
		ctx = context.WithValue(ctx, HypervisorPidKey{}, hid)
	}

	if err := prestartHookFunc(ctx); err != nil {
		s.Logger().Errorf("fail to run prestartHook for sandbox %s: %s", s.id, err)
		return err
	}

	return nil
}

// startVM starts the VM.
func (s *Sandbox) startVM(ctx context.Context, prestartHookFunc func(context.Context) error) (err error) {
	span, ctx := katatrace.Trace(ctx, s.Logger(), "startVM", sandboxTracingTags, map[string]string{"sandbox_id": s.id})
	defer span.End()

	s.Logger().Info("Starting VM")

	if s.config.HypervisorConfig.Debug {
		// create console watcher
		consoleWatcher, err := newConsoleWatcher(ctx, s)
		if err != nil {
			return err
		}
		s.cw = consoleWatcher
	}

	defer func() {
		if err != nil {
			// Log error, otherwise nobody might see it - StopVM could kill this process.
			s.Logger().WithError(err).Error("Cannot start VM")
			s.hypervisor.StopVM(ctx, false)
		}
	}()

	caps := s.hypervisor.Capabilities(ctx)
	// If the hypervisor does not support device hotplug, run prestart hooks
	// before spawning the VM so that it is possible to let the hooks set up
	// netns and thus network devices are set up statically.
	if !caps.IsNetworkDeviceHotplugSupported() && prestartHookFunc != nil {
		err = s.runPrestartHooks(ctx, prestartHookFunc)
		if err != nil {
			return err
		}
		// If we want the network, scan the netns again to update the network
		// configuration after the prestart hooks have run.
		if !s.config.NetworkConfig.DisableNewNetwork {
			if _, err := s.network.AddEndpoints(ctx, s, nil, false); err != nil {
				return err
			}
		}
	}

	if err := s.network.Run(ctx, func() error {
		if s.factory != nil {
			vm, err := s.factory.GetVM(ctx, VMConfig{
				HypervisorType:   s.config.HypervisorType,
				HypervisorConfig: s.config.HypervisorConfig,
				AgentConfig:      s.config.AgentConfig,
			})
			if err != nil {
				return err
			}

			return vm.assignSandbox(s)
		}

		return s.hypervisor.StartVM(ctx, VmStartTimeout)
	}); err != nil {
		return err
	}

	if caps.IsNetworkDeviceHotplugSupported() && prestartHookFunc != nil {
		err = s.runPrestartHooks(ctx, prestartHookFunc)
		if err != nil {
			return err
		}
	}

	// 1. Do not scan the netns if we want no network for the vmm
	// 2. Do not scan the netns if the vmm does not support device hotplug, in which case
	//    the network is already set up statically
	// 3. In case of vm factory, scan the netns to hotplug interfaces after vm is started.
	// 4. In case of prestartHookFunc, network config might have been changed. We need to
	//    rescan and handle the change.
	if !s.config.NetworkConfig.DisableNewNetwork &&
		caps.IsNetworkDeviceHotplugSupported() &&
		(s.factory != nil || prestartHookFunc != nil) {
		if _, err := s.network.AddEndpoints(ctx, s, nil, true); err != nil {
			return err
		}
	}

	s.Logger().Info("VM started")

	if s.cw != nil {
		s.Logger().Debug("console watcher starts")
		if err := s.cw.start(s); err != nil {
			s.cw.stop()
			return err
		}
	}

	// Skip the in-guest agent startup entirely when this sandbox
	// is the destination of an inbound live migration. QEMU is
	// paused at "-S -incoming defer"; the kata-agent inside the
	// guest is not running and won't be reachable over vsock
	// until the source's memory arrives, the guest is resumed,
	// and the destination shim re-pairs with the migrated agent
	// on its new host-side vsock CID. See
	// containerd-shim-v2/migration_sequence.go OnComplete for
	// the resume + re-pair sequence.
	if s.config.IncomingMigrationURI != "" {
		s.Logger().WithField("listenURI", s.config.IncomingMigrationURI).
			Warn("incoming-migration mode: skipping agent.startSandbox until handoff completes")
	} else {
		// Once the hypervisor is done starting the sandbox,
		// we want to guarantee that it is manageable.
		// For that we need to ask the agent to start the
		// sandbox inside the VM.
		if err := s.agent.startSandbox(ctx, s); err != nil {
			return err
		}

		s.Logger().Info("Agent started in the sandbox")
	}

	defer func() {
		if err != nil {
			if e := s.agent.stopSandbox(ctx, s); e != nil {
				s.Logger().WithError(e).WithField("sandboxid", s.id).Warning("Agent did not stop sandbox")
			}
		}
	}()

	return nil
}

// stopVM: stop the sandbox's VM
func (s *Sandbox) stopVM(ctx context.Context) error {
	span, ctx := katatrace.Trace(ctx, s.Logger(), "stopVM", sandboxTracingTags, map[string]string{"sandbox_id": s.id})
	defer span.End()

	s.Logger().Info("Stopping sandbox in the VM")
	if !s.agentUnreachable {
		if err := s.agent.stopSandbox(ctx, s); err != nil {
			s.Logger().WithError(err).WithField("sandboxid", s.id).Warning("Agent did not stop sandbox")
		}
	}

	s.Logger().Info("Stopping VM")

	// When this sandbox is in a terminal migration mode (saved/migrated),
	// a dual-identity successor on the same node may share the vhost-user
	// socket directory. Signal the hypervisor to preserve the virtiofsd
	// socket file during teardown so the successor's QEMU can connect.
	// The actual type assertion is in a Linux-only file (qemu is Linux-only).
	s.markVirtiofsSocketPreserved()

	return s.hypervisor.StopVM(ctx, s.disableVMShutdown)
}

func (s *Sandbox) addContainer(c *Container) error {
	if _, ok := s.containers[c.id]; ok {
		return fmt.Errorf("Duplicated container: %s", c.id)
	}
	s.containers[c.id] = c

	return nil
}

// CreateContainer creates a new container in the sandbox
// This should be called only when the sandbox is already created.
// It will add new container config to sandbox.config.Containers
func (s *Sandbox) CreateContainer(ctx context.Context, contConfig ContainerConfig) (VCContainer, error) {
	// Update sandbox config to include the new container's config
	s.config.Containers = append(s.config.Containers, contConfig)

	var err error

	defer func() {
		if err != nil {
			if len(s.config.Containers) > 0 {
				// delete container config
				s.config.Containers = s.config.Containers[:len(s.config.Containers)-1]
			}
		}
	}()

	// Create the container object, add devices to the sandbox's device-manager:
	c, err := newContainer(ctx, s, &s.config.Containers[len(s.config.Containers)-1])
	if err != nil {
		return nil, err
	}

	// Incoming-migration destination: the container already exists
	// inside the source guest and will be live-migrated. Skip the
	// agent-side createContainer RPC (would hang — agent unreachable
	// while QEMU is paused on "-S -incoming defer") and the resource
	// update calls below. We still register the container in
	// sandbox bookkeeping so CRI ops that follow can find it. The
	// agent-side container is re-paired when onMigrationComplete
	// resumes the migrated guest.
	if s.config.IncomingMigrationURI != "" {
		// Adopt the source container's ID as InternalID. Without
		// this, agent RPCs ("exec", "stop", "signal", "stats") on
		// the dest land in the agent with this dest's fresh CRI ID,
		// which the agent has never seen → "Invalid container id".
		// The source mapping was stashed by the shim's
		// /migration/topology handler before this CreateContainer
		// call landed. No-op (and harmless) when the mapping is
		// empty or the container-name doesn't match — InternalID()
		// stays equal to ContainerdID(), preserving today's
		// behavior on any non-migration code path that reaches here.
		adopted := s.adoptMigrationContainerID(c)

		// Share the container's rootfs ONLY when adoption fired —
		// the bind path is keyed on c.InternalID() (see
		// fs_share_linux.go), and binding with the un-adopted (dest
		// fresh CRI) ID lands the rootfs at a path the migrated
		// guest doesn't see, leaving agent.exec to fail with EIO.
		// When adoption is deferred (CreateContainer ran before
		// /migration/topology), SetMigrationSourceContainers will
		// fire the share retroactively. See its body for the
		// matching call site.
		if adopted {
			if _, err = s.fsShare.ShareRootFilesystem(ctx, c); err != nil {
				s.Logger().WithError(err).WithFields(logrus.Fields{
					"containerdID": c.id,
					"internalID":   c.InternalID(),
				}).Error("migration-dest: ShareRootFilesystem failed")
				return nil, err
			}
			c.rootfsShared = true
			s.Logger().WithFields(logrus.Fields{
				"containerdID": c.id,
				"internalID":   c.InternalID(),
			}).Warn("migration-dest: workload rootfs bind-mounted into shared dir")
		} else {
			s.Logger().WithField("containerdID", c.id).
				Warn("migration-dest: rootfs share deferred until adoption fires")
		}

		if err = s.addContainer(c); err != nil {
			return nil, err
		}
		return c, nil
	}

	// create and start the container
	if err = c.create(ctx); err != nil {
		return nil, err
	}

	// Add the container to the containers list in the sandbox.
	if err = s.addContainer(c); err != nil {
		return nil, err
	}

	defer func() {
		// Rollback if error happens.
		if err != nil {
			logger := s.Logger().WithFields(logrus.Fields{"container": c.id, "sandbox": s.id, "rollback": true})
			logger.WithError(err).Error("Cleaning up partially created container")

			if errStop := c.stop(ctx, true); errStop != nil {
				logger.WithError(errStop).Error("Could not stop container")
			}

			logger.Debug("Removing stopped container from sandbox store")
			s.removeContainer(c.id)
		}
	}()

	// Sandbox is responsible to update VM resources needed by Containers
	// Update resources after having added containers to the sandbox, since
	// container status is required to know if more resources should be added.
	if err = s.updateResources(ctx); err != nil {
		return nil, err
	}

	if err = s.resourceControllerUpdate(ctx); err != nil {
		return nil, err
	}

	if err = s.checkVCPUsPinning(ctx); err != nil {
		return nil, err
	}

	if err = s.storeSandbox(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

// StartContainer starts a container in the sandbox
func (s *Sandbox) StartContainer(ctx context.Context, containerID string) (VCContainer, error) {
	// Fetch the container.
	c, err := s.findContainer(containerID)
	if err != nil {
		return nil, err
	}

	// Start it.
	if err = c.start(ctx); err != nil {
		return nil, err
	}

	if err = s.storeSandbox(ctx); err != nil {
		return nil, err
	}

	s.Logger().WithField("container", containerID).Info("Container is started")

	// Update sandbox resources in case a stopped container
	// is started
	if err = s.updateResources(ctx); err != nil {
		return nil, err
	}

	if err = s.checkVCPUsPinning(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

// StopContainer stops a container in the sandbox
func (s *Sandbox) StopContainer(ctx context.Context, containerID string, force bool) (VCContainer, error) {
	// Fetch the container.
	c, err := s.findContainer(containerID)
	if err != nil {
		return nil, err
	}

	// Stop it.
	if err := c.stop(ctx, force); err != nil {
		return nil, err
	}

	if err = s.storeSandbox(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// KillContainer signals a container in the sandbox
func (s *Sandbox) KillContainer(ctx context.Context, containerID string, signal syscall.Signal, all bool) error {
	// Fetch the container.
	c, err := s.findContainer(containerID)
	if err != nil {
		return err
	}

	// Send a signal to the process.
	err = c.kill(ctx, signal, all)

	// SIGKILL should never fail otherwise it is
	// impossible to clean things up.
	if signal == syscall.SIGKILL {
		return nil
	}

	return err
}

// DeleteContainer deletes a container from the sandbox
func (s *Sandbox) DeleteContainer(ctx context.Context, containerID string) (VCContainer, error) {
	if containerID == "" {
		return nil, types.ErrNeedContainerID
	}

	// Fetch the container.
	c, err := s.findContainer(containerID)
	if err != nil {
		return nil, err
	}

	// Delete it.
	if err = c.delete(ctx); err != nil {
		return nil, err
	}

	// Update sandbox config
	for idx, contConfig := range s.config.Containers {
		if contConfig.ID == containerID {
			s.config.Containers = append(s.config.Containers[:idx], s.config.Containers[idx+1:]...)
			break
		}
	}

	// update the sandbox resource controller
	if err = s.resourceControllerUpdate(ctx); err != nil {
		return nil, err
	}

	if err = s.checkVCPUsPinning(ctx); err != nil {
		return nil, err
	}

	if err = s.storeSandbox(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// StatusContainer gets the status of a container
func (s *Sandbox) StatusContainer(containerID string) (ContainerStatus, error) {
	if containerID == "" {
		return ContainerStatus{}, types.ErrNeedContainerID
	}

	if c, ok := s.containers[containerID]; ok {
		rootfs := c.config.RootFs.Source
		if c.config.RootFs.Mounted {
			rootfs = c.config.RootFs.Target
		}

		return ContainerStatus{
			ID:          c.id,
			State:       c.state,
			PID:         c.process.Pid,
			StartTime:   c.process.StartTime,
			RootFs:      rootfs,
			Annotations: c.config.Annotations,
		}, nil
	}

	return ContainerStatus{}, types.ErrNoSuchContainer
}

// EnterContainer is the virtcontainers container command execution entry point.
// EnterContainer enters an already running container and runs a given command.
func (s *Sandbox) EnterContainer(ctx context.Context, containerID string, cmd types.Cmd) (VCContainer, *Process, error) {
	// Fetch the container.
	c, err := s.findContainer(containerID)
	if err != nil {
		return nil, nil, err
	}

	// Enter it.
	process, err := c.enter(ctx, cmd)
	if err != nil {
		return nil, nil, err
	}

	return c, process, nil
}

// UpdateContainer update a running container.
func (s *Sandbox) UpdateContainer(ctx context.Context, containerID string, resources specs.LinuxResources) error {
	// Fetch the container.
	c, err := s.findContainer(containerID)
	if err != nil {
		return err
	}

	if err = c.update(ctx, resources); err != nil {
		return err
	}

	if err := s.resourceControllerUpdate(ctx); err != nil {
		return err
	}

	if err = s.checkVCPUsPinning(ctx); err != nil {
		return err
	}

	if err = s.storeSandbox(ctx); err != nil {
		return err
	}
	return nil
}

// StatsContainer return the stats of a running container
func (s *Sandbox) StatsContainer(ctx context.Context, containerID string) (ContainerStats, error) {
	// Fetch the container.
	c, err := s.findContainer(containerID)
	if err != nil {
		return ContainerStats{}, err
	}

	stats, err := c.stats(ctx)
	if err != nil {
		return ContainerStats{}, err
	}
	return *stats, nil
}

// Stats returns the stats of a running sandbox
func (s *Sandbox) Stats(ctx context.Context) (SandboxStats, error) {

	metrics, err := s.sandboxController.Stat()
	if err != nil {
		return SandboxStats{}, err
	}

	stats := SandboxStats{}

	// TODO Do we want to aggregate the overhead cgroup stats to the sandbox ones?
	switch mt := metrics.(type) {
	case *v1.Metrics:
		stats.CgroupStats.CPUStats.CPUUsage.TotalUsage = mt.CPU.Usage.Total
		stats.CgroupStats.MemoryStats.Usage.Usage = mt.Memory.Usage.Usage
	case *v2.Metrics:
		stats.CgroupStats.CPUStats.CPUUsage.TotalUsage = mt.CPU.UsageUsec
		stats.CgroupStats.MemoryStats.Usage.Usage = mt.Memory.Usage
	default:
		return SandboxStats{}, fmt.Errorf("unknown metrics type %T", mt)
	}

	tids, err := s.hypervisor.GetThreadIDs(ctx)
	if err != nil {
		return stats, err
	}
	stats.Cpus = len(tids.vcpus)

	return stats, nil
}

// PauseContainer pauses a running container.
func (s *Sandbox) PauseContainer(ctx context.Context, containerID string) error {
	// Fetch the container.
	c, err := s.findContainer(containerID)
	if err != nil {
		return err
	}

	// Pause the container.
	if err := c.pause(ctx); err != nil {
		return err
	}

	if err = s.storeSandbox(ctx); err != nil {
		return err
	}
	return nil
}

// ResumeContainer resumes a paused container.
func (s *Sandbox) ResumeContainer(ctx context.Context, containerID string) error {
	// Fetch the container.
	c, err := s.findContainer(containerID)
	if err != nil {
		return err
	}

	// Resume the container.
	if err := c.resume(ctx); err != nil {
		return err
	}

	if err = s.storeSandbox(ctx); err != nil {
		return err
	}
	return nil
}

// createContainers registers all containers, create the
// containers in the guest.
func (s *Sandbox) createContainers(ctx context.Context) error {
	span, ctx := katatrace.Trace(ctx, s.Logger(), "createContainers", sandboxTracingTags, map[string]string{"sandbox_id": s.id})
	defer span.End()

	for i := range s.config.Containers {
		c, err := newContainer(ctx, s, &s.config.Containers[i])
		if err != nil {
			return err
		}
		if err := c.create(ctx); err != nil {
			return err
		}

		if err := s.addContainer(c); err != nil {
			return err
		}
	}

	// Update resources after having added containers to the sandbox, since
	// container status is required to know if more resources should be added.
	if err := s.updateResources(ctx); err != nil {
		return err
	}
	if err := s.resourceControllerUpdate(ctx); err != nil {
		return err
	}

	if err := s.checkVCPUsPinning(ctx); err != nil {
		return err
	}

	if err := s.storeSandbox(ctx); err != nil {
		return err
	}
	return nil
}

// Start starts a sandbox. The containers that are making the sandbox
// will be started.
func (s *Sandbox) Start(ctx context.Context) error {
	if err := s.state.ValidTransition(s.state.State, types.StateRunning); err != nil {
		return err
	}

	prevState := s.state.State

	if err := s.setSandboxState(types.StateRunning); err != nil {
		return err
	}

	var startErr error
	defer func() {
		if startErr != nil {
			s.setSandboxState(prevState)
		}
	}()
	for _, c := range s.containers {
		if startErr = c.start(ctx); startErr != nil {
			return startErr
		}
	}

	if err := s.storeSandbox(ctx); err != nil {
		return err
	}

	s.Logger().Info("Sandbox is started")

	return nil
}

// Stop stops a sandbox. The containers that are making the sandbox
// will be destroyed.
// When force is true, ignore guest related stop failures.
// agentReachableProbeTimeout bounds the agent reachability probe used at force
// teardown / teardown-kill. A healthy agent answers a Check in well under a
// second; this only caps how long we wait on an UNRESPONSIVE agent before
// giving up on it. Kept short relative to the kubelet/containerd StopPodSandbox
// budget (~2m) so teardown completes well within it.
const agentReachableProbeTimeout = 15 * time.Second

// agentReachableCacheTTL is how long an AgentReachable probe result is
// reused before re-probing. The shim's Kill handler probes while holding
// its service mutex and the kubelet retries StopContainer in a tight loop,
// so consecutive probes within the TTL must not each pay the full probe
// timeout under the lock. Short enough that a just-resumed agent is
// re-detected promptly.
const agentReachableCacheTTL = 5 * time.Second

// AgentReachable reports whether the in-guest agent answers a Check within a
// short bound. It is the FR-054 / #254 building block: teardown paths that
// would otherwise issue a blocking agent RPC (kill / waitProcess /
// signalProcess) consult this and skip the RPC when the agent has moved or
// wedged, so a warm-resumed (dual-identity) or post-migration sandbox does not
// hang `delete` and stick the pod Terminating with a live QEMU. A reachable
// agent answers quickly, so normal stops/kills are unaffected. Results are
// cached for agentReachableCacheTTL so retry loops (kubelet StopContainer)
// don't pay the probe timeout on every attempt.
func (s *Sandbox) AgentReachable(ctx context.Context) bool {
	if s.agent == nil {
		return false
	}

	s.agentReachMu.Lock()
	if time.Now().Before(s.agentReachExpiry) {
		v := s.agentReachVal
		s.agentReachMu.Unlock()
		return v
	}
	s.agentReachMu.Unlock()

	probeCtx, cancel := context.WithTimeout(ctx, agentReachableProbeTimeout)
	defer cancel()
	reachable := s.agent.check(probeCtx) == nil

	s.agentReachMu.Lock()
	s.agentReachVal = reachable
	s.agentReachExpiry = time.Now().Add(agentReachableCacheTTL)
	s.agentReachMu.Unlock()

	return reachable
}

func (s *Sandbox) Stop(ctx context.Context, force bool) error {
	span, ctx := katatrace.Trace(ctx, s.Logger(), "Stop", sandboxTracingTags, map[string]string{"sandbox_id": s.id})
	defer span.End()

	// INSTR: kata-sandbox-stop-instr-v1
	s.Logger().WithFields(logrus.Fields{
		"marker":      "kata-sandbox-stop-instr-v1",
		"force":       force,
		"stateNow":    string(s.state.State),
		"containerCt": len(s.containers),
		"stack":       string(debug.Stack()),
	}).Warn("INSTR: Sandbox.Stop: entered. About to stop containers, then VM. Caller stack is above.")

	if s.state.State == types.StateStopped {
		s.Logger().Info("sandbox already stopped")
		return nil
	}

	if err := s.state.ValidTransition(s.state.State, types.StateStopped); err != nil {
		return err
	}

	// FR-054 / #254: on a force teardown, if the in-guest agent is unreachable
	// (a warm-resumed dual-identity pod torn down in ModeOwner, or a
	// post-migration source whose agent has moved), the per-container stop
	// below would block forever on its agent RPCs and leave the QEMU alive with
	// the pod stuck Terminating. Probe once; if the agent does not answer, mark
	// it unreachable so c.stop skips those RPCs and falls through to stopVM's
	// SIGKILL. Keyed on the agent's ACTUAL reachability rather than the mode
	// alone, so it covers every dead-agent teardown; a reachable agent is
	// untouched and keeps its graceful stop.
	if force && !s.agentUnreachable && !s.AgentReachable(ctx) {
		s.Logger().Warn("Sandbox.Stop: in-guest agent unreachable on force teardown — skipping agent RPCs and force-killing the VM (FR-054)")
		s.agentUnreachable = true
	}

	for _, c := range s.containers {
		if err := c.stop(ctx, force); err != nil {
			return err
		}
	}

	if err := s.stopVM(ctx); err != nil && !force {
		return err
	}

	// shutdown console watcher if exists
	if s.cw != nil {
		s.Logger().Debug("stop the console watcher")
		s.cw.stop()
	}

	if err := s.setSandboxState(types.StateStopped); err != nil {
		return err
	}

	// Remove the network.
	if err := s.removeNetwork(ctx); err != nil && !force {
		return err
	}

	if err := s.storeSandbox(ctx); err != nil {
		return err
	}

	// Stop communicating with the agent.
	if !s.agentUnreachable {
		if err := s.agent.disconnect(ctx); err != nil && !force {
			return err
		}
	}

	s.cleanSwap(ctx)

	return nil
}

// setSandboxState sets the in-memory state of the sandbox.
func (s *Sandbox) setSandboxState(state types.StateString) error {
	if state == "" {
		return types.ErrNeedState
	}

	// update in-memory state
	s.state.State = state

	return nil
}

const maxBlockIndex = 65535

// getAndSetSandboxBlockIndex retrieves an unused sandbox block index from
// the BlockIndexMap and marks it as used. This index is used to maintain the
// index at which a block device is assigned to a container in the sandbox.
func (s *Sandbox) getAndSetSandboxBlockIndex() (int, error) {
	currentIndex := -1
	for i := 0; i < maxBlockIndex; i++ {
		if _, ok := s.state.BlockIndexMap[i]; !ok {
			currentIndex = i
			break
		}
	}
	if currentIndex == -1 {
		return -1, errors.New("no available block index")
	}
	s.state.BlockIndexMap[currentIndex] = struct{}{}

	return currentIndex, nil
}

// unsetSandboxBlockIndex deletes the current sandbox block index from BlockIndexMap.
// This is used to recover from failure while adding a block device.
func (s *Sandbox) unsetSandboxBlockIndex(index int) error {
	var err error
	original := index
	delete(s.state.BlockIndexMap, index)
	defer func() {
		if err != nil {
			s.state.BlockIndexMap[original] = struct{}{}
		}
	}()

	return nil
}

// HotplugAddDevice is used for add a device to sandbox
// Sandbox implement DeviceReceiver interface from device/api/interface.go
func (s *Sandbox) HotplugAddDevice(ctx context.Context, device api.Device, devType config.DeviceType) error {
	span, ctx := katatrace.Trace(ctx, s.Logger(), "HotplugAddDevice", sandboxTracingTags, map[string]string{"sandbox_id": s.id})
	defer span.End()

	if s.sandboxController != nil {
		if err := s.sandboxController.AddDevice(device.GetHostPath()); err != nil {
			s.Logger().WithError(err).WithField("device", device).
				Warnf("Could not add device to the %s controller", s.sandboxController)
		}
	}

	switch devType {
	case config.DeviceVFIO:
		vfioDevices, ok := device.GetDeviceInfo().([]*config.VFIODev)
		if !ok {
			return fmt.Errorf("device type mismatch, expect device type to be %s", devType)
		}

		// adding a group of VFIO devices
		for _, dev := range vfioDevices {
			if _, err := s.hypervisor.HotplugAddDevice(ctx, dev, VfioDev); err != nil {
				s.Logger().
					WithFields(logrus.Fields{
						"sandbox":         s.id,
						"vfio-device-ID":  dev.ID,
						"vfio-device-BDF": dev.BDF,
					}).WithError(err).Error("failed to hotplug VFIO device")
				return err
			}
		}
		return nil
	case config.DeviceBlock:
		blockDevice, ok := device.(*drivers.BlockDevice)
		if !ok {
			return fmt.Errorf("device type mismatch, expect device type to be %s", devType)
		}
		_, err := s.hypervisor.HotplugAddDevice(ctx, blockDevice.BlockDrive, BlockDev)
		return err
	case config.VhostUserBlk:
		vhostUserBlkDevice, ok := device.(*drivers.VhostUserBlkDevice)

		if !ok {
			return fmt.Errorf("device type mismatch, expect device type to be %s", devType)
		}
		_, err := s.hypervisor.HotplugAddDevice(ctx, vhostUserBlkDevice.VhostUserDeviceAttrs, VhostuserDev)
		return err
	case config.DeviceGeneric:
		// TODO: what?
		return nil
	}
	return nil
}

// HotplugRemoveDevice is used for removing a device from sandbox
// Sandbox implement DeviceReceiver interface from device/api/interface.go
func (s *Sandbox) HotplugRemoveDevice(ctx context.Context, device api.Device, devType config.DeviceType) error {
	defer func() {
		if s.sandboxController != nil {
			if err := s.sandboxController.RemoveDevice(device.GetHostPath()); err != nil {
				s.Logger().WithError(err).WithField("device", device).
					Warnf("Could not add device to the %s controller", s.sandboxController)
			}
		}
	}()

	switch devType {
	case config.DeviceVFIO:
		vfioDevices, ok := device.GetDeviceInfo().([]*config.VFIODev)
		if !ok {
			return fmt.Errorf("device type mismatch, expect device type to be %s", devType)
		}

		// remove a group of VFIO devices
		for _, dev := range vfioDevices {
			if _, err := s.hypervisor.HotplugRemoveDevice(ctx, dev, VfioDev); err != nil {
				s.Logger().WithError(err).
					WithFields(logrus.Fields{
						"sandbox":         s.id,
						"vfio-device-ID":  dev.ID,
						"vfio-device-BDF": dev.BDF,
					}).Error("failed to hot unplug VFIO device")
				return err
			}
		}
		return nil
	case config.DeviceBlock:
		blockDrive, ok := device.GetDeviceInfo().(*config.BlockDrive)
		if !ok {
			return fmt.Errorf("device type mismatch, expect device type to be %s", devType)
		}
		// PMEM devices cannot be hot removed
		if blockDrive.Pmem {
			s.Logger().WithField("path", blockDrive.File).Infof("Skip device: cannot hot remove PMEM devices")
			return nil
		}
		_, err := s.hypervisor.HotplugRemoveDevice(ctx, blockDrive, BlockDev)
		return err
	case config.VhostUserBlk:
		vhostUserDeviceAttrs, ok := device.GetDeviceInfo().(*config.VhostUserDeviceAttrs)
		if !ok {
			return fmt.Errorf("device type mismatch, expect device type to be %s", devType)
		}
		_, err := s.hypervisor.HotplugRemoveDevice(ctx, vhostUserDeviceAttrs, VhostuserDev)
		return err
	case config.DeviceGeneric:
		// TODO: what?
		return nil
	}
	return nil
}

// GetAndSetSandboxBlockIndex is used for getting and setting virtio-block indexes
// Sandbox implement DeviceReceiver interface from device/api/interface.go
func (s *Sandbox) GetAndSetSandboxBlockIndex() (int, error) {
	return s.getAndSetSandboxBlockIndex()
}

// UnsetSandboxBlockIndex unsets block indexes
// Sandbox implement DeviceReceiver interface from device/api/interface.go
func (s *Sandbox) UnsetSandboxBlockIndex(index int) error {
	return s.unsetSandboxBlockIndex(index)
}

// AppendDevice can only handle vhost user device currently, it adds a
// vhost user device to sandbox
// Sandbox implement DeviceReceiver interface from device/api/interface.go
func (s *Sandbox) AppendDevice(ctx context.Context, device api.Device) error {
	switch device.DeviceType() {
	case config.VhostUserSCSI, config.VhostUserNet, config.VhostUserBlk, config.VhostUserFS:
		return s.hypervisor.AddDevice(ctx, device.GetDeviceInfo().(*config.VhostUserDeviceAttrs), VhostuserDev)
	case config.DeviceVFIO:
		vfioDevs := device.GetDeviceInfo().([]*config.VFIODev)
		for _, d := range vfioDevs {
			return s.hypervisor.AddDevice(ctx, *d, VfioDev)
		}
	default:
		s.Logger().WithField("device-type", device.DeviceType()).
			Warn("Could not append device: unsupported device type")
	}

	return fmt.Errorf("unsupported device type")
}

// AddDevice will add a device to sandbox
func (s *Sandbox) AddDevice(ctx context.Context, info config.DeviceInfo) (api.Device, error) {
	if s.devManager == nil {
		return nil, fmt.Errorf("device manager isn't initialized")
	}

	var err error
	add, err := s.devManager.NewDevice(info)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			s.devManager.RemoveDevice(add.DeviceID())
		}
	}()

	if err = s.devManager.AttachDevice(ctx, add.DeviceID(), s); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			s.devManager.DetachDevice(ctx, add.DeviceID(), s)
		}
	}()

	return add, nil
}

// GetVfioDeviceGuestPciPath return a device's guest PCI path by its host BDF
func (s *Sandbox) GetVfioDeviceGuestPciPath(hostBDF string) types.PciPath {
	devices := s.devManager.GetAllDevices()
	for _, device := range devices {
		switch device.DeviceType() {
		case config.DeviceVFIO:
			vfioDevices, ok := device.GetDeviceInfo().([]*config.VFIODev)
			if !ok {
				continue
			}
			for _, vfioDev := range vfioDevices {
				if vfioDev.BDF == hostBDF {
					return vfioDev.GuestPciPath
				}
			}
		default:
			continue
		}
	}

	return types.PciPath{}
}

// updateResources will:
// - calculate the resources required for the virtual machine, and adjust the virtual machine
// sizing accordingly. For a given sandbox, it will calculate the number of vCPUs required based
// on the sum of container requests, plus default CPUs for the VM. Similar is done for memory.
// If changes in memory or CPU are made, the VM will be updated and the agent will online the
// applicable CPU and memory.
func (s *Sandbox) updateResources(ctx context.Context) error {
	if s == nil {
		return errors.New("sandbox is nil")
	}

	if s.config == nil {
		return fmt.Errorf("sandbox config is nil")
	}

	if s.config.StaticResourceMgmt {
		s.Logger().Debug("no resources updated: static resource management is set")
		return nil
	}

	sandboxVCPUs, err := s.calculateSandboxCPUs()
	if err != nil {
		return err
	}
	// Add default vcpus for sandbox
	sandboxVCPUs += s.hypervisor.HypervisorConfig().NumVCPUsF

	sandboxMemoryByte, sandboxneedPodSwap, sandboxSwapByte := s.calculateSandboxMemory()

	// Add default / rsvd memory for sandbox.
	hypervisorMemoryByteI64 := int64(s.hypervisor.HypervisorConfig().MemorySize) << utils.MibToBytesShift
	hypervisorMemoryByte := uint64(hypervisorMemoryByteI64)
	sandboxMemoryByte += hypervisorMemoryByte
	if sandboxneedPodSwap {
		sandboxSwapByte += hypervisorMemoryByteI64
	}
	s.Logger().WithField("sandboxMemoryByte", sandboxMemoryByte).WithField("sandboxneedPodSwap", sandboxneedPodSwap).WithField("sandboxSwapByte", sandboxSwapByte).Debugf("updateResources: after calculateSandboxMemory")

	// Setup the SWAP in the guest
	if sandboxSwapByte > 0 {
		err = s.setupSwap(ctx, sandboxSwapByte)
		if err != nil {
			return err
		}
	}

	// Update VCPUs
	s.Logger().WithField("cpus-sandbox", sandboxVCPUs).Debugf("Request to hypervisor to update vCPUs")
	oldCPUs, newCPUs, err := s.hypervisor.ResizeVCPUs(ctx, RoundUpNumVCPUs(sandboxVCPUs))
	if err != nil {
		return err
	}

	s.Logger().Debugf("Request to hypervisor to update oldCPUs/newCPUs: %d/%d", oldCPUs, newCPUs)
	// If the CPUs were increased, ask agent to online them
	if oldCPUs < newCPUs {
		s.Logger().Debugf("Request to onlineCPUMem with %d CPUs", newCPUs)
		if err := s.agent.onlineCPUMem(ctx, newCPUs, true); err != nil {
			return err
		}
	}
	s.Logger().Debugf("Sandbox CPUs: %d", newCPUs)

	// Update Memory --
	// If we're using ACPI hotplug for memory, there's a limitation on the amount of memory which can be hotplugged at a single time.
	// We must have enough free memory in the guest kernel to cover 64bytes per (4KiB) page of memory added for mem_map.
	// See https://github.com/kata-containers/kata-containers/issues/4847 for more details.
	// For a typical pod lifecycle, we expect that each container is added when we start the workloads. Based on this, we'll "assume" that majority
	// of the guest memory is readily available. From experimentation, we see that we can add approximately 48 times what is already provided to
	// the guest workload. For example, a 256 MiB guest should be able to accommodate hotplugging 12 GiB of memory.
	//
	// If virtio-mem is being used, there isn't such a limitation - we can hotplug the maximum allowed memory at a single time.
	//
	newMemoryMB := uint32(sandboxMemoryByte >> utils.MibToBytesShift)
	finalMemoryMB := newMemoryMB

	hconfig := s.hypervisor.HypervisorConfig()

	for {
		currentMemoryMB := s.hypervisor.GetTotalMemoryMB(ctx)

		maxhotPluggableMemoryMB := currentMemoryMB * acpiMemoryHotplugFactor

		// In the case of virtio-mem, we don't have a restriction on how much can be hotplugged at
		// a single time. As a result, the max hotpluggable is only limited by the maximum memory size
		// of the guest.
		if hconfig.VirtioMem {
			maxhotPluggableMemoryMB = uint32(hconfig.DefaultMaxMemorySize) - currentMemoryMB
		}

		deltaMB := int32(finalMemoryMB - currentMemoryMB)

		if deltaMB > int32(maxhotPluggableMemoryMB) {
			s.Logger().Warnf("Large hotplug. Adding %d MB of %d total memory", maxhotPluggableMemoryMB, deltaMB)
			newMemoryMB = currentMemoryMB + maxhotPluggableMemoryMB
		} else {
			newMemoryMB = finalMemoryMB
		}

		// Add the memory to the guest and online the memory:
		if err := s.updateMemory(ctx, newMemoryMB); err != nil {
			return err
		}

		if newMemoryMB == finalMemoryMB {
			break
		}
	}

	tmpfsMounts, err := s.prepareEphemeralMounts(finalMemoryMB)
	if err != nil {
		return err
	}
	if err := s.agent.updateEphemeralMounts(ctx, tmpfsMounts); err != nil {
		// upgrade path: if runtime is newer version, but agent is old
		// then ignore errUnimplemented
		if grpcStatus.Convert(err).Code() == codes.Unimplemented {
			s.Logger().Warnf("agent does not support updateMounts")
			return nil
		}
		return err
	}

	return nil
}

func (s *Sandbox) prepareEphemeralMounts(memoryMB uint32) ([]*grpc.Storage, error) {
	tmpfsMounts := []*grpc.Storage{}
	for _, c := range s.containers {
		for _, mount := range c.mounts {
			// if a tmpfs ephemeral mount is present
			// update its size to occupy the entire sandbox's memory
			if mount.Type == KataEphemeralDevType {
				sizeLimited := false
				for _, opt := range mount.Options {
					if strings.HasPrefix(opt, "size") {
						sizeLimited = true
					}
				}
				if sizeLimited { // do not resize sizeLimited emptyDirs
					continue
				}

				mountOptions := []string{"remount", fmt.Sprintf("size=%dM", memoryMB)}

				origin_src := mount.Source
				stat := syscall.Stat_t{}
				err := syscall.Stat(origin_src, &stat)
				if err != nil {
					return nil, err
				}

				// if volume's gid isn't root group(default group), this means there's
				// an specific fsGroup is set on this local volume, then it should pass
				// to guest.
				if stat.Gid != 0 {
					mountOptions = append(mountOptions, fmt.Sprintf("%s=%d", fsGid, stat.Gid))
				}

				tmpfsMounts = append(tmpfsMounts, &grpc.Storage{
					Driver:     KataEphemeralDevType,
					MountPoint: filepath.Join(ephemeralPath(), filepath.Base(mount.Source)),
					Source:     "tmpfs",
					Fstype:     "tmpfs",
					Options:    mountOptions,
				})
			}
		}
	}
	return tmpfsMounts, nil
}

func (s *Sandbox) updateMemory(ctx context.Context, newMemoryMB uint32) error {
	// online the memory:
	s.Logger().WithField("memory-sandbox-size-mb", newMemoryMB).Debugf("Request to hypervisor to update memory")
	newMemory, updatedMemoryDevice, err := s.hypervisor.ResizeMemory(ctx, newMemoryMB, s.state.GuestMemoryBlockSizeMB, s.state.GuestMemoryHotplugProbe)
	if err != nil {
		if err == noGuestMemHotplugErr {
			s.Logger().Warnf("%s, memory specifications cannot be guaranteed", err)
		} else {
			return err
		}
	}
	s.Logger().Debugf("Sandbox memory size: %d MB", newMemory)
	if s.state.GuestMemoryHotplugProbe && updatedMemoryDevice.Addr != 0 {
		// notify the guest kernel about memory hot-add event, before onlining them
		s.Logger().Debugf("notify guest kernel memory hot-add event via probe interface, memory device located at 0x%x", updatedMemoryDevice.Addr)
		if err := s.agent.memHotplugByProbe(ctx, updatedMemoryDevice.Addr, uint32(updatedMemoryDevice.SizeMB), s.state.GuestMemoryBlockSizeMB); err != nil {
			return err
		}
	}
	if err := s.agent.onlineCPUMem(ctx, 0, false); err != nil {
		return err
	}
	return nil
}

func (s *Sandbox) calculateSandboxMemory() (uint64, bool, int64) {
	memorySandbox := uint64(0)
	needPodSwap := false
	swapSandbox := int64(0)
	for _, c := range s.config.Containers {
		// Do not hot add again non-running containers resources
		if cont, ok := s.containers[c.ID]; ok && cont.state.State == types.StateStopped {
			s.Logger().WithField("container", c.ID).Debug("Do not taking into account memory resources of not running containers")
			continue
		}

		if m := c.Resources.Memory; m != nil {
			currentLimit := int64(0)
			if m.Limit != nil && *m.Limit > 0 {
				currentLimit = *m.Limit
				memorySandbox += uint64(currentLimit)
				s.Logger().WithField("memory limit", memorySandbox).Info("Memory Sandbox + Memory Limit ")
			}

			// Add hugepages memory
			// HugepageLimit is uint64 - https://github.com/opencontainers/runtime-spec/blob/master/specs-go/config.go#L242
			for _, l := range c.Resources.HugepageLimits {
				memorySandbox += l.Limit
			}

			// Add swap
			if s.config.HypervisorConfig.GuestSwap && m.Swappiness != nil && *m.Swappiness > 0 {
				currentSwap := int64(0)
				if m.Swap != nil {
					currentSwap = *m.Swap
				}
				if currentSwap == 0 {
					if currentLimit == 0 {
						needPodSwap = true
					} else {
						swapSandbox += currentLimit
					}
				} else if currentSwap > currentLimit {
					swapSandbox = currentSwap - currentLimit
				}
			}
		}
	}

	return memorySandbox, needPodSwap, swapSandbox
}

func (s *Sandbox) calculateSandboxCPUs() (float32, error) {
	floatCPU := float32(0)
	cpusetCount := int(0)

	for _, c := range s.config.Containers {
		// Do not hot add again non-running containers resources
		if cont, ok := s.containers[c.ID]; ok && cont.state.State == types.StateStopped {
			s.Logger().WithField("container", c.ID).Debug("Do not taking into account CPU resources of not running containers")
			continue
		}

		if cpu := c.Resources.CPU; cpu != nil {
			if cpu.Period != nil && cpu.Quota != nil {
				floatCPU += utils.CalculateCPUsF(*cpu.Quota, *cpu.Period)
			}

			set, err := cpuset.Parse(cpu.Cpus)
			if err != nil {
				return 0, nil
			}
			cpusetCount += set.Size()
		}
	}

	// If we aren't being constrained, then we could have two scenarios:
	//  1. BestEffort QoS: no proper support today in Kata.
	//  2. We could be constrained only by CPUSets. Check for this:
	if floatCPU == 0 && cpusetCount > 0 {
		return float32(cpusetCount), nil
	}

	return floatCPU, nil
}

// GetHypervisorType is used for getting Hypervisor name currently used.
// Sandbox implement DeviceReceiver interface from device/api/interface.go
func (s *Sandbox) GetHypervisorType() string {
	return string(s.config.HypervisorType)
}

// MigrateOut delegates to the underlying hypervisor. See
// docs/design/live-migration.md for semantics.
func (s *Sandbox) MigrateOut(ctx context.Context, uri string, opts MigrateOptions) error {
	return s.hypervisor.MigrateOut(ctx, uri, opts)
}

// MigrateIncoming delegates to the underlying hypervisor.
func (s *Sandbox) MigrateIncoming(ctx context.Context, uri string, opts MigrateOptions) error {
	return s.hypervisor.MigrateIncoming(ctx, uri, opts)
}

// PauseVM delegates to the underlying hypervisor (QMP stop for QEMU).
// The snapshot-save path freezes the guest before streaming state to a
// sink: a paused guest dirties no pages, so the save is one clean pass
// instead of an iterative pre-copy. The matching ResumeVM (shared with
// the migration destination's post-handoff resume) lives further down.
func (s *Sandbox) PauseVM(ctx context.Context) error {
	return s.hypervisor.PauseVM(ctx)
}

// HypervisorUUID returns the underlying hypervisor's process UUID
// (QEMU's `-uuid` for the QEMU hypervisor). Exposed for the shim's
// /migration/status to propagate the source UUID to the destination
// — required for multifd's source/dest UUID equality check.
func (s *Sandbox) HypervisorUUID() string {
	return s.hypervisor.HypervisorUUID()
}

// GetMigrationStatus delegates to the underlying hypervisor.
func (s *Sandbox) GetMigrationStatus(ctx context.Context) (MigrationStatus, error) {
	return s.hypervisor.GetMigrationStatus(ctx)
}

// GetVMRunState delegates to the underlying hypervisor.
func (s *Sandbox) GetVMRunState(ctx context.Context) (string, error) {
	return s.hypervisor.GetVMRunState(ctx)
}

// CancelMigration delegates to the underlying hypervisor.
func (s *Sandbox) CancelMigration(ctx context.Context) error {
	return s.hypervisor.CancelMigration(ctx)
}

// MigrationContinue delegates to the underlying hypervisor — resumes
// a migration parked at `state` (typically "pre-switchover").
func (s *Sandbox) MigrationContinue(ctx context.Context, state string) error {
	return s.hypervisor.MigrationContinue(ctx, state)
}

// GetHotpluggedMemoryDevices delegates to the underlying
// hypervisor. Used by the source shim during a migration handoff
// to enumerate the devices the destination must pre-create.
func (s *Sandbox) GetHotpluggedMemoryDevices(ctx context.Context) ([]MemoryDevice, error) {
	return s.hypervisor.GetHotpluggedMemoryDevices(ctx)
}

// GetHotpluggedVCPUCount delegates to the underlying hypervisor.
// Source shim ships this count to the destination so the dest can
// pre-create matching APIC slots before the migration stream
// arrives.
func (s *Sandbox) GetHotpluggedVCPUCount(ctx context.Context) (uint32, error) {
	return s.hypervisor.GetHotpluggedVCPUCount(ctx)
}

// HotplugVCPUs adds `count` vCPUs to the running VM using the
// hypervisor's existing CPU hot-plug path. Destination shim calls
// this during a migration handoff so its APIC layout matches the
// source. Source's slot picking is driven by QEMU's
// query-hotpluggable-cpus enumeration order, which is identical on
// any QEMU instance launched with the same -smp config, so
// reproducing the count is sufficient — no per-slot replay needed.
func (s *Sandbox) HotplugVCPUs(ctx context.Context, count uint32) error {
	if count == 0 {
		return nil
	}
	_, err := s.hypervisor.HotplugAddDevice(ctx, count, CpuDev)
	return err
}

// HotplugMemoryDevices delegates to the underlying hypervisor.
// Used by the destination shim before a migration stream arrives,
// to replay the source's runtime memory topology onto the dest VM.
func (s *Sandbox) HotplugMemoryDevices(ctx context.Context, devices []MemoryDevice) error {
	return s.hypervisor.HotplugMemoryDevices(ctx, devices)
}

// ResumeVM delegates to the underlying hypervisor's ResumeVM.
// Used by the destination shim after a successful CompleteHandoff
// to take the migrated guest out of its paused state.
func (s *Sandbox) ResumeVM(ctx context.Context) error {
	return s.hypervisor.ResumeVM(ctx)
}

// CheckAgent delegates to the kata-agent's gRPC Check RPC.
// Returns nil when the agent server inside the guest is reachable.
func (s *Sandbox) CheckAgent(ctx context.Context) error {
	if k, ok := s.agent.(*kataAgent); ok {
		return k.check(ctx)
	}
	// Non-kata agent types (rare in our deployment); treat as
	// trivially reachable.
	return nil
}

// PairAgentAfterMigration finalises the destination sandbox after a
// successful live-migration handoff:
//
//  1. Populates the kata-agent's connection URL from the destination
//     hypervisor's freshly-allocated vmSocket so the next sendReq
//     dials the right vsock CID. Without this the agent client's
//     gRPC dial fails immediately with "Invalid scheme:".
//
//  2. Renumbers the guest's network interfaces to match the
//     destination pod's CNI assignment. The migrated guest's eth0
//     still carries the SOURCE pod's IP because that's what was
//     captured in the migration stream. The destination pod was
//     assigned a NEW IP by the host CNI, configured on the pod
//     netns's eth0 (and pushed via TC-redirect to tap0_kata). Until
//     the in-guest agent reconfigures eth0 to the new IP, the guest
//     drops ARP requests for the destination IP and the host kernel
//     never populates a neighbor entry — every external dial to the
//     migrated pod returns "no route to host". configureGuestNetwork
//     pushes interface + route state from sandbox.network.Endpoints()
//     (which has the destination CNI's assignment) to the in-guest
//     agent over the freshly-paired vsock.
//
//  3. Flips the sandbox's state machine to Running. Normal bringup
//     does this in Sandbox.Start() but that path is skipped for
//     incoming-migration sandboxes (sandbox.go:1676-1678) — without
//     this, checkSandboxRunning() (container.go:1462) sees state =
//     Ready and refuses exec/enter with "Sandbox not running,
//     impossible to ... the container".
//
//  4. Flips each container's state to Running. The enter() path also
//     checks container state. Containers existed only as bookkeeping
//     stubs on the incoming side; their actual processes live inside
//     the migrated guest, so flipping the state field is enough.
//
// Step 1 is fatal — without an agent URL nothing else can talk to
// the guest. Step 2 is best-effort logged-and-continued — its
// failure means the data plane stays broken until manual repair,
// but the sandbox is otherwise usable for CRI ops. Steps 3 and 4
// are local bookkeeping. Returns nil and does nothing for non-kata
// agents.
func (s *Sandbox) PairAgentAfterMigration(ctx context.Context) error {
	// Settle-measurement zero point (FR-062a): this runs immediately after
	// the resumed guest was verified running, so "time since here" ≈ "time
	// since resume" for the settle instrumentation.
	s.agentSettleStart = time.Now()

	// Step 1: agent URL.
	if k, ok := s.agent.(*kataAgent); ok {
		// Drop any stale client state from the source sandbox that
		// might have been carried in via Restore(). Next sendReq
		// dials fresh against the new URL.
		if k.client != nil {
			_ = k.disconnect(ctx)
		}
		if err := k.setAgentURL(); err != nil {
			return fmt.Errorf("set agent URL after migration: %w", err)
		}
	}

	// Step 2: schedule the guest network renumber asynchronously. We
	// must NOT block here. configureGuestNetwork calls updateInterface
	// on the kata-agent inside the guest over vsock, and observed
	// behavior post-migration is that the in-guest agent does not
	// respond to UpdateInterface for the first ~10s after resume
	// (each attempt hits the gRPC default deadline, and
	// updateInterface's internal retry.Do only re-attempts on
	// "Link not found" — every other error is wrapped in
	// retry.Unrecoverable and the loop exits after one shot).
	//
	// Critical: we run inside the dest's CompleteHandoff gRPC handler.
	// Source side is blocked on the response. If we wait synchronously
	// for the agent to settle (~10-30s), the source's sandbox monitor
	// — which pings the agent every 30s and finds it unresponsive
	// because source QEMU is paused post-migration — declares the
	// source dead and tears it down before CompleteHandoff returns.
	// The whole migration is reported failed even though both sides
	// completed QEMU transfer cleanly.
	//
	// Solution: fire-and-forget goroutine that retries with backoff
	// for up to renumberMaxWindow. CompleteHandoff returns promptly
	// (sub-second). When the in-guest agent finally answers, the
	// renumber lands and traffic starts flowing. If the agent never
	// answers within the budget, we log loudly and the pod stays
	// reachable for CRI ops but not for traffic — fixable by manual
	// repair without forcing a full migration retry.
	//
	// We snapshot s.Logger() and detach from ctx (it'll be cancelled
	// when CompleteHandoff returns); the goroutine uses its own bounded
	// context so it can run after the handler exits.
	go s.renumberGuestNetworkAsync()

	// Step 3: sandbox state. Validate the transition before flipping
	// so we don't bypass the state machine — if the sandbox is
	// already Running (somehow) this is a no-op; if it's in a state
	// from which Running isn't reachable, the error surfaces here.
	if s.state.State != types.StateRunning {
		if err := s.state.ValidTransition(s.state.State, types.StateRunning); err != nil {
			return fmt.Errorf("validate sandbox transition to Running after migration: %w", err)
		}
		if err := s.setSandboxState(types.StateRunning); err != nil {
			return fmt.Errorf("set sandbox state to Running after migration: %w", err)
		}
	}

	// Step 4: container states. For incoming-migration sandboxes
	// CreateContainer skipped c.create(), so c.state.State is the
	// zero value (empty StateString). The normal state machine has
	// no "" → Running transition (only Ready, Paused, Stopped can
	// move to Running per types/sandbox.go::validTransition), so
	// asking it to validate the transition errors out with
	// "Can not move from <ptr> to running".
	//
	// We bypass the guard for uninitialized containers — the
	// container's processes already exist (inside the migrated
	// guest) and we're restoring the shim's bookkeeping, not
	// transitioning through a normal lifecycle. For any container
	// that DID go through some lifecycle (e.g., test fixtures with
	// pre-set state), still use ValidTransition to keep the
	// invariants intact.
	for cid, c := range s.containers {
		if c.state.State == types.StateRunning {
			continue
		}
		if c.state.State == "" {
			// Uninitialized — direct restore, no transition guard.
			c.state.State = types.StateRunning
			continue
		}
		if err := c.state.ValidTransition(c.state.State, types.StateRunning); err != nil {
			s.Logger().WithError(err).WithField("container", cid).
				WithField("currentState", c.state.State).
				Warn("PairAgentAfterMigration: container state-machine refused Running; skipping (exec to this container will fail)")
			continue
		}
		c.state.State = types.StateRunning
	}

	if err := s.storeSandbox(ctx); err != nil {
		return fmt.Errorf("persist sandbox state after migration: %w", err)
	}
	return nil
}

// renumberGuestNetworkAsync pushes the destination's CNI-assigned IP
// onto the migrated guest's eth0 over vsock. Runs in a fire-and-forget
// goroutine so the CompleteHandoff gRPC response is not blocked on
// the in-guest agent's post-resume readiness.
//
// We build a *stripped-down* Interface proto rather than reusing
// generateVCNetworkStructures, for two reasons rooted in agent
// behavior we discovered the hard way:
//
//  1. devicePath: the agent (src/agent/src/rpc.rs::update_interface)
//     calls wait_for_pci_net_interface() when devicePath is non-empty.
//     That function does check_existing() against sysfs, and if it
//     can't match the host-supplied PCI path against what the guest
//     sees in sysfs (likely post-migration because enumeration may
//     differ), falls through to wait_for_uevent() — which blocks
//     forever waiting for a "net" add uevent that will never fire
//     because the virtio-net device was added at QEMU startup, long
//     before migration. The RPC then hangs until gRPC's deadline.
//     Clearing devicePath makes the agent skip wait_for_pci_net_interface
//     entirely and go straight to the netlink update.
//
//  2. hwAddr: the host's new pod-netns has a fresh veth+tap with a
//     new MAC. Sending that MAC in the request would ask the agent
//     to flip the guest's eth0 MAC (ip link set down + set address +
//     up). Even if that works, it's unnecessary — in TC-redirect
//     mode the host doesn't care what MAC the guest uses internally;
//     the host kernel learns whatever MAC the guest answers ARP with.
//     Clearing hwAddr makes the netlink update apply only to IP
//     addresses, sidestepping any MAC-change netlink contention.
func (s *Sandbox) renumberGuestNetworkAsync() {
	const (
		renumberMaxWindow      = 2 * time.Minute
		renumberPerAttempt     = 30 * time.Second
		renumberInitialBackoff = 2 * time.Second
		renumberMaxBackoff     = 15 * time.Second
	)
	overallCtx, overallCancel := context.WithTimeout(context.Background(), renumberMaxWindow)
	defer overallCancel()

	start := time.Now()
	backoff := renumberInitialBackoff
	attempt := 0

	for {
		attempt++

		// Settle instrumentation (spec 022 FR-062a, marker
		// kata-agent-settle-instr-v1): a short bounded agent Check before
		// the real work, logged with latency and error shape. Across
		// attempts this yields the settle curve the root-cause needs —
		// probe latency ≈ full 3s bound means the guest vsock listener
		// isn't accepting yet (dial-side); a fast error means it accepts
		// but the agent can't answer (agent-side); a fast success bounds
		// the settle at this attempt. The dial itself honors this
		// deadline (client.go caps dial by ctx), and a bounded dial
		// failure never marks the agent dead.
		probeStart := time.Now()
		probeCtx, probeCancel := context.WithTimeout(overallCtx, 3*time.Second)
		probeErr := s.agent.check(probeCtx)
		probeCancel()
		probeFields := logrus.Fields{
			"marker":         "kata-agent-settle-instr-v1",
			"attempt":        attempt,
			"probeLatencyMs": time.Since(probeStart).Milliseconds(),
			"probeOk":        probeErr == nil,
		}
		if !s.agentSettleStart.IsZero() {
			probeFields["sinceResumeMs"] = time.Since(s.agentSettleStart).Milliseconds()
		}
		if probeErr != nil {
			probeFields["probeErrType"] = fmt.Sprintf("%T", probeErr)
			probeFields["probeErr"] = probeErr.Error()
		}
		s.Logger().WithFields(probeFields).Warn("INSTR: post-resume agent settle probe")

		attemptCtx, attemptCancel := context.WithTimeout(overallCtx, renumberPerAttempt)
		err := s.pushDestIPsToGuestAgent(attemptCtx)
		attemptCancel()
		if err == nil {
			doneFields := logrus.Fields{
				"attempt": attempt,
				"elapsed": time.Since(start).String(),
			}
			if !s.agentSettleStart.IsZero() {
				// The definitive settle datum: how long after resume the
				// renumber actually landed in the guest.
				doneFields["settleMs"] = time.Since(s.agentSettleStart).Milliseconds()
			}
			s.Logger().WithFields(doneFields).
				Warn("renumberGuestNetworkAsync: guest network renumbered to destination CNI assignment")
			return
		}
		s.Logger().WithError(err).WithField("attempt", attempt).
			WithField("elapsed", time.Since(start).String()).
			Warn("renumberGuestNetworkAsync: attempt failed; will retry")

		// Stop if we're out of overall budget.
		if overallCtx.Err() != nil {
			s.Logger().WithError(err).WithField("attempts", attempt).
				WithField("elapsed", time.Since(start).String()).
				Warn("renumberGuestNetworkAsync: giving up — guest network was not renumbered within the budget; pod will be unreachable on its destination IP until repaired")
			return
		}

		select {
		case <-time.After(backoff):
		case <-overallCtx.Done():
			s.Logger().WithError(err).WithField("attempts", attempt).
				WithField("elapsed", time.Since(start).String()).
				Warn("renumberGuestNetworkAsync: budget expired during backoff; giving up")
			return
		}
		// Exponential-ish backoff capped at renumberMaxBackoff.
		backoff = backoff * 2
		if backoff > renumberMaxBackoff {
			backoff = renumberMaxBackoff
		}
	}
}

// PushDestIPsToGuestAgent is the exported wrapper around the renumber
// logic so the shim's HTTP handler (handleMigrationRenumberGuest in
// migration_admin.go) can force a renumber without going through
// onMigrationComplete. Same body, just an exported name.
func (s *Sandbox) PushDestIPsToGuestAgent(ctx context.Context) error {
	return s.pushDestIPsToGuestAgent(ctx)
}

// pushDestIPsToGuestAgent asks the in-guest agent to swap its eth0 IP
// to the destination pod's CNI-assigned IP. The hard parts are
// agent-side quirks the API doesn't make obvious; see comments below.
//
// Why this can't reuse generateVCNetworkStructures + updateInterface
// directly:
//
//  1. devicePath: when populated, the agent's update_interface handler
//     (src/agent/src/rpc.rs) calls wait_for_pci_net_interface — which
//     hangs forever waiting for a "net add" uevent that already fired
//     long ago (the virtio-net device was added at QEMU startup). We
//     MUST clear devicePath.
//
//  2. The agent looks up the target link by MAC, not name
//     (src/agent/src/netlink.rs::update_interface, line 113:
//     find_link(LinkFilter::Address(&iface.hwAddr))). The migrated
//     guest's eth0 still carries the SOURCE pod's MAC (virtio-net
//     state was preserved across migration). The destination's
//     CNI-assigned veth has a NEW MAC. If we send the new MAC, the
//     agent can't find any link with it inside the guest. If we send
//     an empty MAC, the agent's MAC parser barfs with
//     "cannot parse integer from empty string". So we must send a
//     MAC that EXISTS inside the guest.
//
//     We discover the in-guest MAC by calling ListInterfaces first
//     and matching by name (eth0). Then we issue UpdateInterface
//     with the existing MAC and the destination IPAddresses.
func (s *Sandbox) pushDestIPsToGuestAgent(ctx context.Context) error {
	endpoints := s.network.Endpoints()
	s.Logger().WithField("endpointCount", len(endpoints)).
		Warn("pushDestIPsToGuestAgent: ENTRY")
	if len(endpoints) == 0 {
		// Network endpoints weren't populated. Try a late rescan;
		// RescanNetwork polls the netns and re-runs AddEndpoints.
		s.Logger().Warn("pushDestIPsToGuestAgent: endpoints empty; attempting RescanNetwork")
		if err := s.RescanNetwork(ctx); err != nil {
			s.Logger().WithError(err).Warn("pushDestIPsToGuestAgent: RescanNetwork failed")
		}
		endpoints = s.network.Endpoints()
		s.Logger().WithField("endpointCountAfterRescan", len(endpoints)).
			Warn("pushDestIPsToGuestAgent: post-rescan")
		if len(endpoints) == 0 {
			return fmt.Errorf("no network endpoints on sandbox (post-rescan); nothing to renumber")
		}
	}

	// Log each endpoint's view from the kata-shim side so we can match
	// it up against what the guest actually has. Name/HwAddr/IPs are
	// the load-bearing fields; PciPath is here to confirm we're not
	// inadvertently including a non-network endpoint (e.g. a VFIO
	// device showing up via the same Endpoints() call).
	for i, ep := range endpoints {
		addrs := ep.Properties().Addrs
		ips := make([]string, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IPNet.String())
		}
		s.Logger().WithFields(logrus.Fields{
			"idx":     i,
			"name":    ep.Name(),
			"type":    string(ep.Type()),
			"hwAddr":  ep.HardwareAddr(),
			"pciPath": ep.PciPath().String(),
			"ips":     ips,
		}).Warn("pushDestIPsToGuestAgent: host-side endpoint")
	}

	srcInterfaces, _, _, err := generateVCNetworkStructures(ctx, endpoints)
	if err != nil {
		return fmt.Errorf("generating network structures: %w", err)
	}
	k, ok := s.agent.(*kataAgent)
	if !ok {
		return fmt.Errorf("renumber requires a kata-agent (got %T)", s.agent)
	}

	// Discover what the guest currently sees so we can address the
	// link by its real (migrated) MAC.
	listStart := time.Now()
	guestInterfaces, err := k.listInterfaces(ctx)
	if err != nil {
		s.Logger().WithError(err).WithField("elapsed", time.Since(listStart).String()).
			Warn("pushDestIPsToGuestAgent: listInterfaces failed")
		return fmt.Errorf("listing in-guest interfaces: %w", err)
	}
	s.Logger().WithFields(logrus.Fields{
		"count":   len(guestInterfaces),
		"elapsed": time.Since(listStart).String(),
	}).Warn("pushDestIPsToGuestAgent: listInterfaces returned")
	for i, gi := range guestInterfaces {
		ips := make([]string, 0, len(gi.IPAddresses))
		for _, addr := range gi.IPAddresses {
			ips = append(ips, fmt.Sprintf("%s/%s", addr.Address, addr.Mask))
		}
		s.Logger().WithFields(logrus.Fields{
			"idx":    i,
			"name":   gi.Name,
			"hwAddr": gi.HwAddr,
			"mtu":    gi.Mtu,
			"ips":    ips,
		}).Warn("pushDestIPsToGuestAgent: guest-side interface")
	}

	guestByName := make(map[string]*pbTypes.Interface, len(guestInterfaces))
	for _, gi := range guestInterfaces {
		guestByName[gi.Name] = gi
	}

	for _, src := range srcInterfaces {
		gi, found := guestByName[src.Name]
		if !found {
			// Build a comma-list of guest interface names so the operator
			// can see at a glance what the agent reported.
			names := make([]string, 0, len(guestInterfaces))
			for _, gi := range guestInterfaces {
				names = append(names, gi.Name)
			}
			s.Logger().WithFields(logrus.Fields{
				"wantName":   src.Name,
				"guestNames": names,
			}).Warn("pushDestIPsToGuestAgent: source-side interface name not in guest list")
			return fmt.Errorf("in-guest interface %q not found (guest has %d ifaces: %v)",
				src.Name, len(guestInterfaces), names)
		}
		if gi.HwAddr == "" {
			return fmt.Errorf("in-guest interface %q reports empty hwAddr (cannot address link)",
				src.Name)
		}

		// Send guest's EXISTING MAC (skip MAC change — the netlink
		// MAC-set call against virtio-net hangs the agent for 41s).
		// Strip IPv6 link-local from the IP list: the host-side
		// endpoint's LL is derived from the dest veth's MAC, NOT the
		// guest's MAC. Pushing it would either trigger a kernel
		// rejection (link-local MAC mismatch) or DAD that marks the
		// interface tentative briefly. We only need IPv4 reachability;
		// strip the v6 LL.
		ifc := *src
		ifc.DevicePath = ""
		ifc.HwAddr = gi.HwAddr
		// Filter IPAddresses to IPv4 only.
		ipv4Only := make([]*pbTypes.IPAddress, 0, len(ifc.IPAddresses))
		for _, addr := range ifc.IPAddresses {
			if addr.Family == pbTypes.IPFamily_v4 {
				ipv4Only = append(ipv4Only, addr)
			}
		}
		ifc.IPAddresses = ipv4Only
		s.Logger().WithField("ipv4Count", len(ipv4Only)).
			Warn("pushDestIPsToGuestAgent: stripped IPv6, sending IPv4-only")

		// Log exactly what we send so post-hoc analysis can compare
		// against what the agent applied. Keep this terse — full
		// proto dump if we ever need more detail.
		srcIPs := make([]string, 0, len(ifc.IPAddresses))
		for _, addr := range ifc.IPAddresses {
			srcIPs = append(srcIPs, fmt.Sprintf("%s/%s", addr.Address, addr.Mask))
		}
		s.Logger().WithFields(logrus.Fields{
			"name":   ifc.Name,
			"hwAddr": ifc.HwAddr,
			"mtu":    ifc.Mtu,
			"ips":    srcIPs,
		}).Warn("pushDestIPsToGuestAgent: sending UpdateInterface")

		updStart := time.Now()
		ret, err := s.agent.updateInterface(ctx, &ifc)
		if err != nil {
			s.Logger().WithError(err).WithField("elapsed", time.Since(updStart).String()).
				Warn("pushDestIPsToGuestAgent: updateInterface FAILED")
			return fmt.Errorf("updating interface %s in guest: %w", ifc.Name, err)
		}
		retIPs := []string{}
		retHwAddr := ""
		retName := ""
		if ret != nil {
			retName = ret.Name
			retHwAddr = ret.HwAddr
			for _, addr := range ret.IPAddresses {
				retIPs = append(retIPs, fmt.Sprintf("%s/%s", addr.Address, addr.Mask))
			}
		}
		s.Logger().WithFields(logrus.Fields{
			"elapsed":   time.Since(updStart).String(),
			"retName":   retName,
			"retHwAddr": retHwAddr,
			"retIPs":    retIPs,
			"retIsNil":  ret == nil,
		}).Warn("pushDestIPsToGuestAgent: updateInterface returned")
	}

	// Push routes too. Without this, the guest's routing table still
	// reflects the SOURCE pod's gateway (carried in QEMU's migrated
	// state). When the guest tries to reply to an inbound connection,
	// it consults its routing table and tries to route via the wrong
	// gateway — packet either fails ARP for an unreachable next-hop
	// or rp_filter drops it. Push the dest's routes (default GW =
	// dest pod-netns gateway) so the guest can actually reply.
	_, routes, _, err := generateVCNetworkStructures(ctx, endpoints)
	if err == nil && len(routes) > 0 {
		// Set Source on the default route to the dest's CNI-allocated
		// IPv4. After migration, the guest's eth0 ends up holding TWO
		// IPv4s: the SOURCE pod IP (preserved across QEMU memory
		// migration) AND the dest CNI IP (added by UpdateInterface
		// above). Without an explicit Source hint, Linux's source-
		// address-selection picks the first-added IP — which is the
		// source IP — for ALL new outbound connections. The downstream
		// CNI (e.g., Cilium) doesn't recognize that IP on the dest node
		// (Pod.status.podIPs only has the dest CNI IP, and the K8s API
		// forbids adding a second IPv4 to status.podIPs), so reply
		// traffic to the source IP gets dropped on the way back.
		//
		// Setting Source = dest CNI IP on the default route makes new
		// outbound connections use the CNI IP as source, which the CNI
		// recognizes natively. Existing TCP sockets keep using their
		// bound source IP via conntrack, so connection preservation is
		// unaffected.
		//
		// The dest CNI IP is the first IPv4 we just sent via
		// UpdateInterface — srcInterfaces[*].IPAddresses contains it.
		// pushDestIPsToGuestAgent runs from the shim's
		// onMigrationComplete callback, BEFORE the controller's IPMover
		// patches the source IP into the dest pod-netns, so the
		// host-side endpoints at this moment only contain the CNI IP.
		var destCNIPv4 string
		for _, si := range srcInterfaces {
			for _, addr := range si.IPAddresses {
				if addr.Family == pbTypes.IPFamily_v4 && addr.Address != "" {
					destCNIPv4 = addr.Address
					break
				}
			}
			if destCNIPv4 != "" {
				break
			}
		}
		if destCNIPv4 != "" {
			// Format as CIDR /32 — the agent's update_routes parses
			// route.source via Ipv4Network::from_str which requires
			// CIDR notation. A bare IP would fail the parse and the
			// whole route update would error out. Per-host source is
			// /32 by definition.
			destCNIPv4CIDR := destCNIPv4 + "/32"
			for _, r := range routes {
				if r.Family != pbTypes.IPFamily_v4 {
					continue
				}
				// Only stamp the default route (dest=0.0.0.0/0 or
				// empty) — leave connected and link-scope routes
				// alone, they don't pick a source IP anyway.
				if r.Dest == "" || r.Dest == "0.0.0.0/0" {
					r.Source = destCNIPv4CIDR
				}
			}
			s.Logger().WithField("destCNIPv4", destCNIPv4CIDR).
				Warn("pushDestIPsToGuestAgent: stamped default route Source for new-outbound source-IP selection")
		}

		s.Logger().WithField("routeCount", len(routes)).
			Warn("pushDestIPsToGuestAgent: pushing routes to guest")
		for i, r := range routes {
			s.Logger().WithFields(logrus.Fields{
				"idx":     i,
				"dest":    r.Dest,
				"gateway": r.Gateway,
				"device":  r.Device,
				"family":  r.Family.String(),
				"source":  r.Source,
			}).Warn("pushDestIPsToGuestAgent: route entry")
		}
		routesStart := time.Now()
		if _, err := s.agent.updateRoutes(ctx, routes); err != nil {
			s.Logger().WithError(err).WithField("elapsed", time.Since(routesStart).String()).
				Warn("pushDestIPsToGuestAgent: updateRoutes failed (best-effort, continuing)")
		} else {
			s.Logger().WithField("elapsed", time.Since(routesStart).String()).
				Warn("pushDestIPsToGuestAgent: updateRoutes succeeded")
		}
	}

	// Re-poll the guest to confirm the update actually landed. If the
	// agent's update_interface ADDS addresses (vs REPLACES), the IP
	// might be applied but coexisting with the source IP — both show
	// up here. If the IP isn't on the interface at all, we know the
	// netlink call silently no-op'd.
	verifyStart := time.Now()
	postUpdate, err := k.listInterfaces(ctx)
	if err != nil {
		s.Logger().WithError(err).Warn("pushDestIPsToGuestAgent: post-update listInterfaces failed; cannot verify")
		return nil
	}
	for i, gi := range postUpdate {
		ips := make([]string, 0, len(gi.IPAddresses))
		for _, addr := range gi.IPAddresses {
			ips = append(ips, fmt.Sprintf("%s/%s", addr.Address, addr.Mask))
		}
		s.Logger().WithFields(logrus.Fields{
			"idx":    i,
			"name":   gi.Name,
			"hwAddr": gi.HwAddr,
			"ips":    ips,
			"phase":  "post-update",
		}).Warn("pushDestIPsToGuestAgent: post-update guest interface")
	}
	s.Logger().WithField("elapsed", time.Since(verifyStart).String()).
		Warn("pushDestIPsToGuestAgent: verify complete")

	// Install permanent static ARP entries on the host root netns for
	// each (destPodIP → guestMAC) mapping. Without this, the host
	// kernel's normal ARP exchange fails because Cilium's BPF program
	// on the lxc veth drops ARP packets whose source MAC doesn't
	// match the endpoint MAC that was registered when CNI created
	// the dest pod's veth (and the guest's MAC is the SOURCE pod's
	// MAC, carried across in QEMU virtio-net migration state).
	//
	// Empirically: TCP packets (which carry source IP, matching the
	// dest endpoint's registered IP after our renumber) pass through
	// Cilium fine. Only ARP exchange is the holdout. A static
	// neighbor entry sidesteps the need for ARP entirely — host's
	// route+neigh lookup yields the guest MAC directly, packets go
	// out with the correct dst MAC, traffic flows.
	//
	// Best-effort: if this fails the renumber as a whole is still
	// useful for in-cluster callers that share Cilium identity-based
	// routing (which doesn't go through ARP).
	if err := s.installStaticARPForGuest(postUpdate); err != nil {
		s.Logger().WithError(err).
			Warn("pushDestIPsToGuestAgent: static ARP install failed (best-effort, continuing)")
	}
	return nil
}

// installStaticARPForGuest writes a permanent neighbor entry on the
// host root netns for each (destPodIP, guestMAC) pair. See the call
// site comment for why this is needed (Cilium drops ARP for the
// post-migration MAC mismatch). Idempotent — uses NeighSet which
// replaces existing entries.
func (s *Sandbox) installStaticARPForGuest(guestInterfaces []*pbTypes.Interface) error {
	// Find the guest's eth0 to harvest its MAC.
	var guestMAC string
	for _, gi := range guestInterfaces {
		if gi.Name == "eth0" {
			guestMAC = gi.HwAddr
			break
		}
	}
	if guestMAC == "" {
		return fmt.Errorf("guest eth0 not found in post-update interfaces; cannot install ARP")
	}
	mac, err := net.ParseMAC(guestMAC)
	if err != nil {
		return fmt.Errorf("parse guest MAC %q: %w", guestMAC, err)
	}

	// Each pod-side endpoint has an IP that the host kernel routes via
	// a corresponding lxc veth in the host root netns. For each IPv4
	// pod IP on the guest's eth0, look up the host-side route and
	// install the neighbor entry.
	var installed int
	var lastErr error
	for _, gi := range guestInterfaces {
		if gi.Name != "eth0" {
			continue
		}
		for _, addr := range gi.IPAddresses {
			// Don't trust addr.Family — the kata-agent's
			// list_interfaces doesn't always populate it, and the
			// zero value of the proto enum is IPFamily_v4. Parse the
			// IP string and check whether it's actually IPv4 (To4
			// returns nil for pure IPv6). Skips link-local, loopback,
			// and any malformed entries.
			ip := net.ParseIP(addr.Address)
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			// Look up which host link routes to this pod IP. On a
			// Cilium-managed EKS node this is the per-pod `lxc<...>`
			// veth created by CNI.
			routes, rerr := netlink.RouteGet(ip)
			if rerr != nil || len(routes) == 0 {
				s.Logger().WithError(rerr).WithField("ip", addr.Address).
					Warn("installStaticARPForGuest: RouteGet found no route; skipping IP")
				continue
			}
			linkIdx := routes[0].LinkIndex
			linkName := ""
			if l, lerr := netlink.LinkByIndex(linkIdx); lerr == nil && l != nil {
				linkName = l.Attrs().Name
			}
			// Leave Family unset — vishvananda/netlink infers it from
			// the IP's address family. Setting it to a literal int
			// (we previously had 4, which is *not* AF_INET = 2) makes
			// the netlink syscall fail with EINVAL.
			neigh := &netlink.Neigh{
				LinkIndex:    linkIdx,
				IP:           ip,
				HardwareAddr: mac,
				State:        netlink.NUD_PERMANENT,
			}
			if err := netlink.NeighSet(neigh); err != nil {
				lastErr = fmt.Errorf("NeighSet %s on link %d (%s): %w",
					addr.Address, linkIdx, linkName, err)
				s.Logger().WithError(err).WithFields(logrus.Fields{
					"ip":   addr.Address,
					"mac":  guestMAC,
					"link": linkName,
				}).Warn("installStaticARPForGuest: NeighSet failed for IP")
				continue
			}
			s.Logger().WithFields(logrus.Fields{
				"ip":   addr.Address,
				"mac":  guestMAC,
				"link": linkName,
			}).Warn("installStaticARPForGuest: installed static ARP entry")
			installed++
		}
	}
	if installed == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

// DumpState returns the sandbox's current state in the same shape
// Save writes to disk, but in memory only — no filesystem I/O. The
// dump* helpers are shared with Save; keeping the assembly here
// (rather than refactoring Save to use this) means Save's failure
// modes don't change and crash-recovery code paths stay byte-identical.
func (s *Sandbox) DumpState() (persistapi.SandboxState, error) {
	var (
		ss = persistapi.SandboxState{}
		cs = make(map[string]persistapi.ContainerState)
	)
	s.dumpVersion(&ss)
	s.dumpState(&ss, cs)
	s.dumpHypervisor(&ss)
	s.dumpDevices(&ss, cs)
	s.dumpProcess(cs)
	s.dumpMounts(cs)
	s.dumpAgent(&ss)
	s.dumpNetwork(&ss)
	s.dumpConfig(&ss)
	return ss, nil
}

// resourceControllerUpdate updates the sandbox cpuset resource controller
// (Linux cgroup) subsystem.
// Also, if the sandbox has an overhead controller, it updates the hypervisor
// constraints by moving the potentially new vCPU threads back to the sandbox
// controller.
func (s *Sandbox) resourceControllerUpdate(ctx context.Context) error {
	cpuset, memset, err := s.getSandboxCPUSet()
	if err != nil {
		return err
	}

	// We update the sandbox controller with potentially new virtual CPUs.
	if err := s.sandboxController.UpdateCpuSet(cpuset, memset); err != nil {
		return err
	}

	if s.overheadController != nil {
		// If we have an overhead controller, new vCPU threads would start there,
		// as being children of the VMM PID.
		// We need to constrain them by moving them into the sandbox controller.
		if err := s.constrainHypervisor(ctx); err != nil {
			return err
		}
	}

	return nil
}

// resourceControllerDelete will move the running processes in the sandbox resource
// cvontroller to the parent and then delete the sandbox controller.
func (s *Sandbox) resourceControllerDelete() error {
	s.Logger().Debugf("Deleting sandbox %s resource controler", s.sandboxController)
	if s.state.SandboxCgroupPath == "" {
		s.Logger().Warnf("sandbox %s resource controler path is empty", s.sandboxController)
		return nil
	}

	sandboxController, err := resCtrl.LoadResourceController(s.state.SandboxCgroupPath, s.config.SandboxCgroupOnly)
	if err != nil {
		return err
	}

	// When sandbox_cgroup_only is enabled, all Kata threads live in the
	// sandbox controller and systemd can move tasks as part of unit deletion.
	// In that mode, a systemd-formatted cgroup path is not a filesystem path,
	// so MoveTo would fail with "invalid group path".
	// Keep MoveTo for the case of using cgroupfs paths and for the
	// non-sandbox_cgroup_only mode. In that mode, Kata may use an overhead
	// cgroup in which case an explicit MoveTo is used to drain tasks.
	if !resCtrl.IsSystemdCgroup(s.state.SandboxCgroupPath) || !s.config.SandboxCgroupOnly {
		resCtrlParent := sandboxController.Parent()
		if err := sandboxController.MoveTo(resCtrlParent); err != nil {
			return err
		}
	}

	if err := sandboxController.Delete(); err != nil {
		return err
	}

	if s.state.OverheadCgroupPath != "" {
		overheadController, err := resCtrl.LoadResourceController(s.state.OverheadCgroupPath, s.config.SandboxCgroupOnly)
		if err != nil {
			return err
		}

		// See comment at above MoveTo: Avoid this action as systemd moves tasks on unit deletion.
		if !resCtrl.IsSystemdCgroup(s.state.OverheadCgroupPath) || !s.config.SandboxCgroupOnly {
			resCtrlParent := overheadController.Parent()
			if err := s.overheadController.MoveTo(resCtrlParent); err != nil {
				return err
			}
		}

		if err := overheadController.Delete(); err != nil {
			return err
		}
	}

	return nil
}

// constrainHypervisor will place the VMM and vCPU threads into resource controllers (cgroups on Linux).
func (s *Sandbox) constrainHypervisor(ctx context.Context) error {
	tids, err := s.hypervisor.GetThreadIDs(ctx)
	if err != nil {
		return fmt.Errorf("failed to get thread ids from hypervisor: %v", err)
	}

	// All vCPU threads move to the sandbox controller.
	for _, i := range tids.vcpus {
		if err := s.sandboxController.AddThread(i); err != nil {
			return err
		}
	}

	return nil
}

// setupResourceController adds the runtime process to either the sandbox resource controller or the
// overhead one, depending on the sandbox_cgroup_only configuration setting.
func (s *Sandbox) setupResourceController() error {
	vmmController := s.sandboxController
	if s.overheadController != nil {
		vmmController = s.overheadController
	}

	// By adding the runtime process to either the sandbox or overhead controller, we are making
	// sure that any child process of the runtime (i.e. *all* processes serving a Kata pod)
	// will initially live in this controller. Depending on the sandbox_cgroup settings, we will
	// then move the vCPU threads between resource controllers.
	runtimePid := os.Getpid()
	// Add the runtime to the VMM sandbox resource controller
	if err := vmmController.AddProcess(runtimePid); err != nil {
		return fmt.Errorf("Could not add runtime PID %d to the sandbox %s resource controller: %v", runtimePid, s.sandboxController, err)
	}

	return nil
}

// GetPatchedOCISpec returns sandbox's OCI specification
// This OCI specification was patched when the sandbox was created
// by containerCapabilities(), SetEphemeralStorageType() and others
// in order to support:
// * Capabilities
// * Ephemeral storage
// * k8s empty dir
// If you need the original (vanilla) OCI spec,
// use compatoci.GetContainerSpec() instead.
func (s *Sandbox) GetPatchedOCISpec() *specs.Spec {
	if s.config == nil {
		return nil
	}

	// Get the container associated with the PodSandbox annotation.
	// In Kubernetes, this represents the pause container.
	// In CRI-compliant runtimes like Containerd, this is the container.
	// On Linux, we derive the cgroup path from this container.
	for _, cConfig := range s.config.Containers {
		if ContainerType(cConfig.Annotations[annotations.ContainerTypeKey]).IsSandbox() {
			return cConfig.CustomSpec
		}
	}

	return nil
}

func (s *Sandbox) GetOOMEvent(ctx context.Context) (string, error) {
	return s.agent.getOOMEvent(ctx)
}

func (s *Sandbox) GetAgentURL() (string, error) {
	return s.agent.getAgentURL()
}

// GetIPTables will obtain the iptables from the guest
func (s *Sandbox) GetIPTables(ctx context.Context, isIPv6 bool) ([]byte, error) {
	return s.agent.getIPTables(ctx, isIPv6)
}

// SetIPTables will set the iptables in the guest
func (s *Sandbox) SetIPTables(ctx context.Context, isIPv6 bool, data []byte) error {
	return s.agent.setIPTables(ctx, isIPv6, data)
}

// SetPolicy will set the policy in the guest
func (s *Sandbox) SetPolicy(ctx context.Context, policy string) error {
	return s.agent.setPolicy(ctx, policy)
}

// GuestVolumeStats return the filesystem stat of a given volume in the guest.
func (s *Sandbox) GuestVolumeStats(ctx context.Context, volumePath string) ([]byte, error) {
	guestMountPath, err := s.guestMountPath(volumePath)
	if err != nil {
		return nil, err
	}
	return s.agent.getGuestVolumeStats(ctx, guestMountPath)
}

// ResizeGuestVolume resizes a volume in the guest.
func (s *Sandbox) ResizeGuestVolume(ctx context.Context, volumePath string, size uint64) error {
	// TODO: https://github.com/kata-containers/kata-containers/issues/3694.
	guestMountPath, err := s.guestMountPath(volumePath)
	if err != nil {
		return err
	}
	return s.agent.resizeGuestVolume(ctx, guestMountPath, size)
}

func (s *Sandbox) guestMountPath(volumePath string) (string, error) {
	// verify the device even exists
	if _, err := os.Stat(volumePath); err != nil {
		s.Logger().WithError(err).WithField("volume", volumePath).Error("Cannot get stats for volume that doesn't exist")
		return "", err
	}

	// verify that we have a mount in this sandbox who's source maps to this
	for _, c := range s.containers {
		for _, m := range c.mounts {
			if volumePath == m.Source {
				return m.GuestDeviceMount, nil
			}
		}
	}
	return "", fmt.Errorf("mount %s not found in sandbox", volumePath)
}

// getSandboxCPUSet returns the union of each of the sandbox's containers' CPU sets'
// cpus and mems as a string in canonical linux CPU/mems list format
func (s *Sandbox) getSandboxCPUSet() (string, string, error) {
	if s.config == nil {
		return "", "", nil
	}

	cpuResult := cpuset.NewCPUSet()
	memResult := cpuset.NewCPUSet()
	for _, ctr := range s.config.Containers {
		if ctr.Resources.CPU != nil {
			currCPUSet, err := cpuset.Parse(ctr.Resources.CPU.Cpus)
			if err != nil {
				return "", "", fmt.Errorf("unable to parse CPUset.cpus for container %s: %v", ctr.ID, err)
			}
			cpuResult = cpuResult.Union(currCPUSet)

			currMemSet, err := cpuset.Parse(ctr.Resources.CPU.Mems)
			if err != nil {
				return "", "", fmt.Errorf("unable to parse CPUset.mems for container %s: %v", ctr.ID, err)
			}
			memResult = memResult.Union(currMemSet)
		}
	}

	return cpuResult.String(), memResult.String(), nil
}

// fetchSandbox fetches a sandbox config from a sandbox ID and returns a sandbox.
func fetchSandbox(ctx context.Context, sandboxID string) (sandbox *Sandbox, err error) {
	virtLog.Info("fetch sandbox")
	if sandboxID == "" {
		return nil, types.ErrNeedSandboxID
	}

	var config SandboxConfig

	// Load sandbox config fromld store.
	c, err := loadSandboxConfig(sandboxID)
	if err != nil {
		virtLog.WithError(err).Warning("failed to get sandbox config from store")
		return nil, err
	}

	config = *c

	// fetchSandbox is not suppose to create new sandbox VM.
	sandbox, err = createSandbox(ctx, config, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox with config %+v: %v", config, err)
	}

	// This sandbox already exists, we don't need to recreate the containers in the guest.
	// We only need to fetch the containers from storage and create the container structs.
	if err := sandbox.fetchContainers(ctx); err != nil {
		return nil, err
	}

	return sandbox, nil
}

// fetchContainers creates new containers structure and
// adds them to the sandbox. It does not create the containers
// in the guest. This should only be used when fetching a
// sandbox that already exists.
func (s *Sandbox) fetchContainers(ctx context.Context) error {
	for i, contConfig := range s.config.Containers {
		// Add spec from bundle path
		spec, err := compatoci.GetContainerSpec(contConfig.Annotations)
		if err != nil {
			return err
		}
		contConfig.CustomSpec = &spec
		s.config.Containers[i] = contConfig

		c, err := newContainer(ctx, s, &s.config.Containers[i])
		if err != nil {
			return err
		}

		if err := s.addContainer(c); err != nil {
			return err
		}
	}

	return nil
}

// checkVCPUsPinning is used to support CPUSet mode of kata container.
// CPUSet mode is on when Sandbox.HypervisorConfig.EnableVCPUsPinning
// is set to true. Then it fetches sandbox's number of vCPU threads
// and number of CPUs in CPUSet. If the two are equal, each vCPU thread
// is then pinned to one fixed CPU in CPUSet.
func (s *Sandbox) checkVCPUsPinning(ctx context.Context) error {
	if s.config == nil {
		return fmt.Errorf("no sandbox config found")
	}
	if !s.config.EnableVCPUsPinning {
		return nil
	}

	// fetch vCPU thread ids and CPUSet
	vCPUThreadsMap, err := s.hypervisor.GetThreadIDs(ctx)
	if err != nil {
		return fmt.Errorf("failed to get vCPU thread ids from hypervisor: %v", err)
	}
	cpuSetStr, _, err := s.getSandboxCPUSet()
	if err != nil {
		return fmt.Errorf("failed to get CPUSet config: %v", err)
	}
	cpuSet, err := cpuset.Parse(cpuSetStr)
	if err != nil {
		return fmt.Errorf("failed to parse CPUSet string: %v", err)
	}
	cpuSetSlice := cpuSet.ToSlice()

	// check if vCPU thread numbers and CPU numbers are equal
	numVCPUs, numCPUs := len(vCPUThreadsMap.vcpus), len(cpuSetSlice)
	// if not equal, we should reset threads scheduling to random pattern
	if numVCPUs != numCPUs {
		if s.isVCPUsPinningOn {
			s.isVCPUsPinningOn = false
			return s.resetVCPUsPinning(ctx, vCPUThreadsMap, cpuSetSlice)
		}
		return nil
	}
	// if equal, we can use vCPU thread pinning
	for i, tid := range vCPUThreadsMap.vcpus {
		if err := resCtrl.SetThreadAffinity(tid, cpuSetSlice[i:i+1]); err != nil {
			if err := s.resetVCPUsPinning(ctx, vCPUThreadsMap, cpuSetSlice); err != nil {
				return err
			}
			return fmt.Errorf("failed to set vcpu thread %d affinity to cpu %d: %v", tid, cpuSetSlice[i], err)
		}
	}
	s.isVCPUsPinningOn = true
	return nil
}

// resetVCPUsPinning cancels current pinning and restores default random vCPU threads scheduling
func (s *Sandbox) resetVCPUsPinning(ctx context.Context, vCPUThreadsMap VcpuThreadIDs, cpuSetSlice []int) error {
	for _, tid := range vCPUThreadsMap.vcpus {
		if err := resCtrl.SetThreadAffinity(tid, cpuSetSlice); err != nil {
			return fmt.Errorf("failed to reset vcpu thread %d affinity: %v", tid, err)
		}
	}
	return nil
}
