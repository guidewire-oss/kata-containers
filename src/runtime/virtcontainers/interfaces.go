// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"io"
	"syscall"

	"github.com/kata-containers/kata-containers/src/runtime/pkg/device/api"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/device/config"
	persistapi "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/api"
	pbTypes "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

// VC is the Virtcontainers interface
type VC interface {
	SetLogger(ctx context.Context, logger *logrus.Entry)
	SetFactory(ctx context.Context, factory Factory)

	CreateSandbox(ctx context.Context, sandboxConfig SandboxConfig, hookFunc func(context.Context) error) (VCSandbox, error)
	CleanupContainer(ctx context.Context, sandboxID, containerID string, force bool) error
}

// VCSandbox is the Sandbox interface
// (required since virtcontainers.Sandbox only contains private fields)
type VCSandbox interface {
	Annotations(key string) (string, error)
	GetNetNs() string
	GetAllContainers() []VCContainer
	GetAnnotations() map[string]string
	GetContainer(containerID string) VCContainer
	ID() string
	SetAnnotations(annotations map[string]string) error

	Stats(ctx context.Context) (SandboxStats, error)

	Start(ctx context.Context) error
	Stop(ctx context.Context, force bool) error
	Release(ctx context.Context) error
	Monitor(ctx context.Context) (chan error, error)
	Delete(ctx context.Context) error
	Status() SandboxStatus
	CreateContainer(ctx context.Context, contConfig ContainerConfig) (VCContainer, error)
	DeleteContainer(ctx context.Context, containerID string) (VCContainer, error)
	StartContainer(ctx context.Context, containerID string) (VCContainer, error)
	StopContainer(ctx context.Context, containerID string, force bool) (VCContainer, error)
	KillContainer(ctx context.Context, containerID string, signal syscall.Signal, all bool) error
	StatusContainer(containerID string) (ContainerStatus, error)
	StatsContainer(ctx context.Context, containerID string) (ContainerStats, error)
	PauseContainer(ctx context.Context, containerID string) error
	ResumeContainer(ctx context.Context, containerID string) error
	EnterContainer(ctx context.Context, containerID string, cmd types.Cmd) (VCContainer, *Process, error)
	UpdateContainer(ctx context.Context, containerID string, resources specs.LinuxResources) error
	WaitProcess(ctx context.Context, containerID, processID string) (int32, error)
	SignalProcess(ctx context.Context, containerID, processID string, signal syscall.Signal, all bool) error
	WinsizeProcess(ctx context.Context, containerID, processID string, height, width uint32) error
	IOStream(containerID, processID string) (io.WriteCloser, io.Reader, io.Reader, error)

	AddDevice(ctx context.Context, info config.DeviceInfo) (api.Device, error)

	AddInterface(ctx context.Context, inf *pbTypes.Interface) (*pbTypes.Interface, error)
	RemoveInterface(ctx context.Context, inf *pbTypes.Interface) (*pbTypes.Interface, error)
	ListInterfaces(ctx context.Context) ([]*pbTypes.Interface, error)
	UpdateRoutes(ctx context.Context, routes []*pbTypes.Route) ([]*pbTypes.Route, error)
	ListRoutes(ctx context.Context) ([]*pbTypes.Route, error)

	GetOOMEvent(ctx context.Context) (string, error)
	GetHypervisorPid() (int, error)
	GetVirtioFsPid() int
	// RescanNetwork re-scans the network namespace for late-discovered endpoints.
	RescanNetwork(ctx context.Context) error

	UpdateRuntimeMetrics() error
	GetAgentMetrics(ctx context.Context) (string, error)
	GetAgentURL() (string, error)

	GuestVolumeStats(ctx context.Context, volumePath string) ([]byte, error)
	ResizeGuestVolume(ctx context.Context, volumePath string, size uint64) error

	GetIPTables(ctx context.Context, isIPv6 bool) ([]byte, error)
	SetIPTables(ctx context.Context, isIPv6 bool, data []byte) error
	SetPolicy(ctx context.Context, policy string) error

	// Live migration — thin pass-through to the underlying
	// Hypervisor's migration methods. See
	// docs/design/live-migration.md and
	// docs/design/live-migration-shim-lifecycle.md for the contract.
	// Hypervisors that do not support migration return
	// ErrMigrationNotSupported.
	MigrateOut(ctx context.Context, uri string, opts MigrateOptions) error
	MigrateIncoming(ctx context.Context, uri string) error
	GetMigrationStatus(ctx context.Context) (MigrationStatus, error)
	CancelMigration(ctx context.Context) error
	// MigrationContinue resumes a migration parked at `state`
	// (typically "pre-switchover") — paired with the
	// pause-before-switchover capability on MigrateOut.
	MigrationContinue(ctx context.Context, state string) error

	// Topology-replay handshake used by the shim's
	// /migration/topology endpoint during a handoff. See the
	// Sandbox method comments and docs/design/live-migration.md.
	GetHotpluggedMemoryDevices(ctx context.Context) ([]MemoryDevice, error)
	HotplugMemoryDevices(ctx context.Context, devices []MemoryDevice) error
	GetHotpluggedVCPUCount(ctx context.Context) (uint32, error)
	HotplugVCPUs(ctx context.Context, count uint32) error

	// ResumeVM unpauses a guest that was previously paused via
	// PauseVM or that started with "-S" (e.g. via the
	// IncomingMigrationURI boot path). Used by the live migration
	// destination shim after the source's CompleteHandoff to bring
	// the migrated guest back online.
	ResumeVM(ctx context.Context) error

	// CheckAgent verifies the kata-agent's gRPC server inside the
	// guest is reachable from this shim. Used by the live migration
	// destination shim post-resume to confirm the migrated agent
	// answers on the destination host's vsock CID.
	CheckAgent(ctx context.Context) error

	// PairAgentAfterMigration finalises an incoming-migration sandbox
	// after handoff: populates the kata-agent's connection URL from
	// the destination's vsock CID, renumbers the guest's network
	// interfaces to match the destination CNI's pod IP assignment,
	// and flips the sandbox + container state machines to Running.
	// Called by the live migration destination shim during
	// onMigrationComplete, before CheckAgent. See sandbox.go for the
	// full per-step rationale.
	PairAgentAfterMigration(ctx context.Context) error

	// PushDestIPsToGuestAgent forces a network renumber on the
	// in-guest kata-agent. Called by the shim's
	// handleMigrationRenumberGuest HTTP handler when the
	// orchestrator wants to trigger renumber explicitly (used when
	// the onMigrationComplete path is not reliably firing). See
	// sandbox.go for the implementation rationale.
	PushDestIPsToGuestAgent(ctx context.Context) error

	// DumpState returns the sandbox's current in-memory state in
	// the same shape the persist layer writes to disk. Used by the
	// source shim during a live migration to ship state to the
	// destination without forcing a Save+read round trip through
	// the filesystem. Per-container state is not included here —
	// that travels through a separate protocol message once
	// defined.
	DumpState() (persistapi.SandboxState, error)

	// SetMigrationSourceContainers stores the {container-name →
	// source-id} mapping the shim received from the topology
	// payload. The destination Sandbox's CreateContainer reads
	// from it to set each adopted Container's InternalID to the
	// source-side ID. See sandbox.go for the lookup logic.
	SetMigrationSourceContainers(map[string]string)

	// SetMigrationSourceMounts stores the per-container OCI bind
	// mounts (resolv.conf, hosts, hostname, configmaps, etc.) the
	// source had bound into its shared sandbox dir. Read by
	// BindMigrationSourceMounts to re-stage equivalent files at the
	// same paths on the destination. Empty/nil clears the field.
	SetMigrationSourceMounts(map[string][]MigrationSourceMount)

	// ShareDeferredWorkloadRootfs binds workload rootfs(es) into
	// the shared sandbox dir for any migration-adopted container
	// whose share has not yet been done. Called by the dest shim's
	// /migration/share-workload-rootfs endpoint after handoff.
	// Returns (sharedCount, failedCount).
	ShareDeferredWorkloadRootfs(ctx context.Context) (int, int)

	// BindMigrationSourceMounts binds the destination's local
	// hosts/hostname/resolv.conf/configmap files at the SOURCE'S
	// HostPaths inside the shared sandbox dir, so the migrated
	// guest's mount table (which still references source paths)
	// can serve them via virtio-fs. Called by the dest shim's
	// /migration/share-workload-rootfs endpoint immediately after
	// ShareDeferredWorkloadRootfs. Returns (boundCount, skippedCount).
	BindMigrationSourceMounts(ctx context.Context) (int, int)
}

// VCContainer is the Container interface
// (required since virtcontainers.Container only contains private fields)
type VCContainer interface {
	GetAnnotations() map[string]string
	GetPid() int
	GetToken() string
	ID() string
	Sandbox() VCSandbox
	Process() Process

	// ContainerdID returns the containerd-assigned CRI container ID
	// (equivalent to ID()). InternalID returns the ID the kata-agent
	// inside the guest knows for this container — equal to ID() for
	// fresh containers, equal to the SOURCE container's ID when this
	// container was adopted on the dest side of a live migration.
	ContainerdID() string
	InternalID() string

	// GetMigrationBindMounts returns the per-container OCI bind
	// mounts that ShareFile bound into the shared sandbox dir at
	// CreateContainer time — every Mount where HostPath != "". The
	// source shim ships these in the migration topology payload so
	// the destination can re-stage the same files at the same paths
	// inside its own shared dir. Returns nil/empty for containers
	// with no bind mounts.
	GetMigrationBindMounts() []Mount
}
