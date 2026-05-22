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

	// Topology-replay handshake used by the shim's
	// /migration/topology endpoint during a handoff. See the
	// Sandbox method comments and docs/design/live-migration.md.
	GetHotpluggedMemoryDevices(ctx context.Context) ([]MemoryDevice, error)
	HotplugMemoryDevices(ctx context.Context, devices []MemoryDevice) error

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

	// DumpState returns the sandbox's current in-memory state in
	// the same shape the persist layer writes to disk. Used by the
	// source shim during a live migration to ship state to the
	// destination without forcing a Save+read round trip through
	// the filesystem. Per-container state is not included here —
	// that travels through a separate protocol message once
	// defined.
	DumpState() (persistapi.SandboxState, error)
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
}
