// Copyright (c) 2016 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"runtime"

	deviceApi "github.com/kata-containers/kata-containers/src/runtime/pkg/device/api"
	deviceConfig "github.com/kata-containers/kata-containers/src/runtime/pkg/device/config"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils/katatrace"
	resCtrl "github.com/kata-containers/kata-containers/src/runtime/pkg/resourcecontrol"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/compatoci"
	vcTypes "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	"github.com/sirupsen/logrus"
)

// apiTracingTags defines tags for the trace span
var apiTracingTags = map[string]string{
	"source":    "runtime",
	"package":   "virtcontainers",
	"subsystem": "api",
}

func init() {
	runtime.LockOSThread()
}

var virtLog = logrus.WithField("source", "virtcontainers")

// SetLogger sets the logger for virtcontainers package.
func SetLogger(ctx context.Context, logger *logrus.Entry) {
	fields := virtLog.Data
	virtLog = logger.WithFields(fields)
	SetHypervisorLogger(virtLog) // TODO: this will move to hypervisors pkg
	deviceApi.SetLogger(virtLog)
	compatoci.SetLogger(virtLog)
	deviceConfig.SetLogger(virtLog)
	resCtrl.SetLogger(virtLog)
}

// CreateSandbox is the virtcontainers sandbox creation entry point.
// CreateSandbox creates a sandbox and its containers. It does not start them.
func CreateSandbox(ctx context.Context, sandboxConfig SandboxConfig, factory Factory, prestartHookFunc func(context.Context) error) (VCSandbox, error) {
	span, ctx := katatrace.Trace(ctx, virtLog, "CreateSandbox", apiTracingTags)
	defer span.End()

	s, err := createSandboxFromConfig(ctx, sandboxConfig, factory, prestartHookFunc)

	return s, err
}

func createSandboxFromConfig(ctx context.Context, sandboxConfig SandboxConfig, factory Factory, prestartHookFunc func(context.Context) error) (_ *Sandbox, err error) {
	span, ctx := katatrace.Trace(ctx, virtLog, "createSandboxFromConfig", apiTracingTags)
	defer span.End()

	// Create the sandbox.
	s, err := createSandbox(ctx, sandboxConfig, factory)
	if err != nil {
		return nil, err
	}

	// Cleanup sandbox resources in case of any failure
	defer func() {
		if err != nil {
			s.Delete(ctx)
		}
	}()

	// network rollback
	defer func() {
		if err != nil {
			virtLog.Info("Removing network after failure in createSandbox")
			s.removeNetwork(ctx)
		}
	}()

	// Create the sandbox network
	if err = s.createNetwork(ctx); err != nil {
		return nil, err
	}

	// Set the sandbox host cgroups.
	if err := s.setupResourceController(); err != nil {
		return nil, err
	}

	// Start the VM
	if err = s.startVM(ctx, prestartHookFunc); err != nil {
		return nil, err
	}

	// rollback to stop VM if error occurs
	defer func() {
		if err != nil {
			s.stopVM(ctx)
		}
	}()

	s.postCreatedNetwork(ctx)

	// Inbound live migration: QEMU is paused at "-incoming defer".
	// The guest is not running, so getAndStoreGuestDetails (which
	// queries the kata-agent) would block forever, and
	// createContainers' agent.createContainer RPC would fail.
	//
	// But we still need the shim's container bookkeeping populated
	// so the CRI Create call from kubelet (which reads back
	// sandbox.GetAllContainers in katautils/create.go and asserts
	// len == 1) succeeds. Do just the newContainer + addContainer
	// half of createContainers; the migrated kata-agent will already
	// own the containers inside the guest once memory transfer
	// completes, and the destination shim re-pairs with them via the
	// onMigrationComplete sequence.
	if sandboxConfig.IncomingMigrationURI != "" {
		for i := range s.config.Containers {
			c, err := newContainer(ctx, s, &s.config.Containers[i])
			if err != nil {
				return nil, err
			}
			if err := s.addContainer(c); err != nil {
				return nil, err
			}
		}
		return s, nil
	}

	if err = s.getAndStoreGuestDetails(ctx); err != nil {
		return nil, err
	}

	// Create Containers
	if err = s.createContainers(ctx); err != nil {
		return nil, err
	}

	return s, nil
}

// CleanupContainer is used by shimv2 to stop and delete a container exclusively, once there is no container
// in the sandbox left, do stop the sandbox and delete it. Those serial operations will be done exclusively by
// locking the sandbox.
func CleanupContainer(ctx context.Context, sandboxID, containerID string, force bool) error {
	span, ctx := katatrace.Trace(ctx, virtLog, "CleanupContainer", apiTracingTags)
	defer span.End()

	if sandboxID == "" {
		return vcTypes.ErrNeedSandboxID
	}

	if containerID == "" {
		return vcTypes.ErrNeedContainerID
	}

	unlock, err := rwLockSandbox(sandboxID)
	if err != nil {
		return err
	}
	defer unlock()

	s, err := fetchSandbox(ctx, sandboxID)
	if err != nil {
		return err
	}
	defer s.Release(ctx)

	// W3: CleanupContainer runs in a fresh shim process where
	// agentUnreachable/agentSaved/mode are lost (in-memory only, not
	// persisted). Without this probe, a departed-guest sandbox would
	// issue blocking agent RPCs at 45s dial_timeout each in c.stop and
	// stopVM — up to 6 RPCs = 270s+ before the bundle clears. Probe
	// once up-front (bounded by agentReachableProbeTimeout = 15s); if
	// the agent does not answer, set agentUnreachable so every gated
	// teardown RPC (kill, waitProcess, stopContainer, getDiagnosticData,
	// stopSandbox, disconnect) is skipped. This runs regardless of
	// `force` — containerd's graceful cleanup path passes force=false,
	// and the probe in Sandbox.Stop is gated on `force &&` and would
	// silently skip it.
	if !s.agentUnreachable && !s.AgentReachable(ctx) {
		virtLog.Warn("CleanupContainer: in-guest agent unreachable; skipping all agent RPCs in teardown")
		s.SetAgentUnreachable(true)
	}

	_, err = s.StopContainer(ctx, containerID, force)
	if err != nil && !force {
		return err
	}

	_, err = s.DeleteContainer(ctx, containerID)
	if err != nil && !force {
		return err
	}

	if len(s.GetAllContainers()) > 0 {
		return nil
	}

	if err = s.Stop(ctx, force); err != nil && !force {
		return err
	}

	if err = s.Delete(ctx); err != nil {
		return err
	}

	return nil
}
