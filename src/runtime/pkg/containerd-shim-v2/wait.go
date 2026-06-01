// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"fmt"
	"os"
	"path"
	"runtime/debug"
	"time"

	"github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/mount"
	"github.com/sirupsen/logrus"

	"github.com/kata-containers/kata-containers/src/runtime/pkg/oci"
)

const defaultCheckInterval = 1 * time.Second

// kata-watchsandbox-instr-v1: unique marker for binary verification
const watchSandboxInstrMarker = "kata-watchsandbox-instr-v1"

func wait(ctx context.Context, s *service, c *container, execID string) (int32, error) {
	var execs *exec
	var err error

	processID := c.id

	if execID == "" {
		//wait until the io closed, then wait the container
		<-c.exitIOch
		shimLog.WithField("container", c.id).Debug("The container io streams closed")
	} else {
		execs, err = c.getExec(execID)
		if err != nil {
			return exitCode255, err
		}
		<-execs.exitIOch
		shimLog.WithFields(logrus.Fields{
			"container": c.id,
			"exec":      execID,
		}).Debug("The container process io streams closed")
		//This wait could be triggered before exec start which
		//will get the exec's id, thus this assignment must after
		//the exec exit, to make sure it get the exec's id.
		processID = execs.id
	}

	ret, err := s.sandbox.WaitProcess(ctx, c.id, processID)
	if err != nil {
		shimLog.WithError(err).WithFields(logrus.Fields{
			"container": c.id,
			"pid":       processID,
		}).Error("Wait for process failed")

		// set return code if wait failed
		if ret == 0 {
			ret = exitCode255
		}
	}

	timeStamp := time.Now()

	s.mu.Lock()
	if execID == "" {
		// Take care of the use case where it is a sandbox.
		// Right after the container representing the sandbox has
		// been deleted, let's make sure we stop and delete the
		// sandbox.

		if c.cType.IsSandbox() {
			// Migration mode guard: when the in-guest agent becomes
			// unreachable post-migration (the VM has moved or is
			// paused at pre-switchover), WaitProcess returns and we
			// land here. Unconditionally calling sandbox.Stop+Delete
			// destroys /run/vc/sbs/<id>/, which kills the shim
			// management socket and breaks every orchestrator call
			// to the source (/migration/continue, /migration/diag,
			// ...). Defer teardown to controller-driven pod delete;
			// kubelet+containerd then drive normal shutdown through
			// shim.Cleanup at pod-delete time.
			//
			// Mirror of the same guard in watchSandbox below — both
			// paths are equivalent triggers for the same destructive
			// cleanup. Without this, the bundle dir vanishes the
			// moment the migrated guest's agent goes silent.
			if mode := s.currentMigrationMode(); mode != ModeOwner {
				shimLog.WithFields(map[string]interface{}{
					"marker":  watchSandboxInstrMarker,
					"sandbox": s.sandbox.ID(),
					"mode":    mode.String(),
					"path":    "wait(): WaitProcess returned",
				}).Warn("INSTR: wait: sandbox in non-owner migration mode — skipping Stop+Delete; teardown deferred to controller-driven pod delete")
			} else {
				// cancel watcher
				if s.monitor != nil {
					shimLog.WithField("sandbox", s.sandbox.ID()).Info("cancel watcher")
					s.monitor <- nil
				}
				if err = s.sandbox.Stop(ctx, true); err != nil {
					shimLog.WithField("sandbox", s.sandbox.ID()).Error("failed to stop sandbox")
				}

				if err = s.sandbox.Delete(ctx); err != nil {
					shimLog.WithField("sandbox", s.sandbox.ID()).Error("failed to delete sandbox")
				}
			}
		} else {
			if _, err = s.sandbox.StopContainer(ctx, c.id, true); err != nil {
				shimLog.WithError(err).WithField("container", c.id).Warn("stop container failed")
			}
		}
		c.status = task.Status_STOPPED
		c.exit = uint32(ret)
		c.exitTime = timeStamp

		c.exitCh <- uint32(ret)
		shimLog.WithField("container", c.id).Debug("The container status is StatusStopped")
	} else {
		execs.status = task.Status_STOPPED
		execs.exitCode = ret
		execs.exitTime = timeStamp

		execs.exitCh <- uint32(ret)
		shimLog.WithFields(logrus.Fields{
			"container": c.id,
			"exec":      execID,
		}).Debug("The container exec status is StatusStopped")
	}
	s.mu.Unlock()

	go cReap(s, int(ret), c.id, execID, timeStamp)

	return ret, nil
}

func watchSandbox(ctx context.Context, s *service) {
	if s.monitor == nil {
		return
	}
	err := <-s.monitor
	shimLog.WithError(err).WithFields(map[string]interface{}{
		"marker":  watchSandboxInstrMarker,
		"sandbox": s.sandbox.ID(),
		"errType": fmt.Sprintf("%T", err),
	}).Info("INSTR: watchSandbox: received from monitor channel")
	if err == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.monitor = nil

	// Migration mode guard: during MigratingOut/Incoming/Migrated/Failed,
	// QEMU and the in-guest agent are EXPECTED to become unreachable —
	// the guest is paused at pre-switchover, vmstate is in flight, or
	// the VM has already moved to the destination. The unconditional
	// Stop+Delete below destroys /run/vc/sbs/<id>/, which takes the
	// shim management socket with it and 502's every subsequent
	// orchestrator call (/migration/continue, /migration/diag,
	// /migration/wire-workload-io, ...). Defer cleanup until the
	// controller deletes the source pod; kubelet+containerd then
	// drive normal shutdown through the shim's regular cleanup path
	// at pod-delete time.
	//
	// Without this guard, watchSandbox fires on the very first agent
	// or QEMU check failure during migration, wipes the source bundle
	// dir, and the controller's next call hits "shim-monitor.sock:
	// no such file or directory".
	if mode := s.currentMigrationMode(); mode != ModeOwner {
		shimLog.WithError(err).WithFields(map[string]interface{}{
			"marker":  watchSandboxInstrMarker,
			"sandbox": s.sandbox.ID(),
			"mode":    mode.String(),
			"errType": fmt.Sprintf("%T", err),
		}).Warn("INSTR: watchSandbox: sandbox in non-owner migration mode — skipping Stop+Delete; teardown deferred to controller-driven pod delete")
		return
	}

	// INSTR: — this is the line that ends the VM. Capture EVERYTHING here.
	stack := string(debug.Stack())
	shimLog.WithError(err).WithFields(map[string]interface{}{
		"marker":   watchSandboxInstrMarker,
		"sandbox":  s.sandbox.ID(),
		"errType":  fmt.Sprintf("%T", err),
		"errChain": fmt.Sprintf("%+v", err),
		"stack":    stack,
	}).Error("INSTR: watchSandbox: sandbox stopped unexpectedly — about to call Stop(ctx,true) which SIGKILLs QEMU + virtiofsd. Root error from monitor:")

	err = s.sandbox.Stop(ctx, true)
	if err != nil {
		shimLog.WithError(err).Warn("INSTR: watchSandbox: stop sandbox failed")
	} else {
		shimLog.WithField("marker", watchSandboxInstrMarker).Warn("INSTR: watchSandbox: sandbox.Stop(true) returned — QEMU killed")
	}
	err = s.sandbox.Delete(ctx)
	if err != nil {
		shimLog.WithError(err).Warn("INSTR: watchSandbox: delete sandbox failed")
	}

	for _, c := range s.containers {
		if !c.mounted {
			continue
		}
		rootfs := path.Join(c.bundle, "rootfs")
		shimLog.WithField("rootfs", rootfs).WithField("container", c.id).Debug("container umount rootfs")
		if err := mount.UnmountAll(rootfs, 0); err != nil {
			shimLog.WithError(err).Warn("failed to cleanup rootfs mount")
		}
	}

	// Existing container/exec will be cleaned up by its waiters.
	// No need to send async events here.
}

func watchOOMEvents(ctx context.Context, s *service) {
	if s.sandbox == nil {
		return
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			containerID, err := s.sandbox.GetOOMEvent(ctx)
			if err != nil {
				if err.Error() == "ttrpc: closed" || err.Error() == "Dead agent" {
					shimLog.WithError(err).Info("agent has shutdown, return from watching of OOM events")
					return
				}
				shimLog.WithError(err).Info("failed to get OOM event from sandbox")
				time.Sleep(defaultCheckInterval)
				continue
			}

			// write oom file for CRI-O
			if c, ok := s.containers[containerID]; ok && oci.IsCRIOContainerManager(c.spec) {
				oomPath := path.Join(c.bundle, "oom")
				shimLog.Infof("write oom file to notify CRI-O: %s", oomPath)

				f, err := os.OpenFile(oomPath, os.O_CREATE, 0666)
				if err != nil {
					shimLog.WithError(err).Warnf("failed to write oom file %s", oomPath)
				} else {
					f.Close()
				}
			}

			// publish event for containerd
			s.send(&events.TaskOOM{
				ContainerID: containerID,
			})
		}
	}
}
