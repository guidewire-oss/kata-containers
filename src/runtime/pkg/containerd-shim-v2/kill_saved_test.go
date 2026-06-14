// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"errors"
	"syscall"
	"testing"

	taskAPI "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/api/types/task"
	"github.com/stretchr/testify/assert"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/vcmock"
)

// A saved/migrated sandbox has no live local VM, so a teardown SIGKILL must
// be a no-op (idempotent) rather than bouncing off SignalProcess with
// "Sandbox not running" — which the kubelet surfaces as FailedKillPod on
// every warm suspend. Owner mode must still signal normally.
func TestKillIsNoOpForSavedSandbox(t *testing.T) {
	newSvc := func(mode SandboxMigrationMode) (*service, *bool) {
		signalled := false
		sandbox := &vcmock.Sandbox{
			MockID: testSandboxID,
			SignalProcessFunc: func(string, string, syscall.Signal, bool) error {
				signalled = true
				return errors.New("Sandbox not running")
			},
		}
		s := &service{
			id:            testSandboxID,
			sandbox:       sandbox,
			containers:    make(map[string]*container),
			ctx:           context.Background(),
			rootCtx:       context.Background(),
			migrationMode: mode,
		}
		c, err := newContainer(s, &taskAPI.CreateTaskRequest{ID: testContainerID}, "", nil, true)
		assert.NoError(t, err)
		c.status = task.Status_RUNNING
		s.containers[testContainerID] = c
		return s, &signalled
	}

	t.Run("saved sandbox: kill is a no-op", func(t *testing.T) {
		s, signalled := newSvc(ModeSaved)
		_, err := s.Kill(context.Background(), &taskAPI.KillRequest{
			ID: testContainerID, Signal: uint32(syscall.SIGKILL),
		})
		assert.NoError(t, err)
		assert.False(t, *signalled, "a saved sandbox must not be signalled — its VM is paused")
	})

	t.Run("owner sandbox: kill signals normally", func(t *testing.T) {
		s, signalled := newSvc(ModeOwner)
		_, err := s.Kill(context.Background(), &taskAPI.KillRequest{
			ID: testContainerID, Signal: uint32(syscall.SIGKILL),
		})
		assert.Error(t, err, "owner-mode kill reaches SignalProcess (which errored in this mock)")
		assert.True(t, *signalled, "an owner sandbox must still be signalled")
	})
}
