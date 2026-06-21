// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"testing"

	taskAPI "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/api/types/task"
	"github.com/stretchr/testify/assert"

	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/vcmock"
)

// A saved or migrated sandbox has no live local VM: a StatsContainer RPC would
// travel over a vsock to a guest that is gone (paused for a snapshot, handed
// off for a migration) and block forever while holding s.mu, which also
// serializes Kill. That wedges the source pod Terminating because the kubelet's
// StopContainer can never acquire the lock. Stats must answer without touching
// the departed guest. Owner mode must still query for live metrics.
func TestStatsDoesNotQueryDepartedGuest(t *testing.T) {
	newSvc := func(mode SandboxMigrationMode) (*service, *bool) {
		queried := false
		sandbox := &vcmock.Sandbox{
			MockID: testSandboxID,
			StatsContainerFunc: func(string) (vc.ContainerStats, error) {
				queried = true
				return vc.ContainerStats{}, nil
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
		return s, &queried
	}

	for _, mode := range []SandboxMigrationMode{ModeSaved, ModeMigrated} {
		mode := mode
		t.Run(mode.String()+": stats does not query the guest", func(t *testing.T) {
			s, queried := newSvc(mode)
			resp, err := s.Stats(context.Background(), &taskAPI.StatsRequest{ID: testContainerID})
			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.False(t, *queried, "a saved/migrated sandbox must not be queried — its guest is gone")
		})
	}

	t.Run("owner sandbox: stats queries the guest", func(t *testing.T) {
		s, queried := newSvc(ModeOwner)
		_, err := s.Stats(context.Background(), &taskAPI.StatsRequest{ID: testContainerID})
		assert.NoError(t, err)
		assert.True(t, *queried, "an owner sandbox must be queried for live metrics")
	})
}
