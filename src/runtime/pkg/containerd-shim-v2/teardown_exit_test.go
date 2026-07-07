// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"syscall"
	"testing"
	"time"

	taskAPI "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/api/types/task"
	"github.com/stretchr/testify/assert"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/vcmock"
)

// newTeardownSvc builds a minimal service in the given migration mode with one
// RUNNING container, an agent reachable/unreachable per the flag, and a buffered
// exit channel so cReap's send never blocks the test.
func newTeardownSvc(t *testing.T, mode SandboxMigrationMode, agentUnreachable bool) (*service, *container) {
	t.Helper()
	reachable := !agentUnreachable
	sb := &vcmock.Sandbox{
		MockID:             testSandboxID,
		AgentReachableFunc: func() bool { return reachable },
	}
	s := &service{
		id:            testSandboxID,
		sandbox:       sb,
		containers:    make(map[string]*container),
		ec:            make(chan exit, bufferSize),
		ctx:           context.Background(),
		rootCtx:       context.Background(),
		migrationMode: mode,
	}
	c, err := newContainer(s, &taskAPI.CreateTaskRequest{ID: testContainerID}, "", nil, true)
	assert.NoError(t, err)
	c.status = task.Status_RUNNING
	s.containers[testContainerID] = c
	return s, c
}

// exitEventPublished reports whether a container-level TaskExit landed on s.ec
// within a short window. cReap (utils.go) is the only producer of that event on
// the teardown path; its absence means the container was NOT reaped.
func exitEventPublished(s *service) bool {
	select {
	case e := <-s.ec:
		return e.id == testContainerID && e.execid == ""
	case <-time.After(500 * time.Millisecond):
		return false
	}
}

// markContainerStoppedForTeardown carries publishExit: true only on the
// confirmed post-handoff path (the workload genuinely departed), false on the
// agent-unreachable path (which can fire mid-migration against a LIVE source).
// Both paths must still flip the container to STOPPED so the kubelet stops
// looping StopContainer (#268), but only the post-handoff path may emit the
// TaskExit that containerd's StopContainer reaps on.
func TestMarkStoppedPublishExitFlag(t *testing.T) {
	t.Run("publishExit=true emits the TaskExit (post-handoff source self-reaps)", func(t *testing.T) {
		s, c := newTeardownSvc(t, ModeMigrated, false)
		markContainerStoppedForTeardown(c, true)
		assert.Equal(t, task.Status_STOPPED, c.status)
		assert.True(t, exitEventPublished(s), "post-handoff teardown must publish a TaskExit")
	})

	t.Run("publishExit=false stops the container but emits NO TaskExit", func(t *testing.T) {
		s, c := newTeardownSvc(t, ModeFailed, true)
		markContainerStoppedForTeardown(c, false)
		assert.Equal(t, task.Status_STOPPED, c.status, "still marked STOPPED to clear the kubelet wedge (#268)")
		assert.False(t, exitEventPublished(s),
			"agent-unreachable teardown must NOT publish a TaskExit — it can fire mid-migration and reap a live source")
	})
}

// Kill-level guard: the regression (#275) was that an agent-unreachable teardown
// kill published exitCode255 on a LIVE source whose migrate-out had FAILED,
// restarting it. ModeFailed keeps the source running (the controller keeps it
// active on failure) but its agent connection is closed by the
// migrating-out -> failed transition, so a teardown kill takes the
// agent-unreachable branch. It must be a no-op kill WITHOUT a TaskExit.
// (ModeMigratingOut itself is rejected earlier by checkOpAllowed, so the
// reap could only ever land once the mode had moved to failed.)
func TestKillAgentUnreachableDoesNotReapFailedSource(t *testing.T) {
	s, c := newTeardownSvc(t, ModeFailed, true /* agent unreachable */)

	_, err := s.Kill(context.Background(), &taskAPI.KillRequest{
		ID: testContainerID, Signal: uint32(syscall.SIGKILL),
	})
	assert.NoError(t, err, "teardown kill on an unreachable agent is a no-op")
	assert.Equal(t, task.Status_STOPPED, c.status)
	assert.False(t, exitEventPublished(s),
		"a live source whose migrate-out failed must NOT be reaped by the agent-unreachable branch (#275 regression)")
}

// The confirmed post-handoff source (ModeMigrated, agent connection already
// closed so it reads unreachable) MUST publish the TaskExit so it self-reaps
// instead of wedging Terminating — the legitimate goal #275 was reaching for.
func TestKillMigratedSourcePublishesExit(t *testing.T) {
	s, c := newTeardownSvc(t, ModeMigrated, true)

	_, err := s.Kill(context.Background(), &taskAPI.KillRequest{
		ID: testContainerID, Signal: uint32(syscall.SIGKILL),
	})
	assert.NoError(t, err)
	assert.Equal(t, task.Status_STOPPED, c.status)
	assert.True(t, exitEventPublished(s),
		"a migrated (handed-off) source must self-reap via a published TaskExit")
}

// FR-063a regression guard: the exit event travels a lossy path and CRI can
// silently discard it. The kubelet retries the teardown kill; EVERY retry on a
// saved/migrated sandbox must RE-publish the TaskExit — the first kill marking
// the container STOPPED must not short-circuit later kills (the exact wedge
// observed live: one lost event, then "process has already stopped" forever).
func TestKillMigratedSourceRepublishesExitOnRetry(t *testing.T) {
	s, c := newTeardownSvc(t, ModeMigrated, true)

	for attempt := 1; attempt <= 3; attempt++ {
		_, err := s.Kill(context.Background(), &taskAPI.KillRequest{
			ID: testContainerID, Signal: uint32(syscall.SIGKILL),
		})
		assert.NoError(t, err, "kill attempt %d", attempt)
		assert.Equal(t, task.Status_STOPPED, c.status)
		assert.True(t, exitEventPublished(s),
			"kill attempt %d must re-offer the TaskExit — a single lost event must not wedge the pod", attempt)
	}
}

// The generic already-stopped early-return still protects the normal
// (non-migration) path: a second SIGKILL on a stopped ModeOwner container is
// a silent no-op with no synthetic exit.
func TestKillAlreadyStoppedOwnerContainerStaysSilent(t *testing.T) {
	s, c := newTeardownSvc(t, ModeOwner, false)
	c.status = task.Status_STOPPED

	_, err := s.Kill(context.Background(), &taskAPI.KillRequest{
		ID: testContainerID, Signal: uint32(syscall.SIGKILL),
	})
	assert.NoError(t, err)
	assert.False(t, exitEventPublished(s),
		"an owner-mode already-stopped container must not emit synthetic exits")
}
