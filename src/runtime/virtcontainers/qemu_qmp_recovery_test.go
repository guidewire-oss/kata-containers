// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A cached QMP session whose command loop has exited must be detected as
// dead so qmpSetup re-dials instead of returning the corpse — otherwise
// every later QMP user fails with "exiting QMP loop, command cancelled"
// until the shim dies (seen live: hibernate failing on a migration
// destination whose QMP session hiccuped around the handoff).
func TestQmpSessionDead(t *testing.T) {
	assert := assert.New(t)

	assert.True(qmpSessionDead(nil), "never-wired session must count as dead")

	open := make(chan struct{})
	assert.False(qmpSessionDead(open), "open disconnect channel = live session")

	closed := make(chan struct{})
	close(closed)
	assert.True(qmpSessionDead(closed), "closed disconnect channel = dead loop")
}

// GetPids must prefer the PID captured at LaunchQemu over the on-disk
// pidfile: on a dual-identity migration destination the pidfile path can
// point into an identity directory that host tooling reclaimed, and the
// failed read used to surface as "Invalid hypervisor PID: [0]" on a live VM.
func TestGetPidsPrefersLaunchedPid(t *testing.T) {
	assert := assert.New(t)

	q := &qemu{launchedPid: 4242}
	// Deliberately no pidfile anywhere near this path.
	q.qemuConfig.PidFile = filepath.Join(t.TempDir(), "does-not-exist", "pid")

	pids := q.GetPids()
	assert.NotEmpty(pids)
	assert.Equal(4242, pids[0])

	q.state.VirtiofsDaemonPid = 77
	pids = q.GetPids()
	assert.Equal([]int{4242, 77}, pids)
}

// Without a launched PID (grpc/VM-cache paths), the pidfile fallback keeps
// its historical behavior.
func TestGetPidsPidfileFallback(t *testing.T) {
	assert := assert.New(t)

	dir := t.TempDir()
	pidfile := filepath.Join(dir, "pid")
	assert.NoError(os.WriteFile(pidfile, []byte("1357\n"), 0o644))

	q := &qemu{}
	q.qemuConfig.PidFile = pidfile
	assert.Equal(1357, q.GetPids()[0])

	q.qemuConfig.PidFile = filepath.Join(dir, "missing")
	assert.Equal([]int{0}, q.GetPids(), "unreadable pidfile with no launched PID keeps the [0] contract")
}
