// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordedBind struct {
	source, target string
	readOnly       bool
}

// withFakeMigrationBind swaps the bind step for a recorder and anchors the
// shared dir under a temp dir, so the re-stage can be exercised without
// CAP_SYS_ADMIN. Returns the recorder and the shared-dir root.
func withFakeMigrationBind(t *testing.T) (*[]recordedBind, string) {
	t.Helper()
	tmp := t.TempDir()
	origShared := kataHostSharedDir
	kataHostSharedDir = func() string { return tmp }
	origBind := migrationBindMount
	calls := &[]recordedBind{}
	migrationBindMount = func(_ context.Context, source, target string, readOnly bool, _ string) error {
		*calls = append(*calls, recordedBind{source: source, target: target, readOnly: readOnly})
		return nil
	}
	t.Cleanup(func() {
		kataHostSharedDir = origShared
		migrationBindMount = origBind
	})
	return calls, tmp
}

func newLateSidecar(s *Sandbox, name, localHosts string) *Container {
	return &Container{
		id:         "dest-" + name,
		internalID: "src-" + name,
		sandbox:    s,
		config: &ContainerConfig{
			Annotations: map[string]string{"io.kubernetes.cri.container-name": name},
			Mounts: []Mount{
				{Destination: "/proc", Source: "proc"},
				{Destination: "/etc/hosts", Source: localHosts},
			},
		},
	}
}

func TestStageLateAdoptedContainerMountsStagesTheSidecar(t *testing.T) {
	// A sidecar created after /migration/topology (and its sweep) must get its
	// own source bind files staged from CreateContainer, under THIS sandbox's
	// shared dir and the SOURCE's file name, and must record them so the next
	// hop's source can report them.
	calls, tmp := withFakeMigrationBind(t)
	local := filepath.Join(tmp, "etc-hosts")
	require.NoError(t, os.WriteFile(local, []byte("127.0.0.1 localhost\n"), 0o644))

	s := &Sandbox{id: "dest-sb", internalID: "src-sb", containers: map[string]*Container{}}
	s.SetMigrationSourceMounts(map[string][]MigrationSourceMount{
		"workload": {{Destination: "/etc/hosts", HostPath: filepath.Join(tmp, "orig-sb", "mounts", "src-workload-aaaa-hosts")}},
		"sidecar":  {{Destination: "/etc/hosts", HostPath: filepath.Join(tmp, "orig-sb", "mounts", "src-sidecar-bbbb-hosts")}},
	})
	c := newLateSidecar(s, "sidecar", local)

	bound, skipped := s.stageLateAdoptedContainerMounts(context.Background(), c)

	assert.Equal(t, 1, bound)
	assert.Equal(t, 0, skipped)
	want := filepath.Join(tmp, "src-sb", "mounts", "src-sidecar-bbbb-hosts")
	require.Equal(t, []recordedBind{{source: local, target: want}}, *calls,
		"the dest's local hosts file is bound at the source's shared-dir name, rebased under this sandbox")
	st, err := os.Stat(want)
	require.NoError(t, err, "the bind target is pre-created")
	assert.False(t, st.IsDir(), "a file source gets a file target")
	got := c.GetMigrationBindMounts()
	require.Len(t, got, 1, "recorded so this container reports it when the pod becomes the next source")
	assert.Equal(t, want, got[0].HostPath)
	assert.Equal(t, "/etc/hosts", got[0].Destination)
}

func TestStageLateAdoptedContainerMountsIsANoopBeforeTopology(t *testing.T) {
	// Before the payload there is nothing to stage; the topology handler's
	// sweep covers containers that already exist when it lands.
	calls, tmp := withFakeMigrationBind(t)
	s := &Sandbox{id: "dest-sb", internalID: "src-sb", containers: map[string]*Container{}}
	c := newLateSidecar(s, "sidecar", filepath.Join(tmp, "etc-hosts"))

	bound, skipped := s.stageLateAdoptedContainerMounts(context.Background(), c)

	assert.Zero(t, bound)
	assert.Zero(t, skipped)
	assert.Empty(t, *calls)
	assert.Empty(t, c.GetMigrationBindMounts())
}

func TestStageLateAdoptedContainerMountsSkipsAContainerWithoutSourceMounts(t *testing.T) {
	// The payload names other containers only: nothing to stage for this one,
	// and nothing is bound for anyone else either.
	calls, tmp := withFakeMigrationBind(t)
	s := &Sandbox{id: "dest-sb", internalID: "src-sb", containers: map[string]*Container{}}
	s.SetMigrationSourceMounts(map[string][]MigrationSourceMount{
		"workload": {{Destination: "/etc/hosts", HostPath: filepath.Join(tmp, "orig-sb", "mounts", "src-workload-aaaa-hosts")}},
	})
	c := newLateSidecar(s, "sidecar", filepath.Join(tmp, "etc-hosts"))

	bound, skipped := s.stageLateAdoptedContainerMounts(context.Background(), c)

	assert.Zero(t, bound)
	assert.Zero(t, skipped)
	assert.Empty(t, *calls)
}

func TestBindMigrationSourceMountsSweepStagesEveryPresentContainer(t *testing.T) {
	// The topology-time sweep is the same per-container step applied to every
	// container present; a container the payload does not name is skipped and
	// does not count as skipped mounts.
	calls, tmp := withFakeMigrationBind(t)
	localA := filepath.Join(tmp, "hosts-a")
	localB := filepath.Join(tmp, "hosts-b")
	require.NoError(t, os.WriteFile(localA, []byte("a\n"), 0o644))
	require.NoError(t, os.WriteFile(localB, []byte("b\n"), 0o644))

	s := &Sandbox{id: "dest-sb", internalID: "src-sb", containers: map[string]*Container{}}
	s.SetMigrationSourceMounts(map[string][]MigrationSourceMount{
		"workload": {{Destination: "/etc/hosts", HostPath: filepath.Join(tmp, "orig-sb", "mounts", "src-workload-aaaa-hosts")}},
		"sidecar":  {{Destination: "/etc/hosts", HostPath: filepath.Join(tmp, "orig-sb", "mounts", "src-sidecar-bbbb-hosts")}},
	})
	workload := newLateSidecar(s, "workload", localA)
	sidecar := newLateSidecar(s, "sidecar", localB)
	unnamed := newLateSidecar(s, "shipper", localB)
	s.containers[workload.id] = workload
	s.containers[sidecar.id] = sidecar
	s.containers[unnamed.id] = unnamed

	bound, skipped := s.BindMigrationSourceMounts(context.Background())

	assert.Equal(t, 2, bound)
	assert.Equal(t, 0, skipped)
	require.Len(t, *calls, 2)
	targets := map[string]string{}
	for _, b := range *calls {
		targets[b.source] = b.target
	}
	assert.Equal(t, filepath.Join(tmp, "src-sb", "mounts", "src-workload-aaaa-hosts"), targets[localA])
	assert.Equal(t, filepath.Join(tmp, "src-sb", "mounts", "src-sidecar-bbbb-hosts"), targets[localB])
	assert.Len(t, workload.GetMigrationBindMounts(), 1)
	assert.Len(t, sidecar.GetMigrationBindMounts(), 1)
	assert.Empty(t, unnamed.GetMigrationBindMounts())
}

func TestStageLateAdoptedContainerMountsReportsAMissingLocalFileAsSkipped(t *testing.T) {
	// The dest spec has no mount for the source's destination (an older
	// controller, a different sidecar shape): the entry is skipped and
	// counted, nothing is bound, nothing is recorded.
	calls, tmp := withFakeMigrationBind(t)
	s := &Sandbox{id: "dest-sb", internalID: "src-sb", containers: map[string]*Container{}}
	s.SetMigrationSourceMounts(map[string][]MigrationSourceMount{
		"sidecar": {{Destination: "/etc/resolv.conf", HostPath: filepath.Join(tmp, "orig-sb", "mounts", "src-sidecar-bbbb-resolv.conf")}},
	})
	c := newLateSidecar(s, "sidecar", filepath.Join(tmp, "etc-hosts"))

	bound, skipped := s.stageLateAdoptedContainerMounts(context.Background(), c)

	assert.Zero(t, bound)
	assert.Equal(t, 1, skipped)
	assert.Empty(t, *calls)
	assert.Empty(t, c.GetMigrationBindMounts())
}
