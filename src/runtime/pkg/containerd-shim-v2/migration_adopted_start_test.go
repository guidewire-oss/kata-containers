// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/vcmock"
)

// A destination pod is created fresh, so the kubelet issues Start for EVERY
// container in spec order — and the sandbox's migration mode flips from
// Incoming to Owner partway through that sequence, when the handoff completes.
//
// Before this guard, containers reached after the flip fell through to
// agent.startContainer, which fails because the process is already running in
// the migrated guest; Container.start()'s error handler then force-stops it,
// killing a live process.
//
// Observed on a two-container pod: the workload (started first, still
// Incoming) survived every hop while the sidecar (started after the flip)
// died, with postgres refused on loopback and on the pod IP.
func TestIsMigrationAdoptedContainer(t *testing.T) {
	assert := assert.New(t)

	sandbox := &vcmock.Sandbox{
		MockID: "sandbox-1",
		MockContainers: []*vcmock.Container{
			// Adopted: InternalID is the SOURCE's id, so it differs from the
			// destination's fresh containerd id.
			{MockID: "dest-id-sidecar", MockInternalID: "source-id-sidecar"},
			// Freshly created here: adoptMigrationContainerID never ran, so
			// InternalID falls back to the container's own id.
			{MockID: "fresh-container"},
		},
	}
	s := &service{sandbox: sandbox}

	assert.True(s.isMigrationAdoptedContainer("dest-id-sidecar"),
		"a container whose InternalID is the source's id is adopted; its process already runs in the guest")
	assert.False(s.isMigrationAdoptedContainer("fresh-container"),
		"a freshly created container must take the normal start path")
	assert.False(s.isMigrationAdoptedContainer("unknown-id"),
		"an id this sandbox does not own is not adopted")
	assert.False(s.isMigrationAdoptedContainer(""),
		"an empty id must never be treated as adopted")
}

// The guard must not depend on a sandbox being present — Start() can be
// reached before the sandbox is wired up.
func TestIsMigrationAdoptedContainerNilSandbox(t *testing.T) {
	s := &service{}
	assert.False(t, s.isMigrationAdoptedContainer("anything"),
		"no sandbox means nothing is adopted, not a panic")
}

// The mode short-circuit and the adoption short-circuit are independent: a
// container can need either one. Owner mode is exactly the case the mode test
// misses, which is why adoption has to be checked separately.
func TestAdoptionIsCheckedIndependentlyOfMode(t *testing.T) {
	assert := assert.New(t)

	sandbox := &vcmock.Sandbox{
		MockID: "sandbox-1",
		MockContainers: []*vcmock.Container{
			{MockID: "dest-id-sidecar", MockInternalID: "source-id-sidecar"},
		},
	}
	s := &service{sandbox: sandbox}
	s.migrationMode = ModeOwner

	assert.Equal(ModeOwner, s.currentMigrationMode(),
		"the handoff has completed, so the mode test alone would let this through")
	assert.True(s.isMigrationAdoptedContainer("dest-id-sidecar"),
		"adoption still holds after the flip — it is the durable fact, the mode is transient")
}
