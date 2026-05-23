// Copyright (c) 2019 Huawei Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"os"
	"testing"

	"github.com/kata-containers/kata-containers/src/runtime/pkg/device/config"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/device/manager"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	"github.com/stretchr/testify/assert"
)

func TestSandboxRestore(t *testing.T) {
	var err error
	assert := assert.New(t)
	sconfig := SandboxConfig{
		ID: "test-exp",
	}
	container := make(map[string]*Container)
	container["test-exp"] = &Container{}

	network, err := NewNetwork()
	assert.NoError(err)

	sandbox := Sandbox{
		id:         "test-exp",
		containers: container,
		devManager: manager.NewDeviceManager(config.VirtioSCSI, false, "", 0, nil),
		hypervisor: &mockHypervisor{},
		network:    network,
		ctx:        context.Background(),
		config:     &sconfig,
		state:      types.SandboxState{BlockIndexMap: make(map[int]struct{})},
	}

	sandbox.store, err = persist.GetDriver()
	assert.NoError(err)
	assert.NotNil(sandbox.store)

	// if we don't call Save(), we can get nothing from disk
	err = sandbox.Restore()
	assert.NotNil(t, err)
	assert.True(os.IsNotExist(err))

	// disk data are empty
	err = sandbox.Save()
	assert.NoError(err)

	err = sandbox.Restore()
	assert.NoError(err)
	assert.Equal(sandbox.state.State, types.StateString(""))
	assert.Equal(sandbox.state.GuestMemoryBlockSizeMB, uint32(0))
	assert.Equal(len(sandbox.state.BlockIndexMap), 0)

	// set state data and Save again
	sandbox.state.State = types.StateString("running")
	sandbox.state.GuestMemoryBlockSizeMB = uint32(1024)
	sandbox.state.BlockIndexMap[2] = struct{}{}
	// flush data to disk
	err = sandbox.Save()
	assert.Nil(err)

	// empty the sandbox
	sandbox.state = types.SandboxState{}
	if sandbox.store, err = persist.GetDriver(); err != nil || sandbox.store == nil {
		t.Fatal("failed to get persist driver")
	}

	// restore data from disk
	err = sandbox.Restore()
	assert.NoError(err)
	assert.Equal(sandbox.state.State, types.StateString("running"))
	assert.Equal(sandbox.state.GuestMemoryBlockSizeMB, uint32(1024))
	assert.Equal(len(sandbox.state.BlockIndexMap), 1)
	assert.Equal(sandbox.state.BlockIndexMap[2], struct{}{})
}

func TestSandboxConfigMigrationSourceSandboxIDRoundTrip(t *testing.T) {
	// MigrationSourceSandboxID must survive a save/load cycle so a
	// destination-side shim restart can reconstruct the same
	// internal identity. Without this, the second incarnation of
	// the shim would default InternalID() back to ContainerdID()
	// and any kata-owned path that was set up under the source's
	// ID would suddenly be invisible.
	assert := assert.New(t)

	sconfig := &SandboxConfig{
		ID:             "dest-sb-roundtrip",
		HypervisorType: QemuHypervisor,
		HypervisorConfig: HypervisorConfig{
			MigrationSourceSandboxID: "source-sb-xyz",
		},
	}

	network, err := NewNetwork()
	assert.NoError(err)

	sandbox := &Sandbox{
		id:         "dest-sb-roundtrip",
		internalID: "source-sb-xyz",
		containers: map[string]*Container{},
		devManager: manager.NewDeviceManager(config.VirtioSCSI, false, "", 0, nil),
		hypervisor: &mockHypervisor{},
		network:    network,
		ctx:        context.Background(),
		config:     sconfig,
		state:      types.SandboxState{BlockIndexMap: make(map[int]struct{})},
	}
	sandbox.store, err = persist.GetDriver()
	assert.NoError(err)
	assert.NotNil(sandbox.store)

	assert.NoError(sandbox.Save())

	loaded, err := loadSandboxConfig("dest-sb-roundtrip")
	assert.NoError(err)
	assert.NotNil(loaded)
	assert.Equal("source-sb-xyz", loaded.HypervisorConfig.MigrationSourceSandboxID,
		"MigrationSourceSandboxID must survive Save()/loadSandboxConfig() so a destination shim restart preserves InternalID")
}
