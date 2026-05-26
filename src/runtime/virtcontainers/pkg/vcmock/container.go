// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package vcmock

import (
	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
)

// ID implements the VCContainer function of the same name.
func (c *Container) ID() string {
	return c.MockID
}

// Sandbox implements the VCContainer function of the same name.
func (c *Container) Sandbox() vc.VCSandbox {
	return c.MockSandbox
}

// Process implements the VCContainer function of the same name.
func (c *Container) Process() vc.Process {
	// always return a mockprocess with a non-zero Pid
	if c.MockProcess.Pid == 0 {
		c.MockProcess.Pid = 1000
	}
	return c.MockProcess
}

// GetToken implements the VCContainer function of the same name.
func (c *Container) GetToken() string {
	return c.MockToken
}

// GetPid implements the VCContainer function of the same name.
func (c *Container) GetPid() int {
	return c.MockPid
}

// GetAnnotations implements the VCContainer function of the same name.
func (c *Container) GetAnnotations() map[string]string {
	return c.MockAnnotations
}

// ContainerdID implements the VCContainer function of the same name.
// Always equals MockID — vcmock has no notion of dest/source split.
func (c *Container) ContainerdID() string {
	return c.MockID
}

// InternalID implements the VCContainer function of the same name.
// Returns MockInternalID when set (used by migration adoption tests
// that want to surface a distinct agent-known ID); falls back to
// MockID so non-migration tests stay green without setup.
func (c *Container) InternalID() string {
	if c.MockInternalID != "" {
		return c.MockInternalID
	}
	return c.MockID
}

// GetMigrationBindMounts implements the VCContainer function of the
// same name. vcmock has no real bind-mount table, so returns nil —
// migration tests that exercise this path use the real Container.
func (c *Container) GetMigrationBindMounts() []vc.Mount {
	return nil
}
