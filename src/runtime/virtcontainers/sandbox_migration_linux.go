// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

// markVirtiofsSocketPreserved signals the hypervisor to preserve the
// virtiofsd vhost-user socket file during teardown. Called from
// Sandbox.stopVM when agentSaved is true (ModeSaved / ModeMigrated
// terminal modes), so a dual-identity successor sandbox on the same
// node can connect to the same vhost-user-fs backend after the source's
// virtiofsd is killed.
//
// Linux-only because the qemu type (which holds preserveVirtiofsSocket)
// is defined in qemu.go (//go:build linux). Non-Linux builds use a
// no-op stub.
func (s *Sandbox) markVirtiofsSocketPreserved() {
	if !s.agentSaved {
		return
	}
	if q, ok := s.hypervisor.(*qemu); ok {
		q.preserveVirtiofsSocket = true
	}
}
