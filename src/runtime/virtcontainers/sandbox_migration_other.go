// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

//go:build !linux

package virtcontainers

// markVirtiofsSocketPreserved is a no-op on non-Linux platforms where
// the qemu type (which holds preserveVirtiofsSocket) is not available.
// The Linux implementation lives in sandbox_migration_linux.go.
func (s *Sandbox) markVirtiofsSocketPreserved() {}
