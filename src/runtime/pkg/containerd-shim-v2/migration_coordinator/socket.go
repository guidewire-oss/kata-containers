// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

// Package migration_coordinator implements the shim-to-shim handoff
// protocol described in
// docs/design/live-migration-shim-lifecycle.md. The destination shim
// runs a Server bound to a per-sandbox unix socket; the source shim
// uses a Client to drive the handoff. Both halves are inert unless
// the experimental.live_migration feature is enabled in the shim's
// runtime configuration.
package migration_coordinator

import "path/filepath"

// socketRoot is the directory under which per-sandbox migration
// coordinator sockets are created. Matches the conventional Kata
// runtime data root so operators looking for these sockets find
// them in the expected place. /run is tmpfs in modern systemd
// installations so we don't leave residue across reboots.
const socketRoot = "/run/kata-containers"

// socketBasename is the unix socket file dropped inside each
// sandbox's directory. The path layout is
// `<socketRoot>/<sandboxID>/<socketBasename>` so different sandboxes
// get isolated directories — easier to operate, easier to clean
// up after a crashed shim.
//
// The name is kept short because Linux caps the total unix socket
// path at sizeof(sockaddr_un.sun_path)=108 bytes; with a 64-char
// containerd-style sandbox ID and the conventional /run/kata-
// containers/ root we have ~22 bytes of headroom for the basename.
const socketBasename = "migrate.sock"

// SocketPath returns the deterministic unix socket path that the
// destination shim binds and the source shim dials for a given
// sandbox ID. An empty sandbox ID returns "" so a caller using the
// result as a dial target fails loudly rather than silently sharing
// a socket across sandboxes.
func SocketPath(sandboxID string) string {
	if sandboxID == "" {
		return ""
	}
	return filepath.Join(socketRoot, sandboxID, socketBasename)
}
