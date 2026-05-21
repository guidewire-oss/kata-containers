// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package migration_coordinator

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSocketPathDeterministicForSandbox(t *testing.T) {
	// Same sandbox ID must always produce the same path — the
	// source shim derives its dial target from this function
	// against the destination's sandbox ID.
	id := "a1b2c3d4-e5f6-4a5b-9c8d-1234567890ab"
	assert.Equal(t, SocketPath(id), SocketPath(id))
}

func TestSocketPathDistinctSandboxes(t *testing.T) {
	a := SocketPath("aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
	b := SocketPath("bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb")
	assert.NotEqual(t, a, b, "different sandbox IDs must produce different paths")
}

func TestSocketPathFitsLinuxUnixSocketLimit(t *testing.T) {
	// Linux caps unix socket paths at 108 bytes
	// (sizeof(sockaddr_un.sun_path) - 1 for the null terminator).
	// Container runtimes routinely have long IDs, so verify the
	// derived path stays under the limit for a generous worst case.
	const linuxUnixSocketPathLimit = 108
	worstCase := strings.Repeat("a", 64) // longer than any real sandbox ID
	p := SocketPath(worstCase)
	if len(p) >= linuxUnixSocketPathLimit {
		t.Fatalf("socket path is %d bytes (limit %d): %s",
			len(p), linuxUnixSocketPathLimit, p)
	}
}

func TestSocketPathRejectsEmpty(t *testing.T) {
	// An empty sandbox ID is a programmer error — the source must
	// always know which sandbox it is migrating. Return an empty
	// path so a caller using it as a dial target fails loudly
	// rather than silently sharing a socket across sandboxes.
	assert.Equal(t, "", SocketPath(""))
}

func TestSocketDirContainsSandboxID(t *testing.T) {
	// The path includes the sandbox ID as a directory component
	// so concurrent migrations on the same host get isolated
	// directories — easier to operate, easier to clean up.
	id := "deadbeef-1234-5678-9abc-def012345678"
	assert.Contains(t, SocketPath(id), id)
}
