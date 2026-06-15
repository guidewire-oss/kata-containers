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

// A sandbox that reaches a terminal saved/migrated/failed mode has a paused or
// departed guest, so its in-guest agent can no longer answer. The shim MUST
// mark the agent unreachable on that transition so teardown skips agent RPCs
// (agent.waitProcess on a paused guest never returns) and `delete` does not
// hang with the pod stuck Terminating. ModeOwner is the reachable state and
// MUST clear the flag.
func TestTransitionMarksAgentUnreachable(t *testing.T) {
	cases := []struct {
		name string
		from SandboxMigrationMode
		to   SandboxMigrationMode
		want bool
	}{
		{"save pauses the guest", ModeMigratingOut, ModeSaved, true},
		{"migrated out — guest gone", ModeMigratingOut, ModeMigrated, true},
		{"failed — guest wedged", ModeMigratingOut, ModeFailed, true},
		{"handoff complete — agent reachable", ModeIncoming, ModeOwner, false},
		{"abort back to owner — agent reachable", ModeMigratingOut, ModeOwner, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb := &vcmock.Sandbox{MockID: testSandboxID, AgentUnreachableVal: !tc.want}
			s := &service{id: testSandboxID, sandbox: sb, migrationMode: tc.from}
			assert.NoError(t, s.transitionMigrationMode(tc.to))
			assert.Equal(t, tc.to, s.currentMigrationMode())
			assert.Equal(t, tc.want, sb.AgentUnreachableVal,
				"agent-unreachable flag after %s -> %s", tc.from, tc.to)
		})
	}
}
