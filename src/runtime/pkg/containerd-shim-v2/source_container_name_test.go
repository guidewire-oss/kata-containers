// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The source roster keys each container by its CRI container-name. A freshly
// created source reads the name straight from the live OCI annotation. A
// chained source — a pod that itself adopted its identity during a prior
// migration — no longer carries that annotation on its reconstructed
// container, so the name must be recovered from the name->InternalID roster
// this shim recorded when it was a destination. Without the fallback the
// container is dropped from SourceContainers and the next destination cannot
// map it, failing the incoming migration.
func TestResolveSourceContainerName(t *testing.T) {
	const cname = "workload"
	const internalID = "abc123internal"
	nameByInternalID := map[string]string{internalID: cname}

	t.Run("live annotation wins", func(t *testing.T) {
		ann := map[string]string{"io.kubernetes.cri.container-name": cname}
		assert.Equal(t, cname, resolveSourceContainerName(ann, internalID, nameByInternalID))
	})

	t.Run("chained source: recovered from adopted roster by InternalID", func(t *testing.T) {
		ann := map[string]string{} // adopted container lost the annotation
		assert.Equal(t, cname, resolveSourceContainerName(ann, internalID, nameByInternalID))
	})

	t.Run("unknown: no annotation and not in roster -> empty (dropped)", func(t *testing.T) {
		ann := map[string]string{}
		assert.Equal(t, "", resolveSourceContainerName(ann, "unknown-id", nameByInternalID))
	})

	t.Run("nil roster is safe", func(t *testing.T) {
		ann := map[string]string{}
		assert.Equal(t, "", resolveSourceContainerName(ann, internalID, nil))
	})
}
