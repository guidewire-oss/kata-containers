// Copyright (c) 2026 Kata Containers contributors
//
// SPDX-License-Identifier: Apache-2.0

package virtcontainers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A bind target must match the KIND of its source. Creating a file
// unconditionally meant every directory mount — which is every Kubernetes
// volume — failed to bind with ENOTDIR and was skipped, leaving the migrated
// guest with a mount entry pointing at nothing and EIO on every read below it.
func TestPrecreateBindTarget(t *testing.T) {
	assert := assert.New(t)

	t.Run("directory source yields a directory target", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "src-volume")
		assert.NoError(os.MkdirAll(src, 0o755))
		target := filepath.Join(root, "shared", "cid-rand-workspace")

		assert.NoError(precreateBindTarget(src, target))

		st, err := os.Stat(target)
		assert.NoError(err)
		assert.True(st.IsDir(), "a directory mount needs a directory target, or bindMount fails ENOTDIR")
	})

	t.Run("file source yields a file target", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "resolv.conf")
		assert.NoError(os.WriteFile(src, []byte("nameserver 1.1.1.1\n"), 0o644))
		target := filepath.Join(root, "shared", "cid-rand-resolv.conf")

		assert.NoError(precreateBindTarget(src, target))

		st, err := os.Stat(target)
		assert.NoError(err)
		assert.False(st.IsDir(), "the aux-file behaviour this path was written for must not regress")
	})

	t.Run("an existing target is left untouched", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "src-volume")
		assert.NoError(os.MkdirAll(src, 0o755))
		target := filepath.Join(root, "already-there")
		assert.NoError(os.WriteFile(target, []byte("keep me"), 0o644))

		assert.NoError(precreateBindTarget(src, target))

		body, err := os.ReadFile(target)
		assert.NoError(err)
		assert.Equal("keep me", string(body), "re-creating an existing target would be destructive")
	})

	t.Run("a missing source falls back to a file, as before", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "shared", "cid-rand-gone")

		assert.NoError(precreateBindTarget(filepath.Join(root, "does-not-exist"), target))

		st, err := os.Stat(target)
		assert.NoError(err)
		assert.False(st.IsDir())
	})
}
