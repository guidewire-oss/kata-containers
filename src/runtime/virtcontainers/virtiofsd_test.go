// Copyright (c) 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVirtiofsdStart(t *testing.T) {
	// nolint: govet
	type fields struct {
		path       string
		socketPath string
		cache      string
		extraArgs  []string
		sourcePath string
		PID        int
		ctx        context.Context
	}

	sourcePath := t.TempDir()
	socketDir := t.TempDir()

	socketPath := path.Join(socketDir, "socket.s")

	validConfig := fields{
		path:       "/usr/bin/virtiofsd-path",
		socketPath: socketPath,
		sourcePath: sourcePath,
	}
	NoDirectorySocket := validConfig
	NoDirectorySocket.socketPath = "/tmp/path/to/virtiofsd/socket.sock"

	// nolint: govet
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"empty config", fields{}, true},
		{"Directory socket does not exist", NoDirectorySocket, true},
		{"valid config", validConfig, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &virtiofsd{
				path:       tt.fields.path,
				socketPath: tt.fields.socketPath,
				cache:      tt.fields.cache,
				extraArgs:  tt.fields.extraArgs,
				sourcePath: tt.fields.sourcePath,
				PID:        tt.fields.PID,
				ctx:        tt.fields.ctx,
			}
			ctx := context.Background()
			_, err := v.Start(ctx, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("virtiofsd.Start() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestVirtiofsdArgs(t *testing.T) {
	assert := assert.New(t)

	v := &virtiofsd{
		path:       "/usr/bin/virtiofsd",
		sourcePath: "/run/kata-shared/foo",
		cache:      "never",
	}

	// The migration-mode and migration-on-error flags are emitted
	// unconditionally so source and dest virtiofsd negotiate state
	// transfer correctly during a live migration. See virtiofsd.go::args().
	migrationFlags := "--migration-mode=find-paths --migration-on-error=guest-error"

	expected := "--syslog --cache=never --shared-dir=/run/kata-shared/foo --fd=123 " + migrationFlags
	args, err := v.args(123)
	assert.NoError(err)
	assert.Equal(expected, strings.Join(args, " "))

	expected = "--syslog --cache=never --shared-dir=/run/kata-shared/foo --fd=456 " + migrationFlags
	args, err = v.args(456)
	assert.NoError(err)
	assert.Equal(expected, strings.Join(args, " "))
}

func TestValid(t *testing.T) {
	a := assert.New(t)

	sourcePath := t.TempDir()
	socketDir := t.TempDir()

	socketPath := socketDir + "socket.s"

	newVirtiofsdFunc := func() *virtiofsd {
		return &virtiofsd{
			path:       "/usr/bin/virtiofsd",
			sourcePath: sourcePath,
			socketPath: socketPath,
			cache:      "auto",
		}
	}

	type fieldFunc func(v *virtiofsd)
	type assertFunc func(name string, assert *assert.Assertions, v *virtiofsd)

	// nolint: govet
	tests := []struct {
		name         string
		f            fieldFunc
		wantErr      error
		customAssert assertFunc
	}{
		{"valid case", nil, nil, nil},
		{"no path", func(v *virtiofsd) {
			v.path = ""
		}, errVirtiofsdDaemonPathEmpty, nil},
		{"no sourcePath", func(v *virtiofsd) {
			v.sourcePath = ""
		}, errVirtiofsdSourcePathEmpty, nil},
		{"no socketPath", func(v *virtiofsd) {
			v.socketPath = ""
		}, errVirtiofsdSocketPathEmpty, nil},
		{"source is not available", func(v *virtiofsd) {
			v.sourcePath = "/foo/bar"
		}, errVirtiofsdSourceNotAvailable, nil},
		{"invalid cache mode", func(v *virtiofsd) {
			v.cache = "foo"
		}, errVirtiofsdInvalidVirtiofsCacheMode("foo"), nil},
		{"valid metadata cache mode", func(v *virtiofsd) {
			v.cache = typeVirtioFSCacheModeMetadata
		}, nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newVirtiofsdFunc()
			if tt.f != nil {
				tt.f(v)
			}
			err := v.valid()
			if tt.wantErr != nil && err == nil {
				t.Errorf("test case %+s: virtiofsd.valid() should get error `%+v`, but got nil", tt.name, tt.wantErr)
			} else if tt.wantErr == nil && err != nil {
				t.Errorf("test case %+s: virtiofsd.valid() should get no erro, but got `%+v`", tt.name, err)
			} else if tt.wantErr != nil && err != nil {
				a.Equal(err.Error(), tt.wantErr.Error(), "test case %+s", tt.name)
			}

			if tt.customAssert != nil {
				tt.customAssert(tt.name, a, v)
			}
		})
	}
}

// startVirtiofsdTestProcess starts a real child process whose PID stands in
// for virtiofsd, so Stop's kill path runs against a live process. Reaped on
// test cleanup.
func startVirtiofsdTestProcess(t *testing.T) *exec.Cmd {
	cmd := exec.Command("sleep", "60")
	assert.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd
}

// With preserveSocket set (a dual-identity successor may share the
// /run/vc/vm/<InternalID>/ dir), Stop must kill the process but leave the
// vhost-user socket file in place for the successor's QEMU.
func TestVirtiofsdStopPreservesSocketForSuccessor(t *testing.T) {
	assert := assert.New(t)

	cmd := startVirtiofsdTestProcess(t)
	sock := filepath.Join(t.TempDir(), "vhost-fs.sock")
	assert.NoError(os.WriteFile(sock, nil, 0o600))

	v := &virtiofsd{PID: cmd.Process.Pid, socketPath: sock, preserveSocket: true}
	assert.NoError(v.Stop(context.Background()))

	_, err := os.Stat(sock)
	assert.NoError(err, "socket file must survive Stop when preserveSocket is set")
}

// Default (non-migration) teardown keeps the original behavior: kill the
// process and remove the socket file.
func TestVirtiofsdStopRemovesSocketByDefault(t *testing.T) {
	assert := assert.New(t)

	cmd := startVirtiofsdTestProcess(t)
	sock := filepath.Join(t.TempDir(), "vhost-fs.sock")
	assert.NoError(os.WriteFile(sock, nil, 0o600))

	v := &virtiofsd{PID: cmd.Process.Pid, socketPath: sock}
	assert.NoError(v.Stop(context.Background()))

	_, err := os.Stat(sock)
	assert.True(os.IsNotExist(err), "socket file must be removed on default Stop")
}

// A virtiofsd that is already dead (kill returns ESRCH) must not fail Stop
// and must leave the socket alone — the early-return path a dual-identity
// successor relies on.
func TestVirtiofsdStopDeadProcessLeavesSocket(t *testing.T) {
	assert := assert.New(t)

	cmd := exec.Command("sleep", "60")
	assert.NoError(cmd.Start())
	assert.NoError(cmd.Process.Kill())
	_, _ = cmd.Process.Wait() // reap so the PID is gone

	sock := filepath.Join(t.TempDir(), "vhost-fs.sock")
	assert.NoError(os.WriteFile(sock, nil, 0o600))

	v := &virtiofsd{PID: cmd.Process.Pid, socketPath: sock}
	assert.NoError(v.Stop(context.Background()))

	_, err := os.Stat(sock)
	assert.NoError(err, "socket must remain when the process was already dead")
}
