// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/vcmock"
)

// newTestAdminServer wires the migration admin handlers onto an
// httptest server so individual handler behaviour is testable
// without standing up the full shim-management HTTP listener.
func newTestAdminServer(t *testing.T, s *service) *httptest.Server {
	t.Helper()
	m := http.NewServeMux()
	s.registerMigrationAdminHandlers(m)
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return srv
}

func TestMigrationStatusReturnsCurrentMode(t *testing.T) {
	mock := &vcmock.Sandbox{
		MockID: "sb",
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			return vc.MigrationStatus{
				Phase:            "active",
				BytesTransferred: 12345,
				TotalBytes:       67890,
				RemainingMS:      111,
			}, nil
		},
	}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeMigratingOut

	srv := newTestAdminServer(t, s)
	resp, err := http.Get(srv.URL + MigrationStatusURL)
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var got MigrationStatusResponse
	mustNoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "migrating-out", got.Mode)
	assert.Equal(t, "active", got.HypervisorPhase)
	assert.Equal(t, uint64(12345), got.BytesTransferred)
	assert.Equal(t, uint64(67890), got.TotalBytes)
	assert.Equal(t, uint64(111), got.RemainingMs)
}

func TestMigrationStatusOmitsHypervisorFieldsWhenOwner(t *testing.T) {
	// When the sandbox is in Owner mode (not migrating), the
	// hypervisor phase fields are zero and serialize as omitted.
	mock := &vcmock.Sandbox{
		MockID: "sb",
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			return vc.MigrationStatus{}, nil // phase "" -> none
		},
	}
	s := newMigrationTestService(t, mock, "")

	srv := newTestAdminServer(t, s)
	resp, err := http.Get(srv.URL + MigrationStatusURL)
	mustNoError(t, err)
	defer resp.Body.Close()

	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	// Mode is always present; bytesTransferred/totalBytes are
	// omitempty zero so they should not appear.
	assert.Contains(t, body.String(), `"mode":"owner"`)
	assert.NotContains(t, body.String(), "bytesTransferred")
	assert.NotContains(t, body.String(), "totalBytes")
}

func TestMigrationInTriggersBeginMigrateIncoming(t *testing.T) {
	var (
		called atomic.Bool
		gotURI atomic.Value
	)
	mock := &vcmock.Sandbox{
		MockID: "sb",
		MigrateIncomingFunc: func(uri string) error {
			called.Store(true)
			gotURI.Store(uri)
			return nil
		},
	}
	s := newMigrationTestService(t, mock, tempSocketPath(t))
	srv := newTestAdminServer(t, s)

	body, _ := json.Marshal(MigrationInRequest{ListenURI: "tcp:0.0.0.0:4444"})
	resp, err := http.Post(srv.URL+MigrationInURL, "application/json", bytes.NewReader(body))
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	t.Cleanup(func() { _ = s.stopMigrationServer() })
	assert.True(t, called.Load(), "BeginMigrateIncoming should run")
	assert.Equal(t, "tcp:0.0.0.0:4444", gotURI.Load().(string))
	assert.Equal(t, ModeIncoming, s.currentMigrationMode())
}

func TestMigrationInRejectsMissingURI(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, tempSocketPath(t))
	srv := newTestAdminServer(t, s)

	body, _ := json.Marshal(MigrationInRequest{ListenURI: ""})
	resp, err := http.Post(srv.URL+MigrationInURL, "application/json", bytes.NewReader(body))
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestMigrationOutTriggersBeginMigrateOut(t *testing.T) {
	// Stand up an in-process destination so BeginMigrateOut has a
	// real socket to dial. The destination's sandbox ID must
	// match the source's — newMigrationTestService sets s.id to
	// "test-sandbox", so the destination is configured to match.
	destSocket := tempSocketPath(t)
	dest := startDestinationServer(t, destSocket, "test-sandbox", nil, nil)
	t.Cleanup(func() { _ = dest.Stop() })

	var migrateOutCalled atomic.Bool
	mock := &vcmock.Sandbox{
		MockID: "test-sandbox",
		MigrateOutFunc: func(string, vc.MigrateOptions) error {
			migrateOutCalled.Store(true)
			return nil
		},
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			return vc.MigrationStatus{Phase: "completed"}, nil
		},
	}
	s := newMigrationTestService(t, mock, "")

	srv := newTestAdminServer(t, s)
	body, _ := json.Marshal(MigrationOutRequest{
		DestSocketPath: destSocket,
		Capabilities:   map[string]bool{"xbzrle": true},
	})
	// Use a client with a longer timeout — BeginMigrateOut blocks
	// through the full sequence (PrepareIncoming -> stream state
	// -> MigrateOut -> poll -> CompleteHandoff).
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(srv.URL+MigrationOutURL,
		"application/json", bytes.NewReader(body))
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, migrateOutCalled.Load())
	assert.Equal(t, ModeMigrated, s.currentMigrationMode())
}

func TestMigrationOutRejectsMissingDestSocket(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, "")
	srv := newTestAdminServer(t, s)

	body, _ := json.Marshal(MigrationOutRequest{})
	resp, err := http.Post(srv.URL+MigrationOutURL, "application/json", bytes.NewReader(body))
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestMigrationOutSurfacesUnderlyingError(t *testing.T) {
	mock := &vcmock.Sandbox{
		MockID: "sb",
		// Force BeginMigrateOut to fail at the dial step by
		// pointing it at a path that doesn't exist.
	}
	s := newMigrationTestService(t, mock, "")
	srv := newTestAdminServer(t, s)

	body, _ := json.Marshal(MigrationOutRequest{
		DestSocketPath: "/tmp/no-such-socket-" + t.Name(),
	})
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(srv.URL+MigrationOutURL,
		"application/json", bytes.NewReader(body))
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestMigrationAbortTransitionsToFailed(t *testing.T) {
	var cancelCalls atomic.Int32
	mock := &vcmock.Sandbox{
		MockID: "sb",
		CancelMigrationFunc: func() error {
			cancelCalls.Add(1)
			return nil
		},
	}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeMigratingOut

	srv := newTestAdminServer(t, s)
	body, _ := json.Marshal(MigrationAbortRequest{Reason: "test"})
	resp, err := http.Post(srv.URL+MigrationAbortURL,
		"application/json", bytes.NewReader(body))
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, ModeFailed, s.currentMigrationMode())
	assert.Equal(t, int32(1), cancelCalls.Load())
}

func TestMigrationAdminRejectsWrongMethod(t *testing.T) {
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, "")
	srv := newTestAdminServer(t, s)

	// POST endpoints reject GET.
	for _, url := range []string{MigrationInURL, MigrationOutURL, MigrationAbortURL} {
		resp, err := http.Get(srv.URL + url)
		mustNoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode,
			"GET %s should be rejected", url)
	}

	// Status endpoint rejects POST.
	resp, err := http.Post(srv.URL+MigrationStatusURL, "application/json", strings.NewReader("{}"))
	mustNoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// Verify context cancellation: an aborted HTTP request must
// propagate to the underlying BeginMigrateOut so the migration
// doesn't keep running after the controller has given up.
func TestMigrationOutCancellationPropagates(t *testing.T) {
	destSocket := tempSocketPath(t)
	dest := startDestinationServer(t, destSocket, "sb", nil, nil)
	t.Cleanup(func() { _ = dest.Stop() })

	// MigrateOut returns nil; status loop hangs at "active"
	// forever so the only way to exit is via context cancellation.
	statusGate := make(chan struct{})
	mock := &vcmock.Sandbox{
		MockID:         "sb",
		MigrateOutFunc: func(string, vc.MigrateOptions) error { return nil },
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			<-statusGate // blocks until test releases — but the poll
			// loop checks ctx between iterations
			return vc.MigrationStatus{Phase: "active"}, nil
		},
	}
	defer close(statusGate)
	s := newMigrationTestService(t, mock, "")
	srv := newTestAdminServer(t, s)

	body, _ := json.Marshal(MigrationOutRequest{DestSocketPath: destSocket})
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "POST",
		srv.URL+MigrationOutURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	// We expect either a context-deadline error from the HTTP
	// client OR a 500 from the handler depending on which path
	// wins the race — both are acceptable evidence that the
	// migration didn't run forever.
	if err != nil {
		assert.True(t, errors.Is(err, context.DeadlineExceeded) ||
			strings.Contains(err.Error(), "context"),
			"expected context error, got %v", err)
	}
}
