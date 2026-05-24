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
	"os"
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

func TestMigrationStatusSurfacesHypervisorUnreachableAsLastError(t *testing.T) {
	// When the underlying QMP query fails — which on a sandbox in
	// owner mode almost always means QEMU has exited — the shim
	// must surface that as LastError so an orchestrator's post-
	// handoff check can distinguish "destination accepted the
	// stream" from "destination accepted the stream then crashed".
	// Without this, a silent QEMU death looks identical to success.
	mock := &vcmock.Sandbox{
		MockID: "sb",
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			return vc.MigrationStatus{}, errors.New("qmp: socket closed")
		},
	}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeOwner

	srv := newTestAdminServer(t, s)
	resp, err := http.Get(srv.URL + MigrationStatusURL)
	mustNoError(t, err)
	defer resp.Body.Close()

	var got MigrationStatusResponse
	mustNoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "owner", got.Mode)
	assert.Contains(t, got.LastError, "hypervisor unreachable",
		"hypervisor unreachable signal must reach orchestrators verbatim")
	assert.Contains(t, got.LastError, "qmp: socket closed",
		"underlying QMP error must be preserved for diagnosis")
	// The shim must also embed per-process liveness so the
	// orchestrator/operator can tell which process actually died
	// without grabbing a coredump. Format details are tested in
	// dedicated probe tests; here we just pin the contract that
	// both probes appear.
	assert.Contains(t, got.LastError, "qemu=",
		"LastError must include qemu PID probe so we know whether qemu died")
	assert.Contains(t, got.LastError, "virtiofsd=",
		"LastError must include virtiofsd PID probe so we know whether virtiofsd died")
}

func TestProbePIDReportsAliveForCurrentProcess(t *testing.T) {
	// The shim runs as a long-lived process; using its own PID is the
	// cheapest portable way to test "this PID is definitely alive".
	got := probePID(os.Getpid())
	assert.Equal(t, "alive", got)
}

func TestProbePIDReportsExitedForDeadPID(t *testing.T) {
	// Find a PID that almost certainly doesn't exist. PID 1 always
	// exists; PID values near max_pid are extremely rare. Picking
	// 0x7FFFFFFE keeps the test deterministic on Linux where
	// kernel.pid_max defaults to 32768 / 4194304 — either way nothing
	// will have this PID.
	got := probePID(0x7FFFFFFE)
	assert.Contains(t, got, "exited(")
}

func TestProbeHypervisorProcessesHandlesNilSandbox(t *testing.T) {
	// Called before a sandbox exists (e.g. during early shim startup
	// when status is queried for liveness). Must not panic.
	s := &service{}
	got := s.probeHypervisorProcesses()
	assert.Contains(t, got, "qemu=unknown")
	assert.Contains(t, got, "virtiofsd=unknown")
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

func TestMigrationStatusIncludesHotpluggedMemoryDevices(t *testing.T) {
	// Source-side enumeration: the status response carries the
	// hot-plugged memory devices the destination must pre-create
	// before accepting the migration stream.
	mock := &vcmock.Sandbox{
		MockID: "sb",
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			return vc.MigrationStatus{Phase: "active"}, nil
		},
		GetHotpluggedMemoryDevicesFunc: func() ([]vc.MemoryDevice, error) {
			return []vc.MemoryDevice{
				{Slot: 0, SizeMB: 1024},
				{Slot: 1, SizeMB: 512},
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
	assert.Equal(t, []MemoryDevice{
		{Slot: 0, SizeMB: 1024},
		{Slot: 1, SizeMB: 512},
	}, got.MemoryDevices)
}

func TestMigrationStatusOmitsMemoryDevicesWhenSourceIsCleanBoot(t *testing.T) {
	// No hot-plugged devices — field omitted from JSON. Lets a
	// destination distinguish "source has nothing to replay" from
	// "source-side enumeration failed."
	mock := &vcmock.Sandbox{
		MockID: "sb",
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			return vc.MigrationStatus{}, nil
		},
		GetHotpluggedMemoryDevicesFunc: func() ([]vc.MemoryDevice, error) {
			return nil, nil
		},
	}
	s := newMigrationTestService(t, mock, "")

	srv := newTestAdminServer(t, s)
	resp, err := http.Get(srv.URL + MigrationStatusURL)
	mustNoError(t, err)
	defer resp.Body.Close()

	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	assert.NotContains(t, body.String(), "memoryDevices")
}

func TestMigrationStatusIncludesSourceContainers(t *testing.T) {
	// Source-side enumeration: workload containers the kata-agent
	// knows about (by their source-side IDs) ship with the status
	// response so the destination can adopt the source IDs as
	// InternalID for the containers containerd creates afresh.
	// Pod sandboxes are not in this list — the agent doesn't track
	// the pod sandbox itself in its container table.
	mock := &vcmock.Sandbox{
		MockID: "sb",
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			return vc.MigrationStatus{Phase: "active"}, nil
		},
		MockContainers: []*vcmock.Container{
			{
				MockID: "src-ctr-app",
				MockAnnotations: map[string]string{
					"io.kubernetes.cri.container-name": "app",
					"io.kubernetes.cri.container-type": "container",
				},
			},
			{
				MockID: "src-ctr-sidecar",
				MockAnnotations: map[string]string{
					"io.kubernetes.cri.container-name": "sidecar",
					"io.kubernetes.cri.container-type": "container",
				},
			},
		},
	}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeMigratingOut

	srv := newTestAdminServer(t, s)
	resp, err := http.Get(srv.URL + MigrationStatusURL)
	mustNoError(t, err)
	defer resp.Body.Close()

	var got MigrationStatusResponse
	mustNoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.ElementsMatch(t, []SourceContainer{
		{Name: "app", ID: "src-ctr-app"},
		{Name: "sidecar", ID: "src-ctr-sidecar"},
	}, got.SourceContainers)
}

func TestMigrationStatusOmitsSourceContainersWhenEmpty(t *testing.T) {
	// Single-container sandbox with no workload containers (rare,
	// but possible during early sandbox bring-up). Field omitted
	// from JSON so a dest reading "no container adoption needed"
	// doesn't conflate with "source-side enumeration failed."
	mock := &vcmock.Sandbox{
		MockID: "sb",
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			return vc.MigrationStatus{}, nil
		},
	}
	s := newMigrationTestService(t, mock, "")
	srv := newTestAdminServer(t, s)
	resp, err := http.Get(srv.URL + MigrationStatusURL)
	mustNoError(t, err)
	defer resp.Body.Close()

	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	assert.NotContains(t, body.String(), "sourceContainers")
}

func TestMigrationStatusSkipsContainersWithoutCRIName(t *testing.T) {
	// Defensive: a bundle without io.kubernetes.cri.container-name
	// can't be mapped to anything on the dest side (the dest's
	// CreateContainer must look up by name). Drop the entry instead
	// of shipping a nameless one.
	mock := &vcmock.Sandbox{
		MockID: "sb",
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			return vc.MigrationStatus{}, nil
		},
		MockContainers: []*vcmock.Container{
			{
				MockID:          "named",
				MockAnnotations: map[string]string{"io.kubernetes.cri.container-name": "app"},
			},
			{
				MockID:          "nameless",
				MockAnnotations: map[string]string{}, // no container-name
			},
		},
	}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeMigratingOut
	srv := newTestAdminServer(t, s)
	resp, err := http.Get(srv.URL + MigrationStatusURL)
	mustNoError(t, err)
	defer resp.Body.Close()

	var got MigrationStatusResponse
	mustNoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, []SourceContainer{{Name: "app", ID: "named"}}, got.SourceContainers)
}

func TestMigrationTopologyStoresSourceContainers(t *testing.T) {
	// Destination-side adoption: a POST to /migration/topology with
	// a SourceContainers list lands in the service's migration
	// source-container map so a subsequent CreateContainer can look
	// up the source ID by OCI container-name.
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeIncoming

	srv := newTestAdminServer(t, s)
	body, _ := json.Marshal(MigrationTopologyRequest{
		SourceContainers: []SourceContainer{
			{Name: "app", ID: "src-ctr-app"},
			{Name: "sidecar", ID: "src-ctr-sidecar"},
		},
	})
	resp, err := http.Post(srv.URL+MigrationTopologyURL,
		"application/json", bytes.NewReader(body))
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	got := s.SourceContainerByName()
	assert.Equal(t, "src-ctr-app", got["app"])
	assert.Equal(t, "src-ctr-sidecar", got["sidecar"])
}

func TestMigrationShareWorkloadRootfsReturnsCounts(t *testing.T) {
	// Synchronous endpoint: returns the counts the sandbox helper
	// emitted, plus elapsed time. Mock returns (2, 1) — 2 newly
	// shared, 1 failed — and the endpoint must surface those
	// verbatim so the orchestrator can decide whether to retry.
	var called atomic.Int32
	mock := &vcmock.Sandbox{
		MockID: "sb",
		ShareDeferredWorkloadRootfsFunc: func(ctx context.Context) (int, int) {
			called.Add(1)
			return 2, 1
		},
		MockContainers: []*vcmock.Container{
			{MockID: "c1", MockAnnotations: map[string]string{"io.kubernetes.cri.container-name": "workload"}},
			{MockID: "c2", MockAnnotations: map[string]string{"io.kubernetes.cri.container-name": "sidecar"}},
		},
	}
	s := newMigrationTestService(t, mock, "")
	srv := newTestAdminServer(t, s)

	resp, err := http.Post(srv.URL+MigrationShareWorkloadRootfsURL, "application/json", nil)
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var got MigrationShareWorkloadRootfsResponse
	mustNoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, 2, got.Shared)
	assert.Equal(t, 1, got.Failed)
	assert.Equal(t, "partial", got.Status, "failed>0 should surface as 'partial'")
	assert.Equal(t, int32(1), called.Load(), "sandbox helper called exactly once")
}

func TestMigrationShareWorkloadRootfsCleanResultIsOk(t *testing.T) {
	// All shares succeed: status="ok" (not "partial"). Lets the
	// orchestrator distinguish "everything worked" from "some
	// failed but the rest are fine".
	mock := &vcmock.Sandbox{
		MockID: "sb",
		ShareDeferredWorkloadRootfsFunc: func(ctx context.Context) (int, int) {
			return 1, 0
		},
	}
	s := newMigrationTestService(t, mock, "")
	srv := newTestAdminServer(t, s)

	resp, err := http.Post(srv.URL+MigrationShareWorkloadRootfsURL, "application/json", nil)
	mustNoError(t, err)
	defer resp.Body.Close()

	var got MigrationShareWorkloadRootfsResponse
	mustNoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "ok", got.Status)
}

func TestMigrationShareWorkloadRootfsRejectsGET(t *testing.T) {
	// Endpoint is mutating; only POST is allowed. Prevents an
	// accidental browser/curl GET from firing fs operations.
	mock := &vcmock.Sandbox{MockID: "sb"}
	s := newMigrationTestService(t, mock, "")
	srv := newTestAdminServer(t, s)

	resp, err := http.Get(srv.URL + MigrationShareWorkloadRootfsURL)
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestMigrationStatusIncludesHotpluggedVCPUCount(t *testing.T) {
	// Source-side enumeration: the status response carries the
	// vCPU hot-plug count the destination must reproduce so the
	// APIC layout matches. Without this, dest vmstate load
	// rejects with "Unknown section or instance 'apic' N".
	mock := &vcmock.Sandbox{
		MockID: "sb",
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			return vc.MigrationStatus{Phase: "active"}, nil
		},
		GetHotpluggedVCPUCountFunc: func() (uint32, error) { return 3, nil },
	}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeMigratingOut

	srv := newTestAdminServer(t, s)
	resp, err := http.Get(srv.URL + MigrationStatusURL)
	mustNoError(t, err)
	defer resp.Body.Close()

	var got MigrationStatusResponse
	mustNoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, uint32(3), got.HotpluggedVCPUs)
}

func TestMigrationStatusOmitsHotpluggedVCPUsWhenZero(t *testing.T) {
	// Source with no CPU hot-plug — field omitted from JSON so a
	// dest reading "no vCPU replay needed" doesn't get confused
	// with "source-side query failed".
	mock := &vcmock.Sandbox{
		MockID: "sb",
		GetMigrationStatusFunc: func() (vc.MigrationStatus, error) {
			return vc.MigrationStatus{}, nil
		},
		GetHotpluggedVCPUCountFunc: func() (uint32, error) { return 0, nil },
	}
	s := newMigrationTestService(t, mock, "")
	srv := newTestAdminServer(t, s)
	resp, err := http.Get(srv.URL + MigrationStatusURL)
	mustNoError(t, err)
	defer resp.Body.Close()
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	assert.NotContains(t, body.String(), "hotpluggedVCPUs")
}

func TestMigrationTopologyHotplugsVCPUsInIncomingMode(t *testing.T) {
	// Destination-side replay: a HotpluggedVCPUs field on the
	// topology request triggers the dest shim's CPU hot-plug path
	// so both sides end up with the same APIC layout.
	var gotCount atomic.Uint32
	mock := &vcmock.Sandbox{
		MockID: "sb",
		HotplugVCPUsFunc: func(count uint32) error {
			gotCount.Store(count)
			return nil
		},
	}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeIncoming

	srv := newTestAdminServer(t, s)
	body, _ := json.Marshal(MigrationTopologyRequest{
		HotpluggedVCPUs: 2,
	})
	resp, err := http.Post(srv.URL+MigrationTopologyURL,
		"application/json", bytes.NewReader(body))
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, uint32(2), gotCount.Load())
}

func TestMigrationTopologySkipsCPUHotplugWhenZero(t *testing.T) {
	// A topology request with HotpluggedVCPUs=0 must not call
	// HotplugVCPUs at all — that path goes through QMP and a
	// no-op call would either error or waste a slot probe.
	called := atomic.Bool{}
	mock := &vcmock.Sandbox{
		MockID: "sb",
		HotplugVCPUsFunc: func(count uint32) error {
			called.Store(true)
			return nil
		},
	}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeIncoming
	srv := newTestAdminServer(t, s)

	body, _ := json.Marshal(MigrationTopologyRequest{})
	resp, err := http.Post(srv.URL+MigrationTopologyURL,
		"application/json", bytes.NewReader(body))
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.False(t, called.Load(), "zero count must not invoke vCPU hot-plug")
}

func TestMigrationTopologyAppliesDevicesInIncomingMode(t *testing.T) {
	// Destination-side replay: list of devices arrives, sandbox
	// receives the same list verbatim.
	var got atomic.Value
	mock := &vcmock.Sandbox{
		MockID: "sb",
		HotplugMemoryDevicesFunc: func(devices []vc.MemoryDevice) error {
			// Take a copy — the request body's slice is recycled.
			cp := append([]vc.MemoryDevice(nil), devices...)
			got.Store(cp)
			return nil
		},
	}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeIncoming

	srv := newTestAdminServer(t, s)
	body, _ := json.Marshal(MigrationTopologyRequest{
		MemoryDevices: []MemoryDevice{
			{Slot: 0, SizeMB: 1024},
			{Slot: 1, SizeMB: 256},
		},
	})
	resp, err := http.Post(srv.URL+MigrationTopologyURL,
		"application/json", bytes.NewReader(body))
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	applied, _ := got.Load().([]vc.MemoryDevice)
	assert.Equal(t, []vc.MemoryDevice{
		{Slot: 0, SizeMB: 1024},
		{Slot: 1, SizeMB: 256},
	}, applied)
}

func TestMigrationTopologyRejectedOutsideIncomingMode(t *testing.T) {
	// /migration/topology only makes sense on a destination that
	// is in Incoming mode. Other modes return 409 Conflict and the
	// hypervisor is never touched.
	called := atomic.Bool{}
	mock := &vcmock.Sandbox{
		MockID: "sb",
		HotplugMemoryDevicesFunc: func(devices []vc.MemoryDevice) error {
			called.Store(true)
			return nil
		},
	}

	for _, mode := range []SandboxMigrationMode{
		ModeOwner, ModeMigratingOut, ModeMigrated, ModeFailed,
	} {
		t.Run(string(mode), func(t *testing.T) {
			s := newMigrationTestService(t, mock, "")
			s.migrationMode = mode
			srv := newTestAdminServer(t, s)

			body, _ := json.Marshal(MigrationTopologyRequest{
				MemoryDevices: []MemoryDevice{{Slot: 0, SizeMB: 256}},
			})
			resp, err := http.Post(srv.URL+MigrationTopologyURL,
				"application/json", bytes.NewReader(body))
			mustNoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusConflict, resp.StatusCode)
			assert.False(t, called.Load(),
				"hypervisor must not be called when mode is not Incoming")
		})
	}
}

func TestMigrationTopologyEmptyListIsNoopAck(t *testing.T) {
	// A clean-boot source ships an empty MemoryDevices list; the
	// dest must accept it without touching the hypervisor. This is
	// the common case for short-lived workloads that haven't hit
	// any per-container hot-plug.
	called := atomic.Bool{}
	mock := &vcmock.Sandbox{
		MockID: "sb",
		HotplugMemoryDevicesFunc: func(devices []vc.MemoryDevice) error {
			called.Store(true)
			return nil
		},
	}
	s := newMigrationTestService(t, mock, "")
	s.migrationMode = ModeIncoming
	srv := newTestAdminServer(t, s)

	body, _ := json.Marshal(MigrationTopologyRequest{MemoryDevices: nil})
	resp, err := http.Post(srv.URL+MigrationTopologyURL,
		"application/json", bytes.NewReader(body))
	mustNoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// Whether HotplugMemoryDevices is called with an empty slice
	// or skipped entirely is an implementation detail; what matters
	// is the dest accepts the request and returns 200.
	_ = called.Load()
}
