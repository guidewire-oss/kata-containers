// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/experimental"
)

// Migration admin HTTP endpoints exposed on the shim management
// server. The Phase E orchestration controller (running elsewhere
// in the cluster) calls these via a node-local migration agent.
// Endpoint paths are versioned implicitly: changing them is a
// protocol break.
const (
	MigrationOutURL      = "/migration/out"
	MigrationInURL       = "/migration/in"
	MigrationAbortURL    = "/migration/abort"
	MigrationStatusURL   = "/migration/status"
	MigrationTopologyURL = "/migration/topology"
)

// MemoryDevice is the wire representation of one hot-plugged memory
// device on the source QEMU. The orchestrator collects these from
// the source's /migration/status response and replays them via
// /migration/topology on the destination before issuing migrate.
//
// Only Slot and SizeMB cross the wire. Mem-path, share, and the
// memory backend kind come from the destination's local kata config
// — both ends are expected to run the same config, so kata's
// getMemArgs produces the matching backend on the destination
// automatically. Address is QEMU-assigned and not portable.
type MemoryDevice struct {
	Slot   int `json:"slot"`
	SizeMB int `json:"sizeMB"`
}

// MigrationInRequest is the body for POST /migration/in.
type MigrationInRequest struct {
	// ListenURI is the address QEMU should bind for the incoming
	// migration (e.g. "tcp:0.0.0.0:4444"). Required.
	ListenURI string `json:"listenURI"`
}

// MigrationOutRequest is the body for POST /migration/out.
type MigrationOutRequest struct {
	// DestSocketPath is the unix socket of the destination shim's
	// MigrationCoordinator. Required.
	DestSocketPath string `json:"destSocketPath"`

	// DataHostHint is the address the source's QEMU should dial
	// for the actual memory transfer. The destination QEMU binds
	// its `migrate-incoming tcp:0.0.0.0:<port>` listener INSIDE
	// the sandbox network namespace, so the host derived from
	// DestSocketPath (the coordinator's host — typically a node
	// IP because the shim runs in the host netns) is the wrong
	// place to send the data. The orchestrator that knows both
	// the coordinator and the destination pod IP passes the pod
	// IP here so rewriteIncomingHost picks it up.
	// Empty == legacy behavior (use the host from DestSocketPath).
	DataHostHint string `json:"dataHostHint,omitempty"`

	// Capabilities passed to MigrateOptions. Optional.
	Capabilities map[string]bool `json:"capabilities,omitempty"`

	// Parameters passed to MigrateOptions. Optional.
	Parameters map[string]uint64 `json:"parameters,omitempty"`
}

// MigrationAbortRequest is the body for POST /migration/abort.
type MigrationAbortRequest struct {
	// Reason is the free-form text logged with the abort. Optional.
	Reason string `json:"reason,omitempty"`
}

// MigrationStatusResponse is the body returned by GET /migration/status.
type MigrationStatusResponse struct {
	// Mode is the shim's current SandboxMigrationMode string.
	// Always present.
	Mode string `json:"mode"`

	// HypervisorPhase is the underlying hypervisor's reported
	// phase ("setup", "active", "completed", "failed", etc.).
	// Omitted when not migrating.
	HypervisorPhase string `json:"hypervisorPhase,omitempty"`

	// BytesTransferred and TotalBytes are progress indicators
	// from the hypervisor. Omitted when zero.
	BytesTransferred uint64 `json:"bytesTransferred,omitempty"`
	TotalBytes       uint64 `json:"totalBytes,omitempty"`

	// RemainingMs is the hypervisor's estimate of completion
	// time. Omitted when zero.
	RemainingMs uint64 `json:"remainingMs,omitempty"`

	// CoordinatorTCPAddr is the host:port the destination shim's
	// MigrationCoordinator TCP listener is bound to. Present only
	// on destination shims; the orchestrator reads it and passes
	// "tcp:<node-ip>:<port>" to the source's /migration/out.
	CoordinatorTCPAddr string `json:"coordinatorTcpAddr,omitempty"`

	// MemoryDevices lists the memory devices that have been
	// hot-plugged at runtime on the source QEMU. Empty (and
	// omitted) when the source has done no memory hot-plug, or on
	// the destination side. The orchestrator collects this list
	// from the source's status and POSTs it to the destination's
	// /migration/topology before issuing /migration/out, so the
	// destination QEMU's ramblock table matches what the source
	// will send. Without this, runtime-hotplugged ramblocks named
	// `mem<slot>` cause QEMU on the destination to reject the
	// migration with "Unknown ramblock". See the design doc at
	// docs/kata-migration-topology-replay.md in the orchestrator
	// repo (vamos) for the full sequence.
	MemoryDevices []MemoryDevice `json:"memoryDevices,omitempty"`
}

// MigrationTopologyRequest is the body for POST /migration/topology.
type MigrationTopologyRequest struct {
	// MemoryDevices is the list of hot-plugged memory devices the
	// destination should pre-create before accepting the migration
	// stream. Must be in slot order. An empty list is a valid
	// no-op (e.g. when the source has never hot-plugged).
	MemoryDevices []MemoryDevice `json:"memoryDevices"`
}

// liveMigrationConfigured reports whether live_migration appears in
// the runtime config's experimental feature list. Checked at
// management-server startup to decide whether to register the
// migration admin endpoints — operators who haven't opted in see
// 404s and the migration code paths stay dormant.
func (s *service) liveMigrationConfigured() bool {
	if s.config == nil {
		return false
	}
	for _, f := range s.config.Experimental {
		if f.Name == LiveMigrationFeature.Name {
			return true
		}
	}
	return false
}

// registerMigrationAdminHandlers wires the four migration admin
// endpoints onto the supplied mux. The shim management server
// calls this from startManagementServer when the live_migration
// experimental feature is enabled in the runtime config; if it is
// not enabled the endpoints are not registered and requests
// receive 404 from the mux's default handler.
func (s *service) registerMigrationAdminHandlers(m *http.ServeMux) {
	m.HandleFunc(MigrationInURL, s.handleMigrationIn)
	m.HandleFunc(MigrationOutURL, s.handleMigrationOut)
	m.HandleFunc(MigrationAbortURL, s.handleMigrationAbort)
	m.HandleFunc(MigrationStatusURL, s.handleMigrationStatus)
	m.HandleFunc(MigrationTopologyURL, s.handleMigrationTopology)
}

func (s *service) handleMigrationIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req MigrationInRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("decode body: %v", err), http.StatusBadRequest)
		return
	}
	if req.ListenURI == "" {
		http.Error(w, "listenURI is required", http.StatusBadRequest)
		return
	}
	ctx := experimental.ContextWithExp(r.Context(), []string{LiveMigrationFeature.Name})
	if err := s.BeginMigrateIncoming(ctx, req.ListenURI); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *service) handleMigrationOut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req MigrationOutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("decode body: %v", err), http.StatusBadRequest)
		return
	}
	if req.DestSocketPath == "" {
		http.Error(w, "destSocketPath is required", http.StatusBadRequest)
		return
	}
	ctx := experimental.ContextWithExp(r.Context(), []string{LiveMigrationFeature.Name})
	err := s.BeginMigrateOut(ctx, req.DestSocketPath, req.DataHostHint, vc.MigrateOptions{
		Capabilities: req.Capabilities,
		Parameters:   req.Parameters,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *service) handleMigrationAbort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req MigrationAbortRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("decode body: %v", err), http.StatusBadRequest)
		return
	}
	if err := s.AbortMigration(r.Context(), req.Reason); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *service) handleMigrationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := MigrationStatusResponse{
		Mode: s.currentMigrationMode().String(),
	}
	// Best-effort: pull live hypervisor stats. A nil sandbox
	// (during early shim startup) returns zeros which serialize
	// as omitted JSON fields — fine.
	if s.sandbox != nil {
		status, err := s.sandbox.GetMigrationStatus(r.Context())
		if err == nil {
			resp.HypervisorPhase = status.Phase
			resp.BytesTransferred = status.BytesTransferred
			resp.TotalBytes = status.TotalBytes
			resp.RemainingMs = status.RemainingMS
		}
		// Hot-plugged memory devices on the source. Best-effort:
		// if QMP query-memory-devices fails, log and continue —
		// callers that need this list will see an empty value and
		// fail their own preflight cleanly, rather than blocking
		// the rest of the status payload.
		devs, err := s.sandbox.GetHotpluggedMemoryDevices(r.Context())
		if err != nil {
			shimLog.WithError(err).Debug("GetHotpluggedMemoryDevices")
		} else {
			for _, d := range devs {
				resp.MemoryDevices = append(resp.MemoryDevices, MemoryDevice{
					Slot:   d.Slot,
					SizeMB: d.SizeMB,
				})
			}
		}
	}
	// Destination shims expose the kernel-assigned TCP address
	// the MigrationCoordinator is listening on so the
	// orchestrator can hand it to the source's /migration/out.
	if addr := s.coordinatorTCPAddr(); addr != "" {
		resp.CoordinatorTCPAddr = addr
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleMigrationTopology is the destination-side endpoint that
// pre-creates memory devices via QMP before the migration data
// stream arrives. Required when the source has done any runtime
// memory hot-plug — otherwise the destination QEMU rejects the
// stream with "Unknown ramblock".
//
// Gated on mode == Incoming. Idempotent re-invocation will fail at
// the second QMP `device_add` for the same slot — callers should
// invoke this exactly once between "destination shim ready" and
// /migration/out on the source.
func (s *service) handleMigrationTopology(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req MigrationTopologyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("decode body: %v", err), http.StatusBadRequest)
		return
	}
	if s.sandbox == nil {
		http.Error(w, "sandbox not ready", http.StatusServiceUnavailable)
		return
	}
	mode := s.currentMigrationMode()
	if mode != ModeIncoming {
		http.Error(w,
			fmt.Sprintf("topology only accepted in Incoming mode (current=%s)", mode),
			http.StatusConflict)
		return
	}
	devs := make([]vc.MemoryDevice, len(req.MemoryDevices))
	for i, d := range req.MemoryDevices {
		devs[i] = vc.MemoryDevice{Slot: d.Slot, SizeMB: d.SizeMB}
	}
	if err := s.sandbox.HotplugMemoryDevices(r.Context(), devs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// coordinatorTCPAddr returns the bound TCP address of the
// destination-side MigrationCoordinator, or "" if none is bound.
// Reads under migrationMu since migrationServer can be nil during
// the brief window between sandbox creation and
// BeginMigrateIncoming.
func (s *service) coordinatorTCPAddr() string {
	s.migrationMu.Lock()
	srv := s.migrationServer
	s.migrationMu.Unlock()
	if srv == nil {
		return ""
	}
	if tcpAddr, ok := srv.(interface{ TCPAddr() net.Addr }); ok {
		if a := tcpAddr.TCPAddr(); a != nil {
			return a.String()
		}
	}
	return ""
}
