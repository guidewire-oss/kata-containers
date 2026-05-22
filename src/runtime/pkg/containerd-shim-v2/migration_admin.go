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
	MigrationOutURL    = "/migration/out"
	MigrationInURL     = "/migration/in"
	MigrationAbortURL  = "/migration/abort"
	MigrationStatusURL = "/migration/status"
)

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
	err := s.BeginMigrateOut(ctx, req.DestSocketPath, vc.MigrateOptions{
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
