// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"syscall"
	"time"

	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/experimental"
)

// Migration admin HTTP endpoints exposed on the shim management
// server. The Phase E orchestration controller (running elsewhere
// in the cluster) calls these via a node-local migration agent.
// Endpoint paths are versioned implicitly: changing them is a
// protocol break.
const (
	MigrationOutURL           = "/migration/out"
	MigrationInURL            = "/migration/in"
	MigrationAbortURL         = "/migration/abort"
	MigrationStatusURL        = "/migration/status"
	MigrationTopologyURL      = "/migration/topology"
	MigrationRenumberGuestURL = "/migration/renumber-guest"
	// MigrationDiagURL returns a snapshot of the shim's migration
	// state including the source-container map and the per-container
	// {containerdID, internalID, name} list. Diagnostic only — read
	// by operators and manual-migrate.sh after a handoff to confirm
	// internal IDs got adopted before kubectl exec is exercised.
	MigrationDiagURL = "/migration/diag"
	// MigrationShareWorkloadRootfsURL binds each migration-adopted
	// workload container's rootfs into the shared sandbox dir, at
	// the path the migrated kata-agent already references for that
	// container (built from the source's CRI ID = c.InternalID()).
	// The orchestrator calls this AFTER handoff completes, away
	// from the topology hot path. The pattern mirrors
	// /migration/renumber-guest: a synchronous explicit step the
	// caller can retry, instead of an implicit goroutine fired off
	// from a different code path. See sandbox.go's
	// SetMigrationSourceContainers comment for the failure mode
	// this works around.
	MigrationShareWorkloadRootfsURL = "/migration/share-workload-rootfs"
	// MigrationWireWorkloadIOURL wires per-container host-side FIFOs
	// to the migrated kata-agent's stdio vsock streams so kubectl
	// logs returns the workload's stdout/stderr post-migration. The
	// OnComplete-driven path doesn't reliably fire on every code
	// path, so this is invoked synchronously by the orchestrator
	// after observing mode=owner — same pattern as renumber-guest
	// and share-workload-rootfs.
	MigrationWireWorkloadIOURL = "/migration/wire-workload-io"
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

// SourceContainer is the wire representation of one workload
// container on the source as the kata-agent inside the guest knows
// it. The dest reads this list from the source's /migration/status,
// POSTs it to its own /migration/topology, and uses it during the
// dest's containerd-driven CreateContainer call to set the new
// Container's InternalID to the source ID. After live migration the
// guest's agent still has the source container IDs in its table —
// adopting them keeps agent RPCs (exec/signal/stop/stats) routable.
type SourceContainer struct {
	// Name is the io.kubernetes.cri.container-name annotation —
	// stable across the migration because containerd writes it from
	// the PodSpec, not from the runtime.
	Name string `json:"name"`
	// ID is the source's CRI container ID, which equals the ID the
	// kata-agent uses in its container table.
	ID string `json:"id"`
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

	// LastError is QEMU's free-form description of the most recent
	// migration failure, surfaced from the hypervisor's
	// query-migrate response (e.g. "Unknown ramblock mem1",
	// "Failed to load vmstate for device 'virtio-net-pci'"). Set
	// when HypervisorPhase is "failed"; empty otherwise. Lets the
	// orchestrator log a specific cause without scraping the host
	// journal.
	LastError string `json:"lastError,omitempty"`

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

	// HotpluggedVCPUs is the number of vCPUs the source kata
	// runtime hot-plugged on top of the boot count. Reported on
	// source shims so the orchestrator can pre-create the same
	// count on the destination via /migration/topology. Without
	// this the destination's APIC table is short and QEMU rejects
	// vmstate load with "Unknown section or instance 'apic' N".
	// Zero (and omitted) when the source has never hot-plugged.
	HotpluggedVCPUs uint32 `json:"hotpluggedVCPUs,omitempty"`

	// SourceContainers lists the workload containers the kata-agent
	// inside the guest tracks, by source CRI ID and container-name.
	// The dest needs both to adopt the source IDs as InternalID for
	// the freshly-created containerd containers — without that, agent
	// RPCs ("exec", "signal", "stop") on the dest hit the agent with
	// the dest's fresh CRI ID, which the agent has never seen, and
	// return "Invalid container id". Empty (and omitted) on the dest
	// side and when the sandbox has no workload containers yet.
	SourceContainers []SourceContainer `json:"sourceContainers,omitempty"`
}

// MigrationTopologyRequest is the body for POST /migration/topology.
type MigrationTopologyRequest struct {
	// MemoryDevices is the list of hot-plugged memory devices the
	// destination should pre-create before accepting the migration
	// stream. Must be in slot order. An empty list is a valid
	// no-op (e.g. when the source has never hot-plugged).
	MemoryDevices []MemoryDevice `json:"memoryDevices"`

	// HotpluggedVCPUs is the number of vCPUs the destination
	// should hot-plug on top of the boot count so its APIC layout
	// matches the source. The dest uses the runtime's existing CPU
	// hot-plug path (HotplugAddDevice(..., CpuDev)) which picks
	// slots in the same order as the source, so a count is
	// sufficient — no slot-by-slot mapping required for q35. Zero
	// means no CPU replay is needed.
	HotpluggedVCPUs uint32 `json:"hotpluggedVCPUs,omitempty"`

	// SourceContainers carries the source-side {name, id} pairs the
	// dest stashes so its CreateContainer can adopt the source ID
	// as InternalID. See MigrationStatusResponse.SourceContainers
	// for the lookup direction.
	SourceContainers []SourceContainer `json:"sourceContainers,omitempty"`
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
	m.HandleFunc(MigrationRenumberGuestURL, s.handleMigrationRenumberGuest)
	m.HandleFunc(MigrationDiagURL, s.handleMigrationDiag)
	m.HandleFunc(MigrationShareWorkloadRootfsURL, s.handleMigrationShareWorkloadRootfs)
	m.HandleFunc(MigrationWireWorkloadIOURL, s.handleMigrationWireWorkloadIO)
}

// MigrationShareWorkloadRootfsResponse is the body returned by
// POST /migration/share-workload-rootfs. Synchronous: count is the
// number of containers visited, shared is the count newly bound on
// this call, failed is the count whose bind raised an error.
type MigrationShareWorkloadRootfsResponse struct {
	Visited int    `json:"visited"`
	Shared  int    `json:"shared"`
	Failed  int    `json:"failed"`
	Elapsed string `json:"elapsed"`
	Status  string `json:"status"`
}

func (s *service) handleMigrationShareWorkloadRootfs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sandbox == nil {
		http.Error(w, "sandbox not ready", http.StatusServiceUnavailable)
		return
	}
	start := time.Now()
	visited := 0
	for range s.sandbox.GetAllContainers() {
		visited++
	}
	shared, failed := s.sandbox.ShareDeferredWorkloadRootfs(r.Context())
	resp := MigrationShareWorkloadRootfsResponse{
		Visited: visited,
		Shared:  shared,
		Failed:  failed,
		Elapsed: time.Since(start).String(),
		Status:  "ok",
	}
	if failed > 0 {
		resp.Status = "partial"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// MigrationDiagResponse is the body for GET /migration/diag.
type MigrationDiagResponse struct {
	Mode                      string                `json:"mode"`
	MigrationSourceContainers map[string]string     `json:"migrationSourceContainers,omitempty"`
	Containers                []MigrationDiagContainer `json:"containers,omitempty"`
}

// MigrationDiagContainer is one row in the diag response: the dest's
// containerd-side ID, the agent-known InternalID, and the OCI
// container-name annotation. After adoption, InternalID should equal
// the source's ID for matching name in MigrationSourceContainers.
type MigrationDiagContainer struct {
	ContainerdID string `json:"containerdID"`
	InternalID   string `json:"internalID"`
	Name         string `json:"name"`
}

func (s *service) handleMigrationDiag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := MigrationDiagResponse{
		Mode:                      s.currentMigrationMode().String(),
		MigrationSourceContainers: s.SourceContainerByName(),
	}
	if s.sandbox != nil {
		for _, c := range s.sandbox.GetAllContainers() {
			ann := c.GetAnnotations()
			resp.Containers = append(resp.Containers, MigrationDiagContainer{
				ContainerdID: c.ContainerdID(),
				InternalID:   c.InternalID(),
				Name:         ann["io.kubernetes.cri.container-name"],
			})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleMigrationWireWorkloadIO wires per-container host-side FIFOs
// to the kata-agent's stdio vsock streams for every migrated workload
// container. Without this, the in-guest stdout pipe fills up and any
// thread writing to stdout blocks forever on FileOutputStream.write,
// kubectl logs returns empty, and logging-heavy app threads freeze.
//
// Same pattern as handleMigrationRenumberGuest: the OnComplete-driven
// path is not reliably firing on every platform/code-path combination,
// so the orchestrator calls this synchronously after observing mode=
// owner on the destination. Returns 200 with {wired, skipped, elapsed}
// on success; the per-container errors are logged separately at warn
// level so a partial wire-up still reports 200 with a smaller wired
// count.
func (s *service) handleMigrationWireWorkloadIO(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sandbox == nil {
		http.Error(w, "sandbox not initialized on this shim", http.StatusServiceUnavailable)
		return
	}
	shimLog.Warn("handleMigrationWireWorkloadIO: ENTRY")
	start := time.Now()
	wired, skipped := s.startIOForMigratedContainers(r.Context())
	elapsed := time.Since(start).String()
	shimLog.WithFields(map[string]interface{}{
		"wired":   wired,
		"skipped": skipped,
		"elapsed": elapsed,
	}).Warn("handleMigrationWireWorkloadIO: SUCCESS")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"wired":   wired,
		"skipped": skipped,
		"elapsed": elapsed,
	})
}

// handleMigrationRenumberGuest forces a guest network renumber via the
// kata-agent. Called by the orchestrator after observing mode=owner on
// the destination — bypasses the OnComplete-driven path because that
// path is not reliably firing on every platform/code-path combination.
// Synchronous: returns 200 with the elapsed time on success, 500 with
// the agent error on failure.
func (s *service) handleMigrationRenumberGuest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sandbox == nil {
		http.Error(w, "sandbox not initialized on this shim", http.StatusServiceUnavailable)
		return
	}
	shimLog.Warn("handleMigrationRenumberGuest: ENTRY (forced renumber requested)")
	start := time.Now()
	// 30s budget — generous since the in-guest agent can be slow to
	// settle post-migration. Synchronous because the caller wants a
	// definitive yes/no, not "scheduled".
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.sandbox.PushDestIPsToGuestAgent(ctx); err != nil {
		elapsed := time.Since(start).String()
		shimLog.WithError(err).WithField("elapsed", elapsed).
			Warn("handleMigrationRenumberGuest: failed")
		http.Error(w, fmt.Sprintf("renumber failed after %s: %v", elapsed, err),
			http.StatusInternalServerError)
		return
	}
	elapsed := time.Since(start).String()
	shimLog.WithField("elapsed", elapsed).
		Warn("handleMigrationRenumberGuest: SUCCESS")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"elapsed": elapsed,
	})
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
			resp.LastError = status.LastError
		} else {
			// QMP query failed — for an active sandbox this almost
			// always means the hypervisor is unreachable, typically
			// because QEMU exited. Surface as LastError so the
			// orchestrator's post-handoff check catches it instead of
			// treating a mode=owner status as success. A healthy
			// sandbox returns status with phase="none" and err=nil.
			//
			// Probe the QEMU and virtiofsd PIDs and append their
			// liveness so callers (and humans reading the diag log)
			// can immediately tell which process died, instead of
			// having to grab a coredump to find out.
			resp.LastError = fmt.Sprintf("hypervisor unreachable: %v (%s)",
				err, s.probeHypervisorProcesses())
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
		// Hot-plugged vCPU count. Same best-effort treatment as
		// memory — a query failure shouldn't sink the whole status
		// response. Source ships this to the orchestrator so the
		// dest can re-create the matching APIC layout.
		if vcpus, err := s.sandbox.GetHotpluggedVCPUCount(r.Context()); err != nil {
			shimLog.WithError(err).Debug("GetHotpluggedVCPUCount")
		} else {
			resp.HotpluggedVCPUs = vcpus
		}
		// Source-side container roster. Each entry must have a
		// CRI container-name; nameless entries are dropped because
		// the dest's lookup key is the name. The pod sandbox
		// itself is not in GetAllContainers() — sandbox.containers
		// only holds workload containers — so we don't need a
		// container-type filter here.
		all := s.sandbox.GetAllContainers()
		skipped := 0
		for _, c := range all {
			ann := c.GetAnnotations()
			name := ann["io.kubernetes.cri.container-name"]
			if name == "" {
				skipped++
				shimLog.WithField("containerID", c.ID()).
					WithField("annotationKeys", annotationKeys(ann)).
					Warn("migration/status: container has no container-name annotation; dropped from SourceContainers")
				continue
			}
			resp.SourceContainers = append(resp.SourceContainers, SourceContainer{
				Name: name,
				ID:   c.ID(),
			})
		}
		shimLog.WithFields(map[string]interface{}{
			"workloadContainers": len(all),
			"skippedNameless":    skipped,
			"reported":           len(resp.SourceContainers),
			"sandboxID":          s.id,
		}).Warn("migration/status: source-container enumeration done")
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
	// Stash source containers BEFORE any QMP work — the storage is
	// cheap and we want it populated even if memory hot-plug fails,
	// because a subsequent /migration/topology retry would have to
	// resend the same list anyway. Also forward the mapping to the
	// sandbox itself so a subsequent CreateContainer can adopt the
	// source IDs as InternalID for the new dest containers.
	shimLog.WithFields(map[string]interface{}{
		"received":  len(req.SourceContainers),
		"sandboxID": s.id,
	}).Warn("migration/topology: source-containers received")
	if len(req.SourceContainers) > 0 {
		s.migrationMu.Lock()
		if s.migrationSourceContainers == nil {
			s.migrationSourceContainers = make(map[string]string, len(req.SourceContainers))
		}
		dropped := 0
		for _, sc := range req.SourceContainers {
			if sc.Name == "" || sc.ID == "" {
				dropped++
				continue
			}
			s.migrationSourceContainers[sc.Name] = sc.ID
		}
		merged := make(map[string]string, len(s.migrationSourceContainers))
		for k, v := range s.migrationSourceContainers {
			merged[k] = v
		}
		s.migrationMu.Unlock()
		s.sandbox.SetMigrationSourceContainers(merged)
		shimLog.WithFields(map[string]interface{}{
			"stored":     len(merged),
			"dropped":    dropped,
			"names":      mapKeys(merged),
			"sandboxID":  s.id,
			"propagated": true,
		}).Warn("migration/topology: source-containers stored and forwarded to sandbox")
	}
	devs := make([]vc.MemoryDevice, len(req.MemoryDevices))
	for i, d := range req.MemoryDevices {
		devs[i] = vc.MemoryDevice{Slot: d.Slot, SizeMB: d.SizeMB}
	}
	shimLog.WithField("requestedSlots", len(devs)).
		WithField("devices", devs).
		Warn("migration/topology: applying requested memory devices")
	if err := s.sandbox.HotplugMemoryDevices(r.Context(), devs); err != nil {
		shimLog.WithError(err).Error("migration/topology: HotplugMemoryDevices failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Sanity-log what the destination actually has now. If this list
	// diverges from `devs` the source's RAMBlock transfer will write
	// past unmapped pages and QEMU will segfault — surfacing that
	// here gives us a precise pointer to the next blocker.
	if after, err := s.sandbox.GetHotpluggedMemoryDevices(r.Context()); err != nil {
		shimLog.WithError(err).Warn("migration/topology: post-apply GetHotpluggedMemoryDevices")
	} else {
		shimLog.WithField("postApply", after).
			Warn("migration/topology: destination hot-plug state after apply")
	}
	// Replay CPU hot-plug. Uses kata's existing CPU hot-plug path
	// (HotplugAddDevice with CpuDev) which iterates
	// query-hotpluggable-cpus in QEMU's enumeration order and picks
	// the first available slot. Source and destination have the
	// same -smp config and same enumeration, so a count is enough —
	// both sides land in the same APIC slots without us needing to
	// ship per-slot tuples.
	if req.HotpluggedVCPUs > 0 {
		shimLog.WithField("requestedVCPUs", req.HotpluggedVCPUs).
			Warn("migration/topology: hot-plugging vCPUs to match source")
		if err := s.sandbox.HotplugVCPUs(r.Context(), req.HotpluggedVCPUs); err != nil {
			shimLog.WithError(err).Error("migration/topology: HotplugVCPUs failed")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if after, err := s.sandbox.GetHotpluggedVCPUCount(r.Context()); err != nil {
			shimLog.WithError(err).Warn("migration/topology: post-apply GetHotpluggedVCPUCount")
		} else {
			shimLog.WithField("postApply", after).
				Warn("migration/topology: destination vCPU hot-plug count after apply")
		}
	}

	// Bind workload rootfs(es) into the shared sandbox dir BEFORE
	// the source's /migration/out fires. This is load-bearing: dest
	// virtiofsd starts with --migration-mode=find-paths, which
	// during vmstate load re-opens each inode the source had. If
	// those paths aren't present on the dest at that moment,
	// virtiofsd marks the inodes failed AND with
	// --migration-on-error=guest-error every subsequent guest
	// access to those inodes returns EIO permanently. Sharing
	// AFTER handoff (post-resume) is too late — the inodes are
	// already poisoned.
	//
	// Placement: AFTER HotplugMemoryDevices + HotplugVCPUs (which
	// are QMP-sensitive — we proved firing the share BEFORE
	// hot-add crashed dest QEMU). Before this handler returns OK
	// to the controller, which is what unblocks /migration/out on
	// the source.
	//
	// Idempotent: ShareDeferredWorkloadRootfs only fires for
	// adopted containers whose rootfsShared flag is false.
	if shared, failed := s.sandbox.ShareDeferredWorkloadRootfs(r.Context()); shared > 0 || failed > 0 {
		shimLog.WithFields(map[string]interface{}{
			"shared": shared,
			"failed": failed,
		}).Warn("migration/topology: workload rootfs(es) bound before migrate-incoming")
	}

	w.WriteHeader(http.StatusOK)
}

// annotationKeys returns the sorted key list of an annotation map.
// Used in error/warn logs so a missing key reveals what's actually
// present without dumping the values (which can be huge OCI specs).
func annotationKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// mapKeys returns the sorted keys of a string map. Used in
// instrumentation logs for the migration source-container roster
// so the journal entry stays compact and grep-friendly.
func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SourceContainerByName returns a copy of the migration source
// container map for the dest's CreateContainer call to consult. Empty
// map (never nil) means no source containers were registered — either
// no migration is in progress, or the sandbox has no workload
// containers to adopt.
func (s *service) SourceContainerByName() map[string]string {
	s.migrationMu.Lock()
	defer s.migrationMu.Unlock()
	out := make(map[string]string, len(s.migrationSourceContainers))
	for k, v := range s.migrationSourceContainers {
		out[k] = v
	}
	return out
}

// probeHypervisorProcesses asks the kernel whether the QEMU and
// virtiofsd processes are still alive and returns a short string
// suitable for embedding in a LastError. Designed for the case where
// QMP just refused us a query — without this, the only signal we
// surface is "QMP loop, command cancelled" which leaves the caller
// blind to whether QEMU died, virtiofsd died, both died, or both are
// fine and just the socket went away.
//
// Output shape: "qemu=alive virtiofsd=exited(no-such-process)" etc.
// Never returns an empty string and never panics; the worst case is
// "qemu=unknown virtiofsd=unknown".
func (s *service) probeHypervisorProcesses() string {
	qemuStatus := "unknown"
	if s.sandbox != nil {
		if pid, err := s.sandbox.GetHypervisorPid(); err == nil && pid > 0 {
			qemuStatus = fmt.Sprintf("pid=%d %s", pid, probePID(pid))
		} else if err != nil {
			qemuStatus = fmt.Sprintf("lookup-err=%v", err)
		}
	}
	virtiofsStatus := "unknown"
	if s.sandbox != nil {
		if pid := s.sandbox.GetVirtioFsPid(); pid > 0 {
			virtiofsStatus = fmt.Sprintf("pid=%d %s", pid, probePID(pid))
		} else {
			virtiofsStatus = "not-started"
		}
	}
	return fmt.Sprintf("qemu=%s virtiofsd=%s", qemuStatus, virtiofsStatus)
}

// probePID returns "alive", or "exited(<errno>)", by sending signal 0.
// kill(2) on signal 0 performs the permission/existence check without
// delivering anything to the process — it is the standard portable
// liveness probe on Linux.
func probePID(pid int) string {
	proc, err := os.FindProcess(pid)
	if err != nil {
		// On Linux FindProcess never actually fails, but be defensive.
		return fmt.Sprintf("find-err=%v", err)
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return fmt.Sprintf("exited(%v)", err)
	}
	return "alive"
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
