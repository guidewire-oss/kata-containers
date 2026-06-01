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
	osexec "os/exec"
	"sort"
	"strings"
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
	// MigrationContinueURL releases a source-side BeginMigrateOut
	// that is parked at QEMU's "pre-switchover" phase because the
	// pause-before-switchover capability was set on /migration/out.
	// The orchestrator hits this endpoint after the parallel rootfs
	// sync finishes — that's the signal that it's safe to drain RAM
	// dirty pages and cut over. The shim then issues migrate-continue
	// to QEMU and proceeds through the normal completion path.
	//
	// Synchronous: returns 200 once the channel close completes, 409
	// if no migration is parked at pre-switchover (request raced the
	// caller, or pause-before-switchover wasn't set on this migration).
	MigrationContinueURL = "/migration/continue"
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
	// === MigrationSetupSourceIPNATURL: DISABLED, kept here for reference ===
	//
	// Used to install an iptables SNAT rule in the dest pod netns that
	// rewrites src=<source-pod-IP> to src=<dest-pod-IP> on egress, so
	// pre-migration TCP sockets bound to the source pod IP continued
	// to receive replies via conntrack reverse-NAT. The mechanism is
	// sound at the iptables layer but on Cilium ENI clusters the
	// Cilium tc-egress eBPF hook drops the packet for identity
	// mismatch BEFORE iptables NAT runs, so the SNAT never fires.
	//
	// Re-enabling requires CNI-level IP-follow support across pod
	// migration; tracked at https://github.com/cilium/cilium/issues/38576.
	// See the orchestrator-side rationale in
	// ccs-vamos/internal/controller/kata_handoff.go (search for
	// "SetupSourceIPNAT: DISABLED").
	//
	// MigrationSetupSourceIPNATURL = "/migration/setup-source-ip-nat"
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
	// Mounts carries the per-container OCI bind mounts (hosts,
	// hostname, resolv.conf, configmap/secret projections, etc.)
	// that the source had ShareFile-bound into the shared sandbox
	// dir. The destination needs the source-side HostPath so it can
	// bind its own local equivalents into the same path inside the
	// shared dir — the migrated guest's mount table still references
	// those source paths, and virtio-fs returns EIO if the files
	// aren't there. Empty for sandboxes that pre-date the field
	// (older source shims).
	Mounts []SourceMount `json:"mounts,omitempty"`
}

// SourceMount is one per-container OCI bind mount the source had
// staged in the shared sandbox dir at original CreateContainer time.
// Each entry tells the destination two things:
//   - Destination: which guest-side path this mount serves (e.g.
//     "/etc/resolv.conf"). Used to find the destination containerd's
//     equivalent local file by matching against the dest spec.Mounts.
//   - HostPath: the absolute path on the SOURCE node where the bound
//     file lived. ShareFile builds this with a random byte suffix
//     (".../<src-cid>-<random>-<basename>") which means the dest
//     cannot derive it independently — the source must ship it.
//
// The destination binds its own local file to this exact HostPath
// inside its shared sandbox dir (post-adoption, the shared sandbox
// dir is keyed by the source sandbox ID — see dual-identity #72).
// The guest's existing in-VM mount table then finds the file.
type SourceMount struct {
	Destination string `json:"destination"`
	HostPath    string `json:"hostPath"`
	ReadOnly    bool   `json:"readOnly,omitempty"`
}

// MigrationInRequest is the body for POST /migration/in.
type MigrationInRequest struct {
	// ListenURI is the address QEMU should bind for the incoming
	// migration (e.g. "tcp:0.0.0.0:4444"). Required.
	ListenURI string `json:"listenURI"`

	// Capabilities, Parameters, and StringParameters mirror the
	// fields on MigrationOutRequest — destination QEMU must apply
	// the same caps and params as the source's MigrateOut, or QEMU
	// rejects the stream on connect (multifd-channels and the
	// multifd-* knobs are the canonical examples). Optional;
	// callers that don't need negotiation can omit all three.
	Capabilities     map[string]bool   `json:"capabilities,omitempty"`
	Parameters       map[string]uint64 `json:"parameters,omitempty"`
	StringParameters map[string]string `json:"stringParameters,omitempty"`
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

	// StringParameters passed to MigrateOptions for QMP params whose
	// type is a string rather than an integer (multifd-compression is
	// the canonical example: "none"|"zlib"|"zstd"|"qatzip"). Kept
	// separate from Parameters because QEMU's QMP schema is strongly
	// typed and rejects a string passed in a uint64 slot. Optional.
	StringParameters map[string]string `json:"stringParameters,omitempty"`
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
	m.HandleFunc(MigrationContinueURL, s.handleMigrationContinue)
	// SetupSourceIPNAT endpoint is intentionally NOT registered — see
	// the MigrationSetupSourceIPNATURL block above (and the matching
	// handler below) for the Cilium-ENI rationale and the Cilium
	// issue tracking the prerequisite work.
	// m.HandleFunc(MigrationSetupSourceIPNATURL, s.handleMigrationSetupSourceIPNAT)
}

// MigrationSetupSourceIPNATRequest is the body for POST
// /migration/setup-source-ip-nat.
type MigrationSetupSourceIPNATRequest struct {
	// SourcePodIP is the pod IP this venv had on the source side —
	// the address pre-migration TCP sockets inside the guest are
	// still bound to. Required.
	SourcePodIP string `json:"sourcePodIP"`
	// DestPodIP is the pod IP allocated to the destination pod —
	// the address the cluster can route to. Required.
	DestPodIP string `json:"destPodIP"`
}

// MigrationSetupSourceIPNATResponse is the body returned by POST
// /migration/setup-source-ip-nat. Synchronous: the iptables rule
// is in place by the time this returns 200.
type MigrationSetupSourceIPNATResponse struct {
	NetnsPath  string `json:"netnsPath"`
	SourcePodIP string `json:"sourcePodIP"`
	DestPodIP   string `json:"destPodIP"`
	// IPTablesOutput captures iptables stderr+stdout, which is empty
	// on success but carries the operator-actionable error message
	// on failure (e.g. "iptables: No chain/target/match by that name").
	IPTablesOutput string `json:"iptablesOutput,omitempty"`
	// TcpLooseBefore / TcpLooseAfter report the per-netns
	// net.netfilter.nf_conntrack_tcp_loose sysctl. We set it to 1
	// because mid-stream TCP packets (existing connections post-
	// migration) need loose tracking to enter conntrack; without
	// it they're marked INVALID and dropped.
	TcpLooseBefore string `json:"tcpLooseBefore,omitempty"`
	TcpLooseAfter  string `json:"tcpLooseAfter,omitempty"`
	// ConntrackFlushOutput captures the stdout+stderr of the
	// post-iptables `conntrack -D -s <source-pod-IP>` call. Any
	// conntrack entries created BEFORE the SNAT rule was added
	// (e.g. the first few JVM packets sent during the brief window
	// between handoff completion and this endpoint firing) would
	// have NO NAT mapping. iptables rules are only evaluated when
	// conntrack creates a new entry, so those existing entries
	// pin the connection to a no-NAT path even after we add the
	// SNAT rule. Flushing them forces the next packet to recreate
	// the entry with the rule in place.
	ConntrackFlushOutput string `json:"conntrackFlushOutput,omitempty"`
	Elapsed              string `json:"elapsed"`
	Status               string `json:"status"`
}

// MigrationShareWorkloadRootfsResponse is the body returned by
// POST /migration/share-workload-rootfs. Synchronous: count is the
// number of containers visited, shared is the count newly bound on
// this call, failed is the count whose bind raised an error.
//
// MountsBound and MountsSkipped report the per-container OCI bind
// mount step that runs immediately after the rootfs share — re-stages
// hosts/hostname/resolv.conf/configmaps at the source's HostPaths so
// the migrated guest can serve them over virtio-fs. Zero is the
// expected value when the source shim was older than the protocol
// extension (no Mounts in SourceContainers payload).
type MigrationShareWorkloadRootfsResponse struct {
	Visited       int    `json:"visited"`
	Shared        int    `json:"shared"`
	Failed        int    `json:"failed"`
	MountsBound   int    `json:"mountsBound,omitempty"`
	MountsSkipped int    `json:"mountsSkipped,omitempty"`
	Elapsed       string `json:"elapsed"`
	Status        string `json:"status"`
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
	// Bind per-container OCI bind mounts (resolv.conf, hosts, hostname,
	// configmaps) at the SOURCE's HostPaths inside the shared dir.
	// Runs after the rootfs share so the two binds land together at
	// the same point in the migration sequence (post-CompleteHandoff,
	// outside the QMP-sensitive topology window). Zero counts when
	// the source ran an older shim that didn't ship Mounts.
	mountsBound, mountsSkipped := s.sandbox.BindMigrationSourceMounts(r.Context())
	resp := MigrationShareWorkloadRootfsResponse{
		Visited:       visited,
		Shared:        shared,
		Failed:        failed,
		MountsBound:   mountsBound,
		MountsSkipped: mountsSkipped,
		Elapsed:       time.Since(start).String(),
		Status:        "ok",
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

// handleMigrationSetupSourceIPNAT installs a host-netns iptables NAT
// rule that rewrites the migrated guest's pre-existing TCP socket
// addresses so peer return traffic reaches the JVM after cutover.
//
// Why: pre-migration TCP sockets inside the migrated guest are still
// bound to the SOURCE pod's IP (TCP state survived the QEMU memory
// migration but the kernel's per-socket local address is fixed at
// connect-time). The cluster L3 fabric no longer routes traffic
// addressed to source-pod-IP, so peer return traffic gets dropped
// at the cluster edge and the connection becomes half-broken —
// bytesSent climbs, bytesReceived stays flat.
//
// Why host-netns iptables (not in-guest):
// The in-guest path (GetIPTables/SetIPTables RPC) requires the
// kata-agent's is_allowed gate to pass. We observed that on this
// cluster the running agent unconditionally rejects iptables RPCs
// with "policy check: unexpected eval_query result" regardless of
// the agent-policy feature flag we built with. We can't reliably
// get a policy-free agent into the running guest, so the in-guest
// approach is unworkable in practice.
//
// Host-netns is reliable: the shim runs in host netns with
// CAP_NET_ADMIN by default, exec's /sbin/iptables directly, and
// the rule fires on packets crossing the dest pod's veth_peer.
// Conntrack in the host netns handles the reverse-NAT for replies
// automatically — we only need a single POSTROUTING SNAT rule.
//
// Flow:
//
//   1. JVM sends with src=<source-pod-IP>. Packet leaves guest →
//      QEMU TAP → kata's TC-redirect → host's veth_peer.
//   2. POSTROUTING runs in host netns: our SNAT rewrites the src
//      to <dest-pod-IP>. Conntrack records the connection tuple.
//   3. Packet egresses the node with src=<dest-pod-IP>. Peer
//      replies with dst=<dest-pod-IP>.
//   4. Reply arrives at host. Conntrack matches reverse tuple →
//      auto-rewrites dst=<dest-pod-IP> → dst=<source-pod-IP>.
//   5. Packet enters dest pod's veth → TC-redirect → TAP → guest.
//      Guest socket (still bound to source-pod-IP) accepts it.
//
// Idempotent: we check the existing nat-table dump first; if our
// rule is already present we no-op.
func (s *service) handleMigrationSetupSourceIPNAT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req MigrationSetupSourceIPNATRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("decode body: %v", err), http.StatusBadRequest)
		return
	}
	if req.SourcePodIP == "" || req.DestPodIP == "" {
		http.Error(w, "sourcePodIP and destPodIP are required", http.StatusBadRequest)
		return
	}
	if req.SourcePodIP == req.DestPodIP {
		// No rewrite needed — pod IPs are identical.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(MigrationSetupSourceIPNATResponse{
			SourcePodIP: req.SourcePodIP,
			DestPodIP:   req.DestPodIP,
			Status:      "noop",
		})
		return
	}
	start := time.Now()
	shimLog.WithFields(map[string]interface{}{
		"sourcePodIP": req.SourcePodIP,
		"destPodIP":   req.DestPodIP,
	}).Warn("handleMigrationSetupSourceIPNAT: ENTRY (host-netns)")
	resp := MigrationSetupSourceIPNATResponse{
		SourcePodIP: req.SourcePodIP,
		DestPodIP:   req.DestPodIP,
		Status:      "ok",
	}
	// Idempotency check: list the host's nat POSTROUTING chain and
	// see if our rule is already there. iptables-save renders rules
	// with the /32 mask on -s; iptables -S renders them without it.
	// Tolerate both.
	listOut, err := runIptables(r.Context(), "-t", "nat", "-S", "POSTROUTING")
	if err != nil {
		shimLog.WithError(err).Error("handleMigrationSetupSourceIPNAT: iptables -S failed")
		http.Error(w, fmt.Sprintf("iptables list: %v", err), http.StatusInternalServerError)
		return
	}
	ruleNoMask := fmt.Sprintf("-A POSTROUTING -s %s -j SNAT --to-source %s", req.SourcePodIP, req.DestPodIP)
	ruleWithMask := fmt.Sprintf("-A POSTROUTING -s %s/32 -j SNAT --to-source %s", req.SourcePodIP, req.DestPodIP)
	if strings.Contains(string(listOut), ruleNoMask) || strings.Contains(string(listOut), ruleWithMask) {
		shimLog.Warn("handleMigrationSetupSourceIPNAT: rule already in host iptables; skipping")
		resp.Status = "noop-already-installed"
		resp.IPTablesOutput = string(listOut)
		resp.Elapsed = time.Since(start).String()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	// Install the rule. -I prepends; if Cilium installed its own
	// masquerade SNAT later, prepending ensures ours fires first.
	if _, err := runIptables(r.Context(),
		"-t", "nat",
		"-I", "POSTROUTING", "1",
		"-s", req.SourcePodIP,
		"-j", "SNAT",
		"--to-source", req.DestPodIP,
	); err != nil {
		shimLog.WithError(err).Error("handleMigrationSetupSourceIPNAT: iptables -I failed")
		http.Error(w, fmt.Sprintf("iptables install: %v", err), http.StatusInternalServerError)
		return
	}
	// Re-list and include in response for diagnostics.
	postList, _ := runIptables(r.Context(), "-t", "nat", "-S", "POSTROUTING")
	resp.IPTablesOutput = string(postList)
	resp.Elapsed = time.Since(start).String()
	shimLog.WithFields(map[string]interface{}{
		"sourcePodIP": req.SourcePodIP,
		"destPodIP":   req.DestPodIP,
		"elapsed":     resp.Elapsed,
	}).Warn("handleMigrationSetupSourceIPNAT: SUCCESS (rule installed in host netns)")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// runIptables exec's /sbin/iptables with the given args in the
// shim's current network namespace (host netns by default). Returns
// combined stdout+stderr on failure for easier diagnostics.
func runIptables(ctx context.Context, args ...string) ([]byte, error) {
	cmd := osexec.CommandContext(ctx, "iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("iptables %s: %w (output: %s)",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
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
	if err := s.BeginMigrateIncoming(ctx, req.ListenURI, vc.MigrateOptions{
		Capabilities:     req.Capabilities,
		Parameters:       req.Parameters,
		StringParameters: req.StringParameters,
	}); err != nil {
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
		Capabilities:     req.Capabilities,
		Parameters:       req.Parameters,
		StringParameters: req.StringParameters,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleMigrationContinue releases a BeginMigrateOut goroutine that
// is parked at pre-switchover. The orchestrator calls this once its
// out-of-band work (rootfs sync) has finished and the cutover should
// proceed. Returns 200 when the gate is released, 409 if no migration
// is paused (raced, or pause-before-switchover wasn't requested).
func (s *service) handleMigrationContinue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.signalMigrateContinue() {
		http.Error(w, "no migration is paused at pre-switchover", http.StatusConflict)
		return
	}
	shimLog.Warn("handleMigrationContinue: gate released")
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
			// Per-container OCI bind mounts the source had ShareFile-
			// bound into the shared sandbox dir (resolv.conf, hosts,
			// hostname, configmaps, etc.). The destination uses these
			// HostPaths to re-stage equivalent files at the same path
			// in its shared dir — otherwise the migrated guest sees
			// EIO on every /etc/* read post-handoff.
			var mounts []SourceMount
			var mountDests []string
			for _, m := range c.GetMigrationBindMounts() {
				mounts = append(mounts, SourceMount{
					Destination: m.Destination,
					HostPath:    m.HostPath,
					ReadOnly:    m.ReadOnly,
				})
				mountDests = append(mountDests, m.Destination)
			}
			shimLog.WithFields(map[string]interface{}{
				"containerName":     name,
				"containerID":       c.ID(),
				"bindMountCount":    len(mounts),
				"bindMountDestinations": mountDests,
			}).Warn("migration/status: collected per-container bind mounts for source-containers payload")
			resp.SourceContainers = append(resp.SourceContainers, SourceContainer{
				Name:   name,
				ID:     c.ID(),
				Mounts: mounts,
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
		// mountsByName collects the source's per-container OCI bind
		// mounts (resolv.conf, hosts, hostname, configmaps). Kept
		// separate from the id map because Sandbox's
		// SetMigrationSourceContainers signature is map[string]string
		// for backward compatibility; we forward the richer payload
		// via SetMigrationSourceMounts.
		mountsByName := make(map[string][]vc.MigrationSourceMount, len(req.SourceContainers))
		totalMounts := 0
		for _, sc := range req.SourceContainers {
			if sc.Name == "" || sc.ID == "" {
				dropped++
				continue
			}
			s.migrationSourceContainers[sc.Name] = sc.ID
			if len(sc.Mounts) > 0 {
				out := make([]vc.MigrationSourceMount, 0, len(sc.Mounts))
				for _, m := range sc.Mounts {
					if m.HostPath == "" || m.Destination == "" {
						continue
					}
					out = append(out, vc.MigrationSourceMount{
						Destination: m.Destination,
						HostPath:    m.HostPath,
						ReadOnly:    m.ReadOnly,
					})
				}
				if len(out) > 0 {
					mountsByName[sc.Name] = out
					totalMounts += len(out)
				}
			}
		}
		merged := make(map[string]string, len(s.migrationSourceContainers))
		for k, v := range s.migrationSourceContainers {
			merged[k] = v
		}
		s.migrationMu.Unlock()
		s.sandbox.SetMigrationSourceContainers(merged)
		if len(mountsByName) > 0 {
			s.sandbox.SetMigrationSourceMounts(mountsByName)
		}
		shimLog.WithFields(map[string]interface{}{
			"stored":      len(merged),
			"dropped":     dropped,
			"names":       mapKeys(merged),
			"sandboxID":   s.id,
			"propagated":  true,
			"sourceMountContainers": len(mountsByName),
			"sourceMountTotal":      totalMounts,
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
		// Build a diagnostic envelope: requested devices + QEMU
		// reply + post-state, so the controller condition message
		// shows exactly which slot failed and what the dest QEMU
		// was launched with. This is the difference between
		// "TopologyApplyFailed: ..." (cryptic) and a payload an
		// operator can act on without SSHing into the node.
		postState, _ := s.sandbox.GetHotpluggedMemoryDevices(r.Context())
		envelope := map[string]interface{}{
			"error":             err.Error(),
			"phase":             "HotplugMemoryDevices",
			"requestedDevices":  devs,
			"postFailureDevs":   postState,
		}
		shimLog.WithError(err).WithFields(map[string]interface{}{
			"requestedDevices": devs,
			"postFailureDevs":  postState,
		}).Error("migration/topology: HotplugMemoryDevices failed")
		body, _ := json.Marshal(envelope)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(body)
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
		// Idempotency: the controller re-fires /migration/topology
		// on every reconcile until the dest reports a post-topology
		// status, so we must not re-add vCPUs that a prior call
		// already created. HotplugVCPUs's underlying QMP loop adds
		// `count` vCPUs each invocation regardless of current
		// hot-plug state, which on retry blows past
		// DefaultMaxVCPUs. Diff current vs target and only fire
		// the delta.
		currentHot, qErr := s.sandbox.GetHotpluggedVCPUCount(r.Context())
		if qErr != nil {
			shimLog.WithError(qErr).Warn("migration/topology: GetHotpluggedVCPUCount before vCPU add — assuming 0")
			currentHot = 0
		}
		shimLog.WithFields(map[string]interface{}{
			"requestedVCPUs": req.HotpluggedVCPUs,
			"currentHotVCPUs": currentHot,
		}).Warn("migration/topology: hot-plugging vCPUs to match source")
		switch {
		case uint32(currentHot) > req.HotpluggedVCPUs:
			// Dest already has more hot-plugged vCPUs than source —
			// usually means a prior reconcile attempt over-added.
			// Don't unplug here; flag as a topology mismatch.
			err := fmt.Errorf("destination has %d hot-plugged vCPUs but source only has %d — possible double-apply",
				currentHot, req.HotpluggedVCPUs)
			shimLog.WithError(err).Error("migration/topology: vCPU count exceeds source")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		case uint32(currentHot) == req.HotpluggedVCPUs:
			shimLog.WithField("count", currentHot).
				Info("migration/topology: vCPU hot-plug already at target, skipping (idempotent)")
		default:
			delta := req.HotpluggedVCPUs - uint32(currentHot)
			if err := s.sandbox.HotplugVCPUs(r.Context(), delta); err != nil {
				shimLog.WithError(err).Error("migration/topology: HotplugVCPUs failed")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
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
	// Same placement reasoning as the rootfs share above: out of the
	// QMP-sensitive topology window, but BEFORE migrate-incoming so
	// the source's mount-table paths are populated when the migrated
	// guest resumes and tries to read /etc/resolv.conf etc.
	if bound, skipped := s.sandbox.BindMigrationSourceMounts(r.Context()); bound > 0 || skipped > 0 {
		shimLog.WithFields(map[string]interface{}{
			"bound":   bound,
			"skipped": skipped,
		}).Warn("migration/topology: per-container OCI bind mounts re-staged before migrate-incoming")
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
