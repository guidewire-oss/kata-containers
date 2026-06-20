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
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	mc "github.com/kata-containers/kata-containers/src/runtime/pkg/containerd-shim-v2/migration_coordinator"
	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	persistapi "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/api"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/annotations"
)

// ErrLiveMigrationDisabled is returned by the BeginMigrate*
// entry points when the live_migration experimental feature is not
// enabled on the supplied context. Callers must opt in explicitly;
// the orchestrator is responsible for setting the experimental
// feature on the runtime configuration before invoking these.
var ErrLiveMigrationDisabled = errors.New("live migration is not enabled: set experimental = [\"live_migration\"] in configuration.toml")

// statusPollInitial and statusPollCap bound the GetMigrationStatus
// poll backoff. The first wait after a non-terminal phase is
// statusPollInitial; each subsequent wait doubles, capped at
// statusPollCap. The initial value keeps short migrations snappy;
// the cap keeps long-running migrations from hammering QMP.
const (
	statusPollInitial = 50 * time.Millisecond
	statusPollCap     = 2 * time.Second
)

// resumeSettleTimeout bounds how long the destination finalization waits
// for QEMU's incoming load to leave the "inmigrate" run state before it
// issues cont. resumeVerifyAttempts is how many times it (re)issues cont
// and re-checks the run state before giving up. A migrate-to-file restore
// loads the guest paused (the save pauses vCPUs before MigrateOut, so the
// stream's global-state records a stopped run state), and QEMU does NOT
// auto-start it. A cont that lands while still "inmigrate" only sets
// autostart, which the incoming finalization then overrides with the saved
// paused state — so cont must follow the settle and be verified to stick.
const (
	resumeSettleTimeout  = 30 * time.Second
	resumeVerifyAttempts = 5
)

// pollBackoff yields a monotonically growing wait interval, capped
// at a maximum. Reset returns the cursor to the initial value (used
// when the migration phase changes — e.g. setup -> active — so we
// react quickly to the next transition).
type pollBackoff struct {
	next time.Duration
	max  time.Duration
}

func newPollBackoff(initial, max time.Duration) *pollBackoff {
	return &pollBackoff{next: initial, max: max}
}

func (b *pollBackoff) wait() time.Duration {
	d := b.next
	b.next *= 2
	if b.next > b.max {
		b.next = b.max
	}
	return d
}

func (b *pollBackoff) reset(initial time.Duration) {
	b.next = initial
}

// parseIncomingMigrateOptions builds a MigrateOptions from the OCI
// annotation map of an incoming-migration destination pod. The
// returned struct is safe to pass directly into BeginMigrateIncoming;
// missing or malformed annotations degrade to "feature off" rather
// than failing the sandbox create — the migration would just run with
// single-channel defaults like before.
//
// Annotations honoured:
//
//	migration_multifd_channels    -> enables multifd, sets channel count
//	migration_multifd_compression -> multifd compressor (zstd/zlib/...)
//	migration_multifd_zstd_level  -> zstd compression level
//
// The matching source-side values arrive through the orchestrator's
// /migration/out request body (Capabilities, Parameters,
// StringParameters fields of MigrationOutRequest) — both sides MUST
// land the same values or QEMU rejects the stream on connect.
func parseIncomingMigrateOptions(ann map[string]string) vc.MigrateOptions {
	opts := vc.MigrateOptions{}
	if raw := ann[annotations.MigrationMultifdChannels]; raw != "" {
		if n, err := strconv.ParseUint(raw, 10, 64); err == nil && n > 0 {
			if opts.Capabilities == nil {
				opts.Capabilities = map[string]bool{}
			}
			opts.Capabilities["multifd"] = true
			if opts.Parameters == nil {
				opts.Parameters = map[string]uint64{}
			}
			opts.Parameters["multifd-channels"] = n
		} else {
			shimLog.WithFields(map[string]interface{}{
				"annotation": annotations.MigrationMultifdChannels,
				"value":      raw,
			}).Warn("parseIncomingMigrateOptions: invalid multifd channels; ignoring")
		}
	}
	// Compression only meaningful with multifd enabled — but apply
	// regardless and let QEMU reject a misconfigured combination
	// loudly rather than silently drop.
	if raw := ann[annotations.MigrationMultifdCompression]; raw != "" {
		if opts.StringParameters == nil {
			opts.StringParameters = map[string]string{}
		}
		opts.StringParameters["multifd-compression"] = raw
	}
	if raw := ann[annotations.MigrationMultifdZstdLevel]; raw != "" {
		if n, err := strconv.ParseUint(raw, 10, 64); err == nil {
			if opts.Parameters == nil {
				opts.Parameters = map[string]uint64{}
			}
			opts.Parameters["multifd-zstd-level"] = n
		} else {
			shimLog.WithFields(map[string]interface{}{
				"annotation": annotations.MigrationMultifdZstdLevel,
				"value":      raw,
			}).Warn("parseIncomingMigrateOptions: invalid multifd zstd level; ignoring")
		}
	}
	return opts
}

// BeginMigrateIncoming sets the shim up as the destination of an
// inbound live migration. Transitions the mode to Incoming, puts
// the underlying hypervisor in -incoming mode, and binds the
// MigrationCoordinator gRPC server so the source shim can dial in.
//
// Failure semantics:
//   - Feature flag missing            -> ErrLiveMigrationDisabled, mode unchanged
//   - Illegal mode transition         -> ErrInvalidMigrationTransition, mode unchanged
//   - hypervisor.MigrateIncoming err  -> mode transitions to Failed,
//     error returned with cause wrapped
//   - bind/start failure              -> hypervisor.CancelMigration is
//     invoked best-effort, mode goes
//     to Failed, error returned
func (s *service) BeginMigrateIncoming(ctx context.Context, listenURI string, opts vc.MigrateOptions) error {
	shimLog.WithFields(map[string]interface{}{
		"listenURI":    listenURI,
		"caps":         opts.Capabilities,
		"params":       opts.Parameters,
		"stringParams": opts.StringParameters,
	}).Warn("BeginMigrateIncoming: entry")
	if !IsLiveMigrationEnabled(ctx) {
		shimLog.Warn("BeginMigrateIncoming: live migration feature disabled")
		return ErrLiveMigrationDisabled
	}
	shimLog.Warn("BeginMigrateIncoming: about to transition mode to Incoming")
	if err := s.transitionMigrationMode(ModeIncoming); err != nil {
		shimLog.WithError(err).Warn("BeginMigrateIncoming: transitionMigrationMode failed")
		return err
	}
	shimLog.Warn("BeginMigrateIncoming: mode=Incoming; about to call sandbox.MigrateIncoming (QMP)")

	// opts carries the destination-side migration capabilities and
	// parameters (multifd, multifd-channels, multifd-compression,
	// etc.) parsed from the dest pod's annotations. MigrateIncoming
	// applies them via QMP migrate-set-capabilities /
	// migrate-set-parameters BEFORE migrate-incoming so the
	// destination QEMU has them in effect when the source's
	// migrate command connects. Source-side mirror lives in the
	// orchestrator's /migration/out request body.
	if err := s.sandbox.MigrateIncoming(ctx, listenURI, opts); err != nil {
		shimLog.WithError(err).Warn("BeginMigrateIncoming: sandbox.MigrateIncoming failed")
		_ = s.transitionMigrationMode(ModeFailed)
		return fmt.Errorf("hypervisor MigrateIncoming: %w", err)
	}
	shimLog.Warn("BeginMigrateIncoming: sandbox.MigrateIncoming OK; about to bind MigrationCoordinator")

	socketPath := s.migrationSocketPathOverride
	if socketPath == "" {
		socketPath = mc.SocketPath(s.id)
	}

	srv, err := mc.NewServer(mc.ServerOptions{
		SandboxID:    s.id,
		SocketPath:   socketPath,
		IncomingURI:  listenURI,
		StateApplier: s.applyIncomingSandboxState,
		OnComplete:   s.onMigrationComplete,
		OnAbort:      s.onMigrationAbort,
		// Progress hook for the source-inactivity watchdog: a
		// coordinator-less restore (hibernate resume) sends no source
		// RPCs, so the watchdog must instead gate on whether the
		// hypervisor's incoming load is still in flight. Prevents a
		// slow/large S3 restore from being aborted before it completes.
		ProgressFunc: s.incomingMigrationActive,
		// Bind a TCP listener on host network with a
		// kernel-assigned port so a cross-node source shim can
		// dial directly. The chosen address is reported back
		// through the management /migration/status response.
		TCPListenAddr: ":0",
	})
	if err != nil {
		_ = s.sandbox.CancelMigration(ctx)
		_ = s.transitionMigrationMode(ModeFailed)
		return fmt.Errorf("bind migration coordinator: %w", err)
	}
	if err := srv.Start(); err != nil {
		shimLog.WithError(err).Warn("BeginMigrateIncoming: srv.Start failed")
		_ = srv.Stop()
		_ = s.sandbox.CancelMigration(ctx)
		_ = s.transitionMigrationMode(ModeFailed)
		return fmt.Errorf("start migration coordinator: %w", err)
	}
	shimLog.Warn("BeginMigrateIncoming: MigrationCoordinator started; storing srv")

	s.migrationMu.Lock()
	s.migrationServer = srv
	s.migrationMu.Unlock()
	shimLog.Warn("BeginMigrateIncoming: returning nil (success)")
	return nil
}

// stopMigrationServer tears down the destination-side coordinator
// server if one is bound. Idempotent and safe to call concurrently
// — the second caller observes nil and returns.
func (s *service) stopMigrationServer() error {
	s.migrationMu.Lock()
	srv := s.migrationServer
	s.migrationServer = nil
	s.migrationMu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Stop()
}

// incomingMigrationActive reports whether the destination's incoming
// migration is still in an active loading phase, per the hypervisor's
// query-migrate status. The coordinator's source-inactivity watchdog
// uses this (via ServerOptions.ProgressFunc) to avoid aborting a
// slow-but-progressing restore: the hibernate restore path is
// coordinator-less (no source RPCs), so RPC-silence alone is a false
// positive while the hypervisor is still loading the incoming stream.
// Returns false on any error or terminal/idle phase so the watchdog can
// still fire when the incoming genuinely stalls or never starts — the
// byte counters in query-migrate are source-side and unreliable on the
// destination, so we key on the phase string, which IS meaningful here.
func (s *service) incomingMigrationActive() bool {
	if s.sandbox == nil {
		return false
	}
	st, err := s.sandbox.GetMigrationStatus(context.Background())
	if err != nil {
		return false
	}
	return isIncomingActivePhase(st.Phase)
}

// isIncomingActivePhase returns true for QEMU migration phases that mean
// "an incoming load is in flight". Terminal/idle phases (none/completed/
// failed/cancelled/cancelling) return false so the watchdog can still
// abort a stuck or never-started incoming.
func isIncomingActivePhase(phase string) bool {
	switch phase {
	case "setup", "active", "postcopy-active", "device", "colo":
		return true
	default:
		// "", "none", "completed", "failed", "cancelled", "cancelling"
		return false
	}
}

// applyIncomingSandboxState is the StateApplier hook handed to the
// MigrationCoordinator server. The skeleton validates JSON
// decodability and stashes the bytes for inspection; swapping the
// decoded state into the live sandbox struct is deferred to a
// follow-up because the existing sandbox already owns containers,
// devices, and an agent connection that cannot be hot-swapped
// without further surgery.
func (s *service) applyIncomingSandboxState(_ context.Context, payload []byte) error {
	var state persistapi.SandboxState
	if err := json.Unmarshal(payload, &state); err != nil {
		return fmt.Errorf("decode SandboxState: %w", err)
	}
	s.mu.Lock()
	s.pendingMigrationState = append([]byte(nil), payload...)
	s.mu.Unlock()
	return nil
}

// onMigrationComplete is the OnComplete hook handed to the
// MigrationCoordinator server. The source's CompleteHandoff RPC
// reaches us here; we:
//  1. Resume the guest (it was paused with "-S -incoming defer";
//     the migrated memory is in place by the time
//     CompleteHandoff arrives, so cont() brings the workload
//     back to life).
//  2. Check the kata-agent's gRPC server is reachable through
//     the destination host's vsock CID. The migrated agent
//     already listens on guest CID 3 / port 1024 from the
//     guest's perspective; the destination shim's agent client
//     dials destination-host-CID:1024 which the host vsock
//     module translates to the migrated guest's listener.
//  3. Flip Incoming -> Owner so subsequent CRI ops succeed.
//
// Errors during resume/check are surfaced to the source via the
// CompleteHandoff RPC's gRPC status; the source then sees the
// migration as failed and tears down its own QEMU.
func (s *service) onMigrationComplete() error {
	// Entry breadcrumb — proves the OnComplete hook actually fires and
	// surfaces whether s.sandbox is populated. We hit a case where the
	// dst sandbox's /migration/status reported mode=owner with zero
	// onMigrationComplete log lines in the journal; the most likely
	// explanation was either (a) the function executed with s.sandbox
	// nil and skipped the whole body, or (b) it never fired and Owner
	// was set elsewhere. This log decides which.
	shimLog.WithFields(map[string]interface{}{
		"sandboxNil": s.sandbox == nil,
		"shimID":     s.id,
	}).Warn("onMigrationComplete: ENTRY")

	ctx := context.Background()
	if s.sandbox != nil {
		resumeStart := time.Now()
		if err := s.resumeIncomingMigratedVM(ctx); err != nil {
			shimLog.WithError(err).WithField("elapsed", time.Since(resumeStart).String()).
				Error("onMigrationComplete: resume failed")
			_ = s.transitionMigrationMode(ModeFailed)
			return fmt.Errorf("resume migrated VM: %w", err)
		}
		// Warn (not Info) — load-bearing milestone; we want it in the
		// default journal level always.
		shimLog.WithField("elapsed", time.Since(resumeStart).String()).
			Warn("onMigrationComplete: VM resumed")

		// Phase D: rewire everything that Sandbox.Start() would have
		// done if this weren't an incoming-migration sandbox:
		//
		//   - kata-agent client URL (so gRPC reaches the migrated
		//     agent on the destination host's vsock CID)
		//   - guest-side network renumber (so the in-guest eth0
		//     carries the destination pod IP instead of the source
		//     pod IP it was migrated with — without this ARP for
		//     the destination IP never resolves)
		//   - sandbox + container state machine flips (so CRI ops
		//     don't bounce off "Sandbox not running")
		//
		// Step-by-step rationale lives on Sandbox.PairAgentAfterMigration.
		// Done unconditionally — for fresh (non-migration) sandboxes
		// Start() handled all of it; for migrated ones we do.
		pairStart := time.Now()
		if err := s.sandbox.PairAgentAfterMigration(ctx); err != nil {
			shimLog.WithError(err).WithField("elapsed", time.Since(pairStart).String()).
				Warn("onMigrationComplete: PairAgentAfterMigration failed; agent will be unreachable, CRI ops and traffic to this sandbox will fail")
		} else {
			shimLog.WithField("elapsed", time.Since(pairStart).String()).
				Warn("onMigrationComplete: destination sandbox re-paired (agent URL, guest network, state)")
		}

		// Best-effort agent check. A failure here is logged but
		// not fatal — the workload is running inside the guest
		// whether or not the shim can talk to its agent. CRI ops
		// will fail until the agent reconnects, but in-guest
		// services (SSH-into-guest, HTTP, etc.) work immediately.
		checkStart := time.Now()
		if err := s.sandbox.CheckAgent(ctx); err != nil {
			shimLog.WithError(err).WithField("elapsed", time.Since(checkStart).String()).
				Warn("onMigrationComplete: agent CheckAgent failed; guest is running but CRI ops to this sandbox will fail until re-paired")
		} else {
			shimLog.WithField("elapsed", time.Since(checkStart).String()).
				Warn("onMigrationComplete: kata-agent reachable on destination host")
		}

		// Per-container IO wire-up is NOT done from here. See the
		// renumber-guest + share-workload-rootfs pattern: the
		// OnComplete-driven path is not reliably firing on every
		// platform/code-path combination, so the orchestrator calls
		// /migration/wire-workload-io explicitly after observing
		// mode=owner on the destination.
	}
	err := s.transitionMigrationMode(ModeOwner)
	shimLog.WithError(err).Warn("onMigrationComplete: EXIT (about to transition to ModeOwner)")
	return err
}

// resumeIncomingMigratedVM brings a freshly migrated-in guest to the
// running state. It handles two cases that differ only in the run state
// QEMU restores from the migration stream's global-state section:
//
//   - Live migration: the source was running at handoff, so the stream
//     records "running" and QEMU auto-starts the guest as the incoming
//     load finalizes. By the time we look it is already "running" and we
//     issue no cont (a redundant one would be a harmless no-op anyway).
//
//   - Hibernate/suspend restore (migrate-to-file): BeginMigrateSave pauses
//     the vCPUs before MigrateOut for a clean single-pass snapshot, so the
//     stream records a stopped run state and QEMU leaves the guest paused;
//     it must be resumed explicitly. A cont issued while the load is still
//     "inmigrate" only sets autostart, which the incoming finalization then
//     overrides with the saved paused state — leaving the guest frozen. So
//     we wait for the run state to leave "inmigrate", then cont, then verify
//     the guest reaches "running", retrying the cont if the first one raced
//     the tail of the load.
//
// GetVMRunState is best-effort: on a hypervisor that doesn't implement it
// the call errors and we fall back to a single ResumeVM (the prior behavior).
func (s *service) resumeIncomingMigratedVM(ctx context.Context) error {
	// Phase 1: wait for the incoming load to settle out of "inmigrate".
	deadline := time.Now().Add(resumeSettleTimeout)
	backoff := newPollBackoff(statusPollInitial, statusPollCap)
	for {
		state, err := s.sandbox.GetVMRunState(ctx)
		if err != nil {
			shimLog.WithError(err).Warn("resumeIncomingMigratedVM: GetVMRunState unavailable; falling back to a single ResumeVM")
			return s.sandbox.ResumeVM(ctx)
		}
		if state == "running" {
			shimLog.WithField("runState", state).Warn("resumeIncomingMigratedVM: guest already running after incoming load (no cont needed)")
			return nil
		}
		if state != "inmigrate" && state != "finish-migrate" {
			shimLog.WithField("runState", state).Warn("resumeIncomingMigratedVM: incoming load settled; issuing cont")
			break
		}
		if time.Now().After(deadline) {
			shimLog.WithField("runState", state).Warn("resumeIncomingMigratedVM: timed out waiting for incoming load to settle; issuing cont anyway")
			break
		}
		time.Sleep(backoff.wait())
	}

	// Phase 2: cont, then verify the guest actually reaches "running".
	// Retry: the first cont can still race the very tail of the load.
	var lastState string
	for attempt := 1; attempt <= resumeVerifyAttempts; attempt++ {
		if err := s.sandbox.ResumeVM(ctx); err != nil {
			return fmt.Errorf("cont (attempt %d): %w", attempt, err)
		}
		state, err := s.sandbox.GetVMRunState(ctx)
		if err != nil {
			shimLog.WithError(err).Warn("resumeIncomingMigratedVM: GetVMRunState after cont unavailable; assuming resumed")
			return nil
		}
		lastState = state
		if state == "running" {
			shimLog.WithFields(map[string]interface{}{
				"attempt":  attempt,
				"runState": state,
			}).Warn("resumeIncomingMigratedVM: guest running")
			return nil
		}
		shimLog.WithFields(map[string]interface{}{
			"attempt":  attempt,
			"runState": state,
		}).Warn("resumeIncomingMigratedVM: guest not yet running after cont; retrying")
		time.Sleep(statusPollCap)
	}
	return fmt.Errorf("guest did not reach running after %d cont attempts (last run state %q)", resumeVerifyAttempts, lastState)
}

// startIOForMigratedContainers spawns the per-container FIFO ↔ kata-
// agent vsock ioCopy goroutines that normal startContainer (start.go)
// spawns at StartContainer time. Idempotent — skips containers that
// already have a ttyio (rare; an attach() before migration completed
// would set one up). Best-effort per container: a failure on one is
// logged and the rest of the loop continues so a single broken pipe
// doesn't strand the others.
func (s *service) startIOForMigratedContainers(ctx context.Context) (wired int, skipped int) {
	// Snapshot the container set under s.mu so we don't iterate
	// while CreateContainer is concurrently appending. The mutex
	// is short-held; the IO wire-up itself runs outside it.
	s.mu.Lock()
	containers := make([]*container, 0, len(s.containers))
	shimIDs := make([]string, 0, len(s.containers))
	for _, c := range s.containers {
		containers = append(containers, c)
		shimIDs = append(shimIDs, c.id)
	}
	s.mu.Unlock()

	// Two-view diagnostic: shim's s.containers map vs the vc-level
	// Sandbox container list. They CAN diverge:
	//   - shim.Create populates s.containers only when containerd
	//     calls CreateTask, which may be skipped for migration-
	//     incoming workload containers.
	//   - The dual-identity adoption flow can add to the sandbox
	//     container list without going through shim.Create.
	// Printing both sides at ENTRY makes that mismatch grep-able
	// without an extra debug round trip.
	var sandboxIDs []string
	if s.sandbox != nil {
		for _, sc := range s.sandbox.GetAllContainers() {
			sandboxIDs = append(sandboxIDs, fmt.Sprintf("containerdID=%s,internalID=%s",
				truncID(sc.ContainerdID()), truncID(sc.InternalID())))
		}
	}
	shimLog.WithFields(map[string]interface{}{
		"shimContainerCount":    len(containers),
		"shimContainerIDs":      shimIDs,
		"sandboxContainerCount": len(sandboxIDs),
		"sandboxContainerIDs":   sandboxIDs,
	}).Warn("startIOForMigratedContainers: ENTRY (shim+sandbox view)")

	for _, c := range containers {
		// Resolve sandbox-side identity if available — InternalID
		// differs from the shim id only when adoption fired.
		var internalID string
		if s.sandbox != nil {
			for _, sc := range s.sandbox.GetAllContainers() {
				if sc.ContainerdID() == c.id {
					internalID = sc.InternalID()
					break
				}
			}
		}
		clog := shimLog.WithFields(map[string]interface{}{
			"container":  c.id,
			"internalID": truncID(internalID),
			"cType":      c.cType,
			"status":     c.status.String(),
			"terminal":   c.terminal,
			"ttyioSet":   c.ttyio != nil,
			"stdinPath":  truncPath(c.stdin),
			"stdoutPath": truncPath(c.stdout),
			"stderrPath": truncPath(c.stderr),
		})
		clog.Warn("startIOForMigratedContainers: per-container state")
		if c.ttyio != nil {
			clog.Warn("startIOForMigratedContainers: SKIP reason=ttyio already wired")
			skipped++
			continue
		}
		if c.stdin == "" && c.stdout == "" && c.stderr == "" {
			// No FIFOs requested at CreateContainer time. For
			// migration-incoming this usually means containerd's
			// CreateTask never landed for this container (because
			// the workload was migrated, not created on dest).
			// Close the io channels so wait() doesn't hang.
			clog.Warn("startIOForMigratedContainers: SKIP reason=no stdio paths (containerd CreateTask likely never fired for this migrated container)")
			select {
			case <-c.exitIOch:
			default:
				close(c.exitIOch)
			}
			select {
			case <-c.stdinCloser:
			default:
				close(c.stdinCloser)
			}
			skipped++
			continue
		}
		// IOStream calls into kata-agent over vsock to obtain per-
		// container stdin/stdout/stderr streams. The ReadStdout/
		// ReadStderr RPC sends ContainerId=c.InternalID() AND
		// ExecId=processID (whatever we pass here) — and the agent's
		// find_container_process looks the exec_id up in ctr.processes,
		// which is keyed by the SOURCE container's exec_id (== source
		// containerd ID) because that's what CreateContainer registered.
		// Pre-migration c.id == c.InternalID(), so passing c.id worked.
		// After adoption (#80) c.id is the DEST containerd ID while
		// InternalID() is the source one — passing c.id makes the agent
		// answer InvalidExecId and the shim's ioCopy goroutine sees that
		// as an immediate EOF (kubectl logs returns empty post-migration).
		//
		// Use internalID when it's been set by adoption; otherwise
		// fall back to c.id (pre-migration / unadopted path is identical).
		processID := c.id
		if internalID != "" && internalID != c.id {
			processID = internalID
		}
		ioStreamStart := time.Now()
		stdin, stdout, stderr, err := s.sandbox.IOStream(c.id, processID)
		ioStreamElapsed := time.Since(ioStreamStart).String()
		if err != nil {
			clog.WithError(err).WithField("elapsed", ioStreamElapsed).
				Warn("startIOForMigratedContainers: IOStream FAILED; container logs unavailable until shim restart")
			skipped++
			continue
		}
		clog.WithField("elapsed", ioStreamElapsed).
			Warn("startIOForMigratedContainers: IOStream OK (agent vsock streams acquired)")
		c.stdinPipe = stdin
		// Open the host-side FIFOs containerd pre-created during
		// CreateContainer. c.stdin/stdout/stderr hold the absolute
		// paths under /run/containerd/io.containerd.runtime.v2.task/k8s.io/<id>/.
		ttyStart := time.Now()
		tty, ttyErr := newTtyIO(ctx, s.namespace, c.id, c.stdin, c.stdout, c.stderr, c.terminal)
		ttyElapsed := time.Since(ttyStart).String()
		if ttyErr != nil {
			clog.WithError(ttyErr).WithField("elapsed", ttyElapsed).
				Warn("startIOForMigratedContainers: newTtyIO FAILED (host FIFO open); skipping container")
			skipped++
			continue
		}
		clog.WithField("elapsed", ttyElapsed).
			Warn("startIOForMigratedContainers: newTtyIO OK (host FIFOs open)")
		c.ttyio = tty
		// Wrap ioCopy with lifecycle logging so a silently-exiting
		// goroutine is detectable in the journal. Without this we
		// can't tell whether the goroutine is blocked on Read (good)
		// or exited because the agent's stdout stream returned EOF
		// immediately (bad — agent has no captured stdio for this
		// migrated container).
		clogCopy := clog
		go func() {
			startTime := time.Now()
			clogCopy.Warn("ioCopy goroutine STARTED")
			ioCopy(clogCopy, c.exitIOch, c.stdinCloser, tty, stdin, stdout, stderr)
			clogCopy.WithField("ranFor", time.Since(startTime).String()).
				Warn("ioCopy goroutine EXITED — bytes from agent's stdout stream stopped flowing (EOF, stream closed, or container exit)")
		}()
		clog.Warn("startIOForMigratedContainers: IO forwarding WIRED (FIFO ↔ agent vsock copy goroutine spawned)")
		wired++
	}
	shimLog.WithFields(map[string]interface{}{
		"wired":   wired,
		"skipped": skipped,
	}).Warn("startIOForMigratedContainers: EXIT")
	return wired, skipped
}

// truncID shortens a container ID for log readability while keeping
// enough leading bytes to disambiguate across the per-migration
// sandbox set (k8s sandbox IDs collide on the first 8 chars maybe
// once per node lifetime). Empty input → "<none>".
func truncID(id string) string {
	if id == "" {
		return "<none>"
	}
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

// truncPath shows the tail of a path (the per-container subdirectory
// + log filename) so the logged value identifies WHICH FIFO without
// repeating /run/containerd/io.containerd.runtime.v2.task/k8s.io/
// for every line.
func truncPath(p string) string {
	if p == "" {
		return "<empty>"
	}
	if len(p) <= 60 {
		return p
	}
	return "..." + p[len(p)-60:]
}

// onMigrationAbort is the OnAbort hook on the DESTINATION shim. The
// source's AbortHandoff RPC OR the coordinator's
// defaultSourceTimeout firing reaches us here. We flip mode to
// Failed and let the load-bearing cleanup happen via the controller-
// driven /migration/abort-cleanup endpoint, which is reliably
// invoked from the vamos reconciler when it observes the failed
// state.
//
// We intentionally do NOT call sandbox.Stop here. By symmetry with
// onMigrationComplete — which has been empirically observed to skip
// firing in production (see project_onmigrationcomplete_does_not_fire
// memory note) — relying on OnAbort to drive load-bearing cleanup
// would silently leak resources whenever this callback is skipped.
// Doing best-effort work here would mask the design choice that
// abort cleanup must live in a controller-callable HTTP path that
// the controller can verify ran.
func (s *service) onMigrationAbort(reason string) {
	shimLog.WithField("reason", reason).Warn("migration aborted by source")
	// Record WHY for /migration/status: abort-originated failures have no
	// QEMU-side LastError, and "mode=failed, lastError=null" forces journal
	// archaeology on the operator (observed on the first hibernate-restore
	// e2e, where the inactivity watchdog fired invisibly).
	s.migrationMu.Lock()
	s.migrationAbortReason = reason
	s.migrationMu.Unlock()
	_ = s.transitionMigrationMode(ModeFailed)
}

// BeginMigrateOut runs the source-side handoff sequence:
//   - transition to MigratingOut
//   - dial destination MigrationCoordinator
//   - PrepareIncoming
//   - SendSandboxState (streamed)
//   - hypervisor.MigrateOut
//   - poll GetMigrationStatus until completed or failed
//   - CompleteHandoff
//   - transition to Migrated
//
// Failure semantics:
//   - Pre-MigrateOut errors (dial, PrepareIncoming, SendSandboxState)
//     roll back to Owner — nothing irreversible has happened on the
//     source's hypervisor yet.
//   - Post-MigrateOut errors transition to Failed and emit
//     AbortHandoff to the destination — the destination should tear
//     down its QEMU.
//
// dataHostHint, when non-empty, is the host the source's QEMU should
// dial for the actual memory transfer. It overrides the host portion
// of the IncomingUri that the destination returned. Required when
// the destination's QEMU listens inside its sandbox network
// namespace (kata default) and the coordinator's host (typically a
// node IP) doesn't reach the QEMU listener. Empty preserves the
// legacy behavior of reusing destSocketPath's host.
func (s *service) BeginMigrateOut(ctx context.Context, destSocketPath, dataHostHint string, opts vc.MigrateOptions) error {
	if !IsLiveMigrationEnabled(ctx) {
		return ErrLiveMigrationDisabled
	}
	if err := s.transitionMigrationMode(ModeMigratingOut); err != nil {
		return err
	}

	client, err := mc.Dial(ctx, s.id, destSocketPath)
	if err != nil {
		// Nothing irreversible yet — return to Owner.
		_ = s.transitionMigrationMode(ModeOwner)
		return fmt.Errorf("dial destination coordinator: %w", err)
	}
	defer client.Close()

	prepResp, err := client.PrepareIncoming(ctx, capsToList(opts.Capabilities), nil)
	if err != nil {
		_ = s.transitionMigrationMode(ModeOwner)
		return fmt.Errorf("PrepareIncoming: %w", err)
	}

	state, err := s.serializeSandboxState()
	if err != nil {
		_ = s.transitionMigrationMode(ModeFailed)
		_ = client.AbortHandoff(ctx, fmt.Sprintf("serialize state: %v", err))
		return fmt.Errorf("serialize SandboxState: %w", err)
	}
	if _, err := client.SendSandboxState(ctx, bytes.NewReader(state)); err != nil {
		// SendSandboxState applied state on the destination; we
		// can't simply return to Owner. Treat as terminal failure.
		_ = s.transitionMigrationMode(ModeFailed)
		_ = client.AbortHandoff(ctx, fmt.Sprintf("send state: %v", err))
		return fmt.Errorf("SendSandboxState: %w", err)
	}

	// The destination binds QEMU's -incoming socket on 0.0.0.0 so any
	// peer can reach it. The IncomingUri it returns echoes the bind
	// address. From the source's perspective, "tcp:0.0.0.0:port"
	// would resolve to the source's own loopback — useless for memory
	// transfer. Rewrite the host portion to a destination address
	// that actually reaches QEMU. Prefer dataHostHint (typically the
	// destination pod IP, since kata QEMU binds inside the sandbox
	// netns) and fall back to destSocketPath's host (legacy callers).
	migrateURI := rewriteIncomingHost(prepResp.IncomingUri, destSocketPath, dataHostHint)
	shimLog.WithFields(map[string]interface{}{
		"originalIncomingUri": prepResp.IncomingUri,
		"rewrittenURI":        migrateURI,
		"destSocketPath":      destSocketPath,
		"dataHostHint":        dataHostHint,
	}).Warn("BeginMigrateOut: about to run QMP migrate")
	// pause-before-switchover: install the gate BEFORE issuing the
	// migrate command. If we wait until afterwards there's a race
	// window where QEMU reaches pre-switchover and waits for a
	// migrate-continue we have no machinery to deliver yet.
	pauseBeforeSwitchover := opts.Capabilities["pause-before-switchover"]
	if pauseBeforeSwitchover {
		s.armMigrateContinueGate()
		defer s.disarmMigrateContinueGate()
	}

	if err := s.sandbox.MigrateOut(ctx, migrateURI, opts); err != nil {
		_ = s.transitionMigrationMode(ModeFailed)
		_ = client.AbortHandoff(ctx, fmt.Sprintf("MigrateOut: %v", err))
		return fmt.Errorf("hypervisor MigrateOut: %w", err)
	}

	if pauseBeforeSwitchover {
		// Park until QEMU reaches pre-switchover (end of bulk
		// pre-copy), then block on the /migration/continue HTTP
		// trigger before issuing migrate-continue.
		reached, err := s.waitForMigrationPhase(ctx, "pre-switchover")
		if err != nil {
			_ = s.transitionMigrationMode(ModeFailed)
			_ = s.sandbox.CancelMigration(ctx)
			_ = client.AbortHandoff(ctx, fmt.Sprintf("wait pre-switchover: %v", err))
			return fmt.Errorf("wait pre-switchover: %w", err)
		}
		if reached {
			shimLog.Warn("BeginMigrateOut: reached pre-switchover; blocking on /migration/continue")
			if err := s.awaitMigrateContinue(ctx); err != nil {
				_ = s.transitionMigrationMode(ModeFailed)
				_ = s.sandbox.CancelMigration(ctx)
				_ = client.AbortHandoff(ctx, fmt.Sprintf("await continue: %v", err))
				return fmt.Errorf("await migrate-continue: %w", err)
			}
			shimLog.Warn("BeginMigrateOut: /migration/continue received; issuing migrate-continue")
			if err := s.sandbox.MigrationContinue(ctx, "pre-switchover"); err != nil {
				_ = s.transitionMigrationMode(ModeFailed)
				_ = s.sandbox.CancelMigration(ctx)
				_ = client.AbortHandoff(ctx, fmt.Sprintf("migrate-continue: %v", err))
				return fmt.Errorf("migrate-continue: %w", err)
			}
		} else {
			shimLog.Warn("BeginMigrateOut: pause-before-switchover requested but migration completed without parking — proceeding")
		}
	}

	if err := s.waitForMigrationComplete(ctx); err != nil {
		_ = s.transitionMigrationMode(ModeFailed)
		_ = s.sandbox.CancelMigration(ctx)
		_ = client.AbortHandoff(ctx, fmt.Sprintf("wait: %v", err))
		return fmt.Errorf("wait for migration: %w", err)
	}

	if _, err := client.CompleteHandoff(ctx); err != nil {
		_ = s.transitionMigrationMode(ModeFailed)
		return fmt.Errorf("CompleteHandoff: %w", err)
	}

	return s.transitionMigrationMode(ModeMigrated)
}

// BeginMigrateSave checkpoints the running VM to an arbitrary stream
// sink (snapshot save for suspend/hibernate). It is the QEMU-only
// subset of BeginMigrateOut: there is no destination shim, so no
// coordinator dial, no PrepareIncoming/SendSandboxState handshake, and
// no ownership transfer. The caller (a node-local snapshot agent)
// listens on sinkURI's address and persists the stream; the serialized
// sandbox state is RETURNED so the caller can store it alongside the
// stream and replay it to a future incoming shim via the coordinator's
// SendSandboxState at restore time.
//
// Sequence: pause vCPUs → serialize sandbox state → QMP migrate to the
// sink → wait for completion. Pausing first makes the save a single
// clean pass (a frozen guest dirties no pages, so nothing is re-sent
// into the file) and freezes the state the snapshot describes.
//
// Failure semantics differ deliberately from BeginMigrateOut: nothing
// has been handed off, so EVERY failure path resumes the guest and
// returns the sandbox to Owner — a failed save leaves the workload
// running and unharmed. On success the VM is left paused in mode
// Saved — pod delete then runs NORMAL teardown (unlike Migrated,
// which defers it), so no orphan QEMU/virtiofsd/shim survives.
//
// Callers must not enable multifd: a multi-channel stream interleaves
// across connections nondeterministically and cannot be replayed from
// a file. The single default migration channel is the contract.
func (s *service) BeginMigrateSave(ctx context.Context, sinkURI string, opts vc.MigrateOptions) ([]byte, error) {
	if !IsLiveMigrationEnabled(ctx) {
		return nil, ErrLiveMigrationDisabled
	}
	if err := s.transitionMigrationMode(ModeMigratingOut); err != nil {
		return nil, err
	}

	abort := func(stage string, cause error) error {
		_ = s.sandbox.ResumeVM(ctx)
		_ = s.transitionMigrationMode(ModeOwner)
		return fmt.Errorf("%s: %w", stage, cause)
	}

	if err := s.sandbox.PauseVM(ctx); err != nil {
		_ = s.transitionMigrationMode(ModeOwner)
		return nil, fmt.Errorf("pause VM for save: %w", err)
	}
	state, err := s.serializeSandboxState()
	if err != nil {
		return nil, abort("serialize SandboxState", err)
	}

	shimLog.WithFields(map[string]interface{}{
		"sinkURI": sinkURI,
	}).Warn("BeginMigrateSave: VM paused; streaming state to sink")
	if err := s.sandbox.MigrateOut(ctx, sinkURI, opts); err != nil {
		return nil, abort("hypervisor MigrateOut (save)", err)
	}
	if err := s.waitForMigrationComplete(ctx); err != nil {
		_ = s.sandbox.CancelMigration(ctx)
		return nil, abort("wait for save", err)
	}

	// Stay in ModeMigratingOut here — do NOT transition to ModeSaved yet.
	// ModeSaved closes the agent connection (MarkAgentSaved), which unblocks
	// the per-container wait() goroutine and drives Sandbox.Stop ->
	// UnshareRootFilesystem, unmounting the workload rootfs bind. A caller that
	// captures that rootfs (e.g. a snapshot-save that tars the workload
	// filesystem after the vCPUs are paused) MUST do so BEFORE that teardown,
	// then call FinalizeMigrateSave to reach ModeSaved. While in
	// ModeMigratingOut the wait() teardown guard defers Stop+Delete, so the
	// rootfs bind stays mounted for the capture.
	return state, nil
}

// FinalizeMigrateSave completes a BeginMigrateSave by transitioning the paused,
// already-streamed-out sandbox to ModeSaved. ModeSaved closes the agent
// connection and lets the wait()-driven teardown reap QEMU/virtiofsd/shim
// cleanly on pod delete (no orphans). It is split out of BeginMigrateSave so the
// caller can capture the workload rootfs while it is still mounted — the
// ModeSaved teardown unmounts it. transitionMigrationMode rejects an
// out-of-order from-state, so a second call (or one after the sandbox already
// advanced) returns ErrInvalidMigrationTransition rather than re-running the
// teardown hooks.
func (s *service) FinalizeMigrateSave(ctx context.Context) error {
	return s.transitionMigrationMode(ModeSaved)
}

// armMigrateContinueGate installs a fresh channel so callers can park
// at pre-switchover until /migration/continue closes it. Idempotent —
// if a gate is already installed (a previous BeginMigrateOut leaked
// it) it's replaced rather than reused, because the old channel may
// already be closed.
func (s *service) armMigrateContinueGate() {
	s.migrationMu.Lock()
	s.migrationContinueCh = make(chan struct{})
	s.migrationMu.Unlock()
}

// disarmMigrateContinueGate clears the gate. Called from defer in
// BeginMigrateOut so the channel doesn't outlive the migration even
// when the path errors out before consuming the signal.
func (s *service) disarmMigrateContinueGate() {
	s.migrationMu.Lock()
	s.migrationContinueCh = nil
	s.migrationMu.Unlock()
}

// awaitMigrateContinue blocks until the gate's channel is closed (by
// signalMigrateContinue) or ctx is cancelled. Returns ctx.Err() on
// cancellation; nil on the success path.
func (s *service) awaitMigrateContinue(ctx context.Context) error {
	s.migrationMu.Lock()
	ch := s.migrationContinueCh
	s.migrationMu.Unlock()
	if ch == nil {
		// disarmed already — surface as an error so the caller
		// doesn't silently skip the cutover gate.
		return errors.New("migrate-continue gate is not armed")
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// signalMigrateContinue is the entry point /migration/continue calls.
// Closes the gate if one is armed and still open. Returns false if no
// gate is armed (no pause-before-switchover in flight) or if it was
// already signaled — both surface as a 409 to the operator.
func (s *service) signalMigrateContinue() bool {
	s.migrationMu.Lock()
	defer s.migrationMu.Unlock()
	if s.migrationContinueCh == nil {
		return false
	}
	select {
	case <-s.migrationContinueCh:
		// Already closed by a prior call.
		return false
	default:
		close(s.migrationContinueCh)
		return true
	}
}

// waitForMigrationPhase polls until GetMigrationStatus reports the
// named phase. Returns (true, nil) when reached, (false, nil) when
// the migration completed without ever observing the target (e.g.
// the pause-before-switchover capability was silently ignored or the
// migration was tiny enough to skip the park), and (false, err) on
// a terminal failure phase or polling error.
func (s *service) waitForMigrationPhase(ctx context.Context, target string) (bool, error) {
	backoff := newPollBackoff(statusPollInitial, statusPollCap)
	var lastPhase string
	for {
		status, err := s.sandbox.GetMigrationStatus(ctx)
		if err != nil {
			return false, fmt.Errorf("GetMigrationStatus: %w", err)
		}
		if status.Phase != lastPhase {
			shimLog.WithFields(map[string]interface{}{
				"prevPhase":        lastPhase,
				"newPhase":         status.Phase,
				"targetPhase":      target,
				"bytesTransferred": status.BytesTransferred,
				"totalBytes":       status.TotalBytes,
				"remainingMS":      status.RemainingMS,
			}).Warn("waitForMigrationPhase: phase transition")
			lastPhase = status.Phase
			backoff.reset(statusPollInitial)
		}
		if status.Phase == target {
			return true, nil
		}
		switch status.Phase {
		case "failed", "cancelled":
			if status.LastError != "" {
				return false, fmt.Errorf("migration ended in phase %q before reaching %q: %s",
					status.Phase, target, status.LastError)
			}
			return false, fmt.Errorf("migration ended in phase %q before reaching %q",
				status.Phase, target)
		case "completed":
			// QEMU finished without parking at the requested phase.
			// Caller's waitForMigrationComplete will observe the
			// same "completed" on its first poll; no migrate-continue
			// is needed.
			return false, nil
		}
		timer := time.NewTimer(backoff.wait())
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, ctx.Err()
		case <-timer.C:
		}
	}
}

// waitForMigrationComplete polls hypervisor.GetMigrationStatus until
// the phase is "completed" (success) or "failed"/"cancelled" (terminal
// error). Returns ctx.Err() if the context expires first.
//
// Uses an exponential backoff between polls (statusPollInitial ->
// statusPollCap, doubling each round) that resets whenever the phase
// changes, so we stay responsive at transitions but quiet during a
// long stable "active" phase.
func (s *service) waitForMigrationComplete(ctx context.Context) error {
	backoff := newPollBackoff(statusPollInitial, statusPollCap)
	var lastPhase string

	for {
		// Check immediately on the first iteration — tests that
		// complete in one step otherwise wait one full backoff.
		status, err := s.sandbox.GetMigrationStatus(ctx)
		if err != nil {
			return fmt.Errorf("GetMigrationStatus: %w", err)
		}
		// Log every phase transition with the full status — turns
		// "migration ended in phase failed" from an opaque footer
		// into a trail we can read from the journal: which phases
		// were observed, when, how many bytes moved at each, and the
		// QEMU error description on terminal failure.
		if status.Phase != lastPhase {
			shimLog.WithFields(map[string]interface{}{
				"prevPhase":        lastPhase,
				"newPhase":         status.Phase,
				"bytesTransferred": status.BytesTransferred,
				"totalBytes":       status.TotalBytes,
				"dirtyRateBPS":     status.DirtyRate,
				"bandwidthBPS":     status.BandwidthBPS,
				"remainingMS":      status.RemainingMS,
				"lastError":        status.LastError,
			}).Warn("waitForMigrationComplete: phase transition")
		}
		switch status.Phase {
		case "completed":
			shimLog.WithField("bytesTransferred", status.BytesTransferred).
				Warn("waitForMigrationComplete: migration completed")
			return nil
		case "failed", "cancelled":
			shimLog.WithFields(map[string]interface{}{
				"phase":            status.Phase,
				"bytesTransferred": status.BytesTransferred,
				"totalBytes":       status.TotalBytes,
				"lastError":        status.LastError,
			}).Error("waitForMigrationComplete: migration terminated")
			if status.LastError != "" {
				return fmt.Errorf("migration ended in phase %q: %s",
					status.Phase, status.LastError)
			}
			return fmt.Errorf("migration ended in phase %q", status.Phase)
		}
		if status.Phase != lastPhase {
			backoff.reset(statusPollInitial)
			lastPhase = status.Phase
		}

		wait := backoff.wait()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// serializeSandboxState returns the JSON bytes streamed via
// SendSandboxState. Reads the sandbox's live state via DumpState
// (the same assembly path Save uses to persist to disk) so the
// destination receives the full picture: hypervisor config, agent
// URL, network info, device list, cgroup paths. Per-container state
// is intentionally not included — a future protocol message will
// carry that once we settle the wire format.
func (s *service) serializeSandboxState() ([]byte, error) {
	state, err := s.sandbox.DumpState()
	if err != nil {
		return nil, fmt.Errorf("dump sandbox state: %w", err)
	}
	return json.Marshal(state)
}

// AbortMigration is the operator-facing kill switch for an
// in-flight migration. Behaviour depends on the current mode:
//
//   - Owner, Migrated, Failed: idempotent no-op (already not
//     migrating, or already terminal).
//   - MigratingOut (source): invoke hypervisor.CancelMigration and
//     transition to Failed. Any in-flight BeginMigrateOut poll loop
//     will see status=cancelled on its next iteration and tear down
//     its own coordinator client cleanly.
//   - Incoming (destination): stop the coordinator server, invoke
//     hypervisor.CancelMigration, transition to Failed.
//
// Safe to call from any context; safe to call concurrently with
// itself. The underlying transitionMigrationMode is locked.
func (s *service) AbortMigration(ctx context.Context, reason string) error {
	mode := s.currentMigrationMode()
	logger := shimLog.WithField("reason", reason).WithField("mode", mode)
	switch mode {
	case ModeOwner, ModeMigrated, ModeFailed:
		// Either there's nothing to abort or we're already in a
		// terminal state — call is idempotent.
		return nil
	case ModeMigratingOut:
		if err := s.sandbox.CancelMigration(ctx); err != nil {
			logger.WithError(err).Warn("CancelMigration during abort failed; transitioning to Failed anyway")
		}
		_ = s.transitionMigrationMode(ModeFailed)
		logger.Info("source-side migration aborted")
		return nil
	case ModeIncoming:
		_ = s.stopMigrationServer()
		if err := s.sandbox.CancelMigration(ctx); err != nil {
			logger.WithError(err).Warn("CancelMigration during abort failed; transitioning to Failed anyway")
		}
		_ = s.transitionMigrationMode(ModeFailed)
		logger.Info("destination-side migration aborted")
		return nil
	}
	return nil
}

// capsToList converts the MigrateOptions Capabilities map to the
// list form the PrepareIncoming RPC expects — only enabled
// capabilities are sent.
func capsToList(caps map[string]bool) []string {
	out := make([]string, 0, len(caps))
	for name, enabled := range caps {
		if enabled {
			out = append(out, name)
		}
	}
	return out
}

// rewriteIncomingHost substitutes the host portion of the IncomingUri
// the destination returned (typically "tcp:0.0.0.0:PORT" or
// "tcp:[::]:PORT" because the destination's QEMU bound on the
// wildcard address) with an address that actually reaches QEMU.
//
// dataHostHint may be either of two forms:
//
//	"host"       — substitute only the host; reuse incomingURI's port.
//	"host:port"  — full override of both host and port. Used when the
//	               orchestrator inserts an agent-side relay listener
//	               on an ephemeral local port; the destination
//	               QEMU's actual 4444 is not what the source should
//	               dial.
//
// Host/port resolution order:
//  1. dataHostHint when non-empty — see above.
//  2. host portion of dialTarget when it's a "tcp:host:port" dial
//     target — preserves the legacy behavior for callers that don't
//     pass a hint and where the coordinator and QEMU share a netns.
//
// Falls back to the original incomingURI on any parsing surprise
// rather than blocking the migration; the caller will see a QEMU
// migrate failure if the URI ends up unroutable.
func rewriteIncomingHost(incomingURI, dialTarget, dataHostHint string) string {
	if !strings.HasPrefix(incomingURI, "tcp:") {
		return incomingURI
	}
	// Extract port from incomingURI: tcp:HOST:PORT, where HOST may
	// be 0.0.0.0, [::], or a real address.
	inAddr := strings.TrimPrefix(incomingURI, "tcp:")
	_, inPort, ok := splitLastColon(inAddr)
	if !ok {
		return incomingURI
	}
	if dataHostHint != "" {
		// "host:port" → full override (e.g. an agent-relay
		// listener on an ephemeral local port). Use net.SplitHostPort
		// so IPv6 hosts that need bracketing ("[::1]:5555") are
		// detected correctly; an unbracketed "::1" is a bare host
		// and falls through to the host-only branch below.
		if hintHost, hintPort, err := net.SplitHostPort(dataHostHint); err == nil && hintPort != "" {
			return "tcp:" + net.JoinHostPort(hintHost, hintPort)
		}
		return "tcp:" + net.JoinHostPort(dataHostHint, inPort)
	}
	if !strings.HasPrefix(dialTarget, "tcp:") {
		return incomingURI
	}
	dialAddr := strings.TrimPrefix(dialTarget, "tcp:")
	dialHost, _, ok := splitLastColon(dialAddr)
	if !ok {
		return incomingURI
	}
	return "tcp:" + dialHost + ":" + inPort
}

// splitLastColon splits on the last colon so IPv6 hosts with their
// own colons survive — works for "host:port" and "[::1]:port" alike.
func splitLastColon(s string) (host, port string, ok bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}
