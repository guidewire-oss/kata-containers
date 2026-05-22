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
	"time"

	mc "github.com/kata-containers/kata-containers/src/runtime/pkg/containerd-shim-v2/migration_coordinator"
	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	persistapi "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/api"
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

// BeginMigrateIncoming sets the shim up as the destination of an
// inbound live migration. Transitions the mode to Incoming, puts
// the underlying hypervisor in -incoming mode, and binds the
// MigrationCoordinator gRPC server so the source shim can dial in.
//
// Failure semantics:
//   - Feature flag missing            -> ErrLiveMigrationDisabled, mode unchanged
//   - Illegal mode transition         -> ErrInvalidMigrationTransition, mode unchanged
//   - hypervisor.MigrateIncoming err  -> mode transitions to Failed,
//                                        error returned with cause wrapped
//   - bind/start failure              -> hypervisor.CancelMigration is
//                                        invoked best-effort, mode goes
//                                        to Failed, error returned
func (s *service) BeginMigrateIncoming(ctx context.Context, listenURI string) error {
	shimLog.WithField("listenURI", listenURI).Warn("BeginMigrateIncoming: entry")
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

	if err := s.sandbox.MigrateIncoming(ctx, listenURI); err != nil {
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

	s.mu.Lock()
	s.migrationServer = srv
	s.mu.Unlock()
	shimLog.Warn("BeginMigrateIncoming: returning nil (success)")
	return nil
}

// stopMigrationServer tears down the destination-side coordinator
// server if one is bound. Idempotent and safe to call concurrently
// — the second caller observes nil and returns.
func (s *service) stopMigrationServer() error {
	s.mu.Lock()
	srv := s.migrationServer
	s.migrationServer = nil
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Stop()
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
//   1. Resume the guest (it was paused with "-S -incoming defer";
//      the migrated memory is in place by the time
//      CompleteHandoff arrives, so cont() brings the workload
//      back to life).
//   2. Check the kata-agent's gRPC server is reachable through
//      the destination host's vsock CID. The migrated agent
//      already listens on guest CID 3 / port 1024 from the
//      guest's perspective; the destination shim's agent client
//      dials destination-host-CID:1024 which the host vsock
//      module translates to the migrated guest's listener.
//   3. Flip Incoming -> Owner so subsequent CRI ops succeed.
//
// Errors during resume/check are surfaced to the source via the
// CompleteHandoff RPC's gRPC status; the source then sees the
// migration as failed and tears down its own QEMU.
func (s *service) onMigrationComplete() error {
	ctx := context.Background()
	if s.sandbox != nil {
		if err := s.sandbox.ResumeVM(ctx); err != nil {
			shimLog.WithError(err).Error("onMigrationComplete: ResumeVM failed")
			_ = s.transitionMigrationMode(ModeFailed)
			return fmt.Errorf("resume migrated VM: %w", err)
		}
		shimLog.Info("onMigrationComplete: VM resumed")
		// Best-effort agent check. A failure here is logged but
		// not fatal — the workload is running inside the guest
		// whether or not the shim can talk to its agent. CRI ops
		// will fail until the agent reconnects, but in-guest
		// services (SSH-into-guest, HTTP, etc.) work immediately.
		if err := s.sandbox.CheckAgent(ctx); err != nil {
			shimLog.WithError(err).Warn("onMigrationComplete: agent CheckAgent failed; guest is running but CRI ops to this sandbox will fail until re-paired")
		} else {
			shimLog.Info("onMigrationComplete: kata-agent reachable on destination host")
		}
	}
	return s.transitionMigrationMode(ModeOwner)
}

// onMigrationAbort is the OnAbort hook. The source's AbortHandoff
// RPC reaches us here; transition Incoming -> Failed so cleanup
// ops can run and the orchestrator can tear us down.
func (s *service) onMigrationAbort(reason string) {
	shimLog.WithField("reason", reason).Info("migration aborted by source")
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
func (s *service) BeginMigrateOut(ctx context.Context, destSocketPath string, opts vc.MigrateOptions) error {
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

	if err := s.sandbox.MigrateOut(ctx, prepResp.IncomingUri, opts); err != nil {
		_ = s.transitionMigrationMode(ModeFailed)
		_ = client.AbortHandoff(ctx, fmt.Sprintf("MigrateOut: %v", err))
		return fmt.Errorf("hypervisor MigrateOut: %w", err)
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
		switch status.Phase {
		case "completed":
			return nil
		case "failed", "cancelled":
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
