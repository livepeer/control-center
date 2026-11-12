package machineconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/payment"
	"time"
)

func (s *Manager) applied(ctx context.Context, m Machine) (Runtime, string, error) {
	var data []byte
	err := s.store.DB.QueryRowContext(ctx, `SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, m.NodeID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return Runtime{}, "", ErrFenced
	}
	if err != nil {
		return Runtime{}, "", err
	}
	return ReadApplied(data)
}

// Gate holds the applied workload until a fresh report completes its drain.
// The caller saves this state under the enrollment's lease before publication.
func (s *Manager) Gate(ctx context.Context, m Machine, state *State, desired Desired) (bool, error) {
	if desired.PaymentError != nil {
		return false, desired.PaymentError
	}
	if desired.Payment.Paid() {
		state.PaymentSettled = false
	}
	old, manifest, err := s.applied(ctx, m)
	if err != nil {
		return false, err
	}
	desired.State = *state
	desired.State.HeldOrchestrator = ""
	desired.State.HeldUpgradePlan = ""
	digest := Digest(desired)
	// Admission has never opened for this paid target. Its image or rendering
	// can be repaired without asking the failed process to drain again, while
	// retaining the exact payment/storage binding and the admission freeze.
	frozen := state.ApplyingConfigDigest == old.ConfigDigest && state.DrainRequested && !state.PaymentDrainAfter.IsZero()
	initial := state.ApplyingConfigDigest == "" && state.ApprovedConfigDigest == ""
	if old.ConfigDigest != digest && old.Payment.Paid() && !old.PaymentActive && state.ApprovedConfigDigest != old.ConfigDigest && paymentJSON(old.Payment) == paymentJSON(desired.Payment) && old.UpgradeVersion == upgradeVersion(desired) && (frozen || initial) {
		state.HeldOrchestrator, state.HeldUpgradePlan = "", ""
		state.ApplyingConfigDigest = digest
		state.ApplyingUpgradeVersion = upgradeVersion(desired)
		state.PendingConfigDigest = digest
		state.RolloutReason = "rollout_pending"
		return false, nil
	}
	if state.ApplyingConfigDigest != "" {
		if state.ApplyingConfigDigest == digest {
			report, at, e := s.store.Report(ctx, m, "runtime")
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return false, e
			}
			if !report.Ready || report.Generation != state.Generation || report.ConfigDigest != digest || report.K3sVersion != state.ApplyingUpgradeVersion || time.Since(at) > s.config.StatusTTL {
				state.RolloutReason = "rollout_pending"
				return false, nil
			}
			state.ApplyingConfigDigest = ""
			state.ApplyingUpgradeVersion = ""
			state.PendingConfigDigest = ""
			state.DrainRequested = false
			state.ApprovedConfigDigest = digest
			state.RolloutReason = ""
			return false, nil
		}
		// Superseding an already released target retains the admission freeze.
		state.ApplyingConfigDigest = ""
		state.ApplyingUpgradeVersion = ""
	}
	if state.HeldOrchestrator == "" && (state.ApprovedConfigDigest == digest || old.ConfigDigest == digest) {
		if desired.Payment.Paid() && state.ApprovedConfigDigest != digest {
			if !desired.PaymentReady {
				state.RolloutReason = "payment_startup_pending"
				return false, nil
			}
			state.ApprovedConfigDigest = digest
			state.RolloutReason = ""
		}
		return false, nil
	}
	if state.PendingConfigDigest != digest {
		if !state.DrainRequested || state.PendingConfigDigest != "" {
			state.Generation++
		}
		state.PendingConfigDigest = digest
		state.DrainRequested = true
		state.DrainStartedAt = time.Now().UTC()
		state.HeldOrchestrator = manifest
		state.HeldPayment = paymentJSON(old.Payment)
		s.holdUpgrade(ctx, m, state)
	}
	if old.ConfigDigest != digest {
		done, err := s.drainComplete(ctx, m, state)
		if err != nil || !done {
			return true, err
		}
	}
	if old.Payment.Paid() && (!desired.Payment.Paid() || desired.Payment.RedeemerURL != old.Payment.RedeemerURL) {
		if !s.paymentDrained(ctx, m, old, state.PaymentDrainAfter) {
			state.RolloutReason = "payment_drain_pending"
			return true, nil
		}
		if !desired.Payment.Paid() {
			state.PaymentSettled = true
		}
	}
	state.HeldOrchestrator = ""
	state.HeldUpgradePlan = ""
	state.ApplyingConfigDigest = digest
	state.ApplyingUpgradeVersion = upgradeVersion(desired)
	state.Target = ""
	state.RolloutReason = "rollout_pending"
	return false, nil
}

// StageTarget drains for a change whose external prerequisites are prepared by
// another subsystem. Gate releases the held workload once those facts are ready.
func (s *Manager) StageTarget(ctx context.Context, m Machine, state *State, desired Desired, target string) (bool, error) {
	if desired.PaymentError != nil {
		return false, desired.PaymentError
	}
	old, manifest, err := s.applied(ctx, m)
	if err != nil {
		return false, err
	}
	desired.State = *state
	desired.State.HeldOrchestrator = ""
	desired.State.HeldUpgradePlan = ""
	digest := Digest(desired)
	if !state.DrainRequested || state.Target != target {
		state.PendingConfigDigest = ""
		state.HeldOrchestrator = ""
		if old.ConfigDigest == digest {
			return false, nil
		}
		state.Generation++
		state.DrainRequested = true
		state.Target = target
		state.DrainStartedAt = time.Now().UTC()
		state.PendingConfigDigest = digest
		state.HeldOrchestrator = manifest
		state.HeldPayment = paymentJSON(old.Payment)
		s.holdUpgrade(ctx, m, state)
	}
	done, err := s.drainComplete(ctx, m, state)
	return !done, err
}

func (s *State) CancelTarget() {
	s.Generation++
	s.DrainRequested = false
	s.DrainStartedAt = time.Time{}
	s.Target = ""
	s.PendingConfigDigest = ""
	s.HeldOrchestrator = ""
	s.HeldUpgradePlan = ""
	s.ApplyingConfigDigest = ""
	s.ApplyingUpgradeVersion = ""
	s.RolloutReason = ""
}
func (s *Manager) holdUpgrade(ctx context.Context, m Machine, state *State) {
	if state.HeldUpgradePlan != "" {
		return
	}
	var data []byte
	if s.store.DB.QueryRowContext(ctx, `SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, m.NodeID).Scan(&data) == nil {
		if files, err := artifact.Read(data); err == nil {
			state.HeldUpgradePlan = string(files["upgrade-plan/plan.yaml"])
		}
	}
}

func (s *Manager) drainComplete(ctx context.Context, m Machine, state *State) (bool, error) {
	if state.DrainStartedAt.IsZero() || time.Since(state.DrainStartedAt) > s.drainTimeout() {
		state.RolloutReason = "drain_timeout"
		return false, nil
	}
	report, at, err := s.store.Report(ctx, m, "runner")
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if report.Drained && report.Generation == state.Generation && time.Since(at) <= s.config.StatusTTL && validDrainEvidence(m, *state, report, time.Now()) {
		state.PaymentDrainAfter = evidenceTime(report)
		state.RolloutReason = ""
		return true, nil
	}
	state.RolloutReason = "drain_pending"
	return false, nil
}

func (s *Manager) removalComplete(ctx context.Context, m Machine, state *State) (bool, error) {
	if state.DrainedGeneration != state.Generation {
		done, err := s.drainComplete(ctx, m, state)
		if err != nil || !done {
			return false, err
		}
		// A timely Node drain remains complete while slower app cleanup runs.
		state.DrainedGeneration = state.Generation
	}
	pending, err := machineapps.Pending(ctx, s.store.DB, m.NodeID, m.Epoch)
	if err != nil || pending {
		state.RolloutReason = "app_cleanup_pending"
		return false, err
	}
	old, _, e := s.applied(ctx, m)
	if e != nil {
		return false, e
	}
	if !s.paymentDrained(ctx, m, old, state.PaymentDrainAfter) {
		state.RolloutReason = "payment_drain_pending"
		return false, nil
	}
	state.RolloutReason = ""
	return true, nil
}

func (s *Manager) finishRemoval(ctx context.Context, l *Lease) (bool, error) {
	done, err := s.removalComplete(ctx, l.Machine, &l.State)
	if err != nil || !done {
		return false, err
	}
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var yes int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2 AND credential_version=$3 FOR UPDATE`, l.Machine.NodeID, l.Machine.Epoch, l.Machine.CredentialVersion).Scan(&yes)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM lpcc.machine_states WHERE node_id=$1 AND epoch=$2 AND lease_id=$3 AND revision=$4 AND lease_until>now() FOR UPDATE`, l.Machine.NodeID, l.Machine.Epoch, l.ID, l.Revision).Scan(&yes)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE lpcc.payment_machines SET drained=true WHERE node_id=$1`, l.Machine.NodeID); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2`, l.Machine.NodeID, l.Machine.Epoch); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func paymentJSON(c payment.Config) string { b, _ := json.Marshal(c); return string(b) }
func (s *Manager) paymentDrained(ctx context.Context, m Machine, old Runtime, after time.Time) bool {
	if !old.Payment.Paid() {
		return true
	}
	r, at, e := s.store.Report(ctx, m, "runtime")
	return e == nil && !after.IsZero() && !r.ObservedAt.Before(after) && r.Generation == old.Generation && !r.ClockUncertain && time.Since(at) <= s.config.StatusTTL && time.Since(r.ObservedAt) <= s.config.StatusTTL && r.ConfigDigest == old.ConfigDigest && r.Payment != nil && r.Payment.Generation == old.Payment.Generation && r.Payment.Applied && r.Payment.QueueKnown && r.Payment.Unsettled == 0
}

func evidenceTime(r Report) time.Time {
	if r.Evidence == nil {
		return time.Time{}
	}
	return r.Evidence.ObservedAt
}
