package machineconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/runtime/onchain"
	"time"
)

func (s *Manager) applied(ctx context.Context, m Machine) (appliedWorkload, error) {
	var data []byte
	err := s.store.DB.QueryRowContext(ctx, `SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, m.NodeID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return appliedWorkload{}, ErrFenced
	}
	if err != nil {
		return appliedWorkload{}, err
	}
	return readAppliedWorkload(data)
}

// Gate holds the applied workload until its drain completes, is forced, or reaches its deadline.
// The caller saves this state under the enrollment's lease before publication.
func (s *Manager) Gate(ctx context.Context, m Machine, state *State, desired Desired) (bool, error) {
	if desired.OnchainError != nil {
		return false, desired.OnchainError
	}
	old, err := s.applied(ctx, m)
	if err != nil {
		return false, err
	}
	desired.State = *state
	desired.State.HeldOrchestrator = ""
	desired.State.HeldUpgradePlan = ""
	digest := Digest(desired)
	state.observeForcedPublication(old.ConfigDigest)
	forced := state.ForcedDrainTarget != "" && state.ForcedDrainTarget == DrainTarget(m.NodeID, *state) &&
		state.PendingConfigDigest == digest && sameWorkloadEndpoints(old.manifest, desired)
	if state.ForcedDrainTarget != "" && !forced {
		state.ForcedDrainTarget = ""
		if state.ApplyingConfigDigest != "" {
			state.ApplyingConfigDigest = ""
			state.ApplyingUpgradeVersion = ""
			old.hold(state)
		}
	}
	// Admission has never opened for this onchain target. Its image or rendering
	// can be repaired without asking the failed process to drain again, while
	// retaining storage identity, redemption destination and the admission freeze.
	frozen := state.ApplyingConfigDigest == old.ConfigDigest
	initial := state.ApplyingConfigDigest == "" && state.ApprovedConfigDigest == ""
	repair := desired.Onchain.Onchain() && old.Onchain.Recipient == desired.Onchain.Recipient && old.Onchain.ChainID == desired.Onchain.ChainID && old.Onchain.Controller == desired.Onchain.Controller && old.Onchain.RedeemerURL == desired.Onchain.RedeemerURL
	if old.ConfigDigest != digest && old.ConfigDigest != state.UnconfirmedForcedDigest && old.Onchain.Onchain() && !old.OnchainActive && state.ApprovedConfigDigest != old.ConfigDigest && repair && old.UpgradeVersion == upgradeVersion(desired) && (frozen || initial) {
		state.HeldOrchestrator, state.HeldUpgradePlan = "", ""
		state.ApplyingConfigDigest = digest
		state.ApplyingUpgradeVersion = upgradeVersion(desired)
		state.PendingConfigDigest = digest
		state.RolloutReason = "rollout_pending"
		return false, nil
	}
	if state.ApplyingConfigDigest != "" {
		if state.ApplyingConfigDigest == digest {
			if forced {
				state.HeldOrchestrator, state.HeldUpgradePlan = "", ""
				state.RolloutReason = "rollout_pending"
				return false, nil
			}
			report, at, e := s.store.Report(ctx, m, "runtime")
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return false, e
			}
			if (desired.Onchain.Onchain() && !desired.OnchainReady) || !report.Ready || report.Generation != state.Generation || report.ConfigDigest != digest || report.K3sVersion != state.ApplyingUpgradeVersion || time.Since(at) > s.config.StatusTTL {
				state.RolloutReason = "rollout_pending"
				return false, nil
			}
			state.ApplyingConfigDigest = ""
			state.ApplyingUpgradeVersion = ""
			state.PendingConfigDigest = ""
			state.UnconfirmedForcedDigest = ""
			state.HeldOrchestrator, state.HeldUpgradePlan = "", ""
			state.DrainRequested = false
			state.ApprovedConfigDigest = digest
			state.RolloutReason = ""
			return false, nil
		}
		// Superseding an already released target retains the admission freeze.
		state.ApplyingConfigDigest = ""
		state.ApplyingUpgradeVersion = ""
	}
	if !state.DrainRequested && state.HeldOrchestrator == "" && old.ConfigDigest == digest && digest != state.UnconfirmedForcedDigest {
		if desired.Onchain.Onchain() && state.ApprovedConfigDigest != digest {
			if !desired.OnchainReady {
				state.RolloutReason = "onchain_startup_pending"
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
		old.hold(state)
	}
	if old.ConfigDigest != digest && !forced {
		now := time.Now()
		if s.drainExpired(state.DrainStartedAt, now) && state.canForceDrain() &&
			sameWorkloadEndpoints(old.manifest, desired) {
			state.forceDrain(m.NodeID)
		} else if done, err := s.drainComplete(ctx, m, state, now); err != nil || !done {
			return true, err
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
	if desired.OnchainError != nil {
		return false, desired.OnchainError
	}
	old, err := s.applied(ctx, m)
	if err != nil {
		return false, err
	}
	desired.State = *state
	desired.State.HeldOrchestrator = ""
	desired.State.HeldUpgradePlan = ""
	digest := Digest(desired)
	if !state.DrainRequested || state.Target != target {
		if old.ConfigDigest == digest {
			return false, nil
		}
		state.observeForcedPublication(old.ConfigDigest)
		state.ForcedDrainTarget = ""
		// If the route change is canceled, resume waiting for the published workload.
		if state.UnconfirmedForcedDigest == old.ConfigDigest {
			state.ApplyingConfigDigest, state.ApplyingUpgradeVersion = old.ConfigDigest, old.UpgradeVersion
		} else if state.ApplyingConfigDigest != old.ConfigDigest {
			state.ApplyingConfigDigest, state.ApplyingUpgradeVersion = "", ""
		}
		state.Generation++
		state.DrainRequested = true
		state.Target = target
		state.DrainStartedAt = time.Now().UTC()
		state.PendingConfigDigest = digest
		old.hold(state)
	}
	done, err := s.drainComplete(ctx, m, state, time.Now())
	return !done, err
}

func (s *State) CancelTarget() {
	s.Generation++
	s.Target = ""
	s.ForcedDrainTarget = ""
	s.HeldOrchestrator, s.HeldUpgradePlan = "", ""
	s.PendingConfigDigest = s.ApplyingConfigDigest
	if s.ApplyingConfigDigest != "" {
		s.RolloutReason = "rollout_pending"
		return
	}
	s.DrainRequested = false
	s.DrainStartedAt = time.Time{}
	s.ApplyingUpgradeVersion = ""
	s.RolloutReason = ""
}
func (state State) canForceDrain() bool {
	return state.Lifecycle == "active" && state.Target == "" && state.DrainRequested &&
		!state.DrainStartedAt.IsZero() && state.HeldOrchestrator != "" && state.PendingConfigDigest != "" &&
		state.ApplyingConfigDigest == "" && state.ForcedDrainTarget == ""
}

func (state *State) forceDrain(node string) {
	state.Generation++
	state.ForcedDrainTarget = DrainTarget(node, *state)
}

// Publication can be observed even if Runtime has never fetched the bundle.
func (state *State) observeForcedPublication(digest string) {
	if state.ForcedDrainTarget != "" && state.ApplyingConfigDigest == digest {
		state.ForcedDrainTarget = ""
		state.UnconfirmedForcedDigest = digest
		state.HeldOrchestrator, state.HeldUpgradePlan = "", ""
	}
}

func (s *Manager) drainExpired(startedAt, now time.Time) bool {
	return !startedAt.IsZero() && !now.Before(startedAt.Add(s.drainTimeout()))
}

func (s *Manager) drainComplete(ctx context.Context, m Machine, state *State, now time.Time) (bool, error) {
	if state.DrainStartedAt.IsZero() || s.drainExpired(state.DrainStartedAt, now) {
		state.RolloutReason = "drain_timeout"
		return false, nil
	}
	report, at, err := s.store.Report(ctx, m, "runner")
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if report.Drained && report.Generation == state.Generation && time.Since(at) <= s.config.StatusTTL && validDrainEvidence(m, *state, report, time.Now()) {
		state.RolloutReason = ""
		return true, nil
	}
	state.RolloutReason = "drain_pending"
	return false, nil
}

func (s *Manager) removalComplete(ctx context.Context, m Machine, state *State) (bool, error) {
	if state.DrainedGeneration != state.Generation {
		done, err := s.drainComplete(ctx, m, state, time.Now())
		if err != nil || !done {
			return false, err
		}
		// A timely Node drain remains complete while slower app cleanup runs.
		state.DrainedGeneration = state.Generation
	}
	pending, err := machineapps.Pending(ctx, s.store.DB, m.NodeID)
	if err != nil || pending {
		state.RolloutReason = "app_cleanup_pending"
		return false, err
	}
	state.RolloutReason = ""
	return true, nil
}

func (s *Manager) finishRemoval(ctx context.Context, l *Lease) (bool, error) {
	done, err := s.removalComplete(ctx, l.Machine, &l.State)
	if err != nil || !done {
		return false, err
	}
	result, err := s.store.DB.ExecContext(ctx, `DELETE FROM lpcc.machines WHERE node_id=$1 AND credential_version=$4 AND EXISTS(SELECT FROM lpcc.machine_states WHERE node_id=$1 AND lease_id=$2 AND revision=$3 AND lease_until>now())`, l.Machine.NodeID, l.ID, l.Revision, l.Machine.CredentialVersion)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func onchainJSON(c onchain.Config) string { b, _ := json.Marshal(c); return string(b) }
