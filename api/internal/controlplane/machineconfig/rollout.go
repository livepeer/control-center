package machineconfig

import (
	"context"
	"database/sql"
	"errors"
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
	if s.config.DrainTimeout <= 0 && !s.config.RequireDrain && (desired.Exposure == nil || desired.Exposure.IngressDigest == "") {
		return false, nil
	}
	old, manifest, err := s.applied(ctx, m)
	if err != nil {
		return false, err
	}
	desired.State = *state
	desired.State.HeldOrchestrator = ""
	digest := Digest(desired)
	if state.HeldOrchestrator == "" && (state.ApprovedConfigDigest == digest || old.ConfigDigest == digest) {
		return false, nil
	}
	if m.CredentialVersion == 0 || s.config.DrainTimeout <= 0 {
		state.HeldOrchestrator = manifest
		return true, nil
	}
	if state.PendingConfigDigest != digest {
		if !state.DrainRequested || state.PendingConfigDigest != "" {
			state.Generation++
		}
		state.PendingConfigDigest = digest
		state.DrainRequested = true
		state.DrainStartedAt = time.Now().UTC()
		state.HeldOrchestrator = manifest
	}
	if old.ConfigDigest != digest {
		done, err := s.drainComplete(ctx, m, state)
		if err != nil || !done {
			return true, err
		}
	}
	state.HeldOrchestrator = ""
	state.PendingConfigDigest = ""
	state.DrainRequested = false
	state.Target = ""
	state.ApprovedConfigDigest = digest
	state.RolloutReason = ""
	return false, nil
}

// StageTarget drains for a change whose external prerequisites are prepared by
// another subsystem. Gate releases the held workload once those facts are ready.
func (s *Manager) StageTarget(ctx context.Context, m Machine, state *State, desired Desired, target string) (bool, error) {
	old, manifest, err := s.applied(ctx, m)
	if err != nil {
		return false, err
	}
	desired.State = *state
	desired.State.HeldOrchestrator = ""
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
	s.RolloutReason = ""
}

func (s *Manager) drainComplete(ctx context.Context, m Machine, state *State) (bool, error) {
	if state.DrainStartedAt.IsZero() || time.Since(state.DrainStartedAt) > s.config.DrainTimeout {
		state.RolloutReason = "drain_timeout"
		return false, nil
	}
	report, at, err := s.store.Report(ctx, m, "runner")
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if report.Drained && report.Generation == state.Generation && time.Since(at) <= s.config.StatusTTL {
		state.RolloutReason = ""
		return true, nil
	}
	state.RolloutReason = "drain_pending"
	return false, nil
}

func (s *Manager) finishRemoval(ctx context.Context, l *Lease) (bool, error) {
	done, err := s.drainComplete(ctx, l.Machine, &l.State)
	if err != nil || !done {
		return false, err
	}
	result, err := s.store.DB.ExecContext(ctx, `DELETE FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2 AND credential_version=$5 AND EXISTS(SELECT FROM lpcc.machine_states WHERE node_id=$1 AND epoch=$2 AND lease_id=$3 AND revision=$4 AND lease_until>now())`, l.Machine.NodeID, l.Machine.Epoch, l.ID, l.Revision, l.Machine.CredentialVersion)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}
