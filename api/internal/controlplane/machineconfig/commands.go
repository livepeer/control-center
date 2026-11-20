package machineconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNotFound              = errors.New("machine not found")
	ErrDrainChanged          = errors.New("drain intent changed")
	ErrDrainNotExpired       = errors.New("drain deadline has not expired")
	ErrForceDrainUnavailable = errors.New("no expired workload replacement to force")
)

type Change struct {
	NodeID, Lifecycle       string
	Generation              int64
	Changed, AlreadyRemoved bool
}

// Remove participates in the caller's authorization and audit transaction.
func (s *Manager) Remove(ctx context.Context, tx *sql.Tx, node string, force bool) (Change, error) {
	var present int
	result := Change{NodeID: node, Lifecycle: "removed"}
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM lpcc.machines WHERE node_id=$1 FOR UPDATE`, node).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		var retired bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.enrollments WHERE node_id=$1 AND retired_at IS NOT NULL)`, node).Scan(&retired)
		if err != nil {
			return result, err
		}
		if !retired {
			return result, ErrNotFound
		}
		result.AlreadyRemoved = true
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if force {
		_, err = tx.ExecContext(ctx, `DELETE FROM lpcc.machines WHERE node_id=$1`, node)
		result.Changed = true
		return result, err
	}
	var raw []byte
	state := InitialState(false)
	err = tx.QueryRowContext(ctx, `SELECT rollout FROM lpcc.machine_states WHERE node_id=$1 FOR UPDATE`, node).Scan(&raw)
	if err == nil {
		err = json.Unmarshal(raw, &state)
	} else if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	if err != nil {
		return result, err
	}
	result.Changed = state.Lifecycle != "draining"
	if result.Changed {
		state.Generation++
		state.Lifecycle = "draining"
		state.DrainRequested = true
		state.DrainStartedAt = time.Now().UTC()
		state.Target = ""
		state.PendingConfigDigest = ""
		state.ForcedConfigDigest = ""
		state.RolloutReason = "drain_pending"
		raw, _ = json.Marshal(state)
		_, err = tx.ExecContext(ctx, `INSERT INTO lpcc.machine_states(node_id,state,rollout) VALUES($1,'{}',$2) ON CONFLICT(node_id) DO UPDATE SET rollout=EXCLUDED.rollout,revision=lpcc.machine_states.revision+1,next_attempt_at=now()`, node, string(raw))
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `SELECT lpcc.remove_machine_apps($1,'system:machine-removal')`, node)
	}
	result.Lifecycle = "draining"
	result.Generation = state.Generation
	return result, err
}

// RetryDrain starts a fresh drain or authorizes replacement of the held workload.
func (s *Manager) RetryDrain(ctx context.Context, tx *sql.Tx, node string, generation int64, force bool) (Change, error) {
	result := Change{NodeID: node}
	var present int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM lpcc.machines WHERE node_id=$1 FOR UPDATE`, node).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT rollout FROM lpcc.machine_states WHERE node_id=$1 FOR UPDATE`, node).Scan(&raw); err != nil {
		return result, err
	}
	var state State
	if err = json.Unmarshal(raw, &state); err != nil {
		return result, err
	}
	if !state.DrainRequested || state.Generation != generation || state.Lifecycle == "removed" {
		return result, ErrDrainChanged
	}
	if !state.DrainStartedAt.IsZero() && time.Since(state.DrainStartedAt) <= s.drainTimeout() {
		return result, ErrDrainNotExpired
	}
	state.Generation++
	if force {
		if state.Lifecycle != "active" || state.Target != "" || state.DrainStartedAt.IsZero() ||
			state.HeldOrchestrator == "" || state.PendingConfigDigest == "" || state.ApplyingConfigDigest != "" || state.ForcedConfigDigest != "" {
			return result, ErrForceDrainUnavailable
		}
		state.ForcedConfigDigest = state.PendingConfigDigest
		state.RolloutReason = "rollout_pending"
	} else {
		state.ForcedConfigDigest = ""
		state.DrainStartedAt = time.Now().UTC()
		state.RolloutReason = "drain_pending"
	}
	raw, _ = json.Marshal(state)
	_, err = tx.ExecContext(ctx, `UPDATE lpcc.machine_states SET rollout=$2,revision=revision+1,next_attempt_at=now() WHERE node_id=$1`, node, string(raw))
	result.Changed = true
	result.Lifecycle = state.Lifecycle
	result.Generation = state.Generation
	return result, err
}

// FenceCredentialRefresh runs in the credential transaction, after updating the
// enrollment. A waiting state writer must recheck the changed shared revision.
func (s *Manager) FenceCredentialRefresh(ctx context.Context, tx *sql.Tx, node string) error {
	_, err := tx.ExecContext(ctx, `UPDATE lpcc.machine_states SET revision=revision+1,next_attempt_at=now() WHERE node_id=$1`, node)
	return err
}
