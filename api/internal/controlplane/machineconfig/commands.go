package machineconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNotFound          = errors.New("machine not found")
	ErrEnrollmentChanged = errors.New("machine enrollment changed")
	ErrLegacyDrain       = errors.New("legacy enrollment cannot drain")
	ErrDeadlineRequired  = errors.New("configure a drain deadline")
	ErrDrainChanged      = errors.New("drain intent changed")
	ErrDrainNotExpired   = errors.New("drain deadline has not expired")
)

type Change struct {
	Epoch, Lifecycle        string
	Generation              int64
	Changed, AlreadyRemoved bool
}

// Remove participates in the caller's authorization and audit transaction.
func (s *Manager) Remove(ctx context.Context, tx *sql.Tx, node, epoch string, force bool) (Change, error) {
	var current string
	var version int64
	result := Change{Epoch: epoch, Lifecycle: "removed"}
	err := tx.QueryRowContext(ctx, `SELECT enrollment_epoch::text,credential_version FROM lpcc.machines WHERE node_id=$1 FOR UPDATE`, node).Scan(&current, &version)
	if errors.Is(err, sql.ErrNoRows) {
		var retired bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.enrollments WHERE node_id=$1 AND epoch::text=$2 AND retired_at IS NOT NULL)`, node, epoch).Scan(&retired)
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
	if current != epoch {
		return result, ErrEnrollmentChanged
	}
	if force {
		_, err = tx.ExecContext(ctx, `DELETE FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2`, node, epoch)
		result.Changed = true
		return result, err
	}
	if version == 0 {
		return result, ErrLegacyDrain
	}
	var raw []byte
	state := InitialState(false)
	err = tx.QueryRowContext(ctx, `SELECT rollout FROM lpcc.machine_states WHERE node_id=$1 AND epoch=$2 FOR UPDATE`, node, epoch).Scan(&raw)
	if err == nil {
		err = json.Unmarshal(raw, &state)
	} else if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	if err != nil {
		return result, err
	}
	if s.drainTimeout(state) <= 0 {
		return result, ErrDeadlineRequired
	}
	result.Changed = state.Lifecycle != "draining"
	if result.Changed {
		state.Generation++
		state.Lifecycle = "draining"
		state.DrainRequested = true
		state.DrainStartedAt = time.Now().UTC()
		state.Target = ""
		state.PendingConfigDigest = ""
		state.RolloutReason = "drain_pending"
		raw, _ = json.Marshal(state)
		_, err = tx.ExecContext(ctx, `INSERT INTO lpcc.machine_states(node_id,epoch,state,rollout) VALUES($1,$2,'{}',$3) ON CONFLICT(node_id,epoch) DO UPDATE SET rollout=EXCLUDED.rollout,revision=lpcc.machine_states.revision+1,next_attempt_at=now()`, node, epoch, string(raw))
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `SELECT lpcc.remove_machine_apps($1,$2,'system:machine-removal')`, node, epoch)
	}
	result.Lifecycle = "draining"
	result.Generation = state.Generation
	return result, err
}

func (s *Manager) RetryDrain(ctx context.Context, tx *sql.Tx, node, epoch string, generation int64) (Change, error) {
	result := Change{Epoch: epoch}
	var present int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch::text=$2 FOR UPDATE`, node, epoch).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrEnrollmentChanged
	}
	if err != nil {
		return result, err
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT rollout FROM lpcc.machine_states WHERE node_id=$1 AND epoch=$2 FOR UPDATE`, node, epoch).Scan(&raw); err != nil {
		return result, err
	}
	var state State
	if err = json.Unmarshal(raw, &state); err != nil {
		return result, err
	}
	if s.drainTimeout(state) <= 0 {
		return result, ErrDeadlineRequired
	}
	if !state.DrainRequested || state.Generation != generation || state.Lifecycle == "removed" {
		return result, ErrDrainChanged
	}
	if !state.DrainStartedAt.IsZero() && time.Since(state.DrainStartedAt) <= s.drainTimeout(state) {
		return result, ErrDrainNotExpired
	}
	state.Generation++
	state.DrainStartedAt = time.Now().UTC()
	state.RolloutReason = "drain_pending"
	raw, _ = json.Marshal(state)
	_, err = tx.ExecContext(ctx, `UPDATE lpcc.machine_states SET rollout=$3,revision=revision+1,next_attempt_at=now() WHERE node_id=$1 AND epoch=$2`, node, epoch, string(raw))
	result.Changed = true
	result.Lifecycle = state.Lifecycle
	result.Generation = state.Generation
	return result, err
}

// FenceCredentialRefresh runs in the credential transaction, after updating the
// enrollment. A waiting state writer must recheck the changed shared revision.
func (s *Manager) FenceCredentialRefresh(ctx context.Context, tx *sql.Tx, node, epoch string) error {
	_, err := tx.ExecContext(ctx, `UPDATE lpcc.machine_states SET revision=revision+1,next_attempt_at=now() WHERE node_id=$1 AND epoch=$2`, node, epoch)
	return err
}
