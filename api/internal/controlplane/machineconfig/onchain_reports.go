package machineconfig

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Validate and retire grants with the normalized report, in its transaction.
func (s *Manager) acceptOnchainReport(ctx context.Context, tx *sql.Tx, m Machine, r Report) error {
	p := r.Onchain
	if p == nil {
		return nil
	}
	if r.Component != "runtime" || (p.Mode != "onchain" && p.Mode != "offchain") || p.Generation < 0 || len(p.PodUID) > 128 || (p.Handoff != "healthy" && p.Handoff != "degraded" && p.Handoff != "unverified") {
		return ErrStaleStatus
	}
	if !p.Applied {
		return nil
	}
	var bundle []byte
	if err := tx.QueryRowContext(ctx, `SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, m.NodeID).Scan(&bundle); errors.Is(err, sql.ErrNoRows) {
		return ErrStaleStatus
	} else if err != nil {
		return err
	}
	meta, _, err := ReadApplied(bundle)
	if err != nil || meta.Epoch != m.Epoch || meta.CredentialVersion != m.CredentialVersion || meta.ConfigDigest != r.ConfigDigest || meta.Onchain.Generation != p.Generation || meta.Onchain.Mode != p.Mode || p.PodUID == "" {
		return ErrStaleStatus
	}
	trusted := !r.ClockUncertain && time.Since(r.ObservedAt) <= s.config.StatusTTL
	if p.Mode == "onchain" {
		result, err := tx.ExecContext(ctx, `UPDATE lpcc.onchain_grants SET ready_at=CASE WHEN $7 AND $8 THEN COALESCE(ready_at,now()) ELSE ready_at END WHERE grant_id::text=$1 AND node_id=$2 AND epoch=$3 AND onchain_generation=$4 AND config_digest=$5 AND pod_uid=$6 AND revoked_at IS NULL`, p.GrantID, m.NodeID, m.Epoch, p.Generation, r.ConfigDigest, p.PodUID, trusted, p.Ready)
		if err != nil {
			return err
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return ErrStaleStatus
		}
	}
	if !trusted {
		return nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE lpcc.onchain_grants SET revoked_at=now() WHERE node_id=$1 AND epoch=$2 AND revoked_at IS NULL AND ($3='offchain' OR issued_sequence<(SELECT issued_sequence FROM lpcc.onchain_grants WHERE grant_id::text=$4))`, m.NodeID, m.Epoch, p.Mode, p.GrantID)
	return err
}
