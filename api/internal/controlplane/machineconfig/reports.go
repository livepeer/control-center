package machineconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

var ErrStatusAhead = errors.New("status generation is ahead of desired state")
var ErrStaleStatus = errors.New("stale status")

// RecordReport binds observations to the current enrollment credential and
// rejects observations ahead of the persisted machine rollout. It returns
// whether the observation can advance an outstanding drain.
func (s *Manager) RecordReport(ctx context.Context, m Machine, report Report) (bool, error) {
	record, err := s.store.Load(ctx, m.NodeID, m.Epoch)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if report.Generation > max(record.Generation, 1) {
		return false, ErrStatusAhead
	}
	reasons := map[string]bool{"ready": true, "applying": true, "offline": true, "failed": true, "drain_pending": true, "removed": true, "tls_pending": true}
	if !reasons[report.Reason] {
		report.Reason = "failed"
	}
	raw, _ := json.Marshal(report)
	result, err := s.store.DB.ExecContext(ctx, `INSERT INTO lpcc.machine_reports(node_id,epoch,component,generation,credential_version,report) SELECT $1,$2,$3,$4,$5,$6 WHERE EXISTS(SELECT FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2 AND credential_version=$5) ON CONFLICT(node_id,epoch,component) DO UPDATE SET generation=EXCLUDED.generation,credential_version=EXCLUDED.credential_version,report=EXCLUDED.report,received_at=now() WHERE lpcc.machine_reports.generation<=EXCLUDED.generation AND lpcc.machine_reports.credential_version<=EXCLUDED.credential_version`, m.NodeID, m.Epoch, report.Component, report.Generation, m.CredentialVersion, string(raw))
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return false, ErrStaleStatus
	}
	return report.Component == "runner" && report.Drained && record.DrainRequested && report.Generation == record.Generation, nil
}
