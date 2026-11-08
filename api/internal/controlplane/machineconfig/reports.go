package machineconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/livepeer/control-center/runtime/artifact"
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
	var previous Report
	if report.Component == "runner" && (record.BundleFormat >= 2 || report.BundleFormat >= 2) {
		previous, _, err = s.store.Report(ctx, m, "runner")
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		if report.BundleFormat != 2 || report.Sequence == 0 || report.Apps == nil || len(report.Apps.Instances) > 128 {
			return false, ErrStaleStatus
		}
		seen := map[string]bool{}
		for _, i := range report.Apps.Instances {
			if i.InstanceID == "" || len(i.InstanceID) > 64 || seen[i.InstanceID] || len(i.Reason) > 128 {
				return false, ErrStaleStatus
			}
			seen[i.InstanceID] = true
		}
		if report.Drained && !validDrainEvidence(m, record.State, report, time.Now()) {
			return false, ErrStaleStatus
		}
	}
	reasons := map[string]bool{"ready": true, "applying": true, "offline": true, "failed": true, "drain_pending": true, "removed": true, "tls_pending": true}
	if !reasons[report.Reason] {
		report.Reason = "failed"
	}
	raw, _ := json.Marshal(report)
	result, err := s.store.DB.ExecContext(ctx, `INSERT INTO lpcc.machine_reports(node_id,epoch,component,generation,credential_version,report) SELECT $1,$2,$3,$4,$5,$6 WHERE EXISTS(SELECT FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2 AND credential_version=$5) ON CONFLICT(node_id,epoch,component) DO UPDATE SET generation=EXCLUDED.generation,credential_version=EXCLUDED.credential_version,report=EXCLUDED.report,received_at=now() WHERE lpcc.machine_reports.generation<=EXCLUDED.generation AND lpcc.machine_reports.credential_version<=EXCLUDED.credential_version AND ($3<>'runner' OR COALESCE((lpcc.machine_reports.report->>'bundle_format')::int,0)<2 OR COALESCE((lpcc.machine_reports.report->>'sequence')::numeric,0)<COALESCE((EXCLUDED.report->>'sequence')::numeric,0))`, m.NodeID, m.Epoch, report.Component, report.Generation, m.CredentialVersion, string(raw))
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		old, _, e := s.store.Report(ctx, m, report.Component)
		if e == nil && reflect.DeepEqual(old, report) {
			return false, nil
		}
		return false, ErrStaleStatus
	}
	drainWake := report.Component == "runner" && report.Drained && record.DrainRequested && report.Generation == record.Generation
	if report.BundleFormat >= 2 && previous.Drained && previous.Generation == report.Generation && previous.Evidence != nil && report.Evidence != nil && previous.Evidence.Target == report.Evidence.Target && time.Now().Before(previous.Evidence.ExpiresAt) {
		drainWake = false
	}
	return drainWake || (report.Component == "runtime" && ((report.BundleFormat >= 2 && report.BundleFormat > record.BundleFormat) || (report.Ready && record.ApplyingConfigDigest != "" && report.ConfigDigest == record.ApplyingConfigDigest && report.Generation == record.Generation))), nil
}

func validDrainEvidence(m Machine, state State, report Report, now time.Time) bool {
	e := report.Evidence
	if e == nil || !report.Drained || !state.DrainRequested || report.Generation != state.Generation || e.Target != DrainTarget(m.NodeID, m.Epoch, state) || e.WithdrawalID == "" || len(e.WithdrawalID) > 64 || e.Kind != "no_owner" {
		return false
	}
	if e.ObservedAt.Before(state.DrainStartedAt) || e.ObservedAt.After(now.Add(5*time.Second)) || !now.Before(e.ExpiresAt) || !e.ExpiresAt.After(e.ObservedAt) || e.ExpiresAt.Sub(e.ObservedAt) > time.Minute {
		return false
	}
	return e.OwnerID == "" || (artifact.HashPattern.MatchString(e.CredentialFingerprint) && e.MutationSequence > 0)
}
