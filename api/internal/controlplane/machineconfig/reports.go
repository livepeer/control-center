package machineconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
)

var ErrStatusAhead = errors.New("status generation is ahead of desired state")
var ErrStaleStatus = errors.New("stale status")
var ErrReportOrder = errors.New("report ordering state must be restored")

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
	previous, _, err := s.store.Report(ctx, m, report.Component)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if report.ReportVersion != 1 || report.Sequence == 0 || report.ObservedAt.IsZero() {
		return false, ErrStaleStatus
	}
	if report.Sequence == previous.Sequence {
		report.ClockUncertain = report.ClockUncertain || previous.ClockUncertain
	} else {
		report.ClockUncertain = report.ClockUncertain || report.ObservedAt.After(time.Now().Add(5*time.Second)) || (!previous.ClockUncertain && !previous.ObservedAt.IsZero() && report.ObservedAt.Before(previous.ObservedAt))
	}
	if err := s.validateObservations(ctx, m, report); err != nil {
		return false, err
	}
	if m.Terminal {
		if (report.Component != "runner" && report.Component != "app-reconciler") || report.Generation != record.Generation || report.Drained || report.Evidence != nil {
			return false, ErrStaleStatus
		}
	}
	reasons := map[string]bool{"ready": true, "applying": true, "offline": true, "failed": true, "drain_pending": true, "removed": true, "tls_pending": true}
	if !reasons[report.Reason] {
		report.Reason = "failed"
	}
	if report.Sequence == previous.Sequence && reflect.DeepEqual(previous, report) {
		return false, nil
	}

	if report.Component == "runner" {
		if report.BundleFormat != contract.BundleFormat || report.Apps == nil {
			return false, ErrStaleStatus
		}
		if report.Drained && (report.ClockUncertain || !validDrainEvidence(m, record.State, report, time.Now())) {
			return false, ErrStaleStatus
		}
	}
	raw, _ := json.Marshal(report)
	result, err := s.store.DB.ExecContext(ctx, `INSERT INTO lpcc.machine_reports(node_id,epoch,component,generation,credential_version,report)
 SELECT $1,$2,$3,$4,$5,$6 WHERE EXISTS(SELECT FROM lpcc.enrollments e WHERE e.node_id=$1 AND e.epoch=$2 AND e.credential_version=$5
 AND ((NOT $7 AND e.retired_at IS NULL) OR ($7 AND e.retired_at IS NOT NULL AND e.terminal_sha256 IS NOT NULL)))
 ON CONFLICT(node_id,epoch,component) DO UPDATE SET generation=EXCLUDED.generation,credential_version=EXCLUDED.credential_version,report=EXCLUDED.report,received_at=now()
 WHERE lpcc.machine_reports.generation<=EXCLUDED.generation AND lpcc.machine_reports.credential_version<=EXCLUDED.credential_version
 AND ($3<>'runner' OR
 (COALESCE((lpcc.machine_reports.report#>>'{apps,desired_generation}')::bigint,0)<=COALESCE((EXCLUDED.report#>>'{apps,desired_generation}')::bigint,0)
 AND (COALESCE((lpcc.machine_reports.report#>>'{apps,desired_generation}')::bigint,0)<>COALESCE((EXCLUDED.report#>>'{apps,desired_generation}')::bigint,0)
 OR COALESCE(lpcc.machine_reports.report#>>'{apps,desired_digest}','')=COALESCE(EXCLUDED.report#>>'{apps,desired_digest}',''))))
 AND (lpcc.machine_reports.credential_version<EXCLUDED.credential_version OR COALESCE((lpcc.machine_reports.report->>'sequence')::numeric,0)<COALESCE((EXCLUDED.report->>'sequence')::numeric,0))`, m.NodeID, m.Epoch, report.Component, report.Generation, m.CredentialVersion, string(raw), m.Terminal)
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		old, _, e := s.store.Report(ctx, m, report.Component)
		if e == nil && reflect.DeepEqual(old, report) {
			return false, nil
		}
		if report.Component != "runner" && old.CredentialVersion == report.CredentialVersion && old.Sequence >= report.Sequence {
			return false, ErrReportOrder
		}
		return false, ErrStaleStatus
	}
	if m.Terminal {
		return false, nil
	}
	drainWake := report.Component == "runner" && report.Drained && record.DrainRequested && report.Generation == record.Generation
	if previous.Drained && previous.Generation == report.Generation && previous.Evidence != nil && report.Evidence != nil && previous.Evidence.Target == report.Evidence.Target && time.Now().Before(previous.Evidence.ExpiresAt) {
		drainWake = false
	}
	return drainWake || (report.Component == "runtime" && (report.Ready && record.ApplyingConfigDigest != "" && report.ConfigDigest == record.ApplyingConfigDigest && report.Generation == record.Generation)), nil
}

func validDrainEvidence(m Machine, state State, report Report, now time.Time) bool {
	e := report.Evidence
	if e == nil || !report.Drained || !state.DrainRequested || report.Generation != state.Generation || e.Target != DrainTarget(m.NodeID, m.Epoch, state) || e.WithdrawalID == "" || len(e.WithdrawalID) > 64 || e.Kind != "no_owner" {
		return false
	}
	if e.ObservedAt.Before(state.DrainStartedAt) || e.ObservedAt.After(now.Add(5*time.Second)) || !now.Before(e.ExpiresAt) || !e.ExpiresAt.After(e.ObservedAt) || e.ExpiresAt.Sub(e.ObservedAt) > time.Minute {
		return false
	}
	return e.OwnerID == "" || (artifact.HashPattern.MatchString(e.CredentialFingerprint) && e.MutationSequence != nil)
}
