package controlplane

import (
	"context"
	"errors"
	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"time"
)

func (s *Server) Reconcile(ctx context.Context) {
	run := func() {
		// Telemetry revocation follows enrollment changes on every pass. A failed
		// read keeps the previous identities instead of rejecting the fleet.
		telemetryCtx, stopTelemetry := context.WithTimeout(ctx, 10*time.Second)
		if err := s.refreshTelemetry(telemetryCtx); err != nil && ctx.Err() == nil {
			s.logger.Error("telemetry enrollment refresh failed", "error", err)
		}
		stopTelemetry()
		if s.discovery != nil {
			sourceCtx, stop := context.WithTimeout(ctx, 30*time.Second)
			err := s.discovery.Reconcile(sourceCtx)
			stop()
			if err != nil && ctx.Err() == nil {
				s.logger.Error("fleet discovery reconciliation failed", "reason", "reconcile_failed")
			}
		}
		passCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := s.reconcile(passCtx); err != nil && ctx.Err() == nil {
			s.logger.Error("configuration reconciliation failed", "error", err)
		}
	}
	run()
	ticker := time.NewTicker(s.params.ConfigReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		case <-s.reconcileWake:
			run()
		}
	}
}

func (s *Server) reconcile(ctx context.Context) error {
	if _, e := s.db.ExecContext(ctx, `DELETE FROM lpcc.revoked_enrollment_grants WHERE expires_at<=$1`, s.currentTime()); e != nil {
		return e
	}
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, `SELECT m.node_id,m.orchestrator_address::text,p.app_name FROM lpcc.machines m JOIN lpcc.operator_app_policy p ON p.orchestrator_address=m.orchestrator_address WHERE NOT p.denied ORDER BY m.node_id,p.app_name`)
	if e != nil {
		return e
	}
	var pending [][3]string
	for rows.Next() {
		var v [3]string
		if e = rows.Scan(&v[0], &v[1], &v[2]); e != nil {
			break
		}
		pending = append(pending, v)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	for _, v := range pending {
		if e = applyOwnerPolicy(ctx, tx, v[0], v[1], v[2], false); e != nil && !errors.Is(e, machineapps.ErrRequestedBudget) {
			return e
		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	if e = s.reconcileOnchain(ctx); e != nil {
		return e
	}
	return s.configs.Reconcile(ctx)
}
