package controlplane

import (
	"context"
	"time"
)

func (s *Server) Reconcile(ctx context.Context) {
	run := func() {
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

func (s *Server) reconcile(ctx context.Context) error { return s.configs.Reconcile(ctx) }
