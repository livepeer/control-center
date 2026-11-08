package tunnel

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Stage a drain intent while the bundle publisher retains the last applied Node
// workload. Only generation-scoped drain completion allows its replacement.
func (l *tunnelLease) gateNodeConfiguration(ctx context.Context) (bool, error) {
	old, e := l.s.rollout.Applied(ctx, l.m)
	if e != nil {
		return false, e
	}
	state := l.state
	state.HeldOrchestrator = ""
	digest := l.s.rollout.DesiredDigest(l.m, state)
	if l.state.ApprovedConfigDigest == digest && l.state.HeldOrchestrator == "" {
		return false, nil
	}
	if old.Digest == digest && l.state.HeldOrchestrator == "" {
		return false, nil
	}
	if l.state.PendingConfigDigest != digest {
		if !l.state.DrainRequested || l.state.PendingConfigDigest != "" {
			l.state.Generation++
		}
		l.state.PendingConfigDigest = digest
		l.state.DrainRequested = true
		l.state.DrainStartedAt = time.Now().UTC()
		l.state.HeldOrchestrator = old.Manifest
		l.state.Ready = false
		if e = l.save(ctx); e != nil {
			return false, e
		}
	}
	if old.Digest != digest {
		if done, e := l.drainComplete(ctx); e != nil || !done {
			return true, e
		}
	}
	l.state.HeldOrchestrator = ""
	l.state.PendingConfigDigest = ""
	l.state.DrainRequested = false
	l.state.EndpointDrainURL = ""
	l.state.ApprovedConfigDigest = digest
	return false, l.save(ctx)
}

// An endpoint drain belongs to its deliberate target. Cancellation must release
// the old signal, while retries of an unfinished unchanged target keep its deadline.
func (l *tunnelLease) stageEndpoints(ctx context.Context, desired RoutingState) (bool, error) {
	if l.state.EndpointDrainURL != "" && l.state.EndpointDrainURL != desired.ServiceURL {
		l.state.Generation++
		l.state.DrainRequested = false
		l.state.DrainStartedAt = time.Time{}
		l.state.EndpointDrainURL = ""
		l.state.PendingConfigDigest = ""
		l.state.HeldOrchestrator = ""
		l.state.Ready = false
		if e := l.save(ctx); e != nil {
			return false, e
		}
	}
	if desired.ServiceURL == l.state.ServiceURL {
		return false, nil
	}
	if !l.state.DrainRequested || l.state.EndpointDrainURL != desired.ServiceURL {
		state := l.state
		state.ServiceURL = desired.ServiceURL
		state.ProxyURLTemplate = desired.ProxyURLTemplate
		state.HeldOrchestrator = ""
		applied, e := l.s.rollout.Applied(ctx, l.m)
		if e != nil {
			return false, e
		}
		l.state.PendingConfigDigest = ""
		l.state.HeldOrchestrator = ""
		if applied.Digest != l.s.rollout.DesiredDigest(l.m, state) {
			l.state.Generation++
			l.state.DrainRequested = true
			l.state.EndpointDrainURL = desired.ServiceURL
			l.state.DrainStartedAt = time.Now().UTC()
		}
		l.state.Ready = false
		if e = l.save(ctx); e != nil {
			return false, e
		}
	}
	if l.state.DrainRequested {
		if done, e := l.drainComplete(ctx); e != nil || !done {
			return true, e
		}
	}
	l.state.ServiceURL = desired.ServiceURL
	l.state.ProxyURLTemplate = desired.ProxyURLTemplate
	l.state.DiscoveryURL = desired.DiscoveryURL
	l.state.SourceGeneration++
	l.state.EndpointGeneration++
	return false, l.save(ctx)
}

func (l *tunnelLease) finishDrain(ctx context.Context) error {
	done, e := l.drainComplete(ctx)
	if e != nil || !done {
		return e
	}
	_, e = l.s.db.ExecContext(ctx, `DELETE FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2 AND EXISTS(SELECT FROM lpcc.machine_tunnels WHERE node_id=$1 AND epoch=$2 AND lease_id=$3 AND revision=$4 AND lease_until>now())`, l.m.NodeID, l.m.Epoch, l.id, l.revision)
	return e
}

func (l *tunnelLease) drainComplete(ctx context.Context) (bool, error) {
	if l.state.DrainStartedAt.IsZero() || time.Since(l.state.DrainStartedAt) > l.s.params.TunnelDrainTimeout {
		l.state.Reason = "drain_timeout"
		return false, l.save(ctx)
	}
	report, at, e := l.s.report(ctx, l.m, "runner")
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return false, e
	}
	if report.Drained && report.Generation == l.state.Generation && time.Since(at) <= l.s.params.TunnelStatusTTL {
		return true, nil
	}
	l.state.Reason = "drain_pending"
	return false, l.save(ctx)
}
