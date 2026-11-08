package tunnel

import (
	"context"
	"errors"
	"strconv"
)

func (l *tunnelLease) protectionFailure(ctx context.Context, cause error) error {
	if !errors.Is(cause, ErrResourceConflict) && !errors.Is(cause, ErrUnsafeProtection) {
		return cause
	}
	// Persist restoration intent before I/O, including an ambiguous deny response.
	l.state.Quarantined = true
	l.state.Ready = false
	if e := l.save(ctx); e != nil {
		return e
	}
	version, e := l.provider.Configure(ctx, l.state.TunnelID, []IngressRule{{Service: "http_status:404"}})
	if e == nil {
		l.state.ProviderVersion = version
		if e = l.save(ctx); e != nil {
			return e
		}
	}
	return cause
}

func (l *tunnelLease) protectPolicy(ctx context.Context, r CFResource, ids []string) error {
	if e := l.provider.Protect(ctx, r, ids); e != nil {
		return l.protectionFailure(ctx, e)
	}
	return nil
}

func (l *tunnelLease) applyAccessPolicies(ctx context.Context, ids []string) (bool, error) {
	protected := false
	for _, r := range l.state.Resources {
		if r.Kind != "policy" || r.ID == "" || r.Absent {
			continue
		}
		found, e := l.provider.Find(ctx, r)
		if e != nil {
			return false, l.protectionFailure(ctx, e)
		}
		selected := false
		for _, v := range found {
			if v.ID == r.ID {
				selected = true
			}
		}
		if !selected {
			return false, l.protectionFailure(ctx, ErrResourceConflict)
		}
		if e = l.removeDuplicates(ctx, r, found); e != nil {
			return false, e
		}
		if e = l.protectPolicy(ctx, r, ids); e != nil {
			return false, e
		}
		protected = true
	}
	return protected, nil
}

func (l *tunnelLease) restoreProtectedIngress(ctx context.Context) error {
	if !l.state.Quarantined || len(l.state.AppliedIngress) == 0 {
		return nil
	}
	version, e := l.provider.Configure(ctx, l.state.TunnelID, l.state.AppliedIngress)
	if e != nil {
		return e
	}
	l.state.ProviderVersion = version
	l.state.IngressDigest = ingressHash(l.state.AppliedIngress)
	l.state.Quarantined = false
	return l.save(ctx)
}

func (l *tunnelLease) accessAcknowledged(ctx context.Context) (bool, error) {
	var ack bool
	e := l.s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.access_credentials WHERE node_id=$1 AND epoch=$2 AND version=$3 AND acknowledged_at IS NOT NULL AND acknowledged_generation=$4 AND revoked_at IS NULL AND expires_at>now())`, l.Machine.NodeID, l.Machine.Epoch, l.state.AccessVersion, l.state.SourceGeneration).Scan(&ack)
	return ack, e
}

func (l *tunnelLease) retireAcknowledgedCredentials(ctx context.Context) error {
	ack, e := l.accessAcknowledged(ctx)
	if e != nil || !ack {
		return e
	}
	current := l.state.Resources["token-"+strconv.FormatInt(l.state.AccessVersion, 10)]
	if current.ID == "" || current.Absent {
		return nil // Replacement recovery, rather than healthy-overlap cleanup, owns this version.
	}
	var keys []string
	for key, r := range l.state.Resources {
		if r.Kind == "token" && !r.Absent && r.ID != current.ID {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	protected, e := l.applyAccessPolicies(ctx, []string{current.ID})
	if e != nil || !protected {
		return e
	}
	for _, key := range keys {
		if e = l.retireResource(ctx, key); e != nil {
			return e
		}
	}
	l.credentialPoliciesReady(1)
	return l.restoreProtectedIngress(ctx)
}
