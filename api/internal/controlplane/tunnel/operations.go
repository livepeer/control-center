package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"sort"
	"time"
)

func createBackoff(attempts int) time.Duration {
	return min(5*time.Minute, 5*time.Second*time.Duration(1<<min(max(attempts-1, 0), 6)))
}

// A token version and its selected provider ID commit together. Retirement also
// revokes the reference atomically with its durable absent intent, before I/O.
func (l *tunnelLease) storeResource(ctx context.Context, key string, r CFResource, secret *AccessCredential, expiry time.Time) error {
	if r.Kind != "token" || secret == nil && !r.Absent {
		l.state.Resources[key] = r
		return l.save(ctx)
	}
	next := l.state
	next.Resources = maps.Clone(l.state.Resources)
	next.Resources[key] = r
	b, e := json.Marshal(next.RoutingState)
	if e != nil {
		return e
	}
	var keyID string
	var ciphertext []byte
	if secret != nil {
		keyID, ciphertext, e = l.s.keys.seal(credentialRef(l.Machine.NodeID, r.CredentialVersion), *secret)
		if e != nil {
			return e
		}
	}
	tx, e := l.s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	revision, e := l.Lease.Write(ctx, tx, next.State, b, secret != nil)
	if e != nil {
		return e
	}
	if secret != nil {
		result, e := tx.ExecContext(ctx, `INSERT INTO lpcc.access_credentials(node_id,version,provider_id,key_id,ciphertext,expires_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(node_id,version) DO NOTHING`, l.Machine.NodeID, r.CredentialVersion, r.ID, keyID, ciphertext, expiry)
		if e != nil {
			return e
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return errors.New("Access credential version is already bound")
		}
	} else if r.CredentialVersion > 0 {
		if _, e = tx.ExecContext(ctx, `UPDATE lpcc.access_credentials SET revoked_at=COALESCE(revoked_at,now()) WHERE node_id=$1 AND version=$2`, l.Machine.NodeID, r.CredentialVersion); e != nil {
			return e
		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	l.state = next
	l.Revision = revision
	l.Lease.State = next.State
	l.Routing = b
	return nil
}

func (l *tunnelLease) retireResource(ctx context.Context, key string) error {
	r := l.state.Resources[key]
	if !r.Absent {
		r.Absent = true
		r.Watch = r.Watch || r.Pending
		r.ObservedAbsent = false
		if e := l.storeResource(ctx, key, r, nil, time.Time{}); e != nil {
			return e
		}
	}
	return l.sweepResource(ctx, key, true)
}

// Completed retirements only inventory due watches. Reopen durably before any
// deletion so the normal cleanup path can revoke a reappearing connector first.
func (l *tunnelLease) auditCompletedCleanup(ctx context.Context) (bool, error) {
	changed := false
	for key, r := range l.state.Resources {
		if !r.Absent || !r.Watch || r.ObservedAbsent && time.Now().Before(r.AuditAfter) {
			continue
		}
		found, e := l.provider.FindOwned(ctx, r)
		if e != nil {
			return true, e
		}
		if len(found) > 0 {
			r.ObservedAbsent = false
			l.state.Resources[key] = r
			l.state.CleanupComplete = false
			l.state.ConnectorRevoked = false
			return false, l.save(ctx)
		}
		r.AuditAfter = time.Now().UTC().Add(5 * time.Minute)
		r.ObservedAbsent = true
		l.state.Resources[key] = r
		changed = true
	}
	if changed {
		return true, l.save(ctx)
	}
	return true, nil
}

func (l *tunnelLease) sweepResource(ctx context.Context, key string, force bool) error {
	r := l.state.Resources[key]
	if !r.Absent || r.ObservedAbsent && (!r.Watch || !force && time.Now().Before(r.AuditAfter)) {
		return nil
	}
	found, e := l.provider.FindOwned(ctx, r)
	if e != nil {
		return e
	}
	if len(found) > 0 {
		r.ObservedAbsent = false
		l.state.Resources[key] = r
		if l.state.Lifecycle == "removed" {
			l.state.CleanupComplete = false
		}
		if e = l.save(ctx); e != nil {
			return e
		}
		for _, v := range found {
			if e = l.provider.Delete(ctx, v, l.state.TunnelID); e != nil {
				return e
			}
		}
		remaining, e := l.provider.FindOwned(ctx, r)
		if e != nil {
			return e
		}
		if len(remaining) > 0 {
			return errors.New("owned resource deletion is pending")
		}
	}
	r.ObservedAbsent = true
	r.Pending = false
	r.AuditAfter = time.Now().UTC().Add(5 * time.Minute)
	l.state.Resources[key] = r
	return l.save(ctx)
}

func (l *tunnelLease) sweepAbsentResources(ctx context.Context, force bool) error {
	// DNS/tunnel absence precedes removal of Access protection.
	for _, kind := range []string{"dns", "tunnel", "policy", "app", "token"} {
		var keys []string
		for key, r := range l.state.Resources {
			if r.Kind == kind && r.Absent {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			if e := l.sweepResource(ctx, key, force); e != nil {
				return e
			}
		}
	}
	return nil
}

func (l *tunnelLease) removeDuplicates(ctx context.Context, r CFResource, found []CFResource) error {
	for _, v := range found {
		if v.ID != r.ID {
			if e := l.provider.Delete(ctx, v, l.state.TunnelID); e != nil {
				return e
			}
		}
	}
	return nil
}
