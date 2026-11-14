package tunnel

import (
	"context"
	"errors"
	"sort"
	"time"
)

func createBackoff(attempts int) time.Duration {
	return min(5*time.Minute, 5*time.Second*time.Duration(1<<min(max(attempts-1, 0), 6)))
}

func (l *tunnelLease) storeResource(ctx context.Context, key string, r CFResource) error {
	l.state.Resources[key] = r
	return l.save(ctx)
}

func (l *tunnelLease) retireResource(ctx context.Context, key string) error {
	r := l.state.Resources[key]
	if !r.Absent {
		r.Absent = true
		r.Watch = r.Watch || r.Pending
		r.ObservedAbsent = false
		if e := l.storeResource(ctx, key, r); e != nil {
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
	// DNS absence precedes tunnel deletion.
	for _, kind := range []string{"dns", "tunnel"} {
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
