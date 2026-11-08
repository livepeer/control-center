package tunnel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
	"uuid"
)

var errTunnelFenced = errors.New("tunnel lease or generation superseded")

func (s *Manager) Load(ctx context.Context, node, epoch string) (RoutingState, int64, error) {
	var b []byte
	var rev int64
	var state RoutingState
	e := s.db.QueryRowContext(ctx, `SELECT state,revision FROM lpcc.machine_tunnels WHERE node_id=$1 AND epoch=$2`, node, epoch).Scan(&b, &rev)
	if errors.Is(e, sql.ErrNoRows) {
		return state, 0, ErrPending
	}
	if e == nil {
		e = json.Unmarshal(b, &state)
	}
	return state, rev, e
}

type tunnelLease struct {
	s        *Manager
	m        Machine
	id       string
	revision int64
	state    RoutingState
	provider TunnelProvider
}

func (s *Manager) claimTunnel(ctx context.Context, m Machine) (*tunnelLease, error) {
	initial := RoutingFor(m.NodeID, s.params.CloudflareBaseDomain)
	if m.Terminal {
		initial.Lifecycle = "removed"
	}
	b, _ := json.Marshal(initial)
	insert := `INSERT INTO lpcc.machine_tunnels(node_id,epoch,state) SELECT $1,$2,$3 FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2 FOR KEY SHARE ON CONFLICT DO NOTHING`
	if m.Terminal {
		insert = `INSERT INTO lpcc.machine_tunnels(node_id,epoch,state) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`
	}
	if _, e := s.db.ExecContext(ctx, insert, m.NodeID, m.Epoch, b); e != nil {
		return nil, e
	}
	l := &tunnelLease{s: s, m: m, id: uuid.New().String()}
	e := s.db.QueryRowContext(ctx, `UPDATE lpcc.machine_tunnels SET lease_id=$3,lease_until=now()+interval '90 seconds' WHERE node_id=$1 AND epoch=$2 AND next_attempt_at<=now() AND (lease_until IS NULL OR lease_until<now()) RETURNING state,revision`, m.NodeID, m.Epoch, l.id).Scan(&b, &l.revision)
	if e != nil {
		return nil, e
	}
	e = json.Unmarshal(b, &l.state)
	if e != nil {
		return nil, e
	}
	if e = s.db.QueryRowContext(ctx, `SELECT retired_at IS NOT NULL FROM lpcc.enrollments WHERE node_id=$1 AND epoch=$2`, m.NodeID, m.Epoch).Scan(&l.m.Terminal); e != nil {
		return nil, e
	}
	if l.state.AccountID == "" {
		l.state.AccountID = s.params.CloudflareAccountID
		l.state.ZoneID = s.params.CloudflareZoneID
		l.state.TeamName = s.params.CloudflareTeamName
	}
	l.provider = s.providerFor(l.state)
	if l.state.Resources == nil {
		l.state.Resources = map[string]CFResource{}
	}
	return l, e
}

func (s *Manager) providerFor(state RoutingState) TunnelProvider {
	if cf, ok := s.provider.(*cloudflareHTTP); ok && state.AccountID != "" {
		copy := *cf
		copy.params.CloudflareAccountID = state.AccountID
		copy.params.CloudflareZoneID = state.ZoneID
		copy.params.CloudflareTeamName = state.TeamName
		return &copy
	}
	return s.provider
}
func (l *tunnelLease) save(ctx context.Context) error {
	b, e := json.Marshal(l.state)
	if e != nil {
		return e
	}
	e = l.s.db.QueryRowContext(ctx, `UPDATE lpcc.machine_tunnels SET state=$4,revision=revision+1,lease_until=now()+interval '90 seconds' WHERE node_id=$1 AND epoch=$2 AND lease_id=$3 AND revision=$5 AND lease_until>now() RETURNING revision`, l.m.NodeID, l.m.Epoch, l.id, b, l.revision).Scan(&l.revision)
	if errors.Is(e, sql.ErrNoRows) {
		return errTunnelFenced
	}
	return e
}
func (l *tunnelLease) finish(ctx context.Context, failed bool) {
	// Backoff survives API restarts. Provider bodies are never persisted or logged.
	delay := 1.0
	if failed {
		delay = 5
	}
	_, _ = l.s.db.ExecContext(ctx, `UPDATE lpcc.machine_tunnels SET lease_id=NULL,lease_until=NULL,failures=CASE WHEN $4 THEN LEAST(failures+1,8) ELSE 0 END,next_attempt_at=now()+make_interval(secs=>LEAST(300,$5*power(2,CASE WHEN $4 THEN LEAST(failures,6) ELSE 0 END))+random()) WHERE node_id=$1 AND epoch=$2 AND lease_id=$3`, l.m.NodeID, l.m.Epoch, l.id, failed, delay)
}
func resourceName(m Machine, purpose string) string {
	return "lpcc-" + m.NodeID + "-" + strings.ReplaceAll(m.Epoch, "-", "") + "-" + purpose
}
func (l *tunnelLease) ensure(ctx context.Context, key, kind, host, target string) (CFResource, error) {
	r, exists := l.state.Resources[key]
	if !exists && (kind == "app" || kind == "policy" || kind == "dns") {
		var candidates []string
		for oldKey, old := range l.state.Resources {
			if old.Kind == kind && old.Host == host && !old.Absent {
				candidates = append(candidates, oldKey)
			}
		}
		if len(candidates) > 1 {
			return r, ErrResourceConflict
		}
		if len(candidates) == 1 {
			oldKey := candidates[0]
			r = l.state.Resources[oldKey]
			exists = true
			delete(l.state.Resources, oldKey)
			l.state.Resources[key] = r
			if e := l.save(ctx); e != nil {
				return r, e
			}
		}
	}
	if exists && r.ID == "" && r.Attempts > 0 && r.CreationTarget != target {
		// Commit both sides of the handoff before attempting provider cleanup.
		// A failed delete must not leave an absent canonical entry stranded.
		r.Absent = true
		r.Watch = r.Watch || r.Pending
		r.ObservedAbsent = false
		l.state.Resources["retired:"+r.Name] = r
		r = CFResource{OperationVersion: r.OperationVersion + 1}
		exists = false
	}
	if exists && r.Absent {
		return r, ErrResourceConflict
	}
	if !exists {
		operation := max(r.OperationVersion, 1)
		r = CFResource{Kind: kind, Name: resourceName(l.m, key), Host: host, CreationTarget: target, OperationVersion: operation}
		if operation > 1 {
			r.Name += "-op" + strconv.FormatInt(operation, 10)
		}
		if kind == "token" {
			r.CredentialVersion = l.state.AccessVersion
			r.Duration = l.s.params.CloudflareAccessLifetime.String()
		}
		l.state.Resources[key] = r
		if e := l.save(ctx); e != nil {
			return r, e
		}
	}
	if e := l.sweepAbsentResources(ctx, false); e != nil {
		return r, e
	}
	if kind == "token" && r.CredentialVersion == 0 {
		r.CredentialVersion = l.state.AccessVersion
	}
	if r.Attempts == 0 {
		r.CreationTarget = target
	}
	found, e := l.provider.Find(ctx, r)
	if e != nil {
		return r, e
	}
	if kind == "token" {
		var bound string
		e = l.s.db.QueryRowContext(ctx, `SELECT provider_id FROM lpcc.access_credentials WHERE node_id=$1 AND epoch=$2 AND version=$3`, l.m.NodeID, l.m.Epoch, r.CredentialVersion).Scan(&bound)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return r, e
		}
		if bound != "" {
			if r.ID != "" && r.ID != bound {
				return r, ErrResourceConflict
			}
			r.ID = bound
		} else {
			if r.ID != "" {
				return r, errors.New("bound Access credential is unavailable")
			}
			// No durable secret exists: every result is stranded. Retain the
			// operation marker so a crash after deletion can safely retry.
			for _, v := range found {
				if e = l.provider.Delete(ctx, v, l.state.TunnelID); e != nil {
					return r, e
				}
			}
			if len(found) > 0 {
				r.Watch = true
				r.Pending = false
				l.state.Resources[key] = r
				if e = l.save(ctx); e != nil {
					return r, e
				}
			}
			found = nil
		}
	}
	if r.ID == "" && len(found) > 0 {
		sort.Slice(found, func(i, j int) bool { return found[i].ID < found[j].ID })
		r = found[0]
		r.Watch = r.Watch || len(found) > 1
		if e = l.storeResource(ctx, key, r, nil, time.Time{}); e != nil {
			return r, e
		}
	}
	if r.ID != "" {
		var selected *CFResource
		for i := range found {
			if found[i].ID == r.ID {
				selected = &found[i]
				break
			}
		}
		if e = l.removeDuplicates(ctx, r, found); e != nil {
			return r, e
		}
		if selected == nil {
			return r, errors.New("selected owned resource is missing")
		}
		r = *selected
		if kind == "dns" && (r.Target != target+".cfargotunnel.com" || !r.Proxied) {
			if e = l.provider.Route(ctx, r, target); e != nil {
				return r, e
			}
			r.Target = target + ".cfargotunnel.com"
			r.Proxied = true
		}
		return r, l.storeResource(ctx, key, r, nil, time.Time{})
	}
	if r.Pending && time.Since(r.AttemptAt) < createBackoff(r.Attempts) {
		return r, errAmbiguousCreate
	}
	r.Watch = r.Watch || r.Pending
	r.Pending = true
	r.Attempts++
	r.AttemptAt = time.Now().UTC()
	l.state.Resources[key] = r
	if e = l.save(ctx); e != nil {
		return r, e
	}
	created, credential, expiry, e := l.provider.Create(ctx, r, r.CreationTarget)
	if e != nil {
		var failure *ProviderError
		if errors.As(e, &failure) && !failure.Ambiguous {
			r.Pending = false
			l.state.Resources[key] = r
			_ = l.save(ctx)
		}
		return r, e
	}
	if created.ID == "" || kind == "token" && (credential == nil || !expiry.After(time.Now())) {
		return r, errAmbiguousCreate
	}
	created.Pending = false
	if e = l.storeResource(ctx, key, created, credential, expiry); e != nil {
		return r, e
	}
	if created.Watch {
		found, e = l.provider.FindOwned(ctx, created)
		if e != nil {
			return created, e
		}
		if e = l.removeDuplicates(ctx, created, found); e != nil {
			return created, e
		}
	}
	return created, nil
}

// DiscoverySources and ResolveAccessCredential are internal discovery
// interfaces. No browser or machine endpoint exposes Collector credentials.
func (s *Manager) DiscoverySources(ctx context.Context) ([]DiscoverySource, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT node_id,epoch::text,state FROM lpcc.machine_tunnels ORDER BY node_id,epoch`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var sources []DiscoverySource
	for rows.Next() {
		var node, epoch string
		var b []byte
		var r RoutingState
		if e = rows.Scan(&node, &epoch, &b); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &r); e != nil {
			return nil, e
		}
		if r.TunnelID == "" {
			continue
		}
		ready, reason := r.Ready, r.Reason
		if r.VerifiedGeneration != r.SourceGeneration {
			ready = false
		}
		if ready && (r.VerifiedAt.IsZero() || time.Since(r.VerifiedAt) > s.params.TunnelStatusTTL) {
			ready, reason = false, "observation_expired"
		}
		blocked := r.Quarantined || r.Reason == "ownership_conflict" || r.Reason == "predecessor_cleanup_pending" || r.Reason == "ingress_validation_required"
		sources = append(sources, DiscoverySource{ID: node + "/" + epoch, NodeID: node, Epoch: epoch, URL: r.DiscoveryURL, ServiceURL: r.ServiceURL, ProxyURLTemplate: r.ProxyURLTemplate, Lifecycle: r.Lifecycle, Ready: ready, Blocked: blocked, Generation: r.SourceGeneration, VerifiedGeneration: r.VerifiedGeneration, CredentialVersion: r.AccessVersion, CredentialRef: credentialRef(node, epoch, r.AccessVersion), Reason: reason, RotationReason: r.RotationReason})
	}
	return sources, rows.Err()
}
func (s *Manager) ResolveAccessCredential(ctx context.Context, ref string) (AccessCredential, error) {
	var empty AccessCredential
	parts := strings.Split(ref, "/")
	if len(parts) != 4 || parts[0] != "access" || s.keys == nil {
		return empty, errors.New("invalid Access credential reference")
	}
	version, e := strconv.ParseInt(parts[3], 10, 64)
	if e != nil {
		return empty, e
	}
	var key string
	var b []byte
	e = s.db.QueryRowContext(ctx, `SELECT c.key_id,c.ciphertext FROM lpcc.access_credentials c JOIN lpcc.enrollments e USING(node_id,epoch) WHERE c.node_id=$1 AND c.epoch=$2 AND c.version=$3 AND c.revoked_at IS NULL AND c.expires_at>now() AND e.retired_at IS NULL`, parts[1], parts[2], version).Scan(&key, &b)
	if e != nil {
		return empty, errors.New("Access credential is unavailable")
	}
	return s.keys.open(key, ref, b)
}
func (s *Manager) AcknowledgeDiscovery(ctx context.Context, source DiscoverySource) error {
	r, _, e := s.Load(ctx, source.NodeID, source.Epoch)
	if e != nil {
		return e
	}
	if r.Lifecycle != "active" || r.SourceGeneration != source.Generation || r.AccessVersion != source.CredentialVersion || r.DiscoveryURL != source.URL || source.ID != source.NodeID+"/"+source.Epoch || source.CredentialRef != credentialRef(source.NodeID, source.Epoch, source.CredentialVersion) {
		return errors.New("stale discovery acknowledgement")
	}
	result, e := s.db.ExecContext(ctx, `UPDATE lpcc.access_credentials SET acknowledged_at=now(),acknowledged_generation=$4 WHERE node_id=$1 AND epoch=$2 AND version=$3 AND revoked_at IS NULL AND expires_at>now() AND EXISTS(SELECT FROM lpcc.machine_tunnels WHERE node_id=$1 AND epoch=$2 AND state->>'lifecycle'='active' AND (state->>'source_generation')::bigint=$4 AND (state->>'access_version')::bigint=$3 AND state->>'discovery_url'=$5)`, source.NodeID, source.Epoch, source.CredentialVersion, source.Generation, source.URL)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("credential version unavailable")
	}
	return nil
}
func (s *Manager) ReencryptAccessCredentials(ctx context.Context) error {
	rows, e := s.db.QueryContext(ctx, `SELECT node_id,epoch::text,version,key_id,ciphertext FROM lpcc.access_credentials WHERE key_id<>$1`, s.keys.current)
	if e != nil {
		return e
	}
	type record struct {
		node, epoch, key string
		version          int64
		b                []byte
	}
	var records []record
	for rows.Next() {
		var r record
		if e = rows.Scan(&r.node, &r.epoch, &r.version, &r.key, &r.b); e != nil {
			rows.Close()
			return e
		}
		records = append(records, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, r := range records {
		ref := credentialRef(r.node, r.epoch, r.version)
		v, e := s.keys.open(r.key, ref, r.b)
		if e != nil {
			return e
		}
		id, b, e := s.keys.seal(ref, v)
		if e != nil {
			return e
		}
		if _, e = s.db.ExecContext(ctx, `UPDATE lpcc.access_credentials SET key_id=$4,ciphertext=$5 WHERE node_id=$1 AND epoch=$2 AND version=$3 AND key_id=$6`, r.node, r.epoch, r.version, id, b, r.key); e != nil {
			return e
		}
	}
	return nil
}

func (s *Manager) SecureRuntime(ctx context.Context, m Machine) (bool, error) {
	var yes bool
	e := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.machine_reports r JOIN lpcc.machines m ON m.node_id=r.node_id AND m.enrollment_epoch=r.epoch WHERE r.node_id=$1 AND r.epoch=$2 AND component='runtime' AND r.credential_version=$3 AND m.credential_version=$3 AND m.tunnel_eligible AND report->>'https'='true' AND received_at>now()-make_interval(secs=>$4))`, m.NodeID, m.Epoch, m.CredentialVersion, s.params.TunnelStatusTTL.Seconds()).Scan(&yes)
	return yes, e
}
func (s *Manager) report(ctx context.Context, m Machine, component string) (MachineReport, time.Time, error) {
	var b []byte
	var at time.Time
	var v MachineReport
	e := s.db.QueryRowContext(ctx, `SELECT report,received_at FROM lpcc.machine_reports WHERE node_id=$1 AND epoch=$2 AND component=$3 AND credential_version=$4`, m.NodeID, m.Epoch, component, m.CredentialVersion).Scan(&b, &at)
	if e == nil {
		e = json.Unmarshal(b, &v)
	}
	return v, at, e
}
