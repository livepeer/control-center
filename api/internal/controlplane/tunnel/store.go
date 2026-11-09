package tunnel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"sort"
	"strconv"
	"strings"
	"time"
)

var errTunnelFenced = machineconfig.ErrFenced
var errLegacyEndpoints = errors.New("legacy tunnel hostnames require retirement")

func (s *Manager) Load(ctx context.Context, node, epoch string) (Snapshot, int64, error) {
	r, err := (machineconfig.Store{DB: s.db}).Load(ctx, node, epoch)
	var state Snapshot
	if errors.Is(err, sql.ErrNoRows) {
		return state, 0, ErrPending
	}
	if err != nil {
		return state, 0, err
	}
	state.State = r.State
	err = json.Unmarshal(r.Routing, &state.RoutingState)
	state.applyRolloutStatus()
	return state, r.Revision, err
}

func (s *Snapshot) applyRolloutStatus() {
	if s.ReadyGeneration != s.Generation || s.DrainRequested || s.HeldOrchestrator != "" || s.Lifecycle != "active" {
		s.Ready = false
		if s.Reason == "ready" {
			s.Reason = "runtime_pending"
			if s.Lifecycle == "removed" {
				s.Reason = "removing"
			}
		}
	}
	if s.RolloutReason != "" && s.Lifecycle != "removed" {
		s.Reason = s.RolloutReason
	}
}

type tunnelLease struct {
	*machineconfig.Lease
	s        *Manager
	state    Snapshot
	provider TunnelProvider
}

func (s *Manager) claimTunnel(ctx context.Context, m Machine) (*tunnelLease, error) {
	lease, err := (machineconfig.Store{DB: s.db}).Claim(ctx, m, json.RawMessage(`{}`), true)
	if err != nil {
		return nil, err
	}
	l := &tunnelLease{Lease: lease, s: s, state: Snapshot{State: lease.State}}
	initialized := false
	if err = json.Unmarshal(lease.Routing, &l.state.RoutingState); err != nil {
		lease.Release(ctx)
		return nil, err
	}
	if !l.Machine.Terminal && l.state.EndpointSuffix == "" {
		if l.state.ServiceURL != "" {
			if l.state.Ready || l.state.Reason != "legacy_endpoints_require_retirement" {
				l.state.Ready = false
				l.state.Reason = "legacy_endpoints_require_retirement"
				if err := l.save(ctx); err != nil {
					lease.Release(ctx)
					return nil, err
				}
			}
			lease.Release(ctx)
			return nil, errLegacyEndpoints
		}
		suffix, err := s.newEndpointSuffix(ctx, m)
		if err != nil {
			lease.Release(ctx)
			return nil, err
		}
		l.state.RoutingState = RoutingFor(m.NodeID, s.params.CloudflareBaseDomain, suffix).RoutingState
		initialized = true
	}
	if l.state.AccountID == "" {
		initialized = initialized || s.params.CloudflareAccountID != ""
		l.state.AccountID = s.params.CloudflareAccountID
		l.state.ZoneID = s.params.CloudflareZoneID
		l.state.TeamName = s.params.CloudflareTeamName
	}
	l.provider = s.providerFor(l.state.RoutingState)
	if l.state.Resources == nil {
		l.state.Resources = map[string]CFResource{}
		initialized = true
	}
	if initialized {
		if err := l.save(ctx); err != nil {
			lease.Release(ctx)
			return nil, err
		}
	}
	return l, nil
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
	raw, err := json.Marshal(l.state.RoutingState)
	if err != nil {
		return err
	}
	l.Lease.State = l.state.State
	l.Routing = raw
	return l.Lease.Save(ctx)
}
func (l *tunnelLease) finish(ctx context.Context, failed bool) { l.Lease.Finish(ctx, failed) }
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
		r = CFResource{Kind: kind, Name: resourceName(l.Machine, key), Host: host, CreationTarget: target, OperationVersion: operation}
		if kind == "app" {
			r.Hosts = []string{endpointHost(l.state.ServiceURL), host}
		}
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
		e = l.s.db.QueryRowContext(ctx, `SELECT provider_id FROM lpcc.access_credentials WHERE node_id=$1 AND epoch=$2 AND version=$3`, l.Machine.NodeID, l.Machine.Epoch, r.CredentialVersion).Scan(&bound)
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
	rows, e := s.db.QueryContext(ctx, `SELECT node_id,epoch::text,state,rollout FROM lpcc.machine_states ORDER BY node_id,epoch`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var sources []DiscoverySource
	for rows.Next() {
		var node, epoch string
		var b, rollout []byte
		var r Snapshot
		if e = rows.Scan(&node, &epoch, &b, &rollout); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &r.RoutingState); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(rollout, &r.State); e != nil {
			return nil, e
		}
		if r.TunnelID == "" {
			continue
		}
		blocked := r.EndpointSuffix == "" || r.Quarantined || r.Reason == "ownership_conflict" || r.Reason == "predecessor_cleanup_pending" || r.Reason == "ingress_validation_required"
		r.applyRolloutStatus()
		ready, reason := r.Ready, r.Reason
		if r.VerifiedGeneration != r.SourceGeneration {
			ready = false
		}
		if ready && (r.VerifiedAt.IsZero() || time.Since(r.VerifiedAt) > s.params.TunnelStatusTTL) {
			ready, reason = false, "observation_expired"
		}
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
	result, e := s.db.ExecContext(ctx, `UPDATE lpcc.access_credentials SET acknowledged_at=now(),acknowledged_generation=$4 WHERE node_id=$1 AND epoch=$2 AND version=$3 AND revoked_at IS NULL AND expires_at>now() AND EXISTS(SELECT FROM lpcc.machine_states WHERE node_id=$1 AND epoch=$2 AND rollout->>'lifecycle'='active' AND (state->>'source_generation')::bigint=$4 AND (state->>'access_version')::bigint=$3 AND state->>'discovery_url'=$5)`, source.NodeID, source.Epoch, source.CredentialVersion, source.Generation, source.URL)
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
	e := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.machine_reports r JOIN lpcc.machines m ON m.node_id=r.node_id AND m.enrollment_epoch=r.epoch WHERE r.node_id=$1 AND r.epoch=$2 AND component='runtime' AND r.credential_version=$3 AND m.credential_version=$3 AND m.tunnel_eligible AND report->>'https'='true' AND received_at>now()-make_interval(secs=>$4) AND (COALESCE((report->>'report_version')::int,0)=0 OR (COALESCE((report->>'clock_uncertain')::boolean,false)=false AND (report->>'observed_at')::timestamptz>now()-make_interval(secs=>$4) AND (report->>'observed_at')::timestamptz<=now()+interval '5 seconds')))`, m.NodeID, m.Epoch, m.CredentialVersion, s.params.TunnelStatusTTL.Seconds()).Scan(&yes)
	return yes, e
}
func (s *Manager) report(ctx context.Context, m Machine, component string) (MachineReport, time.Time, error) {
	return (machineconfig.Store{DB: s.db}).Report(ctx, m, component)
}
