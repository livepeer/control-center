package tunnel

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"sort"
	"strconv"
	"time"
)

var errTunnelFenced = machineconfig.ErrFenced
var errRoutingMigrationRequired = errors.New("unsupported persisted routing; complete the separate routing migration")

func (s *Manager) Load(ctx context.Context, node string) (Snapshot, int64, error) {
	r, err := (machineconfig.Store{DB: s.db}).Load(ctx, node)
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
	if err := requireMigratedRouting(lease.Routing); err != nil {
		lease.Release(ctx)
		return nil, err
	}
	initialized := false
	if err = json.Unmarshal(lease.Routing, &l.state.RoutingState); err != nil {
		lease.Release(ctx)
		return nil, err
	}
	if !l.Machine.Terminal && l.state.ServiceURL == "" && l.state.TunnelID == "" {
		l.state.RoutingState = RoutingFor(m.NodeID, s.params.CloudflareBaseDomain).RoutingState
		initialized = true
	}
	if l.state.AccountID == "" {
		initialized = initialized || s.params.CloudflareAccountID != ""
		l.state.AccountID = s.params.CloudflareAccountID
		l.state.ZoneID = s.params.CloudflareZoneID
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
	return "lpcc-" + m.NodeID + "-" + purpose
}
func (l *tunnelLease) ensure(ctx context.Context, key, kind, host, target string) (CFResource, error) {
	r, exists := l.state.Resources[key]
	if !exists && kind == "dns" {
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
		if operation > 1 {
			r.Name += "-op" + strconv.FormatInt(operation, 10)
		}
		l.state.Resources[key] = r
		if e := l.save(ctx); e != nil {
			return r, e
		}
	}
	if e := l.sweepAbsentResources(ctx, false); e != nil {
		return r, e
	}
	if r.Attempts == 0 {
		r.CreationTarget = target
	}
	found, e := l.provider.Find(ctx, r)
	if e != nil {
		return r, e
	}
	if r.ID == "" && len(found) > 0 {
		sort.Slice(found, func(i, j int) bool { return found[i].ID < found[j].ID })
		r = found[0]
		r.Watch = r.Watch || len(found) > 1
		if e = l.storeResource(ctx, key, r); e != nil {
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
		return r, l.storeResource(ctx, key, r)
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
	created, e := l.provider.Create(ctx, r, r.CreationTarget)
	if e != nil {
		var failure *ProviderError
		if errors.As(e, &failure) && !failure.Ambiguous {
			r.Pending = false
			l.state.Resources[key] = r
			_ = l.save(ctx)
		}
		return r, e
	}
	if created.ID == "" {
		return r, errAmbiguousCreate
	}
	created.Pending = false
	if e = l.storeResource(ctx, key, created); e != nil {
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

// DiscoverySources projects the routing ledger without exposing private endpoints publicly.
func (s *Manager) DiscoverySources(ctx context.Context) ([]DiscoverySource, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT node_id,state,rollout FROM lpcc.machine_states ORDER BY node_id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var sources []DiscoverySource
	for rows.Next() {
		var node string
		var b, rollout []byte
		var r Snapshot
		if e = rows.Scan(&node, &b, &rollout); e != nil {
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
		blocked := r.ServiceURL == "" || r.ProxyURLTemplate == "" || r.DiscoveryURL == "" || r.Reason == "ownership_conflict" || r.Reason == "ingress_validation_required"
		r.applyRolloutStatus()
		ready, reason := r.Ready, r.Reason
		if r.VerifiedGeneration != r.SourceGeneration {
			ready = false
		}
		if ready && (r.VerifiedAt.IsZero() || time.Since(r.VerifiedAt) > s.params.TunnelStatusTTL) {
			ready, reason = false, "observation_expired"
		}
		sources = append(sources, DiscoverySource{NodeID: node, URL: r.DiscoveryURL, ServiceURL: r.ServiceURL, ProxyURLTemplate: r.ProxyURLTemplate, Lifecycle: r.Lifecycle, Ready: ready, Blocked: blocked, Generation: r.SourceGeneration, VerifiedGeneration: r.VerifiedGeneration, Reason: reason, RotationReason: r.RotationReason})
	}
	return sources, rows.Err()
}
func (s *Manager) SecureRuntime(ctx context.Context, m Machine) (bool, error) {
	var yes bool
	e := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.machine_reports r JOIN lpcc.machines m ON m.node_id=r.node_id WHERE r.node_id=$1 AND component='runtime' AND r.credential_version=$2 AND m.credential_version=$2 AND m.tunnel_eligible AND report->>'https'='true' AND received_at>now()-make_interval(secs=>$3) AND (report->>'report_version')::int=1 AND COALESCE((report->>'clock_uncertain')::boolean,false)=false AND (report->>'observed_at')::timestamptz>now()-make_interval(secs=>$3) AND (report->>'observed_at')::timestamptz<=now()+interval '5 seconds')`, m.NodeID, m.CredentialVersion, s.params.TunnelStatusTTL.Seconds()).Scan(&yes)
	return yes, e
}
func (s *Manager) report(ctx context.Context, m Machine, component string) (MachineReport, time.Time, error) {
	return (machineconfig.Store{DB: s.db}).Report(ctx, m, component)
}

// Reject unsupported persisted routing shapes before provider I/O. Existing
// resources are migrated separately before provisioning is enabled again.
func requireMigratedRouting(raw []byte) error {
	var persisted struct {
		Resources map[string]CFResource `json:"resources"`
		Applied   []json.RawMessage     `json:"applied_ingress"`
	}
	if err := json.Unmarshal(raw, &persisted); err != nil {
		return err
	}
	for _, r := range persisted.Resources {
		if r.Kind != "dns" && r.Kind != "tunnel" {
			return errRoutingMigrationRequired
		}
	}
	for _, data := range persisted.Applied {
		var rule IngressRule
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&rule) != nil {
			return errRoutingMigrationRequired
		}
	}
	return nil
}
