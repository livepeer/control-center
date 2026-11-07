package controlplane

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// Stage a drain intent while the bundle publisher retains the last applied Node
// workload. Only #114's generation-scoped completion allows its replacement.
func (l *tunnelLease) gateNodeConfiguration(ctx context.Context) (bool, error) {
	var data []byte
	if e := l.s.db.QueryRowContext(ctx, `SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, l.m.NodeID).Scan(&data); e != nil {
		return false, e
	}
	old, manifest, e := bundleNodeConfiguration(data)
	if e != nil {
		return false, e
	}
	target := l.m
	state := l.state
	state.HeldOrchestrator = ""
	target.Routing = &state
	digest := orchestratorDigest(target)
	if l.state.ApprovedConfigDigest == digest && l.state.HeldOrchestrator == "" {
		return false, nil
	}
	if old.ConfigDigest == digest && l.state.HeldOrchestrator == "" {
		return false, nil
	}
	if l.state.PendingConfigDigest != digest {
		if !l.state.DrainRequested || l.state.PendingConfigDigest != "" {
			l.state.Generation++
		}
		l.state.PendingConfigDigest = digest
		l.state.DrainRequested = true
		l.state.DrainStartedAt = time.Now().UTC()
		l.state.HeldOrchestrator = manifest
		l.state.Ready = false
		if e = l.save(ctx); e != nil {
			return false, e
		}
	}
	if old.ConfigDigest != digest {
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

// Publisher-side enforcement closes the race between a new desired template,
// the provider worker's drain intent, and the independent configuration loop.
func (s *Server) holdUnapprovedConfiguration(ctx context.Context, m *Machine) error {
	managed := m.Routing != nil && (m.Routing.TunnelID != "" || m.Routing.IngressDigest != "" || len(m.Routing.Resources) > 0 || m.Routing.DrainRequested)
	if !s.params.CloudflareEnabled && !managed {
		return nil
	}
	if m.Terminal || m.Routing != nil && (m.Routing.HeldOrchestrator != "" || m.Routing.ApprovedConfigDigest == orchestratorDigest(*m)) {
		return nil
	}
	var data []byte
	e := s.db.QueryRowContext(ctx, `SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, m.NodeID).Scan(&data)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	old, manifest, e := bundleNodeConfiguration(data)
	if e != nil {
		return e
	}
	if m.Routing == nil {
		// Additive API/adapter upgrades must not restart existing private Node
		// workloads before the enrollment enters the controlled rollout lifecycle.
		m.Routing = &RoutingState{Generation: 1, HeldOrchestrator: manifest}
		return nil
	}
	if old.ConfigDigest != orchestratorDigest(*m) {
		m.Routing.HeldOrchestrator = manifest
	}
	return nil
}

func bundleNodeConfiguration(data []byte) (runtimeDesired, string, error) {
	var d runtimeDesired
	z, e := gzip.NewReader(bytes.NewReader(data))
	if e != nil {
		return d, "", e
	}
	defer z.Close()
	t := tar.NewReader(z)
	var manifest string
	for {
		h, e := t.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return d, "", e
		}
		if h.Name != "runtime.json" && h.Name != "orchestrator.yaml" {
			continue
		}
		if h.Size > 1<<20 || h.Typeflag != tar.TypeReg {
			return d, "", errors.New("invalid stored Node configuration")
		}
		b, e := io.ReadAll(t)
		if e != nil {
			return d, "", e
		}
		if h.Name == "runtime.json" {
			if e = json.Unmarshal(b, &d); e != nil {
				return d, "", e
			}
		} else {
			manifest = string(b)
		}
	}
	// Pre-migration bundles lack runtime.json; derive their exact Node digest.
	if manifest == "" {
		return d, "", errors.New("stored bundle has no Node workload")
	}
	if d.ConfigDigest == "" {
		d.ConfigDigest = orchestratorDigest(Machine{Routing: &RoutingState{HeldOrchestrator: manifest}})
	}
	return d, manifest, nil
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
		target := l.m
		state := l.state
		state.ServiceURL = desired.ServiceURL
		state.ProxyURLTemplate = desired.ProxyURLTemplate
		state.HeldOrchestrator = ""
		target.Routing = &state
		var data []byte
		if e := l.s.db.QueryRowContext(ctx, `SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, l.m.NodeID).Scan(&data); e != nil {
			return false, e
		}
		applied, _, e := bundleNodeConfiguration(data)
		if e != nil {
			return false, e
		}
		l.state.PendingConfigDigest = ""
		l.state.HeldOrchestrator = ""
		if applied.ConfigDigest != orchestratorDigest(target) {
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
