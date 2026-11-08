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

	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
)

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
		m.Routing = &tunnel.RoutingState{Generation: 1, HeldOrchestrator: manifest}
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
		d.ConfigDigest = orchestratorDigest(Machine{Routing: &tunnel.RoutingState{HeldOrchestrator: manifest}})
	}
	return d, manifest, nil
}
