package controlplane

import (
	"context"
	"errors"

	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
)

// Preserve the API configuration's embedded field name and environment flags.
type TunnelParams = tunnel.Config

func (s *Server) newTunnelManager(deps tunnel.Dependencies) *tunnel.Manager {
	deps.DB, deps.Logger, deps.Rollout = s.db, s.logger, tunnelRollout{s}
	return tunnel.New(s.params.TunnelParams, deps)
}

func (s *Server) ConfigureTunnels() error {
	s.tunnels = s.newTunnelManager(tunnel.Dependencies{})
	return s.tunnels.Configure(s.params.PublicAPIURL)
}

func (s *Server) RunTunnels(ctx context.Context) {
	s.tunnels.Run(ctx, s.params.ConfigReconcileInterval, s.requestReconcile)
}

func (s *Server) loadTunnel(ctx context.Context, node, epoch string) (tunnel.RoutingState, int64, error) {
	state, revision, err := s.tunnels.Load(ctx, node, epoch)
	if errors.Is(err, tunnel.ErrPending) {
		err = problem(409, "tunnel_pending", "Tunnel is not provisioned.")
	}
	return state, revision, err
}

func tunnelMachine(m Machine) tunnel.Machine {
	return tunnel.Machine{NodeID: m.NodeID, Epoch: m.Epoch, InstallDir: m.InstallDir, K3sVersion: m.K3sVersion,
		CredentialVersion: m.CredentialVersion, Terminal: m.Terminal}
}

type tunnelRollout struct{ server *Server }

func (t tunnelRollout) DesiredDigest(m tunnel.Machine, state tunnel.RoutingState) string {
	return orchestratorDigest(Machine{NodeID: m.NodeID, Epoch: m.Epoch, InstallDir: m.InstallDir,
		K3sVersion: m.K3sVersion, CredentialVersion: m.CredentialVersion, Terminal: m.Terminal, Routing: &state})
}

func (t tunnelRollout) Applied(ctx context.Context, m tunnel.Machine) (tunnel.AppliedConfiguration, error) {
	var data []byte
	if err := t.server.db.QueryRowContext(ctx, `SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, m.NodeID).Scan(&data); err != nil {
		return tunnel.AppliedConfiguration{}, err
	}
	desired, manifest, err := bundleNodeConfiguration(data)
	return tunnel.AppliedConfiguration{Digest: desired.ConfigDigest, Manifest: manifest}, err
}
