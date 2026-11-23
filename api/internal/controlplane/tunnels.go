package controlplane

import (
	"context"
	"errors"

	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
)

type TunnelParams = tunnel.Config

func (s *Server) newTunnelManager(deps tunnel.Dependencies) *tunnel.Manager {
	deps.SignDiscovery = s.signDiscovery
	deps.DB, deps.Logger, deps.Configurations = s.db, s.logger, s.configs
	config := s.params.TunnelParams
	if s.params.DevelopmentHTTP {
		config.CloudflareAPIToken = ""
	}
	return tunnel.New(config, deps)
}

func (s *Server) RunTunnels(ctx context.Context) {
	s.tunnels.Run(ctx, s.params.ConfigReconcileInterval, s.requestReconcile)
}

func (s *Server) loadTunnel(ctx context.Context, node string) (tunnel.Snapshot, int64, error) {
	state, revision, err := s.tunnels.Load(ctx, node)
	if errors.Is(err, tunnel.ErrPending) {
		err = problem(409, "tunnel_pending", "Tunnel is not provisioned.")
	}
	return state, revision, err
}
