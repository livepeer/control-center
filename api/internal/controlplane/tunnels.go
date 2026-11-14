package controlplane

import (
	"context"
	"errors"

	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
)

// Preserve the API configuration's embedded field name and environment flags.
type TunnelParams = tunnel.Config

func (s *Server) newTunnelManager(deps tunnel.Dependencies) *tunnel.Manager {
	deps.SignDiscovery = s.signDiscovery
	deps.DB, deps.Logger, deps.Configurations = s.db, s.logger, s.configs
	return tunnel.New(s.params.TunnelParams, deps)
}

func (s *Server) ConfigureTunnels() error {
	if err := s.params.validateTunnels(); err != nil {
		return err
	}
	s.tunnels = s.newTunnelManager(tunnel.Dependencies{})
	return s.tunnels.Configure(s.params.PublicAPIURL)
}

func (p Params) validateTunnels() error {
	if p.CloudflareEnabled && !machineconfig.ValidConnectorImage(p.RuntimeImage) {
		return errors.New("RuntimeImage requires an immutable sha256 digest when CloudflareEnabled")
	}
	if p.CloudflareEnabled && !machineconfig.ValidConnectorImage(p.RuntimeConnectorImage) {
		return errors.New("RuntimeConnectorImage requires an immutable sha256 digest when CloudflareEnabled")
	}
	return p.TunnelParams.Validate(p.PublicAPIURL)
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
