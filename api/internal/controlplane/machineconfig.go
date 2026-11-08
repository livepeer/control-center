package controlplane

import (
	"encoding/json"

	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
)

func exposure(r tunnel.RoutingState) *machineconfig.Exposure {
	return &machineconfig.Exposure{TunnelID: r.TunnelID, ServiceURL: r.ServiceURL, ProxyURLTemplate: r.ProxyURLTemplate, DiscoveryURL: r.DiscoveryURL, IngressDigest: r.IngressDigest, CredentialGeneration: r.CredentialGeneration, ProviderVersion: r.ProviderVersion}
}
func (s *Server) newConfigurationManager() *machineconfig.Manager {
	p := s.params
	return machineconfig.New(machineconfig.Config{RequireDrain: p.CloudflareEnabled, APIURL: p.PublicAPIURL, DrainTimeout: p.TunnelDrainTimeout, StatusTTL: p.TunnelStatusTTL, RuntimeImage: p.RuntimeImage, NodeImage: p.RuntimeNodeImage, StopSignals: p.AppStopSignals, Connector: machineconfig.ConnectorConfig{Image: p.CloudflareConnectorImage, NodeAddresses: p.TunnelNodeAddresses, PrivateControlCIDRs: p.TunnelPrivateControlCIDRs}}, machineconfig.Dependencies{DB: s.db, Logger: s.logger,
		Exposure: func(raw json.RawMessage) (*machineconfig.Exposure, error) {
			var r tunnel.RoutingState
			err := json.Unmarshal(raw, &r)
			return exposure(r), err
		},
		Build: func(d machineconfig.Desired) ([]byte, string, error) { return s.build(d) },
	})
}

func configurationMachine(m Machine) machineconfig.Machine {
	return machineconfig.Machine{NodeID: m.NodeID, Epoch: m.Epoch, InstallDir: m.InstallDir, K3sVersion: m.K3sVersion, CredentialVersion: m.CredentialVersion, Terminal: m.Terminal}
}
