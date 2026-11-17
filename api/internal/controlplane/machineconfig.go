package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/livepeer/control-center/runtime/onchain"

	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
)

func exposure(r tunnel.RoutingState) *machineconfig.Exposure {
	return &machineconfig.Exposure{IngressVersion: r.IngressVersion, TunnelID: r.TunnelID, ServiceURL: r.ServiceURL, ProxyURLTemplate: r.ProxyURLTemplate, DiscoveryURL: r.DiscoveryURL, IngressDigest: r.IngressDigest, CredentialGeneration: r.CredentialGeneration, ProviderVersion: r.ProviderVersion}
}
func (s *Server) newConfigurationManager() *machineconfig.Manager {
	p := s.params
	var public []byte
	if p.jwtKey != nil {
		public = p.jwtKey.Keys.JSON()
	}
	return machineconfig.New(machineconfig.Config{IngressPublicKeys: public, APIURL: p.PublicAPIURL, DrainTimeout: p.TunnelDrainTimeout, StatusTTL: p.TunnelStatusTTL, RuntimeImage: p.RuntimeImage, NodeImage: p.RuntimeNodeImage, NodeDrainTimeout: &p.RuntimeNodeDrainTimeout, StopSignals: p.AppStopSignals, Telemetry: p.TelemetryEnabled, TelemetryAppLogs: p.TelemetryAppLogsEnabled, Connector: machineconfig.ConnectorConfig{Image: p.RuntimeConnectorImage, NodeAddresses: p.TunnelNodeAddresses}}, machineconfig.Dependencies{DB: s.db, Logger: s.logger,
		Onchain: func(ctx context.Context, m machineconfig.Machine) (onchain.Config, error) {
			var c onchain.Config
			var err error
			if m.Fingerprint != "" {
				c, err = loadInstallationOnchain(ctx, s.db, "$1", m.Fingerprint)
			} else {
				c, err = loadOnchain(ctx, s.db, m.NodeID)
			}
			if err == nil && s.params.networkMode() == "onchain" && !c.Onchain() {
				return c, errors.New("onchain configuration is missing")
			}
			return c, err
		},
		Exposure: func(raw json.RawMessage) (*machineconfig.Exposure, error) {
			var r tunnel.RoutingState
			err := json.Unmarshal(raw, &r)
			return exposure(r), err
		},
		Build: func(d machineconfig.Desired) ([]byte, string, error) { return s.build(d) },
	})
}

func configurationMachine(m Machine) machineconfig.Machine {
	return machineconfig.Machine{NodeID: m.NodeID, Fingerprint: m.Fingerprint, InstallDir: m.InstallDir, K3sVersion: m.K3sVersion, CredentialVersion: m.CredentialVersion, Terminal: m.Terminal}
}
