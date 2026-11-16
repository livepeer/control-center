package controlplane

import (
	"context"
	"errors"
	"net/http"
	"time"

	fleet "github.com/livepeer/control-center/api/internal/controlplane/discovery"
)

// DiscoveryParams belongs to API configuration; the subsystem has no feature
// flags, administrator policy, database, or machine enrollment dependencies.
type DiscoveryParams struct {
	DiscoveryEnabled            bool          `env:"DISCOVERY_ENABLED" default:"false" descr:"Serve fleet discovery from managed, ingress-protected orchestrators"`
	DiscoveryRefreshInterval    time.Duration `env:"DISCOVERY_REFRESH_INTERVAL" default:"5m" descr:"Node Collector refresh interval"`
	DiscoveryMaxFailedRefreshes int           `env:"DISCOVERY_MAX_FAILED_REFRESHES" default:"6" descr:"Consecutive failures before eviction; zero evicts on first failure"`
	DiscoveryGrants             []string      `env:"DISCOVERY_GRANTS" optional:"true" descr:"Explicit private destination IP/IP:port/CIDR grants for discovery only"`
}

func (p DiscoveryParams) validate() error {
	if !p.DiscoveryEnabled {
		return nil
	}
	return (fleet.Config{RefreshInterval: p.DiscoveryRefreshInterval, ReconcileInterval: time.Second, MaxFailedRefreshes: p.DiscoveryMaxFailedRefreshes}).Validate()
}
func (s *Server) discoveryConfig() fleet.Config {
	return fleet.Config{RefreshInterval: s.params.DiscoveryRefreshInterval, MaxFailedRefreshes: s.params.DiscoveryMaxFailedRefreshes,
		ReconcileInterval: s.params.ConfigReconcileInterval, Grants: s.params.DiscoveryGrants, OwnURL: s.params.PublicAPIURL}
}
func (s *Server) ConfigureDiscovery() error {
	if !s.params.DiscoveryEnabled {
		return nil
	}
	if !s.params.CloudflareIngressApproved {
		return errors.New("fleet discovery requires approved protected machine ingress")
	}
	manager, err := fleet.New(s.discoveryConfig(), fleet.Dependencies{Store: discoveryStore{s}, Logger: s.logger, SignToken: func(source fleet.Source) (string, error) { return s.signDiscovery(source.NodeID) }})
	if err != nil {
		return err
	}
	s.discovery = manager
	return nil
}
func (s *Server) RunDiscovery(ctx context.Context) {
	if s.discovery != nil {
		s.discovery.Run(ctx)
	}
}
func (s *Server) CloseDiscovery() {
	if s.discovery != nil {
		s.discovery.Close()
	}
}
func (s *Server) DiscoveryStatus() fleet.Status {
	if s.discovery == nil {
		return fleet.Status{Sources: []fleet.SourceStatus{}}
	}
	return s.discovery.Status()
}
func (s *Server) discoveryHTTP(w http.ResponseWriter, r *http.Request) {
	if s.discovery == nil {
		fail(w, http.StatusServiceUnavailable, "fleet discovery is disabled")
		return
	}
	s.discovery.ServeHTTP(w, r)
}
func (s *Server) requestReconcile() {
	select {
	case s.reconcileWake <- struct{}{}:
	default:
	}
}

// Adapt the tunnel ledger and protected resolver. The discovery subsystem never
// imports controlplane or obtains the server's other credentials/provider client.
type discoveryStore struct{ server *Server }

func (s discoveryStore) Sources(ctx context.Context) ([]fleet.Source, error) {
	sources, err := s.server.tunnels.DiscoverySources(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]fleet.Source, 0, len(sources))
	for _, source := range sources {
		result = append(result, fleet.Source{NodeID: source.NodeID, URL: source.URL,
			ServiceURL: source.ServiceURL, ProxyURLTemplate: source.ProxyURLTemplate, AuthMode: fleet.AuthBearer,
			Lifecycle: source.Lifecycle, Ready: source.Ready, Blocked: source.Blocked, Generation: source.Generation,
			VerifiedGeneration: source.VerifiedGeneration})
	}
	return result, nil
}
func (s *Server) signDiscovery(node string) (string, error) {
	if s.params.jwtKey == nil {
		return "", errors.New("JWT signing key is unavailable")
	}
	return s.params.jwtKey.Discovery(s.params.signingKeyID(), node, s.currentTime())
}
