// Package tunnel manages provider resources and credentials for machine tunnels.
package tunnel

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

var ErrPending = errors.New("tunnel is not provisioned")

// Machine identifies an enrollment and the installation used to render its
// configuration. Authentication and bundle assembly belong to the caller.
type Machine struct {
	NodeID, Epoch, InstallDir, K3sVersion string
	CredentialVersion                     int64
	Terminal                              bool
}

type AppliedConfiguration struct {
	Digest, Manifest string
}

// Rollout supplies configuration facts without exposing the bundle format or
// importing the HTTP server. DesiredDigest must honor HeldOrchestrator.
type Rollout interface {
	DesiredDigest(Machine, RoutingState) string
	Applied(context.Context, Machine) (AppliedConfiguration, error)
}

type Dependencies struct {
	DB              *sql.DB
	Logger          *slog.Logger
	Rollout         Rollout
	Provider        TunnelProvider
	VerifyEndpoints func(context.Context, RoutingState, AccessCredential) error
}

type Manager struct {
	db               *sql.DB
	params           Config
	logger           *slog.Logger
	rollout          Rollout
	provider         TunnelProvider
	keys             *accessKeyring
	endpointVerifier func(context.Context, RoutingState, AccessCredential) error
}

// New also supports reading persisted state while provisioning is disabled.
// Configure enables provisioning; ConfigureCredentials enables credential reads.
// Both are startup operations and must finish before workers start.
func New(config Config, deps Dependencies) *Manager {
	return &Manager{db: deps.DB, params: config, logger: deps.Logger, rollout: deps.Rollout,
		provider: deps.Provider, endpointVerifier: deps.VerifyEndpoints}
}

func (s *Manager) Configure(publicAPIURL string) error {
	if !s.params.CloudflareEnabled {
		return nil
	}
	if err := s.params.Validate(publicAPIURL); err != nil {
		return err
	}
	if s.params.CloudflareAPIToken == "" {
		return errors.New("Cloudflare provisioning credential is required")
	}
	if err := s.ConfigureCredentials(); err != nil {
		return err
	}
	if s.provider == nil {
		s.provider = &cloudflareHTTP{params: s.params, client: &http.Client{Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, base: "https://api.cloudflare.com/client/v4"}
	}
	return nil
}

func (s *Manager) ConfigureCredentials() error {
	if s.keys != nil {
		return nil
	}
	keys, err := parseAccessKeyring(s.params.CloudflareKeyring)
	if err == nil {
		s.keys = keys
	}
	return err
}

func (s *Manager) Enabled() bool { return s.provider != nil }

func (s *Manager) ConnectorToken(ctx context.Context, state RoutingState) (string, error) {
	return s.providerFor(state).ConnectorToken(ctx, state.TunnelID)
}
