// Package tunnel manages provider resources and credentials for machine tunnels.
package tunnel

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"io"
	"log/slog"
	"net/http"
	"time"
)

var ErrPending = errors.New("tunnel is not provisioned")

type Machine = machineconfig.Machine

type Dependencies struct {
	DB              *sql.DB
	Logger          *slog.Logger
	Configurations  *machineconfig.Manager
	Provider        TunnelProvider
	VerifyEndpoints func(context.Context, RoutingState, AccessCredential) error
	EndpointRandom  io.Reader
}

type Manager struct {
	db               *sql.DB
	params           Config
	logger           *slog.Logger
	rollout          *machineconfig.Manager
	provider         TunnelProvider
	keys             *accessKeyring
	endpointVerifier func(context.Context, RoutingState, AccessCredential) error
	endpointRandom   io.Reader
}

// New also supports reading persisted state while provisioning is disabled.
// Configure enables provisioning; ConfigureCredentials enables credential reads.
// Both are startup operations and must finish before workers start.
func New(config Config, deps Dependencies) *Manager {
	if deps.EndpointRandom == nil {
		deps.EndpointRandom = rand.Reader
	}
	return &Manager{db: deps.DB, params: config, logger: deps.Logger, rollout: deps.Configurations,
		provider: deps.Provider, endpointVerifier: deps.VerifyEndpoints, endpointRandom: deps.EndpointRandom}
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
