// Package tunnel manages provider resources and credentials for machine tunnels.
package tunnel

import (
	"context"
	"database/sql"
	"errors"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"log/slog"
	"net/http"
	"time"
)

var ErrPending = errors.New("tunnel is not provisioned")

type Machine = machineconfig.Machine

type Dependencies struct {
	SignDiscovery   func(string) (string, error)
	DB              *sql.DB
	Logger          *slog.Logger
	Configurations  *machineconfig.Manager
	Provider        TunnelProvider
	VerifyEndpoints func(context.Context, RoutingState, string) error
}

type Manager struct {
	signDiscovery func(string) (string, error)
	db            *sql.DB
	params        Config
	logger        *slog.Logger
	rollout       *machineconfig.Manager
	provider      TunnelProvider

	endpointVerifier func(context.Context, RoutingState, string) error
}

func New(config Config, deps Dependencies) *Manager {
	if deps.Provider == nil && config.CloudflareAPIToken != "" {
		deps.Provider = &cloudflareHTTP{params: config, client: &http.Client{Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, base: "https://api.cloudflare.com/client/v4"}
	}
	return &Manager{signDiscovery: deps.SignDiscovery, db: deps.DB, params: config, logger: deps.Logger, rollout: deps.Configurations,
		provider: deps.Provider, endpointVerifier: deps.VerifyEndpoints}
}

func (s *Manager) Enabled() bool { return s.provider != nil }

func (s *Manager) ConnectorToken(ctx context.Context, state RoutingState) (string, error) {
	return s.providerFor(state).ConnectorToken(ctx, state.TunnelID)
}
