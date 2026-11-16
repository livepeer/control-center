// Package discovery hosts the Node Collector independently of API/auth/database code.
package discovery

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

const (
	AuthBearer = "bearer"
	AuthNone   = "none"
)

// Config controls collection, not machine placement or qualification policy.
type Config struct {
	RefreshInterval    time.Duration
	MaxFailedRefreshes int
	ReconcileInterval  time.Duration
	Grants             []string
	OwnURL             string
}

func (c Config) Validate() error {
	if c.RefreshInterval < time.Second || c.ReconcileInterval < time.Second || c.MaxFailedRefreshes < 0 {
		return errors.New("discovery requires intervals of at least 1s and a nonnegative failure limit")
	}
	return nil
}

// Dependencies supplies only source operations. Transport nil selects Node's
// destination-policy transport; embeddings supplying one must preserve protections.
// It is not exposed as runtime configuration by Control Center.
type Dependencies struct {
	Store     Store
	Logger    *slog.Logger
	Transport http.RoundTripper
	SignToken func(Source) (string, error)
}

// Store projects authoritative managed state; it is not another editable fleet list.
type Store interface {
	Sources(context.Context) ([]Source, error)
}

type Source struct {
	NodeID             string `json:"node_id"`
	URL                string `json:"url"`
	ServiceURL         string `json:"service_url"`
	ProxyURLTemplate   string `json:"proxy_url_template"`
	AuthMode           string `json:"auth_mode"`
	Lifecycle          string `json:"lifecycle"`
	Ready              bool   `json:"ready"`
	Blocked            bool   `json:"blocked"`
	Generation         int64  `json:"generation"`
	VerifiedGeneration int64  `json:"verified_generation"`
}
