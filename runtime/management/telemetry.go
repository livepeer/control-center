package management

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/livepeer/control-center/runtime/transport"
)

// TelemetryGrant is the telemetry relay's only credential. The management agent
// chooses the destinations from its approved Control Center origin, so neither
// the bundle nor the relay can redirect telemetry or reach the machine token.
type TelemetryGrant struct {
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expires_at"`
	NodeID     string    `json:"node_id"`
	MetricsURL string    `json:"metrics_url"`
	LogsURL    string    `json:"logs_url"`
}

type TelemetryTokens struct {
	Control transport.Requester
	// Base is the approved machine operation base, ending in /v1/nodes/<node_id>.
	Base    string
	Desired Desired
	Now     func() time.Time
}

var compactJWT = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// maxTelemetryLifetime bounds tokens accepted from Control Center, with clock tolerance.
const maxTelemetryLifetime = time.Hour + time.Minute

func (t TelemetryTokens) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/telemetry/token" || r.URL.RawQuery != "" {
		http.Error(w, "operation refused", http.StatusForbidden)
		return
	}
	// Retired enrollments receive no telemetry credential.
	m, ok := t.Desired()
	if !ok || m.Terminal || m.NodeID == "" {
		http.Error(w, "configuration unavailable", http.StatusServiceUnavailable)
		return
	}
	b, _, err := t.Control.Request(r.Context(), "telemetry/token", nil, 16384)
	if err != nil {
		status := http.StatusServiceUnavailable
		var remote *transport.HTTPError
		if errors.As(err, &remote) {
			status = remote.Status
		}
		http.Error(w, "telemetry credential unavailable", status)
		return
	}
	var issued struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
		NodeID    string    `json:"node_id"`
	}
	now := time.Now()
	if t.Now != nil {
		now = t.Now()
	}
	if transport.Decode(b, &issued) != nil || issued.NodeID != m.NodeID || len(issued.Token) > 4096 || !compactJWT.MatchString(issued.Token) ||
		!issued.ExpiresAt.After(now) || issued.ExpiresAt.Sub(now) > maxTelemetryLifetime {
		http.Error(w, "telemetry credential refused", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(TelemetryGrant{Token: issued.Token, ExpiresAt: issued.ExpiresAt, NodeID: issued.NodeID,
		MetricsURL: t.Base + "/telemetry/metrics", LogsURL: t.Base + "/telemetry/logs"})
}
