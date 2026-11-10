package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fleet "github.com/livepeer/control-center/api/internal/controlplane/discovery"
	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
)

type fleetRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn fleetRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func reconcileDiscovery(t *testing.T, s *Server) {
	t.Helper()
	if err := s.discovery.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestFleetEncryptedStoreAPIAndRotation(t *testing.T) {
	s, _ := tunnelTestServer(t)
	a := enroll(t, s, ownerA, strings.Repeat("a", 64))
	b := enroll(t, s, ownerB, strings.Repeat("b", 64))
	readyTunnel(t, s, a)
	readyTunnel(t, s, b)
	adminA(t, s)
	s.params.DiscoveryParams = DiscoveryParams{DiscoveryEnabled: true, DiscoveryRefreshInterval: 5 * time.Minute, DiscoveryMaxFailedRefreshes: 6}
	if err := s.ConfigureDiscovery(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.CloseDiscovery)
	var calls atomic.Int32
	// The real database/keyring resolver and Collector are used; only the remote
	// Cloudflare/orchestrator response is simulated. TLS/policy has separate tests.
	s.CloseDiscovery()
	manager, err := fleet.New(s.discoveryConfig(), fleet.Dependencies{Store: discoveryStore{s}, Logger: s.logger, Transport: fleetRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		sources, err := s.tunnels.DiscoverySources(r.Context())
		if err != nil {
			return nil, err
		}
		for _, source := range sources {
			if source.URL != r.URL.String() {
				continue
			}
			credential, err := s.tunnels.ResolveAccessCredential(r.Context(), source.CredentialRef)
			if err != nil {
				return nil, err
			}
			if r.Header.Get("CF-Access-Client-Id") != credential.ClientID || r.Header.Get("CF-Access-Client-Secret") != credential.ClientSecret {
				t.Error("wrong encrypted source credential")
			}
			record := `{"url":"` + source.ServiceURL + `/apps/a/session","app":"test","observed_at":"2000-01-01T00:00:00Z","extension":9007199254740993}`
			body := `[{"address":"` + source.ServiceURL + `","runners":[` + record + `]}]`
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		}
		t.Error("request to unknown managed source")
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	s.discovery = manager
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { manager.Run(ctx); close(done) }()
	stop := func() { cancel(); <-done }
	t.Cleanup(stop)
	reconcileDiscovery(t, s)
	deadline := time.After(3 * time.Second)
	for {
		status := s.DiscoveryStatus()
		if len(status.Sources) == 2 && status.Sources[0].State == "healthy" && status.Sources[1].State == "healthy" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("managed sources did not initialize", status)
		case <-time.After(time.Millisecond):
		}
	}
	reconcileDiscovery(t, s)
	response := request(t, s, "GET", "/discovery", "", nil)
	if response.Code != 200 || strings.Count(response.Body.String(), `"app":"test"`) != 2 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("aggregate API unavailable", response.Code, response.Body.String())
	}
	before := calls.Load()
	request(t, s, "GET", "/discovery", "", nil)
	if calls.Load() != before {
		t.Fatal("HTTP endpoint started collection")
	}
	for _, token := range []string{"", a["token"], "session-b"} {
		w := request(t, s, "GET", "/api/admin/discovery", token, nil)
		if w.Code == 200 {
			t.Fatal("source diagnostics bypassed administrator policy")
		}
	}
	status := request(t, s, "GET", "/api/admin/discovery", "session-a", nil)
	if status.Code != 200 || !strings.Contains(status.Body.String(), `"acknowledged":true`) {
		t.Fatal("authorized freshness diagnostics missing", status.Code, status.Body.String())
	}
	sources, err := s.tunnels.DiscoverySources(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range sources {
		credential, err := s.tunnels.ResolveAccessCredential(t.Context(), source.CredentialRef)
		if err != nil {
			t.Fatal(err)
		}
		for _, output := range []string{response.Body.String(), status.Body.String()} {
			for _, secret := range []string{credential.ClientID, credential.ClientSecret, source.CredentialRef, source.URL, s.params.CloudflareKeyring, s.params.CloudflareAPIToken, tunnel.PrivateOrchestrator} {
				if strings.Contains(output, secret) {
					t.Fatal("secret/private source leaked into API")
				}
			}
		}
	}
	managerBeforeRotation := s.tunnels
	rotate := request(t, s, "POST", "/api/admin/machines/"+a["node_id"]+"/tunnel/rotate", "session-a", map[string]any{"epoch": a["epoch"], "kind": "access"})
	requireStatus(t, rotate, 202)
	driveTunnels(t, s)
	reconcileDiscovery(t, s)
	var acknowledged bool
	if err := s.db.QueryRow(`SELECT acknowledged_at IS NOT NULL FROM lpcc.access_credentials WHERE node_id=$1 AND epoch=$2 AND version=2`, a["node_id"], a["epoch"]).Scan(&acknowledged); err != nil || !acknowledged {
		t.Fatal("new version not acknowledged by actual collection", err)
	}
	driveTunnels(t, s)
	if s.tunnels != managerBeforeRotation {
		t.Fatal("ordinary reconciliation replaced manager with active discovery readers")
	}
	var active int
	if err := s.db.QueryRow(`SELECT count(*) FROM lpcc.access_credentials WHERE node_id=$1 AND epoch=$2 AND revoked_at IS NULL`, a["node_id"], a["epoch"]).Scan(&active); err != nil || active != 1 {
		t.Fatal("acknowledgement did not release predecessor token", err, active)
	}
	requireStatus(t, request(t, s, "DELETE", "/api/admin/machines/"+a["node_id"], "session-a", map[string]any{"epoch": a["epoch"], "force": true}), 202)
	reconcileDiscovery(t, s)
	if strings.Count(request(t, s, "GET", "/discovery", "", nil).Body.String(), `"app":"test"`) != 1 {
		t.Fatal("machine removal did not withdraw only that source")
	}
	// Missing routing identity must withdraw a previously approved source,
	// including before the tunnel worker runs again.
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=state-'endpoint_suffix' WHERE node_id=$1`, b["node_id"])
	reconcileDiscovery(t, s)
	if strings.Contains(request(t, s, "GET", "/discovery", "", nil).Body.String(), `"app":"test"`) {
		t.Fatal("source without routing identity remained advertised")
	}
	// A process restart begins cold, then discovers from the same managed state.
	stop()
	if err := s.ConfigureDiscovery(); err != nil {
		t.Fatal(err)
	}
	if request(t, s, "GET", "/discovery", "", nil).Body.String() != "[]\n" {
		t.Fatal("restart reused in-memory cache")
	}
}

func TestFleetConfigurationAndPublicDisabledRoute(t *testing.T) {
	p := testParams()
	s := New(nil, p, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.ConfigureDiscovery(); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, request(t, s, "GET", "/discovery", "", nil), 503)
	requireStatus(t, request(t, s, "GET", "/healthz", "", nil), 200)
	p.DiscoveryParams = DiscoveryParams{DiscoveryEnabled: true, DiscoveryRefreshInterval: 5 * time.Minute, DiscoveryMaxFailedRefreshes: 6}
	s.params = p
	if s.ConfigureDiscovery() == nil {
		t.Fatal("discovery started without ingress approval")
	}
	s.params.CloudflareIngressApproved = true
	if s.ConfigureDiscovery() == nil {
		t.Fatal("discovery started without protected keyring")
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	s.params.CloudflareKeyring = `{"current":"test","keys":{"test":"` + key + `"}}`
	if err := s.ConfigureTunnels(); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureDiscovery(); err != nil {
		t.Fatal(err)
	}
	defer s.CloseDiscovery()
	if s.tunnels.Enabled() {
		t.Fatal("reader unnecessarily acquired provisioning client")
	}
	if status := s.DiscoveryStatus(); !status.Enabled || status.InstanceID == "" || !status.SelectionStale {
		t.Fatal("startup status treated as fresh inventory")
	}
	for _, p := range []DiscoveryParams{{DiscoveryEnabled: true}, {DiscoveryEnabled: true, DiscoveryRefreshInterval: time.Minute, DiscoveryMaxFailedRefreshes: -1}} {
		if p.validate() == nil {
			t.Fatal("accepted invalid discovery cadence")
		}
	}
	if _, err := json.Marshal(s.DiscoveryStatus()); err != nil {
		t.Fatal(err)
	}
	// Close is safe before workers start and after repeated shutdown calls.
	s.CloseDiscovery()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.RunDiscovery(ctx)
}
