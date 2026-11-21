package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fleet "github.com/livepeer/control-center/api/internal/controlplane/discovery"
	"github.com/livepeer/control-center/runtime/ingressauth"
)

type fleetRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn fleetRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func reconcileDiscovery(t *testing.T, s *Server) {
	t.Helper()
	if err := s.discovery.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestFleetLocalBearerSigningAPIAndRotation(t *testing.T) {
	s, _ := tunnelTestServer(t)
	a := enroll(t, s, ownerA, strings.Repeat("a", 64))
	b := enroll(t, s, ownerB, strings.Repeat("b", 64))
	readyTunnel(t, s, a)
	readyTunnel(t, s, b)
	adminA(t, s)
	s.params.DiscoveryParams = DiscoveryParams{DiscoveryEnabled: true, DiscoveryRefreshInterval: time.Second, DiscoveryMaxFailedRefreshes: 6}
	var calls atomic.Int32
	start := func() func() {
		manager, err := fleet.New(s.discoveryConfig(), fleet.Dependencies{Store: discoveryStore{s}, Logger: s.logger, SignToken: func(source fleet.Source) (string, error) { return s.signDiscovery(source.NodeID) }, Transport: fleetRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			sources, err := s.tunnels.DiscoverySources(r.Context())
			if err != nil {
				return nil, err
			}
			for _, source := range sources {
				if source.URL != r.URL.String() {
					continue
				}
				if err := ingressauth.Verify(s.params.jwtKey.Keys, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), source.NodeID, s.currentTime()); err != nil {
					t.Error("invalid source bearer", err)
				}
				body := `[{"address":"` + source.ServiceURL + `","runners":[{"url":"` + source.ServiceURL + `/apps/a/session","app":"test","observed_at":"2000-01-01T00:00:00Z","extension":9007199254740993}]}]`
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			}
			return &http.Response{StatusCode: 404, Body: http.NoBody}, nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		s.discovery = manager
		reconcileDiscovery(t, s)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { manager.Run(ctx); close(done) }()
		stop := func() { cancel(); <-done; manager.Close() }
		t.Cleanup(stop)
		for deadline := time.Now().Add(4 * time.Second); ; {
			status := s.DiscoveryStatus()
			if len(status.Sources) == 2 && status.Sources[0].State == "healthy" && status.Sources[1].State == "healthy" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("sources did not initialize", status)
			}
			time.Sleep(time.Millisecond)
		}
		return stop
	}
	stop := start()
	response := request(t, s, "GET", "/discovery", "", nil)
	if response.Code != 200 || strings.Count(response.Body.String(), `"app":"test"`) != 2 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("aggregate unavailable", response.Code, response.Body.String())
	}
	before := calls.Load()
	request(t, s, "GET", "/discovery", "", nil)
	if calls.Load() != before {
		t.Fatal("HTTP reads started polling")
	}
	for _, credential := range []string{"", a["token"], "session-b"} {
		if request(t, s, "GET", "/api/admin/discovery", credential, nil).Code == 200 {
			t.Fatal("source status bypassed admin policy")
		}
	}
	status := request(t, s, "GET", "/api/admin/discovery", "session-a", nil)
	requireStatus(t, status, 200)
	for _, output := range []string{response.Body.String(), status.Body.String()} {
		for _, secret := range []string{string(s.params.jwtKey.Private), s.params.CloudflareAPIToken, a["token"]} {
			if strings.Contains(output, secret) {
				t.Fatal("credential leaked")
			}
		}
	}
	// Stop the old process before replacing its mounted signing configuration.
	stop()
	testRotateJWT(&s.params, 2, "next")
	stop = start()
	requireStatus(t, request(t, s, "DELETE", "/api/admin/machines/"+a["node_id"], "session-a", map[string]any{"force": true}), 202)
	reconcileDiscovery(t, s)
	if strings.Count(request(t, s, "GET", "/discovery", "", nil).Body.String(), `"app":"test"`) != 1 {
		t.Fatal("source retirement did not withdraw inventory")
	}
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=state-'service_url' WHERE node_id=$1`, b["node_id"])
	reconcileDiscovery(t, s)
	if strings.Contains(request(t, s, "GET", "/discovery", "", nil).Body.String(), `"app":"test"`) {
		t.Fatal("missing source identity remained published")
	}
	stop()
	if err := s.ConfigureDiscovery(); err != nil {
		t.Fatal(err)
	}
	defer s.CloseDiscovery()
	if request(t, s, "GET", "/discovery", "", nil).Body.String() != "[]\n" {
		t.Fatal("restart reused cache")
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
	p.DiscoveryParams = DiscoveryParams{DiscoveryEnabled: true, DiscoveryRefreshInterval: time.Second, DiscoveryMaxFailedRefreshes: 6}
	s.params = p
	if s.ConfigureDiscovery() == nil {
		t.Fatal("discovery started without ingress approval")
	}
	s.params.CloudflareIngressApproved = true
	if err := s.ConfigureDiscovery(); err != nil {
		t.Fatal(err)
	}
	defer s.CloseDiscovery()
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
