package discovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	shared "github.com/livepeer/node/discovery/shared"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type simulatedDiscoveryBackend struct {
	mu               sync.Mutex
	sources          []Source
	credentials      map[string]Credential
	acknowledgements []Source
	err              bool
}

func (b *simulatedDiscoveryBackend) Sources(context.Context) ([]Source, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err {
		return nil, errors.New("source-store-sentinel")
	}
	return append([]Source(nil), b.sources...), nil
}
func (b *simulatedDiscoveryBackend) Resolve(_ context.Context, ref string) (Credential, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	credential, ok := b.credentials[ref]
	if !ok {
		return Credential{}, errors.New("credential-store-sentinel")
	}
	return credential, nil
}
func (b *simulatedDiscoveryBackend) Acknowledge(_ context.Context, source Source) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.acknowledgements = append(b.acknowledgements, source)
	return nil
}

const discoveryTestRecord = `{"url":"https://orch.example/apps/a/session","app":"test","version":"v1","observed_at":"2000-01-01T00:00:00.123+00:00","mode":"persistent","capacity":4,"capacity_used":1,"capacity_available":3,"gpu":{"name":"H100"},"price_info":{"price":123456789012345678901234567890,"price_usd":0.123456789012345678901234567890123456,"currency":"wei","unit":"seconds"},"extension":{"integer":9007199254740993,"ratio":1.2300e+04}}`
const discoveryTestInventory = `[{"nodes":[{"url":"https://never-follow.example","queried_at":"2000-01-01T00:00:00Z"}]},{"address":"https://orch.example","runners":[` + discoveryTestRecord + `]}]`

func testSource(id, endpoint string) Source {
	return Source{NodeID: id, URL: endpoint + "/discovery", ServiceURL: "https://orch.example", ProxyURLTemplate: "https://{proxy}.apps.example", AuthMode: AuthCloudflare, Lifecycle: "active", Ready: true, Generation: 1, VerifiedGeneration: 1, CredentialRef: "ref-" + id, CredentialVersion: 1}
}
func testFleet(t *testing.T, b *simulatedDiscoveryBackend, servers ...*httptest.Server) (*Manager, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	f, err := New(Config{RefreshInterval: 5 * time.Minute, ReconcileInterval: time.Minute, MaxFailedRefreshes: 6, Grants: []string{"127.0.0.1", "::1"}}, Dependencies{Store: b, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	for _, server := range servers {
		roots.AddCert(server.Certificate())
	}
	f.transport.base.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots}
	t.Cleanup(f.collector.Close)
	return f, &logs
}
func reconcileFleet(t *testing.T, f *Manager) {
	t.Helper()
	if err := f.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
}
func fleetBody(f *Manager) string {
	w := httptest.NewRecorder()
	f.ServeHTTP(w, httptest.NewRequest("GET", "https://aggregate.example/discovery", nil))
	return w.Body.String()
}

func TestFleetIdentityAndPartialPublication(t *testing.T) {
	source := testSource("one", "https://source.example")
	b := &simulatedDiscoveryBackend{sources: []Source{source}, credentials: map[string]Credential{source.CredentialRef: {"client", "secret"}}}
	f, _ := testFleet(t, b)
	var inventory atomic.Value
	bad := `{"url":"http://10.43.0.7/private?token=sentinel","app":"broken","observed_at":"2000-01-01T00:00:00Z"}`
	inventory.Store(`[{"address":"https://orch.example","runners":[` + discoveryTestRecord + `,` + bad + `]}]`)
	f.transport.base = discoveryRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(inventory.Load().(string)))}, nil
	})
	reconcileFleet(t, f)
	f.collector.Refresh(t.Context(), false)
	want := `[{"address":"https://orch.example","runners":[` + discoveryTestRecord + "]}]\n"
	for range 2 {
		if body := fleetBody(f); body != want {
			t.Fatal("healthy sibling changed or unsafe URL published", body)
		}
	}
	reconcileFleet(t, f)
	if !f.Status().Sources[0].PublicationBlocked || len(b.acknowledgements) != 1 {
		t.Fatal("filtered runner blocked credential acknowledgement or lacked diagnostics")
	}
	// Canonical identity values must be exactly those a JSON consumer receives.
	for _, identity := range []string{
		`"url":"http://10.43.0.7/private?token=sentinel","URL":"https://orch.example/apps/a/session","app":"test","observed_at":"2000-01-01T00:00:00Z"`,
		`"url":"http://10.43.0.7/private?token=sentinel","url":"https://orch.example/apps/a/session","app":"test","observed_at":"2000-01-01T00:00:00Z"`,
		`"url":"https://orch.example/apps/a/session","app":"test","App":"other","observed_at":"2000-01-01T00:00:00Z"`,
		`"url":"https://orch.example/apps/a/session","app":"test","observed_at":"2000-01-01T00:00:00Z","Observed_At":"2001-01-01T00:00:00Z"`,
	} {
		inventory.Store(`[{"address":"https://orch.example","runners":[{` + identity + `}]}]`)
		f.collector.Refresh(t.Context(), false)
		if body := fleetBody(f); body != want || f.Status().Sources[0].State != "retained" {
			t.Fatal("ambiguous identity replaced accepted inventory", body)
		}
	}
	// A new version still needs the right owning address. App-level routing
	// errors then affect publication, rather than predecessor credential cleanup.
	b.sources[0].Generation, b.sources[0].VerifiedGeneration = 2, 2
	b.sources[0].CredentialVersion, b.sources[0].CredentialRef = 2, "new-ref"
	b.credentials["new-ref"] = Credential{"new-client", "new-secret"}
	inventory.Store(`[{"address":"https://wrong.example","runners":[` + discoveryTestRecord + `]}]`)
	reconcileFleet(t, f)
	if len(b.acknowledgements) != 1 {
		t.Fatal("wrong owning address acknowledged replacement credential")
	}
	inventory.Store(`[{"address":"https://orch.example","runners":[` + discoveryTestRecord + `,` + bad + `]}]`)
	f.collector.Refresh(t.Context(), false)
	reconcileFleet(t, f)
	if len(b.acknowledgements) != 2 || b.acknowledgements[1].CredentialVersion != 2 || !f.Status().Sources[0].PublicationBlocked || fleetBody(f) != want {
		t.Fatal("filtered runner stalled replacement acknowledgement or changed valid sibling")
	}
}

func TestFleetAcknowledgementRequiresDecodedReplacementCredential(t *testing.T) {
	source := testSource("one", "https://source.example")
	b := &simulatedDiscoveryBackend{sources: []Source{source}, credentials: map[string]Credential{source.CredentialRef: {"old-client", "old-secret"}}}
	f, _ := testFleet(t, b)
	var body atomic.Value
	body.Store(discoveryTestInventory)
	f.transport.base = discoveryRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body.Load().(string)))}, nil
	})
	reconcileFleet(t, f)
	f.collector.Refresh(t.Context(), false)
	reconcileFleet(t, f)
	if len(b.acknowledgements) != 1 || b.acknowledgements[0].CredentialVersion != 1 {
		t.Fatal("initial v1 collection was not acknowledged")
	}
	original := f.collector.Snapshots()[0].QueriedAt
	body.Store("<html>Access login</html>")
	b.sources[0].Generation = 2
	b.sources[0].VerifiedGeneration = 2
	b.sources[0].CredentialVersion = 2
	b.sources[0].CredentialRef = "new-ref"
	b.credentials["new-ref"] = Credential{"new-client", "new-secret"}
	reconcileFleet(t, f)
	f.collector.Refresh(t.Context(), false)
	if len(b.acknowledgements) != 1 || f.Status().Sources[0].State != "retained" || f.collector.Snapshots()[0].QueriedAt != original {
		t.Fatal("HTTP 200 login HTML acknowledged v2 or changed retained v1 observation")
	}
	f.acknowledge(t.Context())
	for _, ack := range b.acknowledgements {
		if ack.CredentialVersion == 2 {
			t.Fatal("retained v1 snapshot acknowledged invalid v2 collection")
		}
	}
	for range 6 {
		f.collector.Refresh(t.Context(), false)
		reconcileFleet(t, f)
	}
	for _, ack := range b.acknowledgements {
		if ack.CredentialVersion == 2 {
			t.Fatal("evicted snapshot acknowledged invalid v2 collection")
		}
	}
	body.Store(discoveryTestInventory)
	f.collector.Refresh(t.Context(), false)
	reconcileFleet(t, f)
	if len(b.acknowledgements) != 2 || b.acknowledgements[1].CredentialVersion != 2 {
		t.Fatal("successful replacement was not acknowledged")
	}
}

func TestFleetRotationDuringPollDoesNotAcknowledgeOldCredential(t *testing.T) {
	source := testSource("one", "https://source.example")
	b := &simulatedDiscoveryBackend{sources: []Source{source}, credentials: map[string]Credential{source.CredentialRef: {"old-client", "old-secret"}}}
	f, _ := testFleet(t, b)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var allowNew atomic.Bool
	f.transport.base = discoveryRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		status, body := 200, discoveryTestInventory
		if r.Header.Get("CF-Access-Client-Secret") == "new-secret" && !allowNew.Load() {
			status, body = 403, "denied"
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	reconcileFleet(t, f)
	done := make(chan struct{})
	go func() { f.collector.Refresh(t.Context(), false); close(done) }()
	<-started
	b.sources[0].Generation, b.sources[0].VerifiedGeneration, b.sources[0].CredentialVersion = 2, 2, 2
	b.sources[0].CredentialRef = "replacement"
	b.credentials["replacement"] = Credential{"new-client", "new-secret"}
	reconcileFleet(t, f)
	close(release)
	<-done
	reconcileFleet(t, f)
	f.collector.Refresh(t.Context(), false)
	reconcileFleet(t, f)
	if len(b.acknowledgements) != 0 || f.Status().Sources[0].State != "retained" {
		t.Fatal("old response or denied replacement acknowledged a credential")
	}
	allowNew.Store(true)
	f.collector.Refresh(t.Context(), false)
	reconcileFleet(t, f)
	if len(b.acknowledgements) != 1 || b.acknowledgements[0].CredentialVersion != 2 {
		t.Fatal("decoded replacement was not acknowledged")
	}
	delete(b.credentials, "replacement")
	reconcileFleet(t, f)
	f.collector.Refresh(t.Context(), false)
	if f.Status().Sources[0].CredentialAvailable || f.Status().Sources[0].State != "retained" {
		t.Fatal("missing credential did not fail closed")
	}
}

func TestFleetSourceAuthenticationAndLosslessAggregate(t *testing.T) {
	b := &simulatedDiscoveryBackend{credentials: map[string]Credential{}}
	var calls atomic.Int32
	var servers []*httptest.Server
	for i := 0; i < 3; i++ {
		id := fmt.Sprint(i)
		pair := Credential{ClientID: "client-sentinel-" + id, ClientSecret: "secret-sentinel-" + id}
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if r.URL.Path != "/discovery" {
				t.Error("unexpected request path")
			}
			if i == 2 {
				if r.Header.Get("CF-Access-Client-Id") != "" || r.Header.Get("CF-Access-Client-Secret") != "" {
					t.Error("unauthenticated source received credentials")
				}
			} else if r.Header.Get("CF-Access-Client-Id") != pair.ClientID || r.Header.Get("CF-Access-Client-Secret") != pair.ClientSecret {
				t.Error("wrong source credential")
				w.WriteHeader(403)
				return
			}
			io.WriteString(w, discoveryTestInventory)
		}))
		t.Cleanup(server.Close)
		source := testSource(id, server.URL)
		if i == 2 {
			source.AuthMode = AuthNone
			source.CredentialRef = ""
		} else {
			b.credentials[source.CredentialRef] = pair
		}
		b.sources = append(b.sources, source)
		servers = append(servers, server)
	}
	f, logs := testFleet(t, b, servers...)
	reconcileFleet(t, f)
	f.collector.Refresh(t.Context(), false)
	reconcileFleet(t, f)
	for range 2 {
		body := fleetBody(f)
		assertDiscoverySchema(t, body)
		var entries []struct {
			Address string            `json:"address"`
			Runners []json.RawMessage `json:"runners"`
		}
		if err := json.Unmarshal([]byte(body), &entries); err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || len(entries[0].Runners) != 1 || string(entries[0].Runners[0]) != discoveryTestRecord {
			t.Fatalf("record changed: %s", body)
		}
		if strings.Contains(body, "nodes") || strings.Contains(body, "127.0.0.1") {
			t.Fatal("aggregate advertised source topology")
		}
	}
	if calls.Load() != 3 {
		t.Fatal("HTTP reads or metadata caused extra polling", calls.Load())
	}
	if len(b.acknowledgements) != 2 {
		t.Fatal("protected source acknowledgements missing")
	}
	status := f.Status()
	if len(status.Sources) != 3 || status.Sources[0].State != "healthy" || status.Sources[0].NewestObservation == nil {
		t.Fatalf("missing source status: %+v", status)
	}
	statusJSON, _ := json.Marshal(status)
	for _, output := range []string{logs.String(), string(statusJSON), fleetBody(f)} {
		for _, sentinel := range []string{"client-sentinel", "secret-sentinel", "ref-", "127.0.0.1", "never-follow"} {
			if strings.Contains(output, sentinel) {
				t.Fatal("sensitive source data in output", sentinel)
			}
		}
	}
}

// The contract fixture is Node's docs/discovery.schema.json at the exact module
// revision pinned in go.mod. Keep it in sync when upgrading the Collector.
func assertDiscoverySchema(t *testing.T, body string) {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	schema, err := compiler.Compile("testdata/discovery.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatal(err)
	}
}

func TestFleetFailuresEvictionEmptyAndRecovery(t *testing.T) {
	var mu sync.Mutex
	status, body := 200, discoveryTestInventory
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer server.Close()
	source := testSource("one", server.URL)
	b := &simulatedDiscoveryBackend{sources: []Source{source}, credentials: map[string]Credential{source.CredentialRef: {"client", "secret"}}}
	f, _ := testFleet(t, b, server)
	reconcileFleet(t, f)
	f.collector.Refresh(t.Context(), false)
	original := f.collector.Snapshots()[0]
	for i, test := range []struct {
		status int
		body   string
	}{{401, "Access denied"}, {403, "Access denied"}, {302, "login"}, {200, "<html>login</html>"}, {200, strings.Repeat(" ", shared.MaxBody+1)}, {200, "null"}} {
		mu.Lock()
		status, body = test.status, test.body
		mu.Unlock()
		f.collector.Refresh(t.Context(), false)
		if i < 5 {
			snapshots := f.collector.Snapshots()
			if len(snapshots) != 1 || snapshots[0].QueriedAt != original.QueriedAt || fleetBody(f) == "[]\n" {
				t.Fatal("failure discarded retained observation")
			}
		} else if len(f.collector.Snapshots()) != 0 {
			t.Fatal("sixth failure did not evict")
		}
	}
	diagnostic := f.Status().Sources[0]
	if diagnostic.State != "evicted" || diagnostic.LastSuccess == nil || diagnostic.Failures != 6 {
		t.Fatalf("eviction diagnostics lost: %+v", diagnostic)
	}
	mu.Lock()
	status, body = 200, discoveryTestInventory
	mu.Unlock()
	f.collector.Refresh(t.Context(), false)
	if fleetBody(f) == "[]\n" {
		t.Fatal("source did not recover")
	}
	mu.Lock()
	body = "[]"
	mu.Unlock()
	f.collector.Refresh(t.Context(), false)
	if fleetBody(f) != "[]\n" || f.Status().Sources[0].State != "healthy" {
		t.Fatal("authoritative empty was not a healthy replacement")
	}
}

func TestFleetSelectionLifecycleAndStoreFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, discoveryTestInventory) }))
	defer server.Close()
	source := testSource("one", server.URL)
	source.Generation, source.VerifiedGeneration = 5, 5
	b := &simulatedDiscoveryBackend{sources: []Source{source}, credentials: map[string]Credential{source.CredentialRef: {"client", "secret"}}}
	f, _ := testFleet(t, b, server)
	reconcileFleet(t, f)
	f.collector.Refresh(t.Context(), false)
	b.mu.Lock()
	b.sources[0].Ready = false

	b.mu.Unlock()
	reconcileFleet(t, f)
	if fleetBody(f) == "[]\n" {
		t.Fatal("offline source was removed instead of retained")
	}
	b.mu.Lock()
	b.err = true
	b.mu.Unlock()
	if f.Reconcile(t.Context()) == nil || !f.Status().ReconciliationFailed || fleetBody(f) == "[]\n" {
		t.Fatal("failed source read became an empty selection")
	}
	b.mu.Lock()
	b.err = false
	b.sources[0].Lifecycle = "draining"
	b.mu.Unlock()
	reconcileFleet(t, f)
	if !f.Status().Sources[0].Selected {
		t.Fatal("draining source lost withdrawal polling")
	}
	b.mu.Lock()
	b.sources[0].NodeID = "new-node"
	b.sources[0].URL = "https://replacement.example/discovery"
	f.transport.base = discoveryRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(discoveryTestInventory))}, nil
	})
	b.sources[0].Generation, b.sources[0].VerifiedGeneration = 1, 1
	b.sources[0].Lifecycle = "active"
	b.sources[0].Ready = true
	b.mu.Unlock()
	reconcileFleet(t, f)
	if len(f.collector.Snapshots()) != 0 || f.Status().Sources[0].Acknowledged {
		t.Fatal("node-only replacement reused predecessor cache or acknowledgement")
	}
	f.collector.Refresh(t.Context(), false)
	reconcileFleet(t, f)
	if len(b.acknowledgements) != 2 || b.acknowledgements[1].NodeID != "new-node" {
		t.Fatal("node-only replacement did not receive its own acknowledgement")
	}
	b.mu.Lock()
	b.sources[0].NodeID = "unverified-node"
	b.sources[0].URL = "https://unverified.example/discovery"
	b.sources[0].Generation, b.sources[0].VerifiedGeneration = 2, 1
	b.sources[0].Ready = false
	b.mu.Unlock()
	reconcileFleet(t, f)
	if f.Status().Sources[0].Selected || len(f.collector.Snapshots()) != 0 || fleetBody(f) != "[]\n" {
		t.Fatal("unverified replacement retained predecessor incarnation")
	}
	b.mu.Lock()
	b.sources[0].Lifecycle = "removed"
	b.mu.Unlock()
	reconcileFleet(t, f)
	if fleetBody(f) != "[]\n" || len(f.collector.Snapshots()) != 0 {
		t.Fatal("removed source remains advertised")
	}
	b.mu.Lock()
	b.sources = nil
	b.mu.Unlock()
	reconcileFleet(t, f)
	if !f.collector.Initialized() {
		t.Fatal("authoritative empty selection is uninitialized")
	}
}

func TestFleetPublicURLBoundary(t *testing.T) {
	source := testSource("one", "https://source.example")
	for _, test := range []struct {
		url   string
		valid bool
	}{{"https://orch.example/apps/a/session", true}, {"https://a.apps.example", true}, {"http://10.0.0.1/app", false}, {"https://other.example/app", false}, {"https://user:token@orch.example/app", false}, {"https://orch.example/app?token=secret", false}, {"https://a.b.apps.example", false}, {"https://api.apps.example", false}, {"https://api-aaaaaaa.apps.example", false}, {"https://discovery.apps.example", false}, {"https://discovery-aaaaaaa.apps.example", false}, {"https://orch.example", false}} {
		entry := shared.Entry[runner]{Address: source.ServiceURL, Runners: []runner{{URL: test.url}}}
		if publicEntry(source, entry) != test.valid {
			t.Error("wrong publication decision", test.url)
		}
	}
}

func TestFleetWorkerStartsEmptyAndClosesPendingWork(t *testing.T) {
	var block atomic.Bool
	started := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if block.Load() {
			started <- struct{}{}
			<-r.Context().Done()
			return
		}
		io.WriteString(w, discoveryTestInventory)
	}))
	defer server.Close()
	synctest.Test(t, func(t *testing.T) {
		b := &simulatedDiscoveryBackend{credentials: map[string]Credential{}}
		f, _ := testFleet(t, b, server)
		f.transport.base.(*http.Transport).DisableKeepAlives = true
		reconcileFleet(t, f)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() { f.collector.Run(ctx, time.Hour); close(done) }()
		source := testSource("one", server.URL)
		b.mu.Lock()
		b.sources = []Source{source}
		b.credentials[source.CredentialRef] = Credential{"client", "secret"}
		b.mu.Unlock()
		reconcileFleet(t, f)
		synctest.Wait()
		if len(f.collector.Snapshots()) == 0 {
			t.Fatal("new source did not wake initially empty worker")
		}
		f.collector.Refresh(ctx, false) // Join the initial refresh before starting another.
		block.Store(true)
		refreshDone := make(chan struct{})
		go func() { f.collector.Refresh(ctx, false); close(refreshDone) }()
		<-started
		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("worker did not cancel and join pending collection")
		}
		<-refreshDone
		f.collector.Refresh(t.Context(), false) // Closed collectors cannot restart.
	})
}

func TestFleetReplacementFencesInFlightResult(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, discoveryTestInventory)
	}))
	defer server.Close()
	source := testSource("one", server.URL)
	b := &simulatedDiscoveryBackend{sources: []Source{source}, credentials: map[string]Credential{source.CredentialRef: {"client", "secret"}}}
	f, _ := testFleet(t, b, server)
	reconcileFleet(t, f)
	done := make(chan struct{})
	go func() { f.collector.Refresh(t.Context(), false); close(done) }()
	<-started
	b.mu.Lock()
	b.sources[0].NodeID = "replacement-node"
	b.sources[0].URL = "https://replacement.example/discovery"
	b.mu.Unlock()
	reconcileFleet(t, f)
	close(release)
	<-done
	if len(f.collector.Snapshots()) != 0 || len(b.acknowledgements) != 0 {
		t.Fatal("replacement accepted predecessor in-flight result")
	}
}

func TestFleetBlockedAndUnverifiedSources(t *testing.T) {
	source := testSource("one", "https://source.example")
	source.Ready = false
	source.VerifiedGeneration = 0
	b := &simulatedDiscoveryBackend{sources: []Source{source}, credentials: map[string]Credential{source.CredentialRef: {"client", "secret"}}}
	f, _ := testFleet(t, b)
	reconcileFleet(t, f)
	if f.Status().Sources[0].Selected {
		t.Fatal("unverified provisioning source was admitted")
	}
	b.sources[0].VerifiedGeneration = 1
	reconcileFleet(t, f)
	if !f.Status().Sources[0].Selected {
		t.Fatal("durably approved offline source cannot recover after restart")
	}
	b.sources[0].Blocked = true
	reconcileFleet(t, f)
	if f.Status().Sources[0].Selected || f.Status().Sources[0].SelectionReason != "blocked" {
		t.Fatal("explicit ingress withdrawal was treated as offline retention")
	}
	b.sources[0].Blocked = false
	b.sources[0].Generation = 2
	b.sources[0].VerifiedGeneration = 2
	reconcileFleet(t, f)
	b.sources[0].Generation = 1
	if f.Reconcile(t.Context()) == nil {
		t.Fatal("older generation replaced newer selection")
	}
}
