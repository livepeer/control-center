package discovery

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/livepeer/node/destination"
)

type discoveryRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn discoveryRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func TestDiscoveryTransportScopeAndRequestClone(t *testing.T) {
	source := testSource("one", "https://source.example")
	credential := "intended-bearer"
	var calls int
	transport := &transport{signToken: func(Source) (string, error) { return credential, nil }, base: discoveryRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Authorization") != "Bearer "+credential || r.Header.Get("Cookie") != "" {
			t.Error("wrong delegated headers")
		}
		for key := range r.Header {
			if key == "authorization" {
				t.Error("noncanonical secret header survived")
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("[]"))}, nil
	})}
	selection := map[string]*authorization{source.URL: {source: source, available: true}}
	transport.install(selection)
	req, _ := http.NewRequest("GET", source.URL, nil)
	req.Header["authorization"] = []string{"injected"}
	req.Header.Set("Authorization", "Bearer injected")
	req.Header.Set("Cookie", "injected=1")
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	//lint:ignore SA1008 Verify the deliberately noncanonical injected header is unchanged.
	if req.Header["authorization"][0] != "injected" || req.Header.Get("Authorization") == "" {
		t.Fatal("transport mutated caller request")
	}
	for _, endpoint := range []string{"http://source.example/discovery", "https://source.example:444/discovery", "https://source.example.attacker.example/discovery", "https://source.example/discovery/", "https://source.example/%64iscovery", "https://source.example/discovery?token=secret", "https://user:secret@source.example/discovery", "https://source.example./discovery", "https://source.example/other"} {
		r, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		if response, err := transport.RoundTrip(r); err == nil {
			response.Body.Close()
			t.Error("accepted out-of-scope request", endpoint)
		}
	}
	req.Host = "another.example"
	if _, err := transport.RoundTrip(req); err == nil {
		t.Error("accepted Host override")
	}
	if calls != 1 {
		t.Error("out-of-scope requests reached delegate", calls)
	}
	for _, invalid := range []string{"", "bad\r\nheader", "with space", strings.Repeat("s", 8193)} {
		transport.signToken = func(Source) (string, error) { return invalid, nil }
		req.Host = ""
		if _, err := transport.RoundTrip(req); err == nil {
			t.Fatal("invalid bearer header accepted")
		}
	}
	if calls != 1 {
		t.Fatal("invalid bearer reached upstream")
	}

}

func TestDiscoveryTransportRejectsRedirectsAndUntrustedTLS(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1); io.WriteString(w, "[]") }))
	defer target.Close()
	var redirect atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirect.Load() {
			w.Header().Set("Location", target.URL+"/discovery")
			w.WriteHeader(302)
			return
		}
		io.WriteString(w, discoveryTestInventory)
	}))
	defer server.Close()
	source := testSource("one", server.URL)
	b := &simulatedDiscoveryBackend{sources: []Source{source}}
	f, logs := testFleet(t, b, server, target)
	reconcileFleet(t, f)
	f.collector.Refresh(t.Context(), false)
	redirect.Store(true)
	f.collector.Refresh(t.Context(), false)
	if targetCalls.Load() != 0 || f.Status().Sources[0].State != "retained" || f.Status().Sources[0].TransportOutcome != "redirect" {
		t.Fatal("redirect was followed or treated as healthy empty")
	}
	if strings.Contains(logs.String(), target.URL) {
		t.Fatal("redirect URL was logged")
	}
	// Recreate a production policy transport: its system trust must reject the
	// simulated source certificate rather than silently weakening TLS.
	policy, _ := destination.New("test discovery", []string{"127.0.0.1"})
	f.transport.CloseIdleConnections()
	f.transport.base = policy.Transport(time.Second)
	f.collector.Refresh(t.Context(), false)
	if f.Status().Sources[0].State != "retained" {
		t.Fatal("untrusted TLS succeeded")
	}
	policy, _ = destination.New("test discovery", nil)
	f.transport.CloseIdleConnections()
	f.transport.base = policy.Transport(time.Second)
	f.collector.Refresh(t.Context(), false)
	if f.Status().Sources[0].TransportOutcome != "denied_destination" {
		t.Fatal("private destination escaped Node policy")
	}
}

func TestDiscoveryTransportTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	source := testSource("one", server.URL)
	b := &simulatedDiscoveryBackend{sources: []Source{source}}
	f, _ := testFleet(t, b, server)
	f.collector.Client.Timeout = 20 * time.Millisecond
	reconcileFleet(t, f)
	f.collector.Refresh(t.Context(), false)
	if f.Status().Sources[0].State != "uninitialized" || f.Status().Sources[0].Failures != 1 {
		t.Fatal("timeout became healthy inventory")
	}
}
