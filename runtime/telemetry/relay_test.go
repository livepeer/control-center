package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/management"
)

const node = "abcdefghijklmnopqrstuvwxyz"

type grants struct {
	mu    sync.Mutex
	calls int
	next  func(int) (management.TelemetryGrant, error)
}

func (g *grants) Request(_ context.Context, endpoint string, payload any, _ int64) ([]byte, http.Header, error) {
	g.mu.Lock()
	g.calls++
	call := g.calls
	g.mu.Unlock()
	if endpoint != "telemetry/token" || payload != nil {
		return nil, nil, errors.New("unexpected management operation")
	}
	grant, err := g.next(call)
	if err != nil {
		return nil, nil, err
	}
	b, _ := json.Marshal(grant)
	return b, nil, nil
}

func (g *grants) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

type upstream struct {
	mu       sync.Mutex
	status   int
	header   http.Header
	requests []*http.Request
	bodies   [][]byte
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.requests, u.bodies = append(u.requests, r), append(u.bodies, body)
	for name, values := range u.header {
		w.Header()[name] = values
	}
	w.WriteHeader(u.status)
	io.WriteString(w, "Control Center detail")
}

func grantFor(base string, token string, expires time.Time) management.TelemetryGrant {
	return grantForNode(base, node, token, expires)
}

func grantForNode(base, id, token string, expires time.Time) management.TelemetryGrant {
	prefix := base + "/v1/nodes/" + id
	return management.TelemetryGrant{Token: token, ExpiresAt: expires, NodeID: id, MetricsURL: prefix + "/telemetry/metrics", LogsURL: prefix + "/telemetry/logs"}
}

func setup(t *testing.T) (*Relay, *grants, *upstream, *time.Time, string) {
	t.Helper()
	up := &upstream{status: http.StatusNoContent}
	server := httptest.NewServer(up)
	t.Cleanup(server.Close)
	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	g := &grants{next: func(call int) (management.TelemetryGrant, error) {
		return grantFor(server.URL, "token-"+string(rune('a'+call-1)), now.Add(time.Hour)), nil
	}}
	r := NewRelay(g, node, true, 1<<20)
	r.Now = func() time.Time { return now }
	return r, g, up, &now, server.URL
}

func write(t *testing.T, r *Relay, path string, body []byte, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	for name, value := range header {
		req.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestRelayForwardsWithGrantOnly(t *testing.T) {
	r, g, up, now, _ := setup(t)
	w := write(t, r, "/metrics/write", []byte("block"), map[string]string{"Content-Type": "application/x-protobuf", "Content-Encoding": "zstd",
		"X-Prometheus-Remote-Write-Version": "0.1.0", "Authorization": "Bearer agent-chosen", "Cookie": "c=1", "X-Forwarded-Host": "attacker.example"})
	if w.Code != http.StatusNoContent || strings.Contains(w.Body.String(), "detail") {
		t.Fatal(w.Code, w.Body.String())
	}
	got := up.requests[0]
	if got.URL.Path != "/v1/nodes/"+node+"/telemetry/metrics" || got.Header.Get("Authorization") != "Bearer token-a" || string(up.bodies[0]) != "block" ||
		got.Header.Get("Content-Encoding") != "zstd" || got.Header.Get("X-Prometheus-Remote-Write-Version") != "0.1.0" ||
		got.Header.Get("Cookie") != "" || got.Header.Get("X-Forwarded-Host") != "" {
		t.Fatal("forwarded request", got.URL, got.Header)
	}
	if w := write(t, r, "/logs/insert", []byte(`{"message":"x"}`), map[string]string{"Content-Type": "application/json"}); w.Code != 204 || up.requests[1].URL.Path != "/v1/nodes/"+node+"/telemetry/logs" {
		t.Fatal("logs", w.Code)
	}
	if g.count() != 1 {
		t.Fatal("grant fetched per request", g.count())
	}
	// Renewal starts at half the grant lifetime.
	*now = now.Add(31 * time.Minute)
	write(t, r, "/metrics/write", []byte("block"), nil)
	if g.count() != 2 || up.requests[2].Header.Get("Authorization") != "Bearer token-b" {
		t.Fatal("grant not renewed at half-life", g.count())
	}
	for path, want := range map[string]int{"/other": 404, "/metrics/write?x=1": 204} {
		if w := write(t, r, path, []byte("x"), nil); w.Code != want {
			t.Fatal(path, w.Code)
		}
	}
	if up.requests[len(up.requests)-1].URL.RawQuery != "" {
		t.Fatal("agent query forwarded")
	}
}

func TestRelayResponses(t *testing.T) {
	for name, tc := range map[string]struct {
		status    int
		header    http.Header
		want      int
		retry     string
		refetched bool
	}{
		"revoked":     {401, nil, 503, "1", true},
		"redirect":    {307, http.Header{"Location": {"https://attacker.example/"}}, 502, "", false},
		"throttled":   {429, http.Header{"Retry-After": {"7"}}, 429, "7", false},
		"unavailable": {503, http.Header{"Retry-After": {"30"}}, 503, "30", false},
		"rejected":    {400, nil, 400, "", false},
		"disabled":    {403, nil, 403, "", false},
		// vmagent retries 413 forever; 409 makes it drop the block.
		"too large": {413, nil, 409, "", false},
	} {
		t.Run(name, func(t *testing.T) {
			r, g, up, _, _ := setup(t)
			up.status, up.header = tc.status, tc.header
			w := write(t, r, "/metrics/write", []byte("block"), nil)
			if w.Code != tc.want || w.Header().Get("Retry-After") != tc.retry || len(up.requests) != 1 {
				t.Fatal(w.Code, w.Header(), len(up.requests))
			}
			up.status = 204
			write(t, r, "/metrics/write", []byte("block"), nil)
			if (g.count() == 2) != tc.refetched {
				t.Fatal("grant refetch", g.count())
			}
		})
	}
	r, _, up, _, _ := setup(t)
	for _, tc := range []struct {
		path   string
		body   []byte
		length int64
		want   int
	}{
		{"/metrics/write", []byte("x"), -1, 411},
		{"/metrics/write", nil, 0, 400},
		{"/metrics/write", make([]byte, 1<<20+1), 1<<20 + 1, 409},
		// Fluent Bit already drops a chunk on 413.
		{"/logs/insert", make([]byte, 1<<20+1), 1<<20 + 1, 413},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(tc.body))
		req.ContentLength = tc.length
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Fatal(tc.path, tc.length, w.Code)
		}
	}
	if len(up.requests) != 0 {
		t.Fatal("invalid writes forwarded")
	}
	up.status = 413
	if w := write(t, r, "/logs/insert", []byte("x"), nil); w.Code != 413 {
		t.Fatal("logs 413 changed", w.Code)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), "livepeer_telemetry_relay_oversize_dropped_total 1\n") {
		t.Fatal("oversize drops not counted", w.Body.String())
	}
}

// After re-enrollment the management agent grants for the new node. The old
// bundle's relay must not send its buffered data under that identity.
func TestRelayPinnedToEnrollment(t *testing.T) {
	r, g, up, now, base := setup(t)
	g.next = func(int) (management.TelemetryGrant, error) {
		return grantForNode(base, "zyxwvutsrqponmlkjihgfedcba", "new-node", now.Add(time.Hour)), nil
	}
	for _, path := range []string{"/metrics/write", "/logs/insert"} {
		if w := write(t, r, path, []byte("x"), nil); w.Code != 503 {
			t.Fatal(path, w.Code)
		}
		*now = now.Add(6 * time.Second)
	}
	if len(up.requests) != 0 {
		t.Fatal("wrote with another node's grant")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), "livepeer_telemetry_relay_grant_node_mismatch_total 2\n") {
		t.Fatal("mismatch not counted", w.Body.String())
	}
}

func TestRelayGrantFailuresAndValidation(t *testing.T) {
	r, g, up, now, base := setup(t)
	fail := errors.New("control_unavailable")
	var answer management.TelemetryGrant
	var answerErr error
	g.next = func(int) (management.TelemetryGrant, error) { return answer, answerErr }
	answerErr = fail
	if w := write(t, r, "/metrics/write", []byte("x"), nil); w.Code != 503 || w.Header().Get("Retry-After") != "5" {
		t.Fatal("unavailable grant", w.Code)
	}
	write(t, r, "/metrics/write", []byte("x"), nil)
	if g.count() != 1 {
		t.Fatal("grant requests not throttled after failure", g.count())
	}
	if w := httptest.NewRecorder(); func() bool { r.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil)); return w.Code != 503 }() {
		t.Fatal("ready without a grant")
	}
	// A failed renewal keeps a grant that is still valid.
	answer, answerErr = grantFor(base, "good", now.Add(time.Hour)), nil
	*now = now.Add(6 * time.Second)
	if w := write(t, r, "/metrics/write", []byte("x"), nil); w.Code != 204 {
		t.Fatal(w.Code)
	}
	answerErr = fail
	*now = now.Add(40 * time.Minute)
	if w := write(t, r, "/metrics/write", []byte("x"), nil); w.Code != 204 || up.requests[len(up.requests)-1].Header.Get("Authorization") != "Bearer good" {
		t.Fatal("valid grant discarded after a failed renewal", w.Code)
	}
	if w := httptest.NewRecorder(); func() bool { r.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil)); return w.Code != 204 }() {
		t.Fatal("not ready with a valid grant")
	}
	valid := grantFor(base, "token", now.Add(time.Hour))
	for name, change := range map[string]func(*management.TelemetryGrant){
		"expired":  func(g *management.TelemetryGrant) { g.ExpiresAt = *now },
		"no token": func(g *management.TelemetryGrant) { g.Token = "" },
		"split origin": func(g *management.TelemetryGrant) {
			g.LogsURL = "http://other.example/v1/nodes/" + node + "/telemetry/logs"
		},
		"other path": func(g *management.TelemetryGrant) { g.MetricsURL = base + "/v1/nodes/" + node + "/status" },
		"other node": func(g *management.TelemetryGrant) { g.NodeID = "zyxwvutsrqponmlkjihgfedcba" },
		"query":      func(g *management.TelemetryGrant) { g.MetricsURL += "?extra_label=x" },
		"credentials": func(g *management.TelemetryGrant) {
			g.MetricsURL = strings.Replace(g.MetricsURL, "http://", "http://u:p@", 1)
		},
	} {
		g := valid
		change(&g)
		if r.validGrant(g, *now) {
			t.Fatal("accepted invalid grant", name)
		}
	}
	if !r.validGrant(valid, *now) {
		t.Fatal("refused valid development grant")
	}
	strict := NewRelay(nil, node, false, 1<<20)
	if strict.validGrant(valid, *now) {
		t.Fatal("HTTP destination accepted without development transport")
	}
}

func TestRelayMetricsAndLoopbackOnly(t *testing.T) {
	r, _, up, _, _ := setup(t)
	write(t, r, "/metrics/write", []byte("x"), nil)
	up.status = 500
	write(t, r, "/logs/insert", []byte("x"), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, line := range []string{`livepeer_telemetry_relay_requests_total{kind="metrics",result="2xx"} 1`, `livepeer_telemetry_relay_requests_total{kind="logs",result="5xx"} 1`, "livepeer_telemetry_relay_grant_expiry_timestamp_seconds 1794913200"} {
		if !strings.Contains(w.Body.String(), line) {
			t.Fatalf("missing %q in\n%s", line, w.Body.String())
		}
	}
	if strings.Contains(w.Body.String(), "token-") {
		t.Fatal("token exposed in metrics")
	}
	for _, address := range []string{":20244", "0.0.0.0:20244", "10.42.0.5:20244", "localhost:20244"} {
		if err := r.Serve(t.Context(), address); err == nil {
			t.Fatal("relay listened beyond loopback", address)
		}
	}
}
