package controlplane

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/ingressauth"
	"github.com/livepeer/control-center/runtime/management"
	"github.com/livepeer/control-center/runtime/telemetry"
)

const telemetryNode = "abcdefghijklmnopqrstuvwxyz"
const otherTelemetryNode = "zyxwvutsrqponmlkjihgfedcba"

type telemetryCapture struct {
	mu       sync.Mutex
	status   int
	requests []capturedTelemetry
}

type capturedTelemetry struct {
	path   string
	query  url.Values
	header http.Header
	body   []byte
}

func (c *telemetryCapture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, capturedTelemetry{r.URL.Path, r.URL.Query(), r.Header.Clone(), body})
	w.WriteHeader(c.status)
	io.WriteString(w, "upstream detail")
}

func (c *telemetryCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *telemetryCapture) last() capturedTelemetry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests[len(c.requests)-1]
}

func enabledTelemetry(metrics, logs string) TelemetryParams {
	return TelemetryParams{TelemetryEnabled: true, TelemetryMetricsURL: metrics, TelemetryLogsURL: logs, TelemetryTokenTTL: time.Hour,
		TelemetryMaxBodyBytes: 1 << 20, TelemetryNodeRateBytes: 64 << 10, TelemetryAppLogsEnabled: true}
}

func telemetryServer(t *testing.T) (*Server, *telemetryCapture) {
	t.Helper()
	capture := &telemetryCapture{status: http.StatusNoContent}
	upstream := httptest.NewServer(capture)
	t.Cleanup(upstream.Close)
	p := testParams()
	p.TelemetryParams = enabledTelemetry(upstream.URL, upstream.URL+"/")
	s := New(nil, p, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.telemetry.replace(map[string]telemetryMachine{telemetryNode: {orchestrator: orchA, credentialVersion: 2}})
	return s, capture
}

func telemetryToken(t *testing.T, s *Server, node, orchestrator string, version int64) string {
	t.Helper()
	raw, _, err := s.params.jwtKey.Telemetry(s.params.signingKeyID(), node, orchestrator, version, time.Hour, s.currentTime())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type telemetryPush struct {
	kind, node, token, query string
	contentType, encoding    string
	body                     []byte
	mutate                   func(*http.Request)
}

func (p telemetryPush) send(t *testing.T, s *Server) *httptest.ResponseRecorder {
	t.Helper()
	path := "/v1/nodes/" + p.node + "/telemetry/" + p.kind
	if p.query != "" {
		path += "?" + p.query
	}
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(p.body))
	if p.token != "" {
		r.Header.Set("Authorization", "Bearer "+p.token)
	}
	if p.contentType != "" {
		r.Header.Set("Content-Type", p.contentType)
	}
	if p.encoding != "" {
		r.Header.Set("Content-Encoding", p.encoding)
	}
	if p.mutate != nil {
		p.mutate(r)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func metricsPush(s *Server, t *testing.T) telemetryPush {
	return telemetryPush{kind: telemetryMetrics, node: telemetryNode, token: telemetryToken(t, s, telemetryNode, orchA, 2),
		contentType: "application/x-protobuf", encoding: "snappy", body: []byte("remote-write")}
}

func logsPush(s *Server, t *testing.T) telemetryPush {
	return telemetryPush{kind: telemetryLogs, node: telemetryNode, token: telemetryToken(t, s, telemetryNode, orchA, 2),
		contentType: "application/json", encoding: "gzip", body: []byte("log-lines")}
}

func TestTelemetryIngestStampsAuthenticatedIdentity(t *testing.T) {
	s, capture := telemetryServer(t)
	push := metricsPush(s, t)
	push.query = "extra_label=node_id%3D" + otherTelemetryNode + "&extra_label=orchestrator%3D" + orchB
	push.mutate = func(r *http.Request) {
		r.Header.Set("Cookie", "session=secret")
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		r.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	}
	if w := push.send(t, s); w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body.String())
	}
	got := capture.last()
	wantQuery := url.Values{"extra_label": {"node_id=" + telemetryNode, "orchestrator=" + orchA}}
	if got.path != "/api/v1/write" || got.query.Encode() != wantQuery.Encode() || !bytes.Equal(got.body, push.body) {
		t.Fatal("metrics upstream", got.path, got.query, string(got.body))
	}
	for name, want := range map[string]string{"Content-Type": "application/x-protobuf", "Content-Encoding": "snappy", "X-Prometheus-Remote-Write-Version": "0.1.0",
		"Authorization": "", "Cookie": "", "X-Forwarded-For": ""} {
		if got.header.Get(name) != want {
			t.Fatalf("upstream header %s = %q, want %q", name, got.header.Get(name), want)
		}
	}

	logs := logsPush(s, t)
	logs.contentType = "application/x-ndjson"
	logs.query = "extra_fields=node_id%3D" + otherTelemetryNode + "&_stream_fields=message"
	if w := logs.send(t, s); w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body.String())
	}
	got = capture.last()
	wantQuery = url.Values{"_stream_fields": {telemetryLogStreamFields}, "_msg_field": {"message"}, "_time_field": {"time"},
		"extra_fields": {"node_id=" + telemetryNode + ",orchestrator=" + orchA}}
	if got.path != "/insert/jsonline" || got.query.Encode() != wantQuery.Encode() {
		t.Fatal("logs upstream", got.path, got.query)
	}
	// A form-encoded body could otherwise override the identity parameters.
	if got.header.Get("Content-Type") != "application/json" || got.header.Get("Content-Encoding") != "gzip" {
		t.Fatal("logs upstream headers", got.header)
	}
}

func TestTelemetryIngestRejections(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		upstream int
		change   func(*Server, *telemetryPush)
	}{
		{"disabled", 403, 0, func(s *Server, p *telemetryPush) { s.params.TelemetryEnabled = false }},
		{"missing token", 401, 0, func(s *Server, p *telemetryPush) { p.token = "" }},
		{"discovery token", 401, 0, func(s *Server, p *telemetryPush) {
			p.token, _ = s.params.jwtKey.Discovery(s.params.signingKeyID(), telemetryNode, s.currentTime())
		}},
		{"other machine path", 403, 0, func(s *Server, p *telemetryPush) {
			p.token = telemetryToken(t, s, otherTelemetryNode, orchA, 2)
		}},
		{"enrollments loading", 503, 0, func(s *Server, p *telemetryPush) { s.telemetry = newTelemetryState() }},
		{"retired machine", 401, 0, func(s *Server, p *telemetryPush) { s.telemetry.replace(map[string]telemetryMachine{}) }},
		{"refreshed credential", 401, 0, func(s *Server, p *telemetryPush) { p.token = telemetryToken(t, s, telemetryNode, orchA, 1) }},
		{"other orchestrator", 401, 0, func(s *Server, p *telemetryPush) { p.token = telemetryToken(t, s, telemetryNode, orchB, 2) }},
		{"expired token", 401, 0, func(s *Server, p *telemetryPush) {
			future := time.Now().Add(2 * time.Hour)
			s.now = func() time.Time { return future }
		}},
		{"unknown length", 411, 0, func(s *Server, p *telemetryPush) {
			p.mutate = func(r *http.Request) { r.ContentLength = -1 }
		}},
		{"empty body", 400, 0, func(s *Server, p *telemetryPush) { p.body = nil }},
		{"too large", 413, 0, func(s *Server, p *telemetryPush) { p.body = make([]byte, 1<<20+1) }},
		{"form body", 415, 0, func(s *Server, p *telemetryPush) { p.contentType = "application/x-www-form-urlencoded" }},
		{"uncompressed remote write", 415, 0, func(s *Server, p *telemetryPush) { p.encoding = "" }},
		{"duplicate encodings", 415, 0, func(s *Server, p *telemetryPush) {
			p.mutate = func(r *http.Request) { r.Header.Add("Content-Encoding", "zstd") }
		}},
		{"logs as metrics", 415, 0, func(s *Server, p *telemetryPush) { p.contentType = "application/json" }},
		{"upstream rejects", 400, 400, nil},
		{"upstream fails", 503, 500, nil},
		{"upstream throttles", 429, 429, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, capture := telemetryServer(t)
			p := metricsPush(s, t)
			if tc.upstream != 0 {
				capture.status = tc.upstream
			}
			if tc.change != nil {
				tc.change(s, &p)
			}
			w := p.send(t, s)
			if w.Code != tc.status {
				t.Fatal(w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "upstream detail") {
				t.Fatal("upstream response body leaked to the machine")
			}
			if tc.status == 401 && w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("missing bearer challenge")
			}
			if forwarded := capture.count(); (tc.upstream == 0) != (forwarded == 0) {
				t.Fatal("unexpected upstream forwarding", forwarded)
			}
		})
	}
	t.Run("logs encodings", func(t *testing.T) {
		s, _ := telemetryServer(t)
		for encoding, want := range map[string]int{"": 204, "gzip": 204, "zstd": 204, "br": 415, "snappy": 415} {
			p := logsPush(s, t)
			p.encoding = encoding
			if w := p.send(t, s); w.Code != want {
				t.Fatal(encoding, w.Code)
			}
		}
	})
	t.Run("storage unreachable", func(t *testing.T) {
		s, _ := telemetryServer(t)
		listener, _ := net.Listen("tcp", "127.0.0.1:0")
		closed := "http://" + listener.Addr().String()
		listener.Close()
		s.params.TelemetryMetricsURL = closed
		if w := metricsPush(s, t).send(t, s); w.Code != 503 || w.Header().Get("Retry-After") == "" {
			t.Fatal(w.Code, w.Header())
		}
	})
}

func TestTelemetryRateLimitPerMachineAndKind(t *testing.T) {
	s, _ := telemetryServer(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	full := metricsPush(s, t)
	full.body = make([]byte, 1<<20)
	for range 2 {
		if w := full.send(t, s); w.Code != 204 {
			t.Fatal("burst capacity refused", w.Code)
		}
	}
	w := full.send(t, s)
	if w.Code != 429 || w.Header().Get("Retry-After") != "16" {
		t.Fatal("rate limit", w.Code, w.Header().Get("Retry-After"))
	}
	if w := logsPush(s, t).send(t, s); w.Code != 204 {
		t.Fatal("log quota shared with metrics", w.Code)
	}
	now = now.Add(16 * time.Second)
	if w := full.send(t, s); w.Code != 204 {
		t.Fatal("bucket did not refill", w.Code)
	}
	// Retiring a machine discards its bucket.
	s.telemetry.replace(map[string]telemetryMachine{})
	if len(s.telemetry.buckets) != 0 {
		t.Fatal("retired machine retained rate state")
	}
}

func TestTelemetryMetricsText(t *testing.T) {
	s, _ := telemetryServer(t)
	metricsPush(s, t).send(t, s)
	bad := logsPush(s, t)
	bad.token = ""
	bad.send(t, s)
	text := request(t, s, http.MethodGet, "/metrics", "", nil).Body.String()
	for _, line := range []string{
		"control_enrollment_grants_issued_total 0\n",
		`control_telemetry_ingest_requests_total{kind="metrics"} 1` + "\n",
		`control_telemetry_ingest_bytes_total{kind="metrics"} 12` + "\n",
		`control_telemetry_ingest_rejected_total{kind="logs",reason="unauthorized"} 1` + "\n",
		`control_telemetry_ingest_rejected_total{kind="metrics",reason="unauthorized"} 0` + "\n",
	} {
		if !strings.Contains(text, line) {
			t.Fatalf("missing %q in\n%s", line, text)
		}
	}
	if strings.Contains(text, telemetryNode) {
		t.Fatal("machine identity exposed as a metric label")
	}
}

func TestTelemetryConfigValidation(t *testing.T) {
	valid := enabledTelemetry("http://victoriametrics:8428", "https://logs.example/")
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	if err := (TelemetryParams{}).validate(); err != nil {
		t.Fatal("disabled telemetry requires settings", err)
	}
	for name, change := range map[string]func(*TelemetryParams){
		"metrics path":  func(p *TelemetryParams) { p.TelemetryMetricsURL = "http://victoriametrics:8428/api/v1/write" },
		"logs query":    func(p *TelemetryParams) { p.TelemetryLogsURL = "http://victorialogs:9428?extra_fields=x" },
		"credentials":   func(p *TelemetryParams) { p.TelemetryLogsURL = "http://user:pass@victorialogs:9428" },
		"scheme":        func(p *TelemetryParams) { p.TelemetryMetricsURL = "unix:///run/vm.sock" },
		"short ttl":     func(p *TelemetryParams) { p.TelemetryTokenTTL = time.Second },
		"long ttl":      func(p *TelemetryParams) { p.TelemetryTokenTTL = 2 * time.Hour },
		"tiny body":     func(p *TelemetryParams) { p.TelemetryMaxBodyBytes = 1024 },
		"huge body":     func(p *TelemetryParams) { p.TelemetryMaxBodyBytes = 1 << 30 },
		"starved quota": func(p *TelemetryParams) { p.TelemetryNodeRateBytes = 1 },
	} {
		p := valid
		change(&p)
		if p.validate() == nil {
			t.Fatal("accepted invalid telemetry configuration", name)
		}
	}
}

func TestTelemetryTokenAndRevocation(t *testing.T) {
	s := newTestServer(t)
	capture := &telemetryCapture{status: http.StatusNoContent}
	upstream := httptest.NewServer(capture)
	t.Cleanup(upstream.Close)
	s.params.TelemetryParams = enabledTelemetry(upstream.URL, upstream.URL)
	machine := enroll(t, s, ownerA, strings.Repeat("a", 64))
	other := enroll(t, s, ownerB, strings.Repeat("b", 64))
	node := machine["node_id"]
	path := "/v1/nodes/" + node + "/telemetry/token"
	for _, token := range []string{"", other["token"], strings.Repeat("0", 64)} {
		if w := request(t, s, http.MethodPost, path, token, map[string]any{}); w.Code != 401 {
			t.Fatal("token issued without the machine credential", w.Code)
		}
	}
	w := request(t, s, http.MethodPost, path, machine["token"], map[string]any{})
	requireStatus(t, w, 200)
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
		NodeID    string    `json:"node_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.NodeID != node {
		t.Fatal(err, out)
	}
	claims, err := ingressauth.VerifyTelemetry(s.params.jwtKey.Keys, out.Token, time.Now())
	if err != nil || claims.Subject != node || claims.Orchestrator != orchA || claims.CredentialVersion != 1 || time.Until(out.ExpiresAt) > time.Hour {
		t.Fatal("telemetry claims", claims, err, out.ExpiresAt)
	}
	push := telemetryPush{kind: telemetryMetrics, node: node, token: out.Token, contentType: "application/x-protobuf", encoding: "zstd", body: []byte("x")}
	if w := push.send(t, s); w.Code != 503 {
		t.Fatal("ingest before enrollment state loaded", w.Code)
	}
	if err := s.refreshTelemetry(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w := push.send(t, s); w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
	// A credential refresh revokes tokens bound to the previous version.
	if _, err := s.db.Exec(`UPDATE lpcc.enrollments SET credential_version=2 WHERE node_id=$1`, node); err != nil {
		t.Fatal(err)
	}
	if err := s.refreshTelemetry(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w := push.send(t, s); w.Code != 401 {
		t.Fatal("refreshed credential kept telemetry access", w.Code)
	}
	if _, err := s.db.Exec(`UPDATE lpcc.enrollments SET credential_version=1 WHERE node_id=$1`, node); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireMachine(t.Context(), node); err != nil {
		t.Fatal(err)
	}
	if err := s.refreshTelemetry(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w := push.send(t, s); w.Code != 401 {
		t.Fatal("retired machine kept telemetry access", w.Code)
	}
	if w := request(t, s, http.MethodPost, path, machine["token"], map[string]any{}); w.Code != 401 {
		t.Fatal("retired machine received a telemetry token", w.Code)
	}
	s.params.TelemetryEnabled = false
	if w := request(t, s, http.MethodPost, "/v1/nodes/"+other["node_id"]+"/telemetry/token", other["token"], map[string]any{}); w.Code != 403 {
		t.Fatal("token issued while telemetry is disabled", w.Code)
	}
}

// Real-binary check that storage enforces the server-stamped identity even when
// a machine sends conflicting labels or fields.
func TestTelemetryStorageOverridesSpoofedIdentity(t *testing.T) {
	vmBinary, vlBinary := os.Getenv("VICTORIAMETRICS_BINARY"), os.Getenv("VICTORIALOGS_BINARY")
	if vmBinary == "" || vlBinary == "" {
		t.Skip("set VICTORIAMETRICS_BINARY and VICTORIALOGS_BINARY to the pinned v1.155.0 and v1.53.0 releases")
	}
	metricsURL, logsURL := startVictoria(t, vmBinary), startVictoria(t, vlBinary)
	s, _ := telemetryServer(t)
	s.params.TelemetryMetricsURL, s.params.TelemetryLogsURL = metricsURL, logsURL
	now := time.Now()

	push := metricsPush(s, t)
	push.body = snappyBlock(remoteWrite(map[string]string{"__name__": "telemetry_probe", "job": "probe", "node_id": otherTelemetryNode, "orchestrator": orchB}, 1, now))
	push.mutate = func(r *http.Request) { r.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0") }
	if w := push.send(t, s); w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
	var series struct {
		Metric map[string]string `json:"metric"`
	}
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		get(t, metricsURL+"/internal/force_flush")
		if body := get(t, metricsURL+"/api/v1/export?"+url.Values{"match[]": {"telemetry_probe"}}.Encode()); len(bytes.TrimSpace(body)) > 0 {
			if err := json.Unmarshal(body, &series); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if series.Metric == nil {
		t.Fatal("metric was not stored", victoriaCounter(t, metricsURL, "vm_rows_inserted_total"))
	}
	if series.Metric["node_id"] != telemetryNode || series.Metric["orchestrator"] != orchA || series.Metric["job"] != "probe" {
		t.Fatal("stored metric identity", series.Metric)
	}

	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	json.NewEncoder(zw).Encode(map[string]string{"time": now.UTC().Format(time.RFC3339Nano), "message": "probe", "node_id": otherTelemetryNode,
		"orchestrator": orchB, "source": "app", "namespace": "livepeer-apps", "pod": "probe", "container": "app"})
	zw.Close()
	logs := logsPush(s, t)
	logs.body = compressed.Bytes()
	if w := logs.send(t, s); w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
	var entry map[string]string
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if body := get(t, logsURL+"/select/logsql/query?query="+url.QueryEscape("_time:5m")); len(bytes.TrimSpace(body)) > 0 {
			if err := json.Unmarshal(body, &entry); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if entry["node_id"] != telemetryNode || entry["orchestrator"] != orchA || entry["_msg"] != "probe" || !strings.Contains(entry["_stream"], `node_id="`+telemetryNode+`"`) {
		t.Fatal("stored log identity", entry)
	}
}

func startVictoria(t *testing.T, binary string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	cmd := exec.Command(binary, "-storageDataPath="+t.TempDir(), "-httpListenAddr="+address, "-loggerLevel=ERROR")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	base := "http://" + address
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if resp, err := http.Get(base + "/health"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return base
			}
		}
	}
	t.Fatal("storage did not become healthy", binary)
	return ""
}

func victoriaCounter(t *testing.T, base, name string) string {
	t.Helper()
	var lines []string
	for _, line := range strings.Split(string(get(t, base+"/metrics")), "\n") {
		if strings.HasPrefix(line, name) {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "; ")
}

func get(t *testing.T, raw string) []byte {
	t.Helper()
	resp, err := http.Get(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatal(raw, resp.StatusCode, string(body))
	}
	return body
}

// remoteWrite encodes a one-sample Prometheus WriteRequest without importing
// the Prometheus protobuf packages.
func remoteWrite(labels map[string]string, value float64, at time.Time) []byte {
	field := func(dst []byte, number int, payload []byte) []byte {
		dst = binary.AppendUvarint(dst, uint64(number<<3|2))
		dst = binary.AppendUvarint(dst, uint64(len(payload)))
		return append(dst, payload...)
	}
	var series []byte
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		series = field(series, 1, field(field(nil, 1, []byte(name)), 2, []byte(labels[name])))
	}
	sample := binary.AppendUvarint(nil, 1<<3|1)
	sample = binary.LittleEndian.AppendUint64(sample, math.Float64bits(value))
	sample = binary.AppendUvarint(sample, 2<<3)
	sample = binary.AppendUvarint(sample, uint64(at.UnixMilli()))
	series = field(series, 2, sample)
	return field(nil, 1, series)
}

// snappyBlock emits a valid snappy block that uses only literal elements.
func snappyBlock(src []byte) []byte {
	out := binary.AppendUvarint(nil, uint64(len(src)))
	for len(src) > 0 {
		n := min(len(src), 1<<16)
		switch l := n - 1; {
		case l < 60:
			out = append(out, byte(l<<2))
		case l < 1<<8:
			out = append(out, 60<<2, byte(l))
		default:
			out = append(out, 61<<2, byte(l), byte(l>>8))
		}
		out, src = append(out, src[:n]...), src[n:]
	}
	return out
}

func TestTelemetryDeliveredOnlyAfterHostFeatureReport(t *testing.T) {
	s := newTestServer(t)
	s.params.TelemetryParams = enabledTelemetry("http://victoriametrics:8428", "http://victorialogs:9428")
	s.configs = s.newConfigurationManager()
	capable := enroll(t, s, ownerA, strings.Repeat("a", 64))
	legacy := enroll(t, s, ownerA, strings.Repeat("b", 64))
	bundle := func(node string) map[string]string {
		t.Helper()
		var data []byte
		if err := s.db.QueryRow(`SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, node).Scan(&data); err != nil {
			t.Fatal(err)
		}
		return archiveFiles(t, data)
	}
	delivered := func(node string) bool {
		files := bundle(node)
		return files["system/telemetry/agent.yaml"] != "" && strings.Contains(files["management/system.yaml"], "name: livepeer-telemetry\n")
	}
	if err := s.configs.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if delivered(capable["node_id"]) || delivered(legacy["node_id"]) {
		t.Fatal("telemetry delivered before the host reported its feature")
	}
	var metadata struct {
		Generation int64 `json:"generation"`
	}
	if err := json.Unmarshal([]byte(bundle(capable["node_id"])["runtime.json"]), &metadata); err != nil {
		t.Fatal(err)
	}
	recorded := time.Now().Add(-time.Minute).UTC()
	report := currentReport(t, s, capable["node_id"], machineconfig.Report{NodeID: capable["node_id"], CredentialVersion: 1, Component: "runtime", Generation: metadata.Generation, Reason: "applying",
		Software: []contract.SoftwareIdentity{{Component: machineconfig.TelemetryHostFeature, Scope: "installed", Version: "1", RecordedAt: &recorded}}})
	requireStatus(t, request(t, s, http.MethodPost, "/v1/nodes/"+capable["node_id"]+"/status", capable["token"], report), 200)
	if err := s.configs.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !delivered(capable["node_id"]) || delivered(legacy["node_id"]) {
		t.Fatal("telemetry must follow each machine's own host feature")
	}
	if !strings.Contains(bundle(capable["node_id"])["system/node/network.yaml"], "livepeer-telemetry") {
		t.Fatal("telemetry agent cannot reach Node metrics")
	}
	s.params.TelemetryEnabled = false
	s.configs = s.newConfigurationManager()
	if err := s.configs.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if delivered(capable["node_id"]) {
		t.Fatal("disabling telemetry kept the agents")
	}
}

type relayGrants struct{ grant management.TelemetryGrant }

func (g relayGrants) Request(context.Context, string, any, int64) ([]byte, http.Header, error) {
	b, err := json.Marshal(g.grant)
	return b, nil, err
}

// Real vmagent pushes through the machine relay and Control Center ingest into
// VictoriaMetrics, exercising remote-write protocol negotiation end to end.
func TestTelemetryVmagentThroughRelay(t *testing.T) {
	vmagent, vmBinary := os.Getenv("VMAGENT_BINARY"), os.Getenv("VICTORIAMETRICS_BINARY")
	if vmagent == "" || vmBinary == "" {
		t.Skip("set VMAGENT_BINARY and VICTORIAMETRICS_BINARY to the pinned v1.155.0 releases")
	}
	metricsURL := startVictoria(t, vmBinary)
	s, _ := telemetryServer(t)
	s.params.TelemetryMetricsURL = metricsURL
	cc := httptest.NewServer(s.Handler())
	t.Cleanup(cc.Close)
	base := cc.URL + "/v1/nodes/" + telemetryNode
	token, expires, err := s.params.jwtKey.Telemetry(s.params.signingKeyID(), telemetryNode, orchA, 2, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	relay := telemetry.NewRelay(relayGrants{management.TelemetryGrant{Token: token, ExpiresAt: expires, NodeID: telemetryNode, MetricsURL: base + "/telemetry/metrics", LogsURL: base + "/telemetry/logs"}}, true, 8<<20)
	relayAddress := freeAddress(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go relay.Serve(ctx, relayAddress)

	exporter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "relay_probe{node_id=\""+otherTelemetryNode+"\",session_id=\"s-1\"} 7\n")
	}))
	t.Cleanup(exporter.Close)
	dir := t.TempDir()
	scrape := filepath.Join(dir, "scrape.yaml")
	relabel := filepath.Join(dir, "relabel.yaml")
	os.WriteFile(scrape, []byte("global: {scrape_interval: 1s}\nscrape_configs:\n- job_name: probe\n  static_configs: [{targets: ['"+strings.TrimPrefix(exporter.URL, "http://")+"']}]\n"), 0600)
	relabelRules, err := os.ReadFile("machineconfig/telemetry/relabel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(relabel, relabelRules, 0600)
	cmd := exec.Command(vmagent, "-httpListenAddr="+freeAddress(t), "-promscrape.config="+scrape, "-remoteWrite.url=http://"+relayAddress+"/metrics/write",
		"-remoteWrite.relabelConfig="+relabel, "-remoteWrite.forceVMProto=true", "-remoteWrite.tmpDataPath="+filepath.Join(dir, "buffer"), "-remoteWrite.flushInterval=200ms", "-loggerLevel=ERROR")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	var series struct {
		Metric map[string]string `json:"metric"`
	}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline) && series.Metric == nil; time.Sleep(500 * time.Millisecond) {
		get(t, metricsURL+"/internal/force_flush")
		if body := bytes.TrimSpace(get(t, metricsURL+"/api/v1/export?"+url.Values{"match[]": {"relay_probe"}}.Encode())); len(body) > 0 {
			if err := json.Unmarshal(bytes.SplitN(body, []byte("\n"), 2)[0], &series); err != nil {
				t.Fatal(err)
			}
		}
	}
	if series.Metric["node_id"] != telemetryNode || series.Metric["orchestrator"] != orchA || series.Metric["session_id"] != "" || series.Metric["job"] != "probe" {
		t.Fatal("vmagent series through relay", series.Metric, victoriaCounter(t, metricsURL, "vm_rows_inserted_total"))
	}
	if s.telemetry.bytes[telemetryMetrics].Load() == 0 {
		t.Fatal("ingest counted no bytes")
	}
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

// Opt-in: the real Fluent Bit image tails kubelet-format logs through the
// relay and Control Center ingest into VictoriaLogs. Docker must use host
// networking so the container reaches the loopback relay.
func TestTelemetryFluentBitThroughRelay(t *testing.T) {
	image, vlBinary := os.Getenv("TELEMETRY_FLUENT_BIT_IMAGE"), os.Getenv("VICTORIALOGS_BINARY")
	docker, err := exec.LookPath("docker")
	if image == "" || vlBinary == "" || err != nil {
		t.Skip("set TELEMETRY_FLUENT_BIT_IMAGE and VICTORIALOGS_BINARY, with Docker available")
	}
	logsURL := startVictoria(t, vlBinary)
	s, _ := telemetryServer(t)
	s.params.TelemetryLogsURL = logsURL
	cc := httptest.NewServer(s.Handler())
	t.Cleanup(cc.Close)
	base := cc.URL + "/v1/nodes/" + telemetryNode
	token, expires, _ := s.params.jwtKey.Telemetry(s.params.signingKeyID(), telemetryNode, orchA, 2, time.Hour, time.Now())
	relay := telemetry.NewRelay(relayGrants{management.TelemetryGrant{Token: token, ExpiresAt: expires, NodeID: telemetryNode, MetricsURL: base + "/telemetry/metrics", LogsURL: base + "/telemetry/logs"}}, true, 8<<20)
	relayAddress := freeAddress(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go relay.Serve(ctx, relayAddress)

	dir, err := os.MkdirTemp("", "lp-fluent-bit-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	install := filepath.Join(dir, "install")
	for _, d := range []string{"etc", "buffer/fluent-bit", "install/logs/pods/livepeer_orchestrator-1_uid-1/orchestrator", "install/logs/pods/livepeer-apps_app-1_uid-2/app"} {
		os.MkdirAll(filepath.Join(dir, d), 0777)
	}
	read := func(name string) string {
		b, err := os.ReadFile("machineconfig/telemetry/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	conf := strings.ReplaceAll(read("fluent-bit.conf"), "@APP_LOGS_INPUT@\n", read("app-logs.conf"))
	conf = strings.ReplaceAll(conf, "@INSTALL_DIR@", install)
	conf = strings.ReplaceAll(conf, "port                     20244", "port                     "+strings.Split(relayAddress, ":")[1])
	// No journal or Kubernetes API exists in this fixture.
	for _, input := range []string{"name                systemd", "name                kubernetes_events"} {
		start := strings.Index(conf, input)
		block := strings.LastIndex(conf[:start], "[INPUT]")
		end := block + strings.Index(conf[block:], "\n\n")
		conf = conf[:block] + conf[end+2:]
	}
	os.WriteFile(filepath.Join(dir, "etc/fluent-bit.conf"), []byte(conf), 0644)
	os.WriteFile(filepath.Join(dir, "etc/parsers.conf"), []byte(read("parsers.conf")), 0644)
	name := "lp-fluent-bit-test-" + strings.ToLower(telemetryNode[:8]) + strings.TrimPrefix(filepath.Base(dir), "lp-fluent-bit-")
	// Production runs as UID 0 to read root-owned kubelet logs; fixture files
	// belong to the test user, so the container runs as that user instead.
	user := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	out, err := exec.Command(docker, "run", "-d", "--name", name, "--network", "host", "--user", user, "--read-only", "--cap-drop", "ALL",
		"-v", filepath.Join(dir, "etc")+":/etc/telemetry:ro", "-v", filepath.Join(dir, "buffer")+":/buffer", "-v", install+"/logs:"+install+"/logs:ro",
		image, "-c", "/etc/telemetry/fluent-bit.conf").CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command(docker, "logs", name).CombinedOutput()
			t.Log(string(logs))
		}
		exec.Command(docker, "rm", "-f", name).Run()
	})
	time.Sleep(3 * time.Second)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	appendLines := func(path string, lines ...string) {
		f, err := os.OpenFile(filepath.Join(install, path), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		for _, line := range lines {
			io.WriteString(f, line+"\n")
		}
	}
	appendLines("logs/pods/livepeer-apps_app-1_uid-2/app/0.log", stamp+" stdout P partial app ", stamp+" stdout F line", stamp+" stderr F {\"node_id\":\"spoofed\"}")
	appendLines("logs/pods/livepeer_orchestrator-1_uid-1/orchestrator/0.log", stamp+" stderr F node ready")
	appendLines("logs/k3s.log", "k3s host line")

	want := map[string]map[string]string{
		"partial app line":      {"source": "app", "namespace": "livepeer-apps", "pod": "app-1", "container": "app"},
		"node ready":            {"source": "system", "namespace": "livepeer", "pod": "orchestrator-1", "container": "orchestrator"},
		"k3s host line":         {"source": "host"},
		`{"node_id":"spoofed"}`: {"source": "app"},
	}
	found := map[string]map[string]string{}
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline) && len(found) < len(want); time.Sleep(time.Second) {
		for _, line := range bytes.Split(bytes.TrimSpace(get(t, logsURL+"/select/logsql/query?query="+url.QueryEscape("_time:10m"))), []byte("\n")) {
			var entry map[string]string
			if json.Unmarshal(line, &entry) == nil {
				found[entry["_msg"]] = entry
			}
		}
	}
	for message, fields := range want {
		entry := found[message]
		if entry == nil || entry["node_id"] != telemetryNode || entry["orchestrator"] != orchA || entry["time"] != "" {
			t.Fatalf("missing or unstamped %q in %v", message, found)
		}
		for key, value := range fields {
			if entry[key] != value {
				t.Fatalf("%q: %s = %q, want %q (%v)", message, key, entry[key], value, entry)
			}
		}
	}
}
