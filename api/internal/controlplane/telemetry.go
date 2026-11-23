package controlplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/livepeer/control-center/runtime/ingressauth"
)

// TelemetryParams configures pushed machine metrics and logs. Payloads are
// stored only in private VictoriaMetrics and VictoriaLogs services. Machine
// identity labels come from the verified token, never from the payload.
type TelemetryParams struct {
	TelemetryEnabled        bool          `env:"TELEMETRY_ENABLED" default:"true" descr:"Accept pushed machine metrics and logs and deliver telemetry agents to capable machines"`
	TelemetryMetricsURL     string        `env:"TELEMETRY_METRICS_URL" default:"http://victoriametrics:8428" descr:"Private VictoriaMetrics base URL"`
	TelemetryLogsURL        string        `env:"TELEMETRY_LOGS_URL" default:"http://victorialogs:9428" descr:"Private VictoriaLogs base URL"`
	TelemetryTokenTTL       time.Duration `env:"TELEMETRY_TOKEN_TTL" default:"1h" descr:"Telemetry write token lifetime, from 1m to 1h"`
	TelemetryMaxBodyBytes   int           `env:"TELEMETRY_MAX_BODY_BYTES" default:"8388608" descr:"Largest accepted telemetry request body, from 1 MiB to 64 MiB"`
	TelemetryNodeRateBytes  int           `env:"TELEMETRY_NODE_RATE_BYTES" default:"1048576" descr:"Sustained ingest bytes per second for each machine and telemetry kind"`
	TelemetryAppLogsEnabled bool          `env:"TELEMETRY_APP_LOGS_ENABLED" default:"true" descr:"Collect app container output; disable to keep app logs on machines"`
}

const (
	telemetryMetrics = "metrics"
	telemetryLogs    = "logs"
)

// VictoriaLogs stream fields identify where a log line came from. Agents must
// emit "time" and "message"; the remaining stream fields are optional.
const telemetryLogStreamFields = "node_id,source,namespace,pod,container"

var telemetryKinds = []string{telemetryMetrics, telemetryLogs}
var telemetryRejectReasons = []string{"disabled", "unauthorized", "forbidden", "unavailable", "invalid", "length_required", "too_large", "unsupported_media_type", "rate_limited", "upstream_rejected", "upstream_unavailable"}

func validTelemetryURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil &&
		u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/")
}

func (p TelemetryParams) validate() error {
	if !p.TelemetryEnabled {
		return nil
	}
	if !validTelemetryURL(p.TelemetryMetricsURL) || !validTelemetryURL(p.TelemetryLogsURL) {
		return errors.New("TelemetryMetricsURL and TelemetryLogsURL must be HTTP(S) origins without credentials, paths, query strings, or fragments")
	}
	if p.TelemetryTokenTTL < time.Minute || p.TelemetryTokenTTL > ingressauth.MaxTelemetryLifetime {
		return errors.New("TelemetryTokenTTL must be between 1m and 1h")
	}
	if p.TelemetryMaxBodyBytes < 1<<20 || p.TelemetryMaxBodyBytes > 64<<20 {
		return errors.New("TelemetryMaxBodyBytes must be between 1 MiB and 64 MiB")
	}
	if p.TelemetryNodeRateBytes < 64<<10 {
		return errors.New("TelemetryNodeRateBytes must be at least 64 KiB per second")
	}
	return nil
}

type telemetryMachine struct {
	orchestrator      string
	credentialVersion int64
}

type telemetryBucket struct {
	tokens float64
	last   time.Time
}

// telemetryState is per replica. Enrollment identities are refreshed by the
// reconciliation loop so the ingest hot path never reads the database.
type telemetryState struct {
	mu       sync.RWMutex
	loaded   bool
	machines map[string]telemetryMachine

	bucketMu sync.Mutex
	buckets  map[[2]string]*telemetryBucket

	transport http.RoundTripper
	requests  map[string]*atomic.Uint64
	bytes     map[string]*atomic.Uint64
	rejected  map[[2]string]*atomic.Uint64
	tokens    atomic.Uint64

	logMu         sync.Mutex
	logAt         map[string]time.Time
	logSuppressed map[string]int
}

func newTelemetryState() *telemetryState {
	t := &telemetryState{machines: map[string]telemetryMachine{}, buckets: map[[2]string]*telemetryBucket{},
		requests: map[string]*atomic.Uint64{}, bytes: map[string]*atomic.Uint64{}, rejected: map[[2]string]*atomic.Uint64{},
		logAt: map[string]time.Time{}, logSuppressed: map[string]int{},
		transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 25 * time.Second,
			DisableCompression:    true,
		}}
	for _, kind := range telemetryKinds {
		t.requests[kind], t.bytes[kind] = new(atomic.Uint64), new(atomic.Uint64)
		for _, reason := range telemetryRejectReasons {
			t.rejected[[2]string{kind, reason}] = new(atomic.Uint64)
		}
	}
	return t
}

func (t *telemetryState) replace(machines map[string]telemetryMachine) {
	t.mu.Lock()
	t.machines, t.loaded = machines, true
	t.mu.Unlock()
	t.bucketMu.Lock()
	for key := range t.buckets {
		if _, ok := machines[key[0]]; !ok {
			delete(t.buckets, key)
		}
	}
	t.bucketMu.Unlock()
}

// warn logs at most once per minute per kind and reason, counting suppressed
// events, so a misbehaving fleet cannot flood Control Center's logs.
func (s *Server) telemetryWarn(kind, reason, node, message string, attrs ...any) {
	t := s.telemetry
	key := kind + "/" + reason
	t.logMu.Lock()
	if time.Since(t.logAt[key]) < time.Minute {
		t.logSuppressed[key]++
		t.logMu.Unlock()
		return
	}
	suppressed := t.logSuppressed[key]
	t.logAt[key], t.logSuppressed[key] = time.Now(), 0
	t.logMu.Unlock()
	s.logger.Warn(message, append([]any{"kind", kind, "reason", reason, "node_id", node, "suppressed", suppressed}, attrs...)...)
}

func (t *telemetryState) machine(node string) (telemetryMachine, bool, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	m, ok := t.machines[node]
	return m, ok, t.loaded
}

// allow charges a per-machine, per-kind token bucket. Capacity holds two of the
// largest bodies so a full bucket always admits one maximal request.
func (t *telemetryState) allow(node, kind string, size int64, rate, capacity float64, now time.Time) (bool, time.Duration) {
	t.bucketMu.Lock()
	defer t.bucketMu.Unlock()
	key := [2]string{node, kind}
	b := t.buckets[key]
	if b == nil {
		b = &telemetryBucket{tokens: capacity, last: now}
		t.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(capacity, b.tokens+elapsed*rate)
	}
	b.last = now
	if float64(size) > b.tokens {
		return false, time.Duration(math.Ceil((float64(size)-b.tokens)/rate)) * time.Second
	}
	b.tokens -= float64(size)
	return true, 0
}

func (s *Server) refreshTelemetry(ctx context.Context) error {
	if !s.params.TelemetryEnabled {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT e.node_id,e.orchestrator_address::text,e.credential_version
 FROM lpcc.enrollments e JOIN lpcc.machines m USING(node_id)
 WHERE e.retired_at IS NULL AND m.tunnel_eligible=$1`, !s.params.DevelopmentHTTP)
	if err != nil {
		return err
	}
	defer rows.Close()
	machines := map[string]telemetryMachine{}
	for rows.Next() {
		var node string
		var m telemetryMachine
		if err = rows.Scan(&node, &m.orchestrator, &m.credentialVersion); err != nil {
			return err
		}
		machines[node] = m
	}
	if err = rows.Err(); err != nil {
		return err
	}
	s.telemetry.replace(machines)
	return nil
}

// telemetryToken exchanges the machine credential for a short-lived write token
// so that telemetry agents never hold the management credential.
func (s *Server) telemetryToken(w http.ResponseWriter, r *http.Request) {
	m, err := s.authenticateMachine(r.Context(), r.PathValue("node_id"), bearer(r), false)
	if err != nil {
		s.respondError(w, err)
		return
	}
	if !s.params.TelemetryEnabled {
		s.respondError(w, problem(403, "telemetry_disabled", "Telemetry is not enabled."))
		return
	}
	if s.params.jwtKey == nil {
		s.respondError(w, problem(503, "signing_unavailable", "Telemetry credentials are temporarily unavailable."))
		return
	}
	raw, expires, err := s.params.jwtKey.Telemetry(s.params.signingKeyID(), m.NodeID, m.OrchestratorAddress, m.CredentialVersion, s.params.TelemetryTokenTTL, s.currentTime())
	if err != nil {
		s.respondError(w, problem(503, "signing_unavailable", "Telemetry credentials are temporarily unavailable."))
		return
	}
	s.telemetry.tokens.Add(1)
	respond(w, 200, map[string]any{"token": raw, "expires_at": expires, "node_id": m.NodeID})
}

// telemetryUpstream builds the complete upstream request URL. Client query
// parameters are never forwarded: they could otherwise replace identity labels.
func (s *Server) telemetryUpstream(kind, node, orchestrator string) *url.URL {
	q := url.Values{}
	var base, path string
	if kind == telemetryMetrics {
		base, path = s.params.TelemetryMetricsURL, "/api/v1/write"
		q["extra_label"] = []string{"node_id=" + node, "orchestrator=" + orchestrator}
	} else {
		base, path = s.params.TelemetryLogsURL, "/insert/jsonline"
		q.Set("_stream_fields", telemetryLogStreamFields)
		q.Set("_msg_field", "message")
		q.Set("_time_field", "time")
		q.Set("extra_fields", "node_id="+node+",orchestrator="+orchestrator)
	}
	u, _ := url.Parse(strings.TrimRight(base, "/") + path)
	u.RawQuery = q.Encode()
	return u
}

// telemetryEncoding returns the upstream Content-Type and Content-Encoding.
// The Content-Type is fixed so that no request body is parsed as form values.
func telemetryEncoding(kind string, h http.Header) (string, string, bool) {
	types, encodings := h.Values("Content-Type"), h.Values("Content-Encoding")
	if len(types) != 1 || len(encodings) > 1 {
		return "", "", false
	}
	media, _, err := mime.ParseMediaType(types[0])
	if err != nil {
		return "", "", false
	}
	encoding := ""
	if len(encodings) == 1 {
		encoding = strings.ToLower(strings.TrimSpace(encodings[0]))
	}
	if kind == telemetryMetrics {
		return "application/x-protobuf", encoding, media == "application/x-protobuf" && (encoding == "snappy" || encoding == "zstd")
	}
	return "application/json", encoding, (media == "application/json" || media == "application/x-ndjson" || media == "application/stream+json") &&
		(encoding == "" || encoding == "gzip" || encoding == "zstd")
}

func (s *Server) telemetryReject(w http.ResponseWriter, kind, reason string, status int, message string) {
	s.telemetry.rejected[[2]string{kind, reason}].Add(1)
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	fail(w, status, message)
}

func (s *Server) telemetryIngest(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t := s.telemetry
		t.requests[kind].Add(1)
		if !s.params.TelemetryEnabled {
			s.telemetryReject(w, kind, "disabled", http.StatusForbidden, "telemetry is not enabled")
			return
		}
		if s.params.jwtKey == nil {
			s.telemetryReject(w, kind, "unavailable", http.StatusServiceUnavailable, "telemetry credentials are temporarily unavailable")
			return
		}
		claims, err := ingressauth.VerifyTelemetry(s.params.jwtKey.Keys, bearer(r), s.currentTime())
		if err != nil {
			s.telemetryReject(w, kind, "unauthorized", http.StatusUnauthorized, "invalid telemetry credential")
			return
		}
		node := r.PathValue("node_id")
		if claims.Subject != node {
			s.telemetryReject(w, kind, "forbidden", http.StatusForbidden, "telemetry credential does not match this machine")
			return
		}
		m, ok, loaded := t.machine(node)
		if !loaded {
			w.Header().Set("Retry-After", "10")
			s.telemetryReject(w, kind, "unavailable", http.StatusServiceUnavailable, "telemetry enrollment state is loading")
			return
		}
		// Credential refresh and retirement revoke outstanding tokens.
		if !ok || m.orchestrator != claims.Orchestrator || m.credentialVersion != claims.CredentialVersion {
			s.telemetryReject(w, kind, "unauthorized", http.StatusUnauthorized, "telemetry credential is no longer current")
			return
		}
		size := r.ContentLength
		switch {
		case size < 0:
			s.telemetryReject(w, kind, "length_required", http.StatusLengthRequired, "telemetry requests require Content-Length")
			return
		case size == 0:
			s.telemetryReject(w, kind, "invalid", http.StatusBadRequest, "telemetry request body is empty")
			return
		case size > int64(s.params.TelemetryMaxBodyBytes):
			s.telemetryReject(w, kind, "too_large", http.StatusRequestEntityTooLarge, "telemetry request body is too large")
			return
		}
		contentType, encoding, ok := telemetryEncoding(kind, r.Header)
		if !ok {
			s.telemetryReject(w, kind, "unsupported_media_type", http.StatusUnsupportedMediaType, "unsupported telemetry encoding")
			return
		}
		rate := float64(s.params.TelemetryNodeRateBytes)
		if allowed, wait := t.allow(node, kind, size, rate, 2*float64(s.params.TelemetryMaxBodyBytes), s.currentTime()); !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(wait/time.Second))))
			s.telemetryReject(w, kind, "rate_limited", http.StatusTooManyRequests, "telemetry rate limit exceeded")
			return
		}
		// Slow uplinks may need longer than the server-wide read timeout; the
		// request context still bounds the whole exchange.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(30 * time.Second))
		upstream := s.telemetryUpstream(kind, node, m.orchestrator)
		proxy := &httputil.ReverseProxy{
			Transport: t.transport,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL, pr.Out.Host = upstream, upstream.Host
				header := http.Header{"Content-Type": {contentType}, "User-Agent": {"livepeer-control-center-telemetry"}}
				if encoding != "" {
					header.Set("Content-Encoding", encoding)
				}
				if version := pr.In.Header.Get("X-Prometheus-Remote-Write-Version"); kind == telemetryMetrics && version != "" && len(version) <= 32 {
					header.Set("X-Prometheus-Remote-Write-Version", version)
				}
				pr.Out.Header = header
			},
			ModifyResponse: func(resp *http.Response) error {
				status, reason := http.StatusNoContent, ""
				switch {
				case resp.StatusCode/100 == 2:
					t.bytes[kind].Add(uint64(size))
				case resp.StatusCode == http.StatusTooManyRequests:
					status, reason = http.StatusTooManyRequests, "upstream_unavailable"
				case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusRequestEntityTooLarge ||
					resp.StatusCode == http.StatusUnsupportedMediaType || resp.StatusCode == http.StatusUnprocessableEntity:
					// Agents drop a block on 400 instead of retrying an unparsable payload forever.
					status, reason = http.StatusBadRequest, "upstream_rejected"
				default:
					status, reason = http.StatusServiceUnavailable, "upstream_unavailable"
				}
				if reason != "" {
					detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
					t.rejected[[2]string{kind, reason}].Add(1)
					s.telemetryWarn(kind, reason, node, "telemetry storage refused a write", "upstream_status", resp.StatusCode, "detail", string(detail))
				}
				resp.Body.Close()
				retry := resp.Header.Get("Retry-After")
				resp.StatusCode, resp.Status = status, strconv.Itoa(status)+" "+http.StatusText(status)
				resp.Header, resp.Body, resp.ContentLength = http.Header{}, http.NoBody, 0
				if retry != "" && status == http.StatusTooManyRequests && len(retry) <= 16 {
					resp.Header.Set("Retry-After", retry)
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				s.telemetryWarn(kind, "upstream_unavailable", node, "telemetry storage is unavailable", "error", err.Error())
				w.Header().Set("Retry-After", "10")
				s.telemetryReject(w, kind, "upstream_unavailable", http.StatusServiceUnavailable, "telemetry storage is temporarily unavailable")
			},
		}
		proxy.ServeHTTP(w, r)
	}
}

// telemetryMetricsText appends ingest counters to Control Center's /metrics.
// Labels are bounded server constants; machine identities are never labels.
func (s *Server) telemetryMetricsText() string {
	if !s.params.TelemetryEnabled {
		return ""
	}
	t := s.telemetry
	var b strings.Builder
	fmt.Fprintf(&b, "control_telemetry_tokens_issued_total %d\n", t.tokens.Load())
	for _, kind := range telemetryKinds {
		fmt.Fprintf(&b, "control_telemetry_ingest_requests_total{kind=%q} %d\n", kind, t.requests[kind].Load())
	}
	for _, kind := range telemetryKinds {
		fmt.Fprintf(&b, "control_telemetry_ingest_bytes_total{kind=%q} %d\n", kind, t.bytes[kind].Load())
	}
	keys := make([][2]string, 0, len(t.rejected))
	for key := range t.rejected {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+"/"+keys[i][1] < keys[j][0]+"/"+keys[j][1] })
	for _, key := range keys {
		fmt.Fprintf(&b, "control_telemetry_ingest_rejected_total{kind=%q,reason=%q} %d\n", key[0], key[1], t.rejected[key].Load())
	}
	return b.String()
}
