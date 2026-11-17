// Package telemetry forwards local agent writes to Control Center with a
// short-lived telemetry token. Agents hold no credential and choose no
// destination: the management agent's grant supplies both.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/livepeer/control-center/runtime/management"
	"github.com/livepeer/control-center/runtime/transport"
)

const (
	kindMetrics = "metrics"
	kindLogs    = "logs"
)

var results = []string{"2xx", "4xx", "5xx", "unavailable"}

type Relay struct {
	Grants    transport.Requester
	Client    *http.Client
	AllowHTTP bool
	MaxBody   int64
	Now       func() time.Time

	mu        sync.Mutex
	grant     *management.TelemetryGrant
	refreshAt time.Time
	failedAt  time.Time

	requests      map[[2]string]*atomic.Uint64
	grantFailures atomic.Uint64
}

func NewRelay(grants transport.Requester, allowHTTP bool, maxBody int64) *Relay {
	client := &http.Client{
		Timeout:       45 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 35 * time.Second,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
	r := &Relay{Grants: grants, Client: client, AllowHTTP: allowHTTP, MaxBody: maxBody, requests: map[[2]string]*atomic.Uint64{}}
	for _, kind := range []string{kindMetrics, kindLogs} {
		for _, result := range results {
			r.requests[[2]string{kind, result}] = new(atomic.Uint64)
		}
	}
	return r
}

func (r *Relay) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// validGrant requires both destinations to share one origin and the approved
// machine operation paths, so a grant cannot point writes anywhere else.
func (r *Relay) validGrant(g management.TelemetryGrant, now time.Time) bool {
	if g.Token == "" || len(g.Token) > 4096 || g.NodeID == "" || !g.ExpiresAt.After(now) {
		return false
	}
	metrics, err1 := url.Parse(g.MetricsURL)
	logs, err2 := url.Parse(g.LogsURL)
	if err1 != nil || err2 != nil || metrics.Host == "" || metrics.Host != logs.Host || metrics.Scheme != logs.Scheme ||
		metrics.User != nil || logs.User != nil || metrics.RawQuery != "" || logs.RawQuery != "" || metrics.Fragment != "" || logs.Fragment != "" {
		return false
	}
	if metrics.Scheme != "https" && (metrics.Scheme != "http" || !r.AllowHTTP) {
		return false
	}
	prefix, ok := strings.CutSuffix(metrics.Path, "/telemetry/metrics")
	return ok && logs.Path == prefix+"/telemetry/logs" && strings.HasSuffix(prefix, "/v1/nodes/"+g.NodeID)
}

// current returns a cached grant, renewing it at half its lifetime. A failed
// renewal keeps a still-valid grant and waits before asking again.
func (r *Relay) current(ctx context.Context) (*management.TelemetryGrant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if r.grant != nil && now.Before(r.refreshAt) {
		return r.grant, nil
	}
	if !r.failedAt.IsZero() && now.Sub(r.failedAt) < 5*time.Second {
		if r.grant != nil && now.Before(r.grant.ExpiresAt.Add(-30*time.Second)) {
			return r.grant, nil
		}
		return nil, errors.New("telemetry_grant_unavailable")
	}
	fetch, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	b, _, err := r.Grants.Request(fetch, "telemetry/token", nil, 16384)
	var g management.TelemetryGrant
	if err == nil && (transport.Decode(b, &g) != nil || !r.validGrant(g, now)) {
		err = errors.New("telemetry_grant_invalid")
	}
	if err != nil {
		r.grantFailures.Add(1)
		r.failedAt = now
		if r.grant != nil && now.Before(r.grant.ExpiresAt.Add(-30*time.Second)) {
			return r.grant, nil
		}
		r.grant = nil
		return nil, err
	}
	r.grant, r.failedAt = &g, time.Time{}
	r.refreshAt = now.Add(g.ExpiresAt.Sub(now) / 2)
	return r.grant, nil
}

// invalidate drops a grant Control Center refused, so the next write fetches a
// new one instead of repeating a revoked token.
func (r *Relay) invalidate(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.grant != nil && r.grant.Token == token {
		r.grant, r.refreshAt = nil, time.Time{}
	}
}

func (r *Relay) ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.grant != nil && r.now().Before(r.grant.ExpiresAt)
}

func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/healthz":
		w.WriteHeader(http.StatusNoContent)
	case req.Method == http.MethodGet && req.URL.Path == "/readyz":
		if r.ready() {
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "telemetry grant unavailable", http.StatusServiceUnavailable)
		}
	case req.Method == http.MethodGet && req.URL.Path == "/metrics":
		r.metrics(w)
	case req.Method == http.MethodPost && req.URL.Path == "/metrics/write":
		r.forward(w, req, kindMetrics)
	case req.Method == http.MethodPost && req.URL.Path == "/logs/insert":
		r.forward(w, req, kindLogs)
	default:
		http.NotFound(w, req)
	}
}

func (r *Relay) forward(w http.ResponseWriter, req *http.Request, kind string) {
	size := req.ContentLength
	switch {
	case size < 0:
		http.Error(w, "Content-Length required", http.StatusLengthRequired)
		return
	case size == 0:
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	case size > r.MaxBody:
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	g, err := r.current(req.Context())
	if err != nil {
		r.requests[[2]string{kind, "unavailable"}].Add(1)
		w.Header().Set("Retry-After", "5")
		http.Error(w, "telemetry grant unavailable", http.StatusServiceUnavailable)
		return
	}
	target := g.MetricsURL
	if kind == kindLogs {
		target = g.LogsURL
	}
	out, err := http.NewRequestWithContext(req.Context(), http.MethodPost, target, http.MaxBytesReader(w, req.Body, size))
	if err != nil {
		http.Error(w, "telemetry destination invalid", http.StatusInternalServerError)
		return
	}
	out.ContentLength = size
	for _, name := range []string{"Content-Type", "Content-Encoding", "X-Prometheus-Remote-Write-Version"} {
		if value := req.Header.Get(name); value != "" && len(value) <= 128 {
			out.Header.Set(name, value)
		}
	}
	out.Header.Set("Authorization", "Bearer "+g.Token)
	out.Header.Set("User-Agent", "livepeer-telemetry-relay")
	resp, err := r.Client.Do(out)
	if err != nil {
		r.requests[[2]string{kind, "unavailable"}].Add(1)
		w.Header().Set("Retry-After", "5")
		http.Error(w, "Control Center unavailable", http.StatusServiceUnavailable)
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	status := resp.StatusCode
	switch {
	case status == http.StatusUnauthorized:
		// The agent retries from its buffer and the retry carries a new token.
		r.invalidate(g.Token)
		status = http.StatusServiceUnavailable
		w.Header().Set("Retry-After", "1")
	case status/100 == 3:
		status = http.StatusBadGateway
	case status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable:
		if retry := resp.Header.Get("Retry-After"); retry != "" && len(retry) <= 16 {
			w.Header().Set("Retry-After", retry)
		}
	}
	result := "5xx"
	switch status / 100 {
	case 2:
		result = "2xx"
	case 4:
		result = "4xx"
	}
	r.requests[[2]string{kind, result}].Add(1)
	w.WriteHeader(status)
}

func (r *Relay) metrics(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	for _, kind := range []string{kindMetrics, kindLogs} {
		for _, result := range results {
			fmt.Fprintf(w, "livepeer_telemetry_relay_requests_total{kind=%q,result=%q} %d\n", kind, result, r.requests[[2]string{kind, result}].Load())
		}
	}
	fmt.Fprintf(w, "livepeer_telemetry_relay_grant_failures_total %d\n", r.grantFailures.Load())
	r.mu.Lock()
	expires := int64(0)
	if r.grant != nil {
		expires = r.grant.ExpiresAt.Unix()
	}
	r.mu.Unlock()
	fmt.Fprintf(w, "livepeer_telemetry_relay_grant_expiry_timestamp_seconds %s\n", strconv.FormatInt(expires, 10))
}

// Serve listens only on loopback. The relay shares a Pod network namespace
// with its agents and must never accept writes from elsewhere.
func (r *Relay) Serve(ctx context.Context, address string) error {
	host, _, err := net.SplitHostPort(address)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		return errors.New("telemetry relay must listen on a loopback address")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	server := &http.Server{Addr: address, Handler: r, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 90 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			_, _ = r.current(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("telemetry relay listener unavailable")
		}
		return nil
	case <-ctx.Done():
	}
	stop, release := context.WithTimeout(context.Background(), 10*time.Second)
	defer release()
	return server.Shutdown(stop)
}
