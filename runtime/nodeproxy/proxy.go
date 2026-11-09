// Package nodeproxy isolates Node's API router from wildcard application Hosts
// and removes Cloudflare credentials after cloudflared has authenticated them.
package nodeproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
)

var proxyLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Handler accepts the exact private authority set by protected ingress rules or
// one application label under the configured template. Ports and trailing dots
// on public Hosts are rejected rather than passed into Node's API fallback.
func Handler(template string, next http.Handler) (http.Handler, error) {
	suffix := ""
	if template != "" {
		u, err := url.Parse(strings.Replace(template, "{proxy}", "lpcc-proxy-marker", 1))
		if err != nil || strings.Count(template, "{proxy}") != 1 || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Host, "lpcc-proxy-marker.") || u.Port() != "" {
			return nil, errors.New("invalid Node proxy template")
		}
		suffix = strings.TrimPrefix(u.Host, "lpcc-proxy-marker")
	}
	private, _ := url.Parse(contract.PrivateOrchestrator)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the local connector probe uses this authority; ingress denies
		// /readyz on every public host before it reaches this listener.
		if r.Host == strings.TrimPrefix(contract.ConnectorOrigin, "http://") && r.Method == http.MethodGet && r.URL.Path == "/readyz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		host := strings.ToLower(r.Host)
		if host != private.Host {
			id, ok := strings.CutSuffix(host, suffix)
			if suffix == "" || !ok || !proxyLabel.MatchString(id) || contract.ReservedProxyID(id) {
				http.NotFound(w, r)
				return
			}
		}
		r = r.Clone(r.Context())
		r.Host = host
		for name := range r.Header {
			if strings.HasPrefix(strings.ToLower(name), "cf-access-") {
				delete(r.Header, name)
			}
		}
		stripAccessCookies(r.Header)
		next.ServeHTTP(w, r)
	}), nil
}

func stripAccessCookies(header http.Header) {
	for name, values := range header {
		if !strings.EqualFold(name, "Cookie") {
			continue
		}
		filtered := values[:0]
		for _, raw := range values {
			parts := strings.Split(raw, ";")
			kept := parts[:0]
			removed := false
			for _, part := range parts {
				key, _, _ := strings.Cut(strings.TrimSpace(part), "=")
				if strings.EqualFold(strings.TrimSpace(key), "CF_Authorization") {
					removed = true
				} else {
					kept = append(kept, part)
				}
			}
			if !removed {
				filtered = append(filtered, raw)
			} else if clean := strings.Join(kept, ";"); strings.TrimSpace(clean) != "" {
				filtered = append(filtered, clean)
			}
		}
		if len(filtered) == 0 {
			delete(header, name)
		} else {
			header[name] = filtered
		}
	}
}

func Serve(ctx context.Context, template, serviceURL string) error {
	u, err := url.Parse(serviceURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid Node service URL")
	}
	transport := nodeTransport(serviceURL, nil)
	defer transport.CloseIdleConnections()
	handler, err := Handler(template, reverseProxy(transport))
	if err != nil {
		return err
	}
	server := &http.Server{Addr: strings.TrimPrefix(contract.ConnectorOrigin, "http://"), Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 1 << 20}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(stop)
	case <-done:
		return errors.New("Node proxy listener unavailable")
	}
}

// Node fixes its routing identity at startup. Verify each new TCP connection
// before transport can send application bytes; a rollout cannot swap backends
// between identity verification and forwarding on that connection.
func nodeTransport(serviceURL string, dial func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if dial == nil {
		dial = transport.DialContext
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		verified := false
		defer func() {
			if !verified {
				_ = conn.Close()
			}
		}()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		deadline := time.Now().Add(5 * time.Second)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, errors.New("Node identity unavailable")
		}
		request, _ := http.NewRequest(http.MethodGet, contract.PrivateOrchestrator+"/discovery", nil)
		if err := request.Write(conn); err != nil {
			return nil, errors.New("Node identity unavailable")
		}
		limited := &io.LimitedReader{R: conn, N: (1 << 20) + (64 << 10)}
		reader := bufio.NewReader(limited)
		response, err := http.ReadResponse(reader, request)
		if err != nil {
			return nil, errors.New("Node identity unavailable")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		_ = response.Body.Close()
		var records []struct {
			Address string `json:"address"`
		}
		if err != nil || len(body) > 1<<20 || response.StatusCode != http.StatusOK || response.Close || reader.Buffered() != 0 || json.Unmarshal(body, &records) != nil || len(records) != 1 || records[0].Address != serviceURL {
			return nil, errors.New("Node routing identity mismatch")
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			return nil, errors.New("Node identity unavailable")
		}
		verified = true
		return conn, nil
	}
	return transport
}

func reverseProxy(transport http.RoundTripper) *httputil.ReverseProxy {
	target, _ := url.Parse(contract.PrivateOrchestrator)
	return &httputil.ReverseProxy{Transport: transport, FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0),
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host
			r.Out.URL.Path, r.Out.URL.RawPath, r.Out.URL.RawQuery = r.In.URL.Path, r.In.URL.RawPath, r.In.URL.RawQuery
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "Node unavailable", http.StatusBadGateway)
		},
	}
}

func Ready(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, contract.ConnectorOrigin+"/readyz", nil)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK
}
