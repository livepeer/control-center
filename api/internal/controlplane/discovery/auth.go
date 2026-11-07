package discovery

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/livepeer/node/destination"
	shared "github.com/livepeer/node/discovery/shared"
)

// Formatting and JSON must not expose process-local credential values.
func (Credential) String() string   { return "[redacted Access credential]" }
func (Credential) GoString() string { return "[redacted Access credential]" }

type authorization struct {
	source     Source
	credential Credential
	available  bool
}

type attempt struct {
	source    Source
	completed time.Time
	before    time.Time
	revision  uint64
	outcome   string
	status    int
}

type transport struct {
	base          http.RoundTripper
	selection     atomic.Pointer[authorizationSnapshot]
	nextSelection atomic.Uint64
	before        func(string) time.Time
	mu            sync.Mutex
	attempts      map[string]attempt
}

type authorizationSnapshot struct {
	revision uint64
	sources  map[string]authorization
}

func (t *transport) install(sources map[string]authorization) uint64 {
	revision := t.nextSelection.Add(1)
	t.selection.Store(&authorizationSnapshot{revision: revision, sources: sources})
	return revision
}

// Complete, canonical endpoints are the authorization keys, not host suffixes or
// URLs advertised in inventories. Managed tunnels use the root /discovery path.
func canonicalEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || shared.ValidateURL(u) != nil || u.Opaque != "" || u.RawPath != "" || u.Path != "/discovery" || strings.HasSuffix(u.Hostname(), ".") || strings.ContainsAny(u.Hostname(), "%\\") {
		return nil, errors.New("invalid discovery endpoint")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid discovery endpoint")
		}
		port = strconv.Itoa(n)
	}
	if port == "443" && u.Scheme == "https" || port == "80" && u.Scheme == "http" {
		port = ""
	}
	u.Host = host
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	}
	return u, nil
}

func validCredential(c Credential) bool {
	for _, value := range []string{c.ClientID, c.ClientSecret} {
		if len(value) == 0 || len(value) > 4096 {
			return false
		}
		for _, b := range []byte(value) {
			if b < 33 || b > 126 {
				return false
			}
		}
	}
	return true
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.Method != http.MethodGet || req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host) {
		return nil, errors.New("discovery request is outside its configured scope")
	}
	u, err := canonicalEndpoint(req.URL.String())
	if err != nil {
		return nil, err
	}
	selection := t.selection.Load()
	if selection == nil {
		return nil, errors.New("discovery source is not configured")
	}
	auth, ok := selection.sources[u.String()]
	if !ok {
		return nil, errors.New("discovery source is not configured")
	}
	var before time.Time
	if t.before != nil {
		before = t.before(u.String())
	}
	finish := func(status int, outcome string) {
		current := t.selection.Load()
		if current == nil || !sameVersion(current.sources[u.String()].source, auth.source) {
			return
		}
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.attempts == nil {
			t.attempts = map[string]attempt{}
		}
		// The Collector joins each batch, including body close, before the
		// next batch starts; attempts for one URL cannot finish out of order.
		t.attempts[u.String()] = attempt{source: auth.source, completed: time.Now().UTC(), before: before, revision: selection.revision, status: status, outcome: outcome}
	}
	clone := req.Clone(req.Context())
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}
	for key := range clone.Header {
		for _, sensitive := range []string{"CF-Access-Client-Id", "CF-Access-Client-Secret", "Authorization", "Proxy-Authorization", "Cookie"} {
			if strings.EqualFold(key, sensitive) {
				delete(clone.Header, key)
			}
		}
	}
	switch auth.source.AuthMode {
	case AuthCloudflare:
		if u.Scheme != "https" || !auth.available || !validCredential(auth.credential) {
			finish(0, "credential_unavailable")
			return nil, errors.New("discovery credential is unavailable")
		}
		clone.Header.Set("CF-Access-Client-Id", auth.credential.ClientID)
		clone.Header.Set("CF-Access-Client-Secret", auth.credential.ClientSecret)
	case AuthNone:
	default:
		finish(0, "credential_unavailable")
		return nil, errors.New("discovery authentication mode is invalid")
	}
	resp, err := t.base.RoundTrip(clone)
	if err != nil {
		outcome := "transport_error"
		var timeout net.Error
		var dns *net.DNSError
		if errors.Is(err, destination.ErrDeniedAddress) {
			outcome = "denied_destination"
		} else if errors.As(err, &dns) {
			outcome = "dns"
		} else if errors.As(err, &timeout) && timeout.Timeout() {
			outcome = "timeout"
		}
		finish(0, outcome)
		// Neither the underlying error nor its URL/headers/body is diagnostic data.
		return nil, errors.New("discovery transport failed")
	}
	outcome := "response_received"
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		outcome = "access_denied"
	} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		outcome = "redirect"
	} else if resp.StatusCode != 200 {
		outcome = "http_error"
	}
	resp.Body = &responseBody{ReadCloser: resp.Body, done: func() { finish(resp.StatusCode, outcome) }}
	return resp, nil
}

// Collector closes the body before recording decode success. Acknowledgement
// compares the successful snapshot marker before/after this exact request;
// wall-clock ordering is deliberately not used as evidence of collection.
type responseBody struct {
	io.ReadCloser
	once sync.Once
	done func()
}

func (b *responseBody) Close() error { err := b.ReadCloser.Close(); b.once.Do(b.done); return err }

func (t *transport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
