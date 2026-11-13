// Package secretclient keeps machine credentials and decrypted values out of artifacts.
package secretclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/livepeer/control-center/runtime/artifact"
	protocol "github.com/livepeer/control-center/secrets"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Client struct {
	Directory string
	mu        sync.Mutex
	nextRenew time.Time
	activated bool
}

func (c *Client) Enabled() bool {
	_, e := os.Stat(filepath.Join(c.Directory, "managed"))
	return e == nil
}

// IdentityReady describes local credential readiness, not service availability.
func (c *Client) IdentityReady() bool {
	if !c.Enabled() {
		return false
	}
	pair, e := tls.LoadX509KeyPair(filepath.Join(c.Directory, "certificate.pem"), filepath.Join(c.Directory, "key.pem"))
	if e != nil {
		return false
	}
	cert, e := x509.ParseCertificate(pair.Certificate[0])
	now := time.Now()
	return e == nil && !now.Before(cert.NotBefore) && now.Before(cert.NotAfter)
}
func (c *Client) call(ctx context.Context, path string, in, out any, identity bool) error {
	raw, e := os.ReadFile(filepath.Join(c.Directory, "url"))
	if e != nil {
		return protocol.ErrUnavailable
	}
	u, e := url.Parse(strings.TrimSpace(string(raw)))
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return protocol.ErrUnavailable
	}
	body, _ := json.Marshal(in)
	req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(u.String(), "/")+path, bytes.NewReader(body))
	if e != nil {
		return protocol.ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if identity {
		cert, e := tls.LoadX509KeyPair(filepath.Join(c.Directory, "certificate.pem"), filepath.Join(c.Directory, "key.pem"))
		if e != nil {
			return protocol.ErrUnavailable
		}
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}}
		defer transport.CloseIdleConnections()
		client.Transport = transport
	}
	res, e := client.Do(req)
	if e != nil {
		return protocol.ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		var v struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&v)
		switch v.Code {
		case "assignment_refused", "identity_refused":
			return protocol.ErrDenied
		case "secret_missing", "secret_unprovisioned":
			return errors.New(v.Code)
		case "version_changed", "authorization_changed":
			return errors.New("secret_changed")
		}
		return protocol.ErrUnavailable
	}
	if json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(out) != nil {
		return protocol.ErrUnavailable
	}
	return nil
}
func (c *Client) Renew(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().Before(c.nextRenew) {
		return nil
	}
	raw, e := os.ReadFile(filepath.Join(c.Directory, "certificate.pem"))
	if e != nil {
		return protocol.ErrUnavailable
	}
	pair, e := tls.X509KeyPair(raw, mustRead(filepath.Join(c.Directory, "key.pem")))
	if e != nil {
		return protocol.ErrUnavailable
	}
	cert, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return protocol.ErrUnavailable
	}
	var id protocol.Identity
	if time.Now().Before(cert.NotAfter) {
		if time.Until(cert.NotAfter) > 12*time.Hour {
			c.nextRenew = cert.NotAfter.Add(-12 * time.Hour)
			return nil
		}
		e = c.call(ctx, "/v1/machines/renew", struct{}{}, &id, true)
	} else {
		key, e2 := protocol.ParsePrivate(mustRead(filepath.Join(c.Directory, "key.pem")))
		if e2 != nil {
			return e2
		}
		var challenge struct {
			ID    string `json:"challenge_id"`
			Nonce []byte `json:"nonce"`
		}
		node := cert.Subject.CommonName
		e = c.call(ctx, "/v1/machines/recover", map[string]string{"node_id": node}, &challenge, false)
		if e == nil {
			sig := ed25519.Sign(key, append([]byte("lpcc-recovery-v1\n"+challenge.ID+"\n"), challenge.Nonce...))
			e = c.call(ctx, "/v1/machines/recover", map[string]any{"node_id": node, "challenge_id": challenge.ID, "signature": sig}, &id, false)
		}
	}
	if e != nil {
		return e
	}
	if e = artifact.AtomicWrite(filepath.Join(c.Directory, "certificate.pem"), id.Certificate, 0600); e != nil {
		return e
	}
	c.nextRenew = time.Now().Add(12 * time.Hour)
	return nil
}
func (c *Client) Activate(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activated {
		return nil
	}
	var result struct {
		Activated bool `json:"activated"`
	}
	if e := c.call(ctx, "/v1/machines/activate", map[string]bool{"admission_ready": true}, &result, true); e != nil {
		return e
	}
	if !result.Activated {
		return protocol.ErrUnavailable
	}
	c.activated = true
	return nil
}
func mustRead(path string) []byte { b, _ := os.ReadFile(path); return b }
func (c *Client) Versions(ctx context.Context, in protocol.ResolveRequest) (protocol.VersionSet, error) {
	var v protocol.VersionSet
	if e := c.Renew(ctx); e != nil {
		return v, e
	}
	e := c.call(ctx, "/v1/runtime/versions", in, &v, true)
	return v, e
}
func (c *Client) Resolve(ctx context.Context, in protocol.ResolveRequest) (protocol.VersionSet, error) {
	var v protocol.VersionSet
	if e := c.Renew(ctx); e != nil {
		return v, e
	}
	e := c.call(ctx, "/v1/runtime/resolve", in, &v, true)
	return v, e
}

func (c *Client) MarkManaged() error {
	if e := os.MkdirAll(c.Directory, 0700); e != nil {
		return e
	}
	return artifact.AtomicWrite(filepath.Join(c.Directory, "managed"), []byte("1"), 0600)
}

func (c *Client) VersionsAll(ctx context.Context, requests []protocol.ResolveRequest) (map[string]protocol.VersionSet, map[string]string, error) {
	var out struct {
		Sets   map[string]protocol.VersionSet `json:"sets"`
		Errors map[string]string              `json:"errors"`
	}
	if e := c.Renew(ctx); e != nil {
		return nil, nil, e
	}
	e := c.call(ctx, "/v1/runtime/batch", map[string]any{"assignments": requests}, &out, true)
	return out.Sets, out.Errors, e
}
