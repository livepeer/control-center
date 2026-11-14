// Package secretclient keeps machine credentials and decrypted values out of artifacts.
package secretclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
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
	activated bool
}

// IdentityReady describes local credential readiness, not service availability.
func (c *Client) IdentityReady() bool {
	_, _, e := c.identity()
	return e == nil
}
func (c *Client) identity() (protocol.Identity, ed25519.PrivateKey, error) {
	var id protocol.Identity
	raw, e := os.ReadFile(filepath.Join(c.Directory, "identity.json"))
	if e != nil || json.Unmarshal(raw, &id) != nil || id.NodeID == "" || id.Owner == "" || id.Generation < 1 {
		return id, nil, protocol.ErrUnavailable
	}
	key, e := protocol.ParsePrivate(mustRead(filepath.Join(c.Directory, "key.pem")))
	if id.Service == nil {
		return id, nil, protocol.ErrUnavailable
	}
	if _, err := protocol.PublicKey(id.Service.PublicKey); err != nil {
		return id, nil, protocol.ErrUnavailable
	}
	return id, key, e
}
func (c *Client) call(ctx context.Context, path string, in, out any) error {
	raw, e := os.ReadFile(filepath.Join(c.Directory, "url"))
	if e != nil {
		return protocol.ErrUnavailable
	}
	u, e := url.Parse(strings.TrimSpace(string(raw)))
	if e != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return protocol.ErrUnavailable
	}
	body, _ := json.Marshal(in)
	req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(u.String(), "/")+path, bytes.NewReader(body))
	if e != nil {
		return protocol.ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	id, key, e := c.identity()
	if e != nil || protocol.SignRequest(req, body, id, key, time.Now()) != nil {
		return protocol.ErrUnavailable
	}
	res, e := client.Do(req)
	if e != nil {
		return protocol.ErrUnavailable
	}
	defer res.Body.Close()
	response, e := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	if e != nil || len(response) > 2<<20 || id.Service.VerifyResponse(req, body, response, res) != nil {
		return protocol.ErrUnavailable
	}
	if res.StatusCode != 200 {
		var v struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(response, &v)
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
	if json.Unmarshal(response, out) != nil {
		return protocol.ErrUnavailable
	}
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
	if e := c.call(ctx, "/v1/machines/activate", map[string]bool{"admission_ready": true}, &result); e != nil {
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
	e := c.call(ctx, "/v1/runtime/versions", in, &v)
	return v, e
}
func (c *Client) Resolve(ctx context.Context, in protocol.ResolveRequest) (protocol.VersionSet, error) {
	var v protocol.VersionSet
	recipient, e := protocol.EncryptionKEM().GenerateKey()
	if e != nil {
		return v, protocol.ErrUnavailable
	}
	request := protocol.DeliveryRequest{ResolveRequest: in, RecipientKey: recipient.PublicKey().Bytes()}
	if e = c.call(ctx, "/v1/runtime/resolve", request, &v); e != nil {
		return v, e
	}
	id, _, e := c.identity()
	if e != nil {
		return protocol.VersionSet{}, protocol.ErrUnavailable
	}
	for i := range v.Values {
		v.Values[i].DataKey, e = protocol.OpenDataKey(recipient, protocol.KeyInfo("delivery", id.Service.Origin, v.Values[i].Binding), v.Values[i].SealedKey)
		if e != nil {
			for j := range v.Values {
				clear(v.Values[j].DataKey)
			}
			return protocol.VersionSet{}, protocol.ErrUnavailable
		}
		v.Values[i].SealedKey = nil
	}
	return v, nil
}

func (c *Client) VersionsAll(ctx context.Context, requests []protocol.ResolveRequest) (map[string]protocol.VersionSet, map[string]string, error) {
	var out struct {
		Sets   map[string]protocol.VersionSet `json:"sets"`
		Errors map[string]string              `json:"errors"`
	}
	e := c.call(ctx, "/v1/runtime/batch", map[string]any{"assignments": requests}, &out)
	return out.Sets, out.Errors, e
}
