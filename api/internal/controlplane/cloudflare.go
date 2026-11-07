package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

var errResourceConflict = errors.New("Cloudflare resource ownership conflict")
var errUnsafeProtection = errors.New("Cloudflare Access protection readback is unsafe")
var errAmbiguousCreate = errors.New("Cloudflare create outcome unknown; waiting for owned resource")

type cloudflareFailure struct {
	status    int
	ambiguous bool
}

func (e *cloudflareFailure) Error() string {
	return fmt.Sprintf("Cloudflare operation failed (status %d)", e.status)
}

type cloudflareHTTP struct {
	params TunnelParams
	client *http.Client
	base   string
}

func (c *cloudflareHTTP) account() string { return "/accounts/" + c.params.CloudflareAccountID }
func (c *cloudflareHTTP) resourcePath(r CFResource) string {
	switch r.Kind {
	case "tunnel":
		return c.account() + "/cfd_tunnel"
	case "token":
		return c.account() + "/access/service_tokens"
	case "app":
		return c.account() + "/access/apps"
	case "policy":
		return c.account() + "/access/apps/" + url.PathEscape(r.Host) + "/policies"
	case "dns":
		return "/zones/" + c.params.CloudflareZoneID + "/dns_records"
	}
	return ""
}
func (c *cloudflareHTTP) call(ctx context.Context, method, path string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return 0, e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if e != nil {
		return 0, errors.New("invalid Cloudflare operation")
	}
	req.Header.Set("Authorization", "Bearer "+c.params.CloudflareAPIToken)
	req.Header.Set("Content-Type", "application/json")
	resp, e := c.client.Do(req)
	if e != nil {
		return 0, &cloudflareFailure{ambiguous: method != "GET"}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 && method == http.MethodDelete {
		return 0, nil
	}
	if resp.StatusCode == http.StatusNoContent && method == http.MethodDelete {
		return 0, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, &cloudflareFailure{status: resp.StatusCode, ambiguous: resp.StatusCode >= 500}
	}
	var envelope struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
		Info    struct {
			TotalPages int `json:"total_pages"`
		} `json:"result_info"`
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if e != nil || len(b) > 4<<20 || json.Unmarshal(b, &envelope) != nil || !envelope.Success {
		return 0, &cloudflareFailure{status: resp.StatusCode, ambiguous: method != "GET"}
	}
	if out != nil && json.Unmarshal(envelope.Result, out) != nil {
		return 0, &cloudflareFailure{status: resp.StatusCode, ambiguous: method != "GET"}
	}
	return envelope.Info.TotalPages, nil
}

type cfObject struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Domain       string          `json:"domain"`
	Audience     string          `json:"aud"`
	Type         string          `json:"type"`
	Comment      string          `json:"comment"`
	ConfigSrc    string          `json:"config_src"`
	Tags         json.RawMessage `json:"tags"`
	ClientID     string          `json:"client_id"`
	ClientSecret string          `json:"client_secret"`
	ExpiresAt    time.Time       `json:"expires_at"`
	CreatedAt    time.Time       `json:"created_at"`
	DeletedAt    *time.Time      `json:"deleted_at"`
	Content      string          `json:"content"`
	Proxied      bool            `json:"proxied"`
}

func (c *cloudflareHTTP) Find(ctx context.Context, r CFResource) ([]CFResource, error) {
	return c.find(ctx, r, false)
}
func (c *cloudflareHTTP) FindOwned(ctx context.Context, r CFResource) ([]CFResource, error) {
	return c.find(ctx, r, true)
}
func (c *cloudflareHTTP) find(ctx context.Context, r CFResource, ownedOnly bool) ([]CFResource, error) {
	var selected *CFResource
	if r.ID != "" {
		var o cfObject
		_, e := c.call(ctx, "GET", c.resourcePath(r)+"/"+url.PathEscape(r.ID), nil, &o)
		var failure *cloudflareFailure
		missing := errors.As(e, &failure) && failure.status == 404
		if e != nil && !missing {
			return nil, e
		}
		if !missing && (!resourceOwned(r, o) || o.ID != r.ID) {
			return nil, errResourceConflict
		}
		if !missing && (r.Kind != "tunnel" || o.DeletedAt == nil || o.DeletedAt.IsZero()) {
			v := observedResource(r, o)
			selected = &v
		}
		if !r.Watch {
			if selected != nil {
				return []CFResource{*selected}, nil
			}
			return nil, nil
		}
	}
	var found []CFResource
	if selected != nil {
		found = append(found, *selected)
	}
	for page := 1; page <= 100; page++ {
		q := url.Values{"page": {strconv.Itoa(page)}, "per_page": {"100"}}
		if r.Kind == "tunnel" {
			q.Set("is_deleted", "false")
			q.Set("name", r.Name)
		}
		if r.Kind == "dns" {
			q.Set("name", r.Host)
		}
		var objects []cfObject
		pages, e := c.call(ctx, "GET", c.resourcePath(r)+"?"+q.Encode(), nil, &objects)
		if e != nil {
			var failure *cloudflareFailure
			if ownedOnly && errors.As(e, &failure) && failure.status == 404 {
				return nil, nil
			}
			return nil, e
		}
		for _, o := range objects {
			owned := resourceOwned(r, o)
			switch r.Kind {
			case "dns":
				if !ownedOnly && o.Name == r.Host && !owned {
					return nil, errResourceConflict
				}
			case "app":
				if !ownedOnly && o.Domain == r.Host && !owned {
					return nil, errResourceConflict
				}
			}
			if owned && o.ID != "" && (selected == nil || o.ID != selected.ID) && (r.Kind != "tunnel" || o.DeletedAt == nil || o.DeletedAt.IsZero()) {
				found = append(found, observedResource(r, o))
			}
		}
		if (pages > 0 && page >= pages) || (pages == 0 && len(objects) < 100) {
			return found, nil
		}
	}
	return nil, errors.New("Cloudflare resource listing exceeds limit")
}

func resourceOwned(r CFResource, o cfObject) bool {
	switch r.Kind {
	case "dns":
		return o.Name == r.Host && o.Type == "CNAME" && o.Comment == r.Name
	case "token":
		var tags map[string]string
		return json.Unmarshal(o.Tags, &tags) == nil && o.Name == r.Name && tags["lpcc-owner"] == r.Name
	case "app":
		return o.Name == r.Name && o.Domain == r.Host && o.Type == "self_hosted"
	case "tunnel":
		return o.Name == r.Name && o.ConfigSrc == "cloudflare"
	case "policy":
		return o.Name == r.Name // parent Access application scopes the lookup
	}
	return false
}
func observedResource(r CFResource, o cfObject) CFResource {
	r.ID = o.ID
	r.Pending = false
	r.Audience = o.Audience
	r.Target = o.Content
	r.Proxied = o.Proxied
	return r
}
func (c *cloudflareHTTP) Create(ctx context.Context, r CFResource, tunnel string) (CFResource, *AccessCredential, time.Time, error) {
	input := map[string]any{"name": r.Name}
	switch r.Kind {
	case "tunnel":
		secret := make([]byte, 32)
		if _, e := rand.Read(secret); e != nil {
			return r, nil, time.Time{}, e
		}
		input["config_src"] = "cloudflare"
		input["tunnel_secret"] = base64.StdEncoding.EncodeToString(secret)
	case "token":
		duration := r.Duration
		if duration == "" {
			duration = c.params.CloudflareAccessLifetime.String()
		}
		input["duration"] = duration
		input["tags"] = map[string]string{"lpcc-owner": r.Name}
	case "app":
		input["domain"] = r.Host
		input["type"] = "self_hosted"
		input["app_launcher_visible"] = false
	case "policy":
		input["decision"] = "non_identity"
		input["include"] = []any{map[string]any{"service_token": map[string]string{"token_id": tunnel}}}
	case "dns":
		input = map[string]any{"name": r.Host, "type": "CNAME", "proxied": true, "content": tunnel + ".cfargotunnel.com", "comment": r.Name}
	default:
		return r, nil, time.Time{}, errors.New("unknown Cloudflare resource")
	}
	var o cfObject
	_, e := c.call(ctx, "POST", c.resourcePath(r), input, &o)
	if e != nil {
		return r, nil, time.Time{}, e
	}
	if o.ID == "" {
		return r, nil, time.Time{}, errAmbiguousCreate
	}
	r.ID = o.ID
	r.Pending = false
	r.Audience = o.Audience
	if r.Kind == "token" {
		if o.ClientID == "" || o.ClientSecret == "" {
			return r, nil, time.Time{}, errAmbiguousCreate
		}
		expiry := o.ExpiresAt
		if expiry.IsZero() {
			if o.CreatedAt.IsZero() {
				return r, nil, time.Time{}, errAmbiguousCreate
			}
			duration := c.params.CloudflareAccessLifetime
			if r.Duration != "" {
				if parsed, err := time.ParseDuration(r.Duration); err == nil {
					duration = parsed
				}
			}
			expiry = o.CreatedAt.Add(duration)
		}
		return r, &AccessCredential{o.ClientID, o.ClientSecret}, expiry, nil
	}
	return r, nil, time.Time{}, nil
}
func (c *cloudflareHTTP) Configure(ctx context.Context, id string, rules []IngressRule) (int64, error) {
	path := c.account() + "/cfd_tunnel/" + url.PathEscape(id) + "/configurations"
	type config struct {
		Version int64 `json:"version"`
		Config  struct {
			Ingress []IngressRule `json:"ingress"`
		} `json:"config"`
	}
	var current config
	_, e := c.call(ctx, "GET", path, nil, &current)
	clean := func(r []IngressRule) []IngressRule {
		for i := range r {
			if r[i].OriginRequest != nil && r[i].OriginRequest.Access == nil {
				r[i].OriginRequest = nil
			}
		}
		return r
	}
	if e == nil && ingressHash(clean(current.Config.Ingress)) == ingressHash(rules) {
		return current.Version, nil
	}
	if e != nil {
		var failure *cloudflareFailure
		if !errors.As(e, &failure) || failure.status != 404 {
			return 0, e
		}
	}
	if _, e = c.call(ctx, "PUT", path, map[string]any{"config": map[string]any{"ingress": rules}}, &current); e != nil {
		return 0, e
	}
	if _, e = c.call(ctx, "GET", path, nil, &current); e != nil {
		return 0, e
	}
	if ingressHash(clean(current.Config.Ingress)) != ingressHash(rules) {
		return 0, errors.New("Cloudflare ingress readback mismatch")
	}
	return current.Version, nil
}
func (c *cloudflareHTTP) Protect(ctx context.Context, policy CFResource, tokens []string) error {
	// Dedicated application: an unexpected policy could bypass Service Auth.
	var policies []cfObject
	if _, e := c.call(ctx, "GET", c.resourcePath(policy), nil, &policies); e != nil {
		return e
	}
	for _, p := range policies {
		if p.ID != policy.ID {
			return errResourceConflict
		}
	}
	include := make([]any, 0, len(tokens))
	for _, id := range tokens {
		include = append(include, map[string]any{"service_token": map[string]string{"token_id": id}})
	}
	input := map[string]any{"name": policy.Name, "decision": "non_identity", "include": include}
	if _, e := c.call(ctx, "PUT", c.resourcePath(policy)+"/"+url.PathEscape(policy.ID), input, nil); e != nil {
		return e
	}
	var read struct {
		Decision string `json:"decision"`
		Include  []struct {
			Token struct {
				ID string `json:"token_id"`
			} `json:"service_token"`
		} `json:"include"`
	}
	if _, e := c.call(ctx, "GET", c.resourcePath(policy)+"/"+url.PathEscape(policy.ID), nil, &read); e != nil {
		return e
	}
	if read.Decision != "non_identity" || len(read.Include) != len(tokens) {
		return errUnsafeProtection
	}
	seen := map[string]bool{}
	for _, v := range read.Include {
		seen[v.Token.ID] = true
	}
	for _, id := range tokens {
		if !seen[id] {
			return errUnsafeProtection
		}
	}
	return nil
}
func (c *cloudflareHTTP) ConnectorToken(ctx context.Context, id string) (string, error) {
	var token string
	_, e := c.call(ctx, "GET", c.account()+"/cfd_tunnel/"+url.PathEscape(id)+"/token", nil, &token)
	if e == nil && (len(token) < 20 || len(token) > 8192) {
		return "", errors.New("invalid connector credential response")
	}
	return token, e
}
func (c *cloudflareHTTP) RotateConnector(ctx context.Context, id string) error {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return e
	}
	_, e := c.call(ctx, "PATCH", c.account()+"/cfd_tunnel/"+url.PathEscape(id), map[string]any{"tunnel_secret": base64.StdEncoding.EncodeToString(b)}, nil)
	return e
}
func (c *cloudflareHTTP) Disconnect(ctx context.Context, id string) error {
	_, e := c.call(ctx, "DELETE", c.account()+"/cfd_tunnel/"+url.PathEscape(id)+"/connections", nil, nil)
	return e
}
func (c *cloudflareHTTP) Delete(ctx context.Context, r CFResource, _ string) error {
	if r.ID == "" {
		return nil
	}
	found, e := c.FindOwned(ctx, r)
	if e != nil {
		return e
	}
	for _, v := range found {
		if v.ID == r.ID {
			_, e = c.call(ctx, "DELETE", c.resourcePath(r)+"/"+url.PathEscape(r.ID), nil, nil)
			if e != nil {
				return e
			}
			remaining, e := c.FindOwned(ctx, r)
			if e != nil {
				return e
			}
			for _, v := range remaining {
				if v.ID == r.ID {
					return errors.New("Cloudflare deletion readback pending")
				}
			}
			return nil
		}
	}
	return nil
}

func (c *cloudflareHTTP) Route(ctx context.Context, r CFResource, tunnel string) error {
	_, e := c.call(ctx, "PUT", c.resourcePath(r)+"/"+url.PathEscape(r.ID), map[string]any{"type": "CNAME", "name": r.Host, "content": tunnel + ".cfargotunnel.com", "proxied": true, "comment": r.Name}, nil)
	return e
}
