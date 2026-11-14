package tunnel

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
	"slices"
	"strconv"
	"time"
)

var ErrResourceConflict = errors.New("resource ownership conflict in Cloudflare")
var errAmbiguousCreate = errors.New("unknown Cloudflare create outcome; waiting for owned resource")

type ProviderError struct {
	Status    int
	Ambiguous bool
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("Cloudflare operation failed (status %d)", e.Status)
}

type cloudflareHTTP struct {
	params Config
	client *http.Client
	base   string
}

func (c *cloudflareHTTP) account() string { return "/accounts/" + c.params.CloudflareAccountID }
func (c *cloudflareHTTP) resourcePath(r CFResource) string {
	switch r.Kind {
	case "tunnel":
		return c.account() + "/cfd_tunnel"
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
		return 0, &ProviderError{Ambiguous: method != "GET"}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 && method == http.MethodDelete {
		return 0, nil
	}
	if resp.StatusCode == http.StatusNoContent && method == http.MethodDelete {
		return 0, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, &ProviderError{Status: resp.StatusCode, Ambiguous: resp.StatusCode >= 500}
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
		return 0, &ProviderError{Status: resp.StatusCode, Ambiguous: method != "GET"}
	}
	if out != nil && json.Unmarshal(envelope.Result, out) != nil {
		return 0, &ProviderError{Status: resp.StatusCode, Ambiguous: method != "GET"}
	}
	return envelope.Info.TotalPages, nil
}

type cfObject struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Comment   string     `json:"comment"`
	ConfigSrc string     `json:"config_src"`
	DeletedAt *time.Time `json:"deleted_at"`
	Content   string     `json:"content"`
	Proxied   bool       `json:"proxied"`
}

func sameHosts(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
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
		var failure *ProviderError
		missing := errors.As(e, &failure) && failure.Status == 404
		if e != nil && !missing {
			return nil, e
		}
		// Deleted tunnels retain an ID/name tombstone but lose config_src.
		// Confirm its identity before treating that provider evidence as absence.
		if !missing && r.Kind == "tunnel" && o.DeletedAt != nil && !o.DeletedAt.IsZero() {
			if o.ID != r.ID || o.Name != r.Name {
				return nil, ErrResourceConflict
			}
			missing = true
		}
		if !missing && (!resourceOwned(r, o) || o.ID != r.ID) {
			return nil, ErrResourceConflict
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
			var failure *ProviderError
			if ownedOnly && errors.As(e, &failure) && failure.Status == 404 {
				return nil, nil
			}
			return nil, e
		}
		for _, o := range objects {
			owned := resourceOwned(r, o)
			switch r.Kind {
			case "dns":
				if !ownedOnly && o.Name == r.Host && !owned {
					return nil, ErrResourceConflict
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
	return nil, errors.New("resource listing from Cloudflare exceeds limit")
}

func resourceOwned(r CFResource, o cfObject) bool {
	switch r.Kind {
	case "dns":
		return o.Name == r.Host && o.Type == "CNAME" && o.Comment == r.Name
	case "tunnel":
		return o.Name == r.Name && o.ConfigSrc == "cloudflare"
	}
	return false
}
func observedResource(r CFResource, o cfObject) CFResource {
	r.ID = o.ID
	r.Pending = false
	r.Target = o.Content
	r.Proxied = o.Proxied
	return r
}
func (c *cloudflareHTTP) Create(ctx context.Context, r CFResource, tunnel string) (CFResource, error) {
	input := map[string]any{"name": r.Name}
	switch r.Kind {
	case "tunnel":
		secret := make([]byte, 32)
		if _, e := rand.Read(secret); e != nil {
			return r, e
		}
		input["config_src"] = "cloudflare"
		input["tunnel_secret"] = base64.StdEncoding.EncodeToString(secret)
	case "dns":
		input = map[string]any{"name": r.Host, "type": "CNAME", "proxied": true, "content": tunnel + ".cfargotunnel.com", "comment": r.Name}
	default:
		return r, errors.New("unknown Cloudflare resource")
	}
	var o cfObject
	_, e := c.call(ctx, "POST", c.resourcePath(r), input, &o)
	if e != nil {
		return r, e
	}
	if o.ID == "" {
		return r, errAmbiguousCreate
	}
	r.ID = o.ID
	r.Pending = false
	return r, nil
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
			if r[i].OriginRequest != nil && r[i].OriginRequest.HTTPHostHeader == "" {
				r[i].OriginRequest = nil
			}
		}
		return r
	}
	if e == nil && ingressHash(clean(current.Config.Ingress)) == ingressHash(rules) {
		return current.Version, nil
	}
	if e != nil {
		var failure *ProviderError
		if !errors.As(e, &failure) || failure.Status != 404 {
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
		return 0, errors.New("ingress readback mismatch from Cloudflare")
	}
	return current.Version, nil
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
					return errors.New("pending Cloudflare deletion readback")
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
