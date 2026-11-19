package controlplane

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const uiOrigin = "https://controlcenter.example"

func edgeRequest(h http.Handler, method, target string, headers map[string]string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func edgeServer(t *testing.T, change func(*Params)) *Server {
	t.Helper()
	p := testParams()
	p.AllowedOrigins = []string{uiOrigin}
	if change != nil {
		change(&p)
	}
	return New(nil, p, nil)
}

func TestCORSPreflight(t *testing.T) {
	h := edgeServer(t, nil).Handler()
	preflight := func(origin, target string) *httptest.ResponseRecorder {
		return edgeRequest(h, http.MethodOptions, target, map[string]string{"Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type"}, "")
	}
	w := preflight(uiOrigin, "/api/bootstrap-token")
	if w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body.String())
	}
	for header, want := range map[string]string{
		"Access-Control-Allow-Origin":  uiOrigin,
		"Access-Control-Allow-Methods": corsAllowMethods,
		"Access-Control-Allow-Headers": corsAllowHeaders,
		"Access-Control-Max-Age":       corsMaxAge,
	} {
		if got := w.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("preflight allowed credentials")
	}
	for _, origin := range []string{"https://evil.example", "https://controlcenter.example.evil.example", "null", strings.ToUpper(uiOrigin)} {
		w := preflight(origin, "/api/bootstrap-token")
		if w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("origin %q: %d %v", origin, w.Code, w.Header())
		}
	}
	// Only the browser API is cross-origin; machine and discovery routes are not.
	for _, target := range []string{"/v1/nodes/register", "/discovery", "/internal/redemption/authorize"} {
		if w := preflight(uiOrigin, target); w.Code == http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("%s answered a CORS preflight: %d", target, w.Code)
		}
	}
}

func TestCORSResponses(t *testing.T) {
	h := edgeServer(t, nil).Handler()
	for origin, want := range map[string]string{uiOrigin: uiOrigin, "https://evil.example": "", "": ""} {
		headers := map[string]string{}
		if origin != "" {
			headers["Origin"] = origin
		}
		w := edgeRequest(h, http.MethodGet, "/api/config", headers, "")
		if w.Code != http.StatusOK {
			t.Fatalf("origin %q: %d %s", origin, w.Code, w.Body.String())
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != want {
			t.Fatalf("origin %q: Access-Control-Allow-Origin = %q, want %q", origin, got, want)
		}
		if w.Header().Get("Vary") != "Origin" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("origin %q: headers %v", origin, w.Header())
		}
	}
	// Authorization still applies to allowed origins.
	w := edgeRequest(h, http.MethodGet, "/api/operator/config", map[string]string{"Origin": uiOrigin}, "")
	if w.Code != http.StatusUnauthorized || w.Header().Get("Access-Control-Allow-Origin") != uiOrigin {
		t.Fatal(w.Code, w.Header())
	}
	// Without configured origins no browser origin is allowed.
	h = edgeServer(t, func(p *Params) { p.AllowedOrigins = nil }).Handler()
	if w := edgeRequest(h, http.MethodGet, "/api/config", map[string]string{"Origin": uiOrigin}, ""); w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("allowed an unconfigured origin")
	}
}

func TestPublicHandlerHidesPrivateRoutes(t *testing.T) {
	h := edgeServer(t, nil).PublicHandler()
	for _, tc := range []struct{ method, target string }{
		{http.MethodPost, "/internal/redemption/authorize"},
		{http.MethodGet, "/internal"},
		{http.MethodGet, "/metrics"},
		{http.MethodPut, "/internal/secrets/nodes/node-1"},
		{http.MethodHead, "/internal/secrets/nodes/node-1"},
		{http.MethodPost, "/internal/users/u/orchestrators/0xabc"},
		{http.MethodGet, "/internal/secrets/nodes/node-1/extra"},
		{http.MethodGet, "/api/../internal/users/u/orchestrators/0xabc"},
		{http.MethodGet, "//internal/secrets/nodes/node-1"},
		{http.MethodGet, "/%69nternal/redemption/authorize"},
		{http.MethodGet, "/internal/secrets/nodes/../../redemption/authorize"},
	} {
		w := edgeRequest(h, tc.method, tc.target, map[string]string{"Authorization": "Bearer " + strings.Repeat("m", 32)}, "")
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s %s = %d %s", tc.method, tc.target, w.Code, w.Body.String())
		}
	}
	// As with the former Caddy site, a secrets service on another host can
	// still reach its metadata callbacks; they require the metadata token.
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/internal/secrets/nodes/node-1"},
		{http.MethodPost, "/internal/secrets/nodes/node-1"},
		{http.MethodGet, "/internal/users/u/orchestrators/0xabc"},
	} {
		if w := edgeRequest(h, tc.method, tc.target, nil, ""); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Fatalf("%s %s = %d, want the handler's credential refusal", tc.method, tc.target, w.Code)
		}
	}
	for _, target := range []string{"/healthz", "/api/config"} {
		if w := edgeRequest(h, http.MethodGet, target, nil, ""); w.Code != http.StatusOK || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s = %d", target, w.Code)
		}
	}
	w := edgeRequest(h, http.MethodOptions, "/api/machines", map[string]string{"Origin": uiOrigin, "Access-Control-Request-Method": "GET"}, "")
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != uiOrigin {
		t.Fatal("public listener lost CORS", w.Code)
	}
}

func TestPublicHandlerRedemption(t *testing.T) {
	var got struct{ method, path, query, body, host, forwarded string }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.method, got.path, got.query, got.body, got.host, got.forwarded = r.Method, r.URL.Path, r.URL.RawQuery, string(body), r.Host, r.Header.Get("X-Forwarded-Proto")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"accepted":1}`)
	}))
	defer upstream.Close()
	h := edgeServer(t, func(p *Params) { p.PublicListen = "127.0.0.1:0"; p.RedeemerUpstreamURL = upstream.URL }).PublicHandler()

	r := httptest.NewRequest(http.MethodPost, "https://api.example/redemption/tickets?batch=1", strings.NewReader(`{"ticket":"t"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted || w.Body.String() != `{"accepted":1}` {
		t.Fatal(w.Code, w.Body.String())
	}
	if got.method != http.MethodPost || got.path != "/tickets" || got.query != "batch=1" || got.body != `{"ticket":"t"}` || got.host != "api.example" || got.forwarded != "https" {
		t.Fatalf("upstream saw %+v", got)
	}

	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/redemption/tickets"},
		{http.MethodPut, "/redemption/tickets"},
		{http.MethodPost, "/redemption/other"},
		{http.MethodPost, "/redemption"},
		{http.MethodPost, "/redemption/tickets/extra"},
		{http.MethodPost, "/redemption//tickets"},
	} {
		got.method = ""
		if w := edgeRequest(h, tc.method, tc.target, nil, "{}"); w.Code != http.StatusNotFound || got.method != "" {
			t.Fatalf("%s %s = %d (upstream %q)", tc.method, tc.target, w.Code, got.method)
		}
	}

	upstream.Close()
	if w := edgeRequest(h, http.MethodPost, "/redemption/tickets", nil, "{}"); w.Code != http.StatusBadGateway {
		t.Fatal("unreachable redeemer", w.Code)
	}
	h = edgeServer(t, nil).PublicHandler()
	if w := edgeRequest(h, http.MethodPost, "/redemption/tickets", nil, "{}"); w.Code != http.StatusNotFound {
		t.Fatal("redemption served without an upstream", w.Code)
	}
}

func TestEdgeConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		change func(*Params)
		want   string
	}{
		{func(p *Params) { p.AllowedOrigins = []string{"*"} }, "AllowedOrigins"},
		{func(p *Params) { p.AllowedOrigins = []string{"https://ui.example/"} }, "AllowedOrigins"},
		{func(p *Params) { p.AllowedOrigins = []string{"https://UI.example"} }, "AllowedOrigins"},
		{func(p *Params) { p.AllowedOrigins = []string{"http://ui.example"} }, "AllowedOrigins"},
		{func(p *Params) { p.AllowedOrigins = []string{"null"} }, "AllowedOrigins"},
		{func(p *Params) { p.PublicListen = p.Listen }, "PublicListen"},
		{func(p *Params) { p.RedeemerUpstreamURL = "http://redeemer:8941" }, "requires PublicListen"},
		{func(p *Params) {
			p.PublicListen = "0.0.0.0:43811"
			p.RedeemerUpstreamURL = "http://redeemer:8941/tickets"
		}, "RedeemerUpstreamURL"},
		{func(p *Params) { p.PublicListen = "0.0.0.0:43811"; p.RedeemerUpstreamURL = "ftp://redeemer" }, "RedeemerUpstreamURL"},
	} {
		p := testParams()
		p.Listen = "0.0.0.0:43812"
		tc.change(&p)
		if err := p.PreValidate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("got %v, want %q", err, tc.want)
		}
	}
	p := testParams()
	p.Listen, p.PublicListen = "0.0.0.0:43812", "0.0.0.0:43811"
	p.AllowedOrigins = []string{"https://controlcenter.livepeer.live", "http://localhost:5173"}
	p.RedeemerUpstreamURL = "http://redeemer:8941"
	if err := p.PreValidate(); err != nil {
		t.Fatal(err)
	}
}
