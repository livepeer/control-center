package controlplane

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"
)

// The UI is served from its own origin and calls /api/* cross-origin with a
// bearer token. No cookies are involved, so credentials are never allowed.
const (
	corsAllowMethods = "GET, POST, PUT, DELETE"
	corsAllowHeaders = "Authorization, Content-Type"
	corsMaxAge       = "7200"
)

// cors answers preflights and labels responses for allowed browser origins.
// Requests without an Origin header, such as machine and service callers, are
// not affected. A disallowed origin gets no Access-Control-Allow-Origin, so
// the browser withholds the response from the page.
func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Origin")
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		allowed := slices.Contains(s.params.AllowedOrigins, origin)
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			if !allowed {
				fail(w, http.StatusForbidden, "origin not allowed")
				return
			}
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Methods", corsAllowMethods)
			h.Set("Access-Control-Allow-Headers", corsAllowHeaders)
			h.Set("Access-Control-Max-Age", corsMaxAge)
			h.Add("Vary", "Access-Control-Request-Method")
			h.Add("Vary", "Access-Control-Request-Headers")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		next.ServeHTTP(w, r)
	})
}

// publicCallback reports whether r is one of the internal callbacks that a
// secrets service on another host may reach through the public hostname over
// HTTPS. Both require the shared metadata token.
func publicCallback(r *http.Request, clean string) bool {
	if r.URL.Path != clean {
		return false
	}
	p := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	switch {
	case len(p) == 4 && p[0] == "internal" && p[1] == "secrets" && p[2] == "nodes" && p[3] != "":
		return r.Method == http.MethodGet || r.Method == http.MethodPost
	case len(p) == 5 && p[0] == "internal" && p[1] == "users" && p[2] != "" && p[3] == "orchestrators" && p[4] != "":
		return r.Method == http.MethodGet
	}
	return false
}

// PublicHandler serves the Internet-facing API hostname. Other internal
// callbacks and metrics stay on the private listener. Winning-ticket
// submissions under the Node-facing redeemer URL (…/redemption) are forwarded
// to the redeemer.
func (s *Server) PublicHandler() http.Handler {
	api := s.Handler()
	redeemer := s.redeemerProxy()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Match on the cleaned path; the mux redirects unclean paths before routing.
		clean := path.Clean("/" + r.URL.Path)
		switch {
		case publicCallback(r, clean):
			api.ServeHTTP(w, r)
		case clean == "/internal" || strings.HasPrefix(clean, "/internal/") || clean == "/metrics":
			fail(w, http.StatusNotFound, "not found")
		case clean == "/redemption" || strings.HasPrefix(clean, "/redemption/"):
			if redeemer == nil || r.URL.Path != "/redemption/tickets" || r.Method != http.MethodPost {
				fail(w, http.StatusNotFound, "not found")
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			redeemer.ServeHTTP(w, r.WithContext(ctx))
		default:
			api.ServeHTTP(w, r)
		}
	})
}

func (s *Server) redeemerProxy() http.Handler {
	if s.params.RedeemerUpstreamURL == "" {
		return nil
	}
	upstream, err := url.Parse(s.params.RedeemerUpstreamURL)
	if err != nil {
		return nil // PreValidate rejects this before serving.
	}
	upstream.Path = ""
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Path, r.Out.URL.RawPath = "/tickets", ""
			r.SetURL(upstream)
			r.Out.Host = r.In.Host
			r.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if s.logger != nil {
				s.logger.Warn("redeemer request failed", "error", err)
			}
			fail(w, http.StatusBadGateway, "redeemer unavailable")
		},
	}
}
