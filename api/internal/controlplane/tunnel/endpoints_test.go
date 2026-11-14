package tunnel

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type endpointRoundTrip func(*http.Request) (*http.Response, error)

func (fn endpointRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

// This fixture models edge Service Auth separately from origin ingress. Real
// Cloudflare JWT enforcement remains part of the release gate.
func endpointFixture(t *testing.T, state RoutingState, node http.Handler, accepted map[string]string) *http.Client {
	t.Helper()
	rules := ingressFor(state, Config{CloudflareTeamName: "team"}, "audience")
	return &http.Client{Transport: endpointRoundTrip(func(req *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		host := strings.ToLower(req.URL.Hostname())
		if host == endpointHost(state.DiscoveryURL) {
			secret, ok := accepted[req.Header.Get("CF-Access-Client-Id")]
			if !ok || secret != req.Header.Get("CF-Access-Client-Secret") {
				w.WriteHeader(401)
				return w.Result(), nil
			}
		} else if req.Header.Get("CF-Access-Client-Id") != "" || req.Header.Get("CF-Access-Client-Secret") != "" {
			t.Error("credentials sent outside protected hosts")
		}
		for _, rule := range rules {
			if rule.Hostname != "" && rule.Hostname != host && !(strings.HasPrefix(rule.Hostname, "*.") && strings.HasSuffix(host, rule.Hostname[1:])) {
				continue
			}
			if rule.Path != "" && !regexp.MustCompile(rule.Path).MatchString(req.URL.Path) {
				continue
			}
			if rule.Service == "http_status:404" {
				w.WriteHeader(404)
				return w.Result(), nil
			}
			clone := req.Clone(req.Context())
			clone.RequestURI = ""
			if rule.OriginRequest != nil {
				if access := rule.OriginRequest.Access; access != nil {
					if !access.Required || len(access.Audience) != 1 || access.Audience[0] != "audience" || host != endpointHost(state.DiscoveryURL) {
						t.Error("invalid discovery audience")
					}
					clone.Header.Set("Cf-Access-Jwt-Assertion", "edge-assertion")
				}
				clone.Host = rule.OriginRequest.HTTPHostHeader
				if clone.Host != endpointHost(PrivateOrchestrator) {
					t.Error("origin Host not rewritten")
				}
			} else {
				clone.Host = req.URL.Host
			}
			node.ServeHTTP(w, clone)
			return w.Result(), nil
		}
		panic("missing catch-all")
	})}
}

func TestReadinessRequiresPublicAPIProtectedDiscoveryAndIsolation(t *testing.T) {
	state := RoutingFor("vkvkvkvkvkvkuaaaaaaaaaaaaa", "example.invalid").RoutingState
	creds := AccessCredential{ClientID: "current", ClientSecret: "secret"}
	node := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != endpointHost(PrivateOrchestrator) {
			w.WriteHeader(404)
			return
		}
		if r.URL.Path == "/discovery" {
			_ = json.NewEncoder(w).Encode([]map[string]string{{"address": state.ServiceURL}})
			return
		}
		if r.URL.Path == "/apps/lpcc-readiness/session" {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(405)
			return
		}
		w.WriteHeader(404)
	})
	client := endpointFixture(t, state, node, map[string]string{"current": "secret"})
	seen := map[string]bool{}
	transport := client.Transport
	client.Transport = endpointRoundTrip(func(req *http.Request) (*http.Response, error) {
		seen[req.URL.Host+req.URL.RequestURI()] = true
		return transport.RoundTrip(req)
	})
	if err := verifyEndpointClient(t.Context(), state, creds, client); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{state.ServiceURL, strings.Replace(state.ProxyURLTemplate, "{proxy}", "lpcc-readiness", 1)} {
		for _, path := range []string{"//discovery", "/%64iscovery"} {
			if !seen[endpointHost(origin)+path] {
				t.Fatal("isolation probe changed its origin or request target", origin, path)
			}
		}
	}
	for _, path := range []string{"/runners/heartbeat", "/metrics", "//discovery"} {
		probeClient := &http.Client{Transport: endpointRoundTrip(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == endpointHost(state.ServiceURL) && req.URL.Path == path {
				return &http.Response{StatusCode: 400, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
			}
			return transport.RoundTrip(req)
		})}
		err := verifyEndpointClient(t.Context(), state, creds, probeClient)
		if (err == nil) != (path == "//discovery") {
			t.Fatal("ordinary API rejection was confused with edge normalization", path, err)
		}
	}
	// Access rejection must not conceal a broken public API route.
	bad := endpointFixture(t, state, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/discovery" {
			_ = json.NewEncoder(w).Encode([]map[string]string{{"address": state.ServiceURL}})
		} else {
			w.WriteHeader(401)
		}
	}), map[string]string{"current": "secret"})
	if err := verifyEndpointClient(t.Context(), state, creds, bad); err == nil {
		t.Fatal("Access rejection concealed broken API routing")
	}
	redirected := false
	redirect := &http.Client{Transport: endpointRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "foreign.example.invalid" {
			redirected = true
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://foreign.example.invalid/discovery"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	})}
	if err := verifyEndpointClient(t.Context(), state, creds, redirect); err == nil || redirected {
		t.Fatal("redirect escaped origin scope", err)
	}
}

func freeListenerAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func TestNodePublicAPIProtectedDiscoveryIntegration(t *testing.T) {
	binary := os.Getenv("NODE_BINARY")
	if binary == "" {
		t.Skip("set NODE_BINARY to a compatible livepeer-orchestrator binary")
	}
	state := RoutingFor("vkvkvkvkvkvkuaaaaaaaaaaaaa", "example.invalid").RoutingState
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cf-Access-Jwt-Assertion") != "" || strings.Contains(r.Header.Get("Cookie"), "CF_Authorization=") {
			t.Error("edge credentials reached application")
		}
		if r.URL.Path == "/echo" {
			_ = json.NewEncoder(w).Encode(r.Header)
			return
		}
		_, _ = io.WriteString(w, "application response")
	}))
	defer app.Close()
	for _, backend := range []struct{ name, service, template string }{
		{"current", state.ServiceURL, state.ProxyURLTemplate},
		{"missing-template", state.ServiceURL, ""},
		{"stale-template", state.ServiceURL, "https://{proxy}.old.invalid"},
		{"held-private", PrivateOrchestrator, ""},
	} {
		t.Run(backend.name, func(t *testing.T) {
			directory := t.TempDir()
			address := freeListenerAddress(t)
			metrics := freeListenerAddress(t)
			runners := filepath.Join(directory, "runners.toml")
			if err := os.WriteFile(runners, []byte(fmt.Sprintf("[[Runners]]\nID = \"app-fixture\"\nApp = \"fixture\"\nRunnerURL = %q\nMode = \"persistent\"\nProxy = true\nCapacity = 2\n\n[[Runners]]\nID = \"app-echo\"\nApp = \"echo\"\nRunnerURL = %q\nMode = \"single-shot\"\nProxy = true\nCapacity = 2\n", app.URL, app.URL)), 0600); err != nil {
				t.Fatal(err)
			}
			config := fmt.Sprintf("Listen = %q\nMetricsListen = %q\nServiceURL = %q\nAPIOriginURL = %q\nRunnerServiceURL = %q\nProxyURLTemplate = %q\nExcludedHeaders = [\"CF-Access-*\", \"Livepeer-Session-*\", \"X-Forwarded-*\"]\nExcludedCookies = [\"CF_Authorization\"]\nRunnerConfig = %q\nRunnerGrants = [%q]\n", address, metrics, backend.service, PrivateOrchestrator, PrivateOrchestrator, backend.template, runners, strings.TrimPrefix(app.URL, "http://"))
			configPath := filepath.Join(directory, "config.toml")
			if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			logfile, err := os.Create(filepath.Join(directory, "node.log"))
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), binary, "--config", configPath)
			command.Stdout = logfile
			command.Stderr = logfile
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait(); _ = logfile.Close() })
			ready := false
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
				response, err := http.Get("http://" + metrics + "/readyz")
				if err == nil {
					_ = response.Body.Close()
					if response.StatusCode == 200 {
						ready = true
						break
					}
				}
				time.Sleep(25 * time.Millisecond)
			}
			if !ready {
				data, _ := os.ReadFile(logfile.Name())
				t.Fatalf("Node did not start: %s", data)
			}
			target, _ := url.Parse("http://" + address)
			private := httputil.NewSingleHostReverseProxy(target)
			accepted := map[string]string{"current": "secret"}
			client := endpointFixture(t, state, private, accepted)
			creds := AccessCredential{ClientID: "current", ClientSecret: "secret"}
			for _, host := range []string{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid", "discovery.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid", "api-wrongsuffix.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid", "discovery-wrongsuffix.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid", "api-wrongsuffix.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid:443", "valid-app.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid:443", "valid-app.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid.", "nested.valid-app.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid", "valid-app.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid:8443", "valid-app.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid", "foreign.invalid"} {
				response, err := client.Get("https://" + host + "/apps/app-fixture/session")
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				want := http.StatusNotFound
				if host == endpointHost(state.ServiceURL) {
					want = http.StatusMethodNotAllowed
				} else if host == endpointHost(state.DiscoveryURL) {
					want = http.StatusUnauthorized
				}
				if response.StatusCode != want {
					t.Fatal("unexpected hostname routing", host, response.StatusCode)
				}
			}
			if backend.template != state.ProxyURLTemplate {
				return
			}
			response, err := client.Get(state.ServiceURL + "/apps/app-echo/app/echo")
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != 404 {
				t.Fatal("API host admitted application traffic", response.StatusCode)
			}
			if err := verifyEndpointClient(t.Context(), state, creds, client); err != nil {
				t.Fatal("real Node readiness", err)
			}
			response, err = client.Post(state.ServiceURL+"/apps/app-fixture/session", "application/json", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var reserved struct {
				AppURL     string `json:"app_url"`
				ControlURL string `json:"control_url"`
			}
			if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&reserved) != nil {
				t.Fatal("public reservation failed", response.StatusCode)
			}
			appURL, err := url.Parse(reserved.AppURL)
			if err != nil || appURL.Host == endpointHost(state.ServiceURL) {
				t.Fatal("reservation did not generate separate proxy origin", reserved.AppURL, err)
			}
			response, err = client.Get(reserved.AppURL + "/test")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			if response.StatusCode != 200 || string(body) != "application response" {
				t.Fatal("Host-preserving public proxy failed", response.StatusCode, string(body))
			}
			response, err = client.Post(reserved.ControlURL+"/stop", "application/json", nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatal("public stop failed", response.StatusCode)
			}
			req, _ := http.NewRequest("GET", strings.Replace(state.ProxyURLTemplate, "{proxy}", "app-echo", 1)+"/echo", nil)
			req.Header.Set("Cf-Access-Jwt-Assertion", "caller-supplied")
			req.Header.Set("Livepeer-Session-Extra", "caller-supplied")
			req.Header.Set("X-Forwarded-Extra", "caller-supplied")
			req.Header.Add("Cookie", "CF_Authorization=edge-cookie; session=app-cookie")
			req.Header.Add("Cookie", "CF_Authorization=duplicate-edge-cookie")
			req.Header.Set("Authorization", "Bearer app-authorization")
			response, err = client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var headers http.Header
			if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&headers) != nil {
				t.Fatal("public application echo failed", response.StatusCode)
			}
			for name := range headers {
				if strings.HasPrefix(strings.ToLower(name), "cf-access-") || strings.HasPrefix(strings.ToLower(name), "livepeer-session-") || strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
					t.Fatal("excluded header reached application", name)
				}
			}
			if headers.Get("Cookie") != "session=app-cookie" || headers.Get("Authorization") != "Bearer app-authorization" {
				t.Fatal("application authentication was lost or Access cookie leaked", headers)
			}
		})
	}
}
