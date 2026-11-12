package tunnel

import (
	"bytes"
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

	"github.com/livepeer/control-center/runtime/nodeproxy"
)

type endpointRoundTrip func(*http.Request) (*http.Response, error)

func (fn endpointRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

// This fixture models edge Service Auth separately from origin ingress. Real
// Cloudflare JWT enforcement remains part of the release gate.
func endpointFixture(t *testing.T, state RoutingState, node http.Handler, accepted map[string]string) *http.Client {
	t.Helper()
	rules := ingressFor(state, Config{CloudflareTeamName: "team"}, "audience")
	guard, err := nodeproxy.Handler(state.ProxyURLTemplate, node)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: endpointRoundTrip(func(req *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		host := strings.ToLower(req.URL.Hostname())
		if host == endpointHost(state.ServiceURL) || host == endpointHost(state.DiscoveryURL) {
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
				if rule.OriginRequest.Access == nil || !rule.OriginRequest.Access.Required || len(rule.OriginRequest.Access.Audience) != 1 || rule.OriginRequest.Access.Audience[0] != "audience" {
					t.Error("missing shared audience")
				}
				clone.Host = rule.OriginRequest.HTTPHostHeader
				if clone.Host != endpointHost(PrivateOrchestrator) {
					t.Error("protected origin Host not rewritten")
				}
			} else {
				clone.Host = req.URL.Host
			}
			guard.ServeHTTP(w, clone)
			return w.Result(), nil
		}
		panic("missing catch-all")
	})}
}

func TestReadinessAuthenticatesBothOriginsAndIsolation(t *testing.T) {
	state := RoutingFor("lp-aaaaaaaaaaaaaaaa", "example.invalid", "aaaaaaa").RoutingState
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
				if req.Header.Get("CF-Access-Client-Secret") != creds.ClientSecret {
					t.Error("API isolation probe lacks valid credentials")
				}
				return &http.Response{StatusCode: 400, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
			}
			return transport.RoundTrip(req)
		})}
		err := verifyEndpointClient(t.Context(), state, creds, probeClient)
		if (err == nil) != (path == "//discovery") {
			t.Fatal("ordinary API rejection was confused with edge normalization", path, err)
		}
	}
	// Access rejection must not conceal a broken authenticated API route.
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

func TestNodeSharedAccessIntegration(t *testing.T) {
	binary := os.Getenv("NODE_BINARY")
	if binary == "" {
		t.Skip("set NODE_BINARY to a compatible livepeer-orchestrator binary")
	}
	state := RoutingFor("lp-aaaaaaaaaaaaaaaa", "example.invalid", "aaaaaaa").RoutingState
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/echo" {
			_ = json.NewEncoder(w).Encode(r.Header)
			return
		}
		_, _ = io.WriteString(w, "application response")
	}))
	defer app.Close()
	directory := t.TempDir()
	address := freeListenerAddress(t)
	metrics := freeListenerAddress(t)
	runners := filepath.Join(directory, "runners.toml")
	if err := os.WriteFile(runners, []byte(fmt.Sprintf("[[Runners]]\nID = \"app-fixture\"\nApp = \"fixture\"\nRunnerURL = %q\nMode = \"persistent\"\nProxy = true\nCapacity = 2\n\n[[Runners]]\nID = \"app-echo\"\nApp = \"echo\"\nRunnerURL = %q\nMode = \"single-shot\"\nProxy = true\nCapacity = 2\n", app.URL, app.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("Listen = %q\nMetricsListen = %q\nServiceURL = %q\nAPIOriginURL = %q\nRunnerServiceURL = %q\nProxyURLTemplate = %q\nRunnerConfig = %q\nRunnerGrants = [%q]\n", address, metrics, state.ServiceURL, PrivateOrchestrator, "http://"+address, state.ProxyURLTemplate, runners, strings.TrimPrefix(app.URL, "http://"))
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
	if err := verifyEndpointClient(t.Context(), state, creds, client); err != nil {
		t.Fatal("real Node readiness", err)
	}
	req, _ := http.NewRequest("POST", state.ServiceURL+"/apps/app-fixture/session", bytes.NewReader(nil))
	req.Header.Set("CF-Access-Client-Id", creds.ClientID)
	req.Header.Set("CF-Access-Client-Secret", creds.ClientSecret)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var reserved struct {
		AppURL string `json:"app_url"`
	}
	if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&reserved) != nil {
		t.Fatal("authenticated reservation failed", response.StatusCode)
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
	for _, host := range []string{"api.lp-aaaaaaaaaaaaaaaa.example.invalid", "discovery.lp-aaaaaaaaaaaaaaaa.example.invalid", "api-wrongsuffix.lp-aaaaaaaaaaaaaaaa.example.invalid", "discovery-wrongsuffix.lp-aaaaaaaaaaaaaaaa.example.invalid", "api-wrongsuffix.lp-aaaaaaaaaaaaaaaa.example.invalid:443", "valid-app.lp-aaaaaaaaaaaaaaaa.example.invalid:443", "valid-app.lp-aaaaaaaaaaaaaaaa.example.invalid.", "nested.valid-app.lp-aaaaaaaaaaaaaaaa.example.invalid"} {
		response, err = client.Post("https://"+host+"/apps/app-fixture/session", "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatal("guessed hostname reached Node API", host, response.StatusCode)
		}
	}
	req, _ = http.NewRequest("GET", strings.Replace(state.ProxyURLTemplate, "{proxy}", "app-echo", 1)+"/echo", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", "caller-supplied")
	req.Header.Set("Cookie", "CF_Authorization=first; session=app-cookie; cf_authorization=second")
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
		if strings.HasPrefix(strings.ToLower(name), "cf-access-") {
			t.Fatal("Access credential reached application", name)
		}
	}
	if headers.Get("Cookie") != "session=app-cookie" || headers.Get("Authorization") != "Bearer app-authorization" {
		t.Fatal("application authentication was lost or Access cookie leaked", headers)
	}
}
