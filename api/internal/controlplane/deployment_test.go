package controlplane

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/j0sh/boa/pkg/boa"
)

func wantDeployment(p Params) map[string]string {
	return map[string]string{
		"revision":                buildRevision,
		"runtime_image":           p.RuntimeImage,
		"runtime_connector_image": p.RuntimeConnectorImage,
		"runtime_node_image":      p.RuntimeNodeImage,
	}
}

// requireDeployment checks that w holds exactly the allowlisted fields.
func requireDeployment(t *testing.T, w *httptest.ResponseRecorder, want map[string]string) {
	t.Helper()
	requireStatus(t, w, http.StatusOK)
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("deployment = %v, want %v", got, want)
	}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("deployment = %v, want %v", got, want)
		}
	}
}

func localRequest(h http.Handler, peer string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/internal/deployment", nil)
	r.RemoteAddr = peer
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestDeploymentResponse(t *testing.T) {
	for _, image := range []string{"", "registry.invalid/node@sha256:" + strings.Repeat("d", 64)} {
		p := testParams()
		p.RuntimeNodeImage = image
		w := httptest.NewRecorder()
		New(nil, p, nil).deployment(w, nil, UserIdentity{})
		requireDeployment(t, w, wantDeployment(p))
	}
}

func TestDeploymentRequiresAuthentication(t *testing.T) {
	s := New(nil, testParams(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	requireStatus(t, request(t, s, http.MethodGet, "/api/admin/deployment", "", nil), http.StatusUnauthorized)
}

func TestDeploymentAdministratorAccess(t *testing.T) {
	s := newTestServer(t)
	s.params.DefaultAdminEmail = "a@example.invalid"
	if err := s.BootstrapAdmin(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, request(t, s, http.MethodGet, "/readyz", "", nil), http.StatusOK)
	requireStatus(t, request(t, s, http.MethodGet, "/api/admin/deployment", "session-b", nil), http.StatusForbidden)
	requireDeployment(t, request(t, s, http.MethodGet, "/api/admin/deployment", "session-a", nil), wantDeployment(s.params))
}

func TestLocalDeploymentNeedsNoCredential(t *testing.T) {
	p := testParams()
	p.MachineTokenSecret = "private-machine-token-secret-value"
	p.SecretsMetadataToken = "private-secrets-metadata-token-value"
	h := New(nil, p, nil).Handler()
	for _, peer := range []string{"127.0.0.1:41000", "127.8.9.10:41000", "[::1]:41000", "[::ffff:127.0.0.1]:41000"} {
		t.Run(peer, func(t *testing.T) {
			w := localRequest(h, peer, nil)
			requireDeployment(t, w, wantDeployment(p))
			for _, private := range []string{p.MachineTokenSecret, p.SecretsMetadataToken, p.SupabasePublishableKey, p.PublicAPIURL} {
				if strings.Contains(w.Body.String(), private) {
					t.Fatalf("deployment probe exposed %q", private)
				}
			}
		})
	}
}

func TestLocalDeploymentRefusesOtherPeers(t *testing.T) {
	h := New(nil, testParams(), nil).Handler()
	for _, tc := range []struct {
		name, peer string
		headers    map[string]string
	}{
		// The Docker bridge gateway: the published host port and, through
		// it, the tunnel.
		{name: "bridge gateway", peer: "172.18.0.1:41000"},
		{name: "other container", peer: "172.18.0.5:41000"},
		{name: "private network", peer: "10.0.0.2:41000"},
		{name: "public address", peer: "203.0.113.9:41000"},
		{name: "ipv6 peer", peer: "[2001:db8::1]:41000"},
		{name: "unspecified", peer: "0.0.0.0:41000"},
		{name: "malformed", peer: "127.0.0.1"},
		{name: "empty", peer: ""},
		{name: "spoofed x-forwarded-for", peer: "172.18.0.5:41000", headers: map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{name: "spoofed forwarded", peer: "10.0.0.2:41000", headers: map[string]string{"Forwarded": "for=127.0.0.1"}},
		{name: "spoofed x-real-ip", peer: "172.18.0.5:41000", headers: map[string]string{"X-Real-IP": "::1"}},
		// A proxy sharing the API's network namespace connects from loopback.
		{name: "local proxy x-forwarded-for", peer: "127.0.0.1:41000", headers: map[string]string{"X-Forwarded-For": "203.0.113.9"}},
		{name: "local proxy forwarded", peer: "127.0.0.1:41000", headers: map[string]string{"Forwarded": "for=203.0.113.9"}},
		{name: "local proxy x-forwarded-host", peer: "127.0.0.1:41000", headers: map[string]string{"X-Forwarded-Host": "controlcenter-api.example"}},
		{name: "local proxy cloudflare", peer: "127.0.0.1:41000", headers: map[string]string{"CF-Connecting-IP": "203.0.113.9"}},
		{name: "local proxy true-client-ip", peer: "[::1]:41000", headers: map[string]string{"True-Client-IP": "203.0.113.9"}},
		{name: "empty forwarding header", peer: "127.0.0.1:41000", headers: map[string]string{"X-Forwarded-For": ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w := localRequest(h, tc.peer, tc.headers); w.Code != http.StatusForbidden {
				t.Fatalf("%s = %d %s", tc.peer, w.Code, w.Body.String())
			}
		})
	}
}

func TestPublicListenerHidesDeploymentProbe(t *testing.T) {
	h := edgeServer(t, nil).PublicHandler()
	for _, target := range []string{"/internal/deployment", "//internal/deployment", "/api/../internal/deployment", "/%69nternal/deployment"} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.RemoteAddr = "127.0.0.1:41000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s = %d %s", target, w.Code, w.Body.String())
		}
	}
}

// The probe reports what the process loaded at startup. Editing the
// configuration file changes nothing until the API restarts and loads it.
func TestLocalDeploymentReportsLoadedConfiguration(t *testing.T) {
	clearConfigEnv(t)
	dir := t.TempDir()
	image := func(name, digit string) string {
		return "registry.invalid/" + name + "@sha256:" + strings.Repeat(digit, 64)
	}
	config := func(node string) string {
		return `Mode = "offchain"
PGConnstrFile = "connection"
JWTSigningPrivateKeyFile = "enrollment"
MachineTokenSecretFile = "machine"
SecretsURL = "https://secrets.example"
SecretsMetadataTokenFile = "metadata"
SupabaseURL = "https://auth.example"
SupabasePublishableKey = "public-key"
CloudflareAccountID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CloudflareZoneID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
CloudflareBaseDomain = "fleet.example"
CloudflareAPITokenFile = "cloudflare"
TunnelStatusTTL = "5m"
TunnelNodeAddresses = ["198.51.100.10/32"]
RuntimeImage = "` + image("runtime", "a") + `"
RuntimeConnectorImage = "` + image("connector", "c") + `"
RuntimeNodeImage = "` + node + `"
`
	}
	files := map[string]string{"connection": "postgres://example:dummy@localhost/test", "enrollment": testJWTPem(), "machine": strings.Repeat("b", 32), "metadata": strings.Repeat("m", 32), "cloudflare": "test-cloudflare-token", "config.toml": config(image("node", "d"))}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(t.TempDir())
	t.Setenv("PUBLIC_API_URL", "https://public.example")
	t.Setenv("CLOUDFLARE_ENABLED", "false")
	load := func() Params {
		var p Params
		if err := (boa.Cmd[Params]{Params: &p, RawArgs: []string{"--config", filepath.Join(dir, "config.toml")}}).Validate(); err != nil {
			t.Fatal(err)
		}
		return p
	}
	running := New(nil, load(), nil).Handler()
	loaded := map[string]string{"revision": buildRevision, "runtime_image": image("runtime", "a"), "runtime_connector_image": image("connector", "c"), "runtime_node_image": image("node", "d")}
	requireDeployment(t, localRequest(running, "127.0.0.1:41000", nil), loaded)

	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(config(image("node", "e"))), 0600); err != nil {
		t.Fatal(err)
	}
	requireDeployment(t, localRequest(running, "127.0.0.1:41000", nil), loaded)
	loaded["runtime_node_image"] = image("node", "e")
	requireDeployment(t, localRequest(New(nil, load(), nil).Handler(), "127.0.0.1:41000", nil), loaded)
}
