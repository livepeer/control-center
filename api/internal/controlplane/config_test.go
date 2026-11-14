package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/j0sh/boa/pkg/boa"
)

func TestPublicConfig(t *testing.T) {
	for name, image := range map[string]string{
		"configured": "registry.invalid/node@sha256:" + strings.Repeat("d", 64),
		"bundled":    "",
	} {
		t.Run(name, func(t *testing.T) {
			p := testParams()
			p.SupabaseURL = "https://auth.example"
			p.SecretsURL = "https://secrets.example"
			p.RuntimeNodeImage = image
			w := request(t, New(nil, p, nil), http.MethodGet, "/api/config", "", nil)
			if w.Code != http.StatusOK {
				t.Fatal(w.Code, w.Body.String())
			}
			var got map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			want := map[string]string{
				"supabase_url":             p.SupabaseURL,
				"supabase_publishable_key": p.SupabasePublishableKey,
			}
			if !maps.Equal(got, want) {
				t.Fatalf("config = %v, want %v", got, want)
			}
		})
	}
}

func TestDeploymentResponse(t *testing.T) {
	for _, image := range []string{"", "registry.invalid/node@sha256:" + strings.Repeat("d", 64)} {
		p := testParams()
		p.RuntimeNodeImage = image
		w := httptest.NewRecorder()
		New(nil, p, nil).deployment(w, nil, UserIdentity{})
		var got map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if want := (map[string]string{"revision": buildRevision, "runtime_node_image": image}); !maps.Equal(got, want) {
			t.Fatalf("deployment = %v, want %v", got, want)
		}
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
	w := request(t, s, http.MethodGet, "/api/admin/deployment", "session-a", nil)
	requireStatus(t, w, http.StatusOK)
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if want := (map[string]string{"revision": buildRevision, "runtime_node_image": s.params.RuntimeNodeImage}); !maps.Equal(got, want) {
		t.Fatalf("deployment = %v, want %v", got, want)
	}
}

func TestOpenDBRejectsPlaintextRoutes(t *testing.T) {
	for _, mode := range []string{"disable", "allow", "prefer"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel() // Regressions must not attempt a real database connection.
			_, err := OpenDB(ctx, "postgres://example:dummy@localhost/test?sslmode="+mode, "")
			if err == nil || err.Error() != "PGConnstr must require TLS" {
				t.Fatalf("accepted a plaintext route for %s: %v", mode, err)
			}
		})
	}
}

func TestTunnelStartupRequiresRuntimeImage(t *testing.T) {
	p := testParams()
	p.RuntimeImage = ""
	if err := p.PreValidate(); err == nil || !strings.Contains(err.Error(), "RuntimeImage") {
		t.Fatal("startup accepted a missing Runtime image", err)
	}
	for _, image := range []string{"", "registry.invalid/runtime:latest"} {
		p := testParams()
		p.CloudflareEnabled = true
		p.RuntimeImage = image
		if p.PreValidate() == nil {
			t.Fatal("startup accepted managed tunnels without a Runtime pin")
		}
		if err := New(nil, p, nil).ConfigureTunnels(); err == nil || !strings.Contains(err.Error(), "RuntimeImage") {
			t.Fatal("provisioning configured without a Runtime pin", err)
		}
	}
}

func TestTOMLConfig(t *testing.T) {
	clearConfigEnv(t)
	dir := t.TempDir()
	files := map[string]string{
		"connection": "postgres://example:[PG_PASSWORD]@localhost/test",
		"metadata":   strings.Repeat("m", 32),
		"webhook":    strings.Repeat("w", 32),
		"password":   "p@ss word", "enrollment": strings.Repeat("a", 32), "machine": strings.Repeat("b", 32),
		"config.toml": `PGConnstrFile = "connection"
PGPasswordFile = "password"
JWTSigningSecretFile = "enrollment"
MachineTokenSecretFile = "machine"
SecretsURL = "https://secrets.example"
SecretsMetadataTokenFile = "metadata"
SupabaseURL = "https://auth.example"
SupabasePublishableKey = "public-key"
RuntimeImage = "registry.invalid/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ConfigReconcileInterval = "75s"
DefaultAdminEmail = "first@example.invalid"
RuntimeNodeImage = "registry.invalid/node@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
OnchainConfigFile = "onchain.json"
OnchainSecretsDir = "/run/onchain-rpc"
OnchainWebhookSecretFile = "webhook"
`,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(t.TempDir())
	t.Setenv("PUBLIC_API_URL", "https://public.example")
	var p Params
	if err := (boa.Cmd[Params]{Params: &p, RawArgs: []string{"--config", filepath.Join(dir, "config.toml"), "--listen", "localhost:43000"}}).Validate(); err != nil {
		t.Fatal(err)
	}
	if p.PGConnstr != files["connection"] || p.PGPassword != files["password"] || p.JWTSigningSecret != files["enrollment"] || p.MachineTokenSecret != files["machine"] || p.OnchainWebhookSecret != files["webhook"] {
		t.Fatal("secret files were not resolved relative to TOML")
	}
	if p.Mode != "onchain" || p.SupabaseURL != "https://auth.example" || p.SupabasePublishableKey != "public-key" || p.ConfigReconcileInterval != 75*time.Second || p.PublicAPIURL != "https://public.example" || p.Listen != "localhost:43000" {
		t.Fatal("configuration fields were not loaded")
	}

	if p.DefaultAdminEmail != "first@example.invalid" {
		t.Fatal("default admin config missing")
	}
	t.Setenv("DEFAULT_ADMIN_EMAIL", "environment@example.invalid")
	p = Params{}
	if err := (boa.Cmd[Params]{Params: &p, RawArgs: []string{"--config", filepath.Join(dir, "config.toml")}}).Validate(); err != nil || p.DefaultAdminEmail != "environment@example.invalid" {
		t.Fatal("admin environment override", err)
	}
}

func clearConfigEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DEFAULT_ADMIN_EMAIL", "")
	for _, name := range []string{"CONTROL_CENTER_CONFIG", "CONTROL_CENTER_MODE", "PG_CONNSTR", "PG_CONNSTR_FILE", "PG_PASSWORD", "PG_PASSWORD_FILE", "LISTEN_ADDR", "PUBLIC_API_URL", "SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY", "JWT_SIGNING_SECRET", "JWT_SIGNING_SECRET_FILE", "MACHINE_TOKEN_SECRET", "MACHINE_TOKEN_SECRET_FILE", "CONFIG_RECONCILE_INTERVAL", "RUNTIME_IMAGE", "SECRETS_URL"} {
		t.Setenv(name, "")
	}
}

func TestConfigValidation(t *testing.T) {
	clearConfigEnv(t)
	validate := func(p Params, args ...string) error {
		p.PGConnstr = "postgres://example@localhost/test"
		return (boa.Cmd[Params]{Params: &p, RawArgs: append([]string{"--config="}, args...)}).Validate()
	}
	for _, raw := range []string{"http://localhost:41932", "https://api.example", "https://api.example/", "https://api.example/control-center/v1_prefix"} {
		p := testParams()
		p.PublicAPIURL = raw
		p.SupabaseURL = "https://auth.example/~prefix"
		if err := validate(p); err != nil {
			t.Fatalf("rejected supported URL %q: %v", raw, err)
		}
	}
	for _, raw := range []string{"https://api.example//prefix", "https://api.example//", "https://api.example/~prefix", "https://api.example/a%20b", "https://api.example/a'b", "http://[2001:db8::1]", "https://api.example:abc"} {
		p := testParams()
		p.PublicAPIURL = raw
		p.SupabaseURL = "https://auth.example"
		if validate(p) == nil {
			t.Fatalf("accepted runtime-incompatible URL %q", raw)
		}
	}
	for _, tc := range []struct {
		change func(*Params)
		want   string
	}{
		{func(p *Params) { p.Mode = "" }, "onchain mode requires"},
		{func(p *Params) { p.SecretsURL = "" }, "SecretsURL"},
		{func(p *Params) { p.SecretsMetadataToken = "" }, "secrets metadata credentials"},
		{func(p *Params) { p.JWTSigningSecret = "short" }, "jwt-signing-secret"},
		{func(p *Params) { p.MachineTokenSecret = "short" }, "machine-token-secret"},
		{func(p *Params) { p.JWTSigningSecret = p.MachineTokenSecret }, "different"},
		{func(p *Params) { p.ConfigReconcileInterval = 500 * time.Millisecond }, "at least 1s"},
		{func(p *Params) { p.SupabaseURL = "https://auth.example/?x=1" }, "HTTP(S) base URLs"},
		{func(p *Params) { p.JWTSigningSecret, p.MachineTokenSecret = "", "" }, "missing required param 'jwt-signing-secret'"},
		{func(p *Params) { p.SupabaseURL = "" }, "missing required param 'supabase-url'"},
		{func(p *Params) { p.DefaultAdminEmail = "Name <admin@example.com>" }, "single email address"},
	} {
		p := testParams()
		p.SupabaseURL = "https://auth.example"
		tc.change(&p)
		if err := validate(p); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected %q, got %v", tc.want, err)
		}
	}
	for _, flag := range []string{"--supabase-url=", "--supabase-publishable-key="} {
		p := testParams()
		p.SupabaseURL = "https://auth.example"
		if validate(p, flag) == nil {
			t.Fatalf("accepted explicit empty setting %s", flag)
		}
	}
}
