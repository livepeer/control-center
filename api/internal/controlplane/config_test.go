package controlplane

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/j0sh/boa/pkg/boa"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
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

func TestDevelopmentHTTPWithoutCloudflare(t *testing.T) {
	p := testParams()
	p.DevelopmentHTTP = true
	p.PublicAPIURL = "http://api.example"
	p.RuntimeConnectorImage = ""
	if err := p.PreValidate(); err != nil {
		t.Fatal(err)
	}
	p.TunnelParams = testTunnelParams()
	if New(nil, p, nil).tunnels.Enabled() {
		t.Fatal("development mode configured a provider")
	}
}

func TestTOMLConfig(t *testing.T) {
	clearConfigEnv(t)
	dir := t.TempDir()
	files := map[string]string{
		"connection": "postgres://example:[PG_PASSWORD]@localhost/test",
		"metadata":   strings.Repeat("m", 32), "cloudflare": "test-cloudflare-token",
		"webhook":  strings.Repeat("w", 32),
		"password": "p@ss word", "enrollment": testJWTPem(), "machine": strings.Repeat("b", 32),
		"config.toml": `PGConnstrFile = "connection"
PGPasswordFile = "password"
JWTSigningPrivateKeyFile = "enrollment"
MachineTokenSecretFile = "machine"
SecretsURL = "https://secrets.example"
SecretsMetadataTokenFile = "metadata"
SupabaseURL = "https://auth.example"
SupabasePublishableKey = "public-key"
RuntimeImage = "registry.invalid/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
RuntimeConnectorImage = "registry.invalid/connector@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
CloudflareAccountID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CloudflareZoneID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
CloudflareBaseDomain = "fleet.example"
CloudflareAPITokenFile = "cloudflare"
TunnelStatusTTL = "5m"
TunnelNodeAddresses = ["198.51.100.10/32"]
ConfigReconcileInterval = "75s"
DefaultAdminEmail = "first@example.invalid"
RuntimeNodeImage = "registry.invalid/node@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
OnchainConfigFile = "onchain.json"
OnchainSecretsDir = "/run/onchain-rpc"
OnchainWebhookSecretFile = "webhook"
PublicListen = "0.0.0.0:43811"
AllowedOrigins = ["https://ui.example", "http://localhost:5173"]
RedeemerUpstreamURL = "http://redeemer:8941"
`,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(t.TempDir())
	t.Setenv("PUBLIC_API_URL", "https://public.example")
	t.Setenv("CLOUDFLARE_ENABLED", "false")
	var p Params
	if err := (boa.Cmd[Params]{Params: &p, RawArgs: []string{"--config", filepath.Join(dir, "config.toml"), "--listen", "localhost:43000"}}).Validate(); err != nil {
		t.Fatal(err)
	}
	if p.PGConnstr != files["connection"] || p.PGPassword != files["password"] || p.jwtKey == nil || p.JWTSigningPrivateKeyFile != filepath.Join(dir, "enrollment") || p.MachineTokenSecret != files["machine"] || p.OnchainWebhookSecret != files["webhook"] {
		t.Fatal("secret files were not resolved relative to TOML")
	}
	if p.CloudflareAPIToken != files["cloudflare"] || !New(nil, p, nil).tunnels.Enabled() {
		t.Fatal("production did not configure Cloudflare")
	}
	if p.Mode != "onchain" || p.SupabaseURL != "https://auth.example" || p.SupabasePublishableKey != "public-key" || p.ConfigReconcileInterval != 75*time.Second || p.PublicAPIURL != "https://public.example" || p.Listen != "localhost:43000" {
		t.Fatal("configuration fields were not loaded")
	}

	if p.PublicListen != "0.0.0.0:43811" || !slices.Equal(p.AllowedOrigins, []string{"https://ui.example", "http://localhost:5173"}) || p.RedeemerUpstreamURL != "http://redeemer:8941" {
		t.Fatal("edge configuration was not loaded", p.PublicListen, p.AllowedOrigins, p.RedeemerUpstreamURL)
	}
	if p.DefaultAdminEmail != "first@example.invalid" {
		t.Fatal("default admin config missing")
	}
	// Telemetry is on by default and its defaults name the compose services.
	if want := (TelemetryParams{TelemetryEnabled: true, TelemetryMetricsURL: "http://victoriametrics:8428", TelemetryLogsURL: "http://victorialogs:9428",
		TelemetryTokenTTL: time.Hour, TelemetryMaxBodyBytes: 8 << 20, TelemetryNodeRateBytes: 1 << 20, TelemetryAppLogsEnabled: true}); p.TelemetryParams != want {
		t.Fatalf("telemetry defaults = %+v, want %+v", p.TelemetryParams, want)
	}
	t.Setenv("DEFAULT_ADMIN_EMAIL", "environment@example.invalid")
	p = Params{}
	if err := (boa.Cmd[Params]{Params: &p, RawArgs: []string{"--config", filepath.Join(dir, "config.toml")}}).Validate(); err != nil || p.DefaultAdminEmail != "environment@example.invalid" {
		t.Fatal("admin environment override", err)
	}
}

func TestDrainTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name, config, appEnv, drainEnv string
		args                           []string
		app, drain                     time.Duration
		wantError                      string
	}{
		{name: "defaults", app: 12 * time.Hour, drain: 12*time.Hour + 10*time.Minute},
		{name: "TOML app timeout", config: "RuntimeAppDrainTimeout = \"45m\"\n", app: 45 * time.Minute, drain: 55 * time.Minute},
		{name: "TOML zeros", config: "RuntimeAppDrainTimeout = \"0s\"\nDrainTimeout = \"0s\"\n"},
		{name: "omitted machine timeout with zero app timeout", appEnv: "0s", drain: 10 * time.Minute},
		{name: "environment zeros", appEnv: "0s", drainEnv: "0s"},
		{name: "flag zeros", args: []string{"--runtime-app-drain-timeout=0s", "--drain-timeout=0s"}},
		{name: "equal timeouts after overrides", config: "RuntimeAppDrainTimeout = \"40m\"\nDrainTimeout = \"50m\"\n", appEnv: "30m", args: []string{"--drain-timeout=30m"}, app: 30 * time.Minute, drain: 30 * time.Minute},
		{name: "machine below app", drainEnv: "10m", wantError: "DrainTimeout must be at least RuntimeAppDrainTimeout"},
		{name: "explicit machine zero below app", args: []string{"--drain-timeout=0s"}, wantError: "DrainTimeout must be at least RuntimeAppDrainTimeout"},
		{name: "negative machine timeout", appEnv: "0s", drainEnv: "-1s", wantError: "DrainTimeout must be at least RuntimeAppDrainTimeout"},
		{name: "negative app timeout", args: []string{"--runtime-app-drain-timeout=-1s"}, wantError: "RuntimeAppDrainTimeout must be between zero and 12h"},
		{name: "excessive app timeout", appEnv: "13h", wantError: "RuntimeAppDrainTimeout must be between zero and 12h"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearConfigEnv(t)
			t.Setenv("RUNTIME_APP_DRAIN_TIMEOUT", tc.appEnv)
			t.Setenv("DRAIN_TIMEOUT", tc.drainEnv)
			p := testParams()
			p.TunnelParams = testTunnelParams()
			p.PGConnstr = "postgres://example@localhost/test"
			p.SupabaseURL = "https://auth.example"
			config := ""
			if tc.config != "" {
				config = filepath.Join(t.TempDir(), "config.toml")
				if err := os.WriteFile(config, []byte(tc.config), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := (boa.Cmd[Params]{Params: &p, RawArgs: append([]string{"--config=" + config}, tc.args...)}).Validate()
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("expected %q, got %v", tc.wantError, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now().UTC().Add(-3 * time.Minute)
			manager := machineconfig.New(machineconfig.Config{
				DrainTimeout:     p.DrainTimeout,
				NodeDrainTimeout: &p.RuntimeAppDrainTimeout,
			}, machineconfig.Dependencies{})
			desired := manager.Desired(machineconfig.Machine{}, machineconfig.State{
				DrainRequested: true,
				DrainStartedAt: started,
			}, nil)
			if got := *desired.NodeDrainTimeout; got != tc.app {
				t.Errorf("Node app drain timeout = %s, want %s", got, tc.app)
			}
			if got, want := machineconfig.DesiredRuntime(desired).DrainDeadline, started.Add(tc.drain); !got.Equal(want) {
				t.Errorf("machine drain deadline = %s, want %s", got, want)
			}
		})
	}
}

func clearConfigEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DEFAULT_ADMIN_EMAIL", "")
	for _, name := range []string{"CONTROL_CENTER_CONFIG", "CONTROL_CENTER_MODE", "PG_CONNSTR", "PG_CONNSTR_FILE", "PG_PASSWORD", "PG_PASSWORD_FILE", "LISTEN_ADDR", "PUBLIC_API_URL", "SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY", "JWT_SIGNING_PRIVATE_KEY_FILE", "MACHINE_TOKEN_SECRET", "MACHINE_TOKEN_SECRET_FILE", "CONFIG_RECONCILE_INTERVAL", "RUNTIME_IMAGE", "SECRETS_URL",
		"TELEMETRY_ENABLED", "TELEMETRY_METRICS_URL", "TELEMETRY_LOGS_URL", "TELEMETRY_TOKEN_TTL", "TELEMETRY_MAX_BODY_BYTES", "TELEMETRY_NODE_RATE_BYTES", "TELEMETRY_APP_LOGS_ENABLED",
		"RUNTIME_APP_DRAIN_TIMEOUT", "DRAIN_TIMEOUT", "DEVELOPMENT_HTTP", "RUNTIME_CONNECTOR_IMAGE", "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_ZONE_ID", "CLOUDFLARE_BASE_DOMAIN",
		"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_TOKEN_FILE", "TUNNEL_STATUS_TTL", "TUNNEL_NODE_ADDRESSES"} {
		t.Setenv(name, "")
	}
}

func TestConfigValidation(t *testing.T) {
	clearConfigEnv(t)
	validate := func(p Params, args ...string) error {
		p.PGConnstr = "postgres://example@localhost/test"
		return (boa.Cmd[Params]{Params: &p, RawArgs: append([]string{"--config="}, args...)}).Validate()
	}
	validParams := func() Params {
		p := testParams()
		p.TunnelParams = testTunnelParams()
		p.SupabaseURL = "https://auth.example"
		return p
	}
	for _, raw := range []string{"https://api.example", "https://api.example/", "https://api.example/control-center/v1_prefix"} {
		p := validParams()
		p.PublicAPIURL = raw
		p.SupabaseURL = "https://auth.example/~prefix"
		if err := validate(p); err != nil {
			t.Fatalf("rejected supported URL %q: %v", raw, err)
		}
	}
	for _, raw := range []string{"https://api.example//prefix", "https://api.example//", "https://api.example/~prefix", "https://api.example/a%20b", "https://api.example/a'b", "http://[2001:db8::1]", "https://api.example:abc"} {
		p := validParams()
		p.PublicAPIURL = raw
		if validate(p) == nil {
			t.Fatalf("accepted runtime-incompatible URL %q", raw)
		}
	}
	for _, tc := range []struct {
		change func(*Params)
		want   string
	}{
		{func(p *Params) { p.Mode = "" }, "onchain mode requires"},
		{func(p *Params) { p.RuntimeImage = "registry.example/runtime:latest" }, "RuntimeImage"},
		{func(p *Params) { p.RuntimeConnectorImage = "" }, "RuntimeConnectorImage"},
		{func(p *Params) { p.CloudflareAccountID = "" }, "Cloudflare account"},
		{func(p *Params) { p.CloudflareAPIToken = "" }, "Cloudflare provisioning credential"},
		{func(p *Params) { p.PublicAPIURL = "http://localhost:41932" }, "PublicAPIURL"},
		{func(p *Params) { p.DevelopmentHTTP = true }, "PublicAPIURL"},
		{func(p *Params) { p.DevelopmentHTTP = true; p.PublicListen = "127.0.0.1:43811" }, "empty PublicListen"},
		{func(p *Params) { p.SecretsURL = "" }, "SecretsURL"},
		{func(p *Params) { p.SecretsMetadataToken = "" }, "secrets metadata credentials"},
		{func(p *Params) { p.jwtKey = nil; p.JWTSigningPrivateKeyFile = "/missing-key" }, "JWTSigningPrivateKeyFile"},
		{func(p *Params) { p.MachineTokenSecret = "short" }, "machine-token-secret"},
		{func(p *Params) { p.ConfigReconcileInterval = 500 * time.Millisecond }, "at least 1s"},
		{func(p *Params) { p.SupabaseURL = "https://auth.example/?x=1" }, "HTTP(S) base URLs"},
		{func(p *Params) { p.jwtKey = nil; p.JWTSigningPrivateKeyFile = "" }, "JWTSigningPrivateKeyFile"},
		{func(p *Params) { p.SupabaseURL = "" }, "missing required param 'supabase-url'"},
		{func(p *Params) { p.DefaultAdminEmail = "Name <admin@example.com>" }, "single email address"},
	} {
		p := validParams()
		tc.change(&p)
		if err := validate(p); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected %q, got %v", tc.want, err)
		}
	}
	for _, flag := range []string{"--supabase-url=", "--supabase-publishable-key=", "--public-api-url=", "--cloudflare-enabled=false"} {
		p := validParams()
		if validate(p, flag) == nil {
			t.Fatalf("accepted explicit empty setting %s", flag)
		}
	}
}
