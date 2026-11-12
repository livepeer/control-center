package tunnel

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Optional account-free validation against the actual pinned parser/matcher.
// This does not exercise the forwarded request, Cloudflare edge or Access.
func TestPinnedCloudflaredIngress(t *testing.T) {
	binary := os.Getenv("CLOUDFLARED_BINARY")
	if binary == "" {
		t.Skip("set CLOUDFLARED_BINARY to verified cloudflared 2026.10.7")
	}
	v, e := exec.CommandContext(t.Context(), binary, "--version").CombinedOutput()
	if e != nil || !strings.Contains(string(v), "version 2026.10.7 ") {
		t.Fatal("requires pinned cloudflared", e)
	}
	rules := ingressFor(RoutingFor("vkvkvkvkvkvkuaaaaaaaaaaaaa", "example.invalid").RoutingState, Config{CloudflareBaseDomain: "example.invalid", CloudflareTeamName: "team"}, "audience")
	data, _ := json.Marshal(map[string]any{"ingress": rules})
	path := filepath.Join(t.TempDir(), "config.yaml")
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	if out, err := exec.CommandContext(t.Context(), binary, "tunnel", "--config", path, "ingress", "validate").CombinedOutput(); err != nil {
		t.Fatalf("invalid pinned ingress: %s (%v)", out, err)
	}
	for _, fixture := range []struct{ host, path, service string }{
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/discovery", "http_status:404"},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/prefix/discovery", "http_status:404"},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/runners/heartbeat", "http_status:404"},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/runner/a/session/b/channels", "http_status:404"},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/apps/a/session", ConnectorOrigin},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/apps/a/session/b/payment", ConnectorOrigin},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/apps/a/app", "http_status:404"},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/apps/a/app/v1", "http_status:404"},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/apps/a/session/b/app", "http_status:404"},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/apps/a/session/b/app/ws", "http_status:404"},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/run/a/x", "http_status:404"},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/proxy/a", "http_status:404"},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/refresh-payment", ConnectorOrigin},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/ai/trickle/a/0", "http_status:404"},
		{"api.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/unknown", "http_status:404"},
		{"discovery.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/apps/a/app", "http_status:404"},
		{"p.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/discovery", "http_status:404"},
		{"p.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/app/discovery", "http_status:404"},
		{"p.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/readyz", "http_status:404"},
		{"p.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/v1/completions", ConnectorOrigin},
		{"discovery.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/discovery", ConnectorOrigin},
		{"discovery.vkvkvkvkvkvkuaaaaaaaaaaaaa", "/apps/a/app", "http_status:404"},
		{"alias", "/discovery", "http_status:404"},
	} {
		t.Run(fixture.host+fixture.path, func(t *testing.T) {
			out, e := exec.CommandContext(t.Context(), binary, "tunnel", "--config", path, "--disable-path-normalization=false", "ingress", "rule", "https://"+fixture.host+".example.invalid"+fixture.path).CombinedOutput()
			if e != nil || !strings.Contains(string(out), "service: "+fixture.service) {
				t.Fatalf("wrong ingress: %s (%v)", out, e)
			}
		})
	}
}
