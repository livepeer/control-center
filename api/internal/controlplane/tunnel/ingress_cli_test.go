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
	rules := ingressFor("lp-aaaaaaaaaaaaaaaa", Config{CloudflareBaseDomain: "example.invalid", CloudflareTeamName: "team"}, "audience")
	data, _ := json.Marshal(map[string]any{"ingress": rules})
	path := filepath.Join(t.TempDir(), "config.yaml")
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	for _, fixture := range []struct{ host, path, service string }{
		{"api-lp-aaaaaaaaaaaaaaaa", "/discovery", "http_status:404"},
		{"api-lp-aaaaaaaaaaaaaaaa", "/prefix/discovery", "http_status:404"},
		{"api-lp-aaaaaaaaaaaaaaaa", "/runners/heartbeat", "http_status:404"},
		{"api-lp-aaaaaaaaaaaaaaaa", "/runner/a/session/b/channels", "http_status:404"},
		{"api-lp-aaaaaaaaaaaaaaaa", "/apps/a/session", PrivateOrchestrator},
		{"api-lp-aaaaaaaaaaaaaaaa", "/apps/a/session/b/payment", PrivateOrchestrator},
		{"api-lp-aaaaaaaaaaaaaaaa", "/apps/a/app/v1", PrivateOrchestrator},
		{"api-lp-aaaaaaaaaaaaaaaa", "/run/a/x", PrivateOrchestrator},
		{"api-lp-aaaaaaaaaaaaaaaa", "/proxy/a", PrivateOrchestrator},
		{"api-lp-aaaaaaaaaaaaaaaa", "/refresh-payment", PrivateOrchestrator},
		{"api-lp-aaaaaaaaaaaaaaaa", "/ai/trickle/a/0", "http_status:404"},
		{"p.apps-lp-aaaaaaaaaaaaaaaa", "/discovery", "http_status:404"},
		{"p.apps-lp-aaaaaaaaaaaaaaaa", "/app/discovery", "http_status:404"},
		{"p.apps-lp-aaaaaaaaaaaaaaaa", "/readyz", "http_status:404"},
		{"p.apps-lp-aaaaaaaaaaaaaaaa", "/v1/completions", PrivateOrchestrator},
		{"discovery-lp-aaaaaaaaaaaaaaaa", "/discovery", PrivateOrchestrator},
		{"discovery-lp-aaaaaaaaaaaaaaaa", "/apps/a/app", "http_status:404"},
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
