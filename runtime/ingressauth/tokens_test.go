package ingressauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testNode = "vkvkvkvkvkvkuaaaaaaaaaaaaa"

func signer(t *testing.T) *Signer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{Private: private, Keys: Keys{"current": public}}
}

func TestDiscoveryTokenBoundaries(t *testing.T) {
	s := signer(t)
	now := time.Now().Truncate(time.Second)
	raw, err := s.Discovery("current", testNode, now)
	if err != nil || Verify(s.Keys, raw, testNode, now) != nil {
		t.Fatal("valid token refused", err)
	}
	if Verify(s.Keys, raw, strings.Repeat("a", 26), now) == nil {
		t.Fatal("wrong machine accepted")
	}
	if Verify(s.Keys, raw, testNode, now.Add(Lifetime+ClockTolerance)) == nil {
		t.Fatal("expired token accepted")
	}
	if Verify(s.Keys, raw, testNode, now.Add(-ClockTolerance-time.Second)) == nil {
		t.Fatal("future token accepted")
	}
	base := Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: Issuer, Subject: testNode, Audience: jwt.ClaimStrings{Audience}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(Lifetime))}, Scope: Scope}
	for name, mutate := range map[string]func(*Claims){
		"issuer":             func(c *Claims) { c.Issuer = "other" },
		"audience":           func(c *Claims) { c.Audience = jwt.ClaimStrings{"livepeer-enrollment"} },
		"multiple audiences": func(c *Claims) { c.Audience = jwt.ClaimStrings{Audience, "other"} },
		"scope":              func(c *Claims) { c.Scope = "machines:register" },
		"missing issuance":   func(c *Claims) { c.IssuedAt = nil },
		"missing expiration": func(c *Claims) { c.ExpiresAt = nil },
		"excess lifetime":    func(c *Claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(Lifetime + time.Second)) },
		"negative lifetime":  func(c *Claims) { c.ExpiresAt = c.IssuedAt },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			raw, _ := s.Sign("current", c)
			if Verify(s.Keys, raw, testNode, now) == nil {
				t.Fatal("invalid claims accepted")
			}
		})
	}
	for _, method := range []jwt.SigningMethod{jwt.SigningMethodHS256, jwt.SigningMethodHS384, jwt.SigningMethodNone} {
		token := jwt.NewWithClaims(method, base)
		token.Header["kid"] = "current"
		var key any = []byte(s.Keys["current"])
		if method == jwt.SigningMethodNone {
			key = jwt.UnsafeAllowNoneSignatureType
		}
		raw, _ := token.SignedString(key)
		if Verify(s.Keys, raw, testNode, now) == nil {
			t.Fatal("legacy/unsigned token accepted")
		}
	}
	for _, id := range []string{"", "unknown"} {
		raw, _ := s.Sign(id, base)
		if Verify(s.Keys, raw, testNode, now) == nil {
			t.Fatal("unknown key accepted")
		}
	}
}

func TestForwardAuthUsesOnlyBearerAndLocalKeys(t *testing.T) {
	s := signer(t)
	h, err := Handler(s.Keys, testNode)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := s.Discovery("current", testNode, time.Now())
	for _, auth := range []string{"", "Basic " + raw, "Bearer invalid", "Bearer " + raw} {
		r := httptest.NewRequest("GET", "/authorize?token="+raw, nil)
		r.Header.Set("Authorization", auth)
		r.Header.Set("Cookie", "token="+raw)
		r.Header.Set("X-Forwarded-Host", "attacker.example")
		r.Header.Set("X-Forwarded-Uri", "/readyz")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := http.StatusUnauthorized
		if auth == "Bearer "+raw {
			want = http.StatusNoContent
		}
		if w.Code != want || strings.Contains(w.Body.String(), raw) {
			t.Fatalf("status=%d want=%d", w.Code, want)
		}
	}
	r := httptest.NewRequest("GET", "/authorize", nil)
	r.Header["Authorization"] = []string{"Bearer " + raw, "Bearer " + raw}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("duplicate authorization accepted")
	}
}

func TestMountedKeysAndRotation(t *testing.T) {
	s := signer(t)
	der, _ := x509.MarshalPKCS8PrivateKey(s.Private)
	dir := t.TempDir()
	private, public := filepath.Join(dir, "identity.pem"), filepath.Join(dir, "public.json")
	if err := os.WriteFile(private, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(public, s.Keys.JSON(), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(private, public, "current")
	if err != nil || !loaded.Private.Equal(s.Private) {
		t.Fatal("mounted key failed", err)
	}
	// Signing/verifying continue from loaded memory after the mounted files vanish.
	os.Remove(private)
	os.Remove(public)
	raw, err := loaded.Discovery("current", testNode, time.Now())
	if err != nil || Verify(loaded.Keys, raw, testNode, time.Now()) != nil {
		t.Fatal("local signing failed", err)
	}
	for _, data := range []string{"null", "{}", `{"x":"short"}`, `{"":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`} {
		if _, err := ParseKeys([]byte(data)); err == nil {
			t.Fatal("invalid public keys accepted")
		}
	}
}

const testOrchestrator = "0x1111111111111111111111111111111111111111"

func TestTelemetryTokenBoundaries(t *testing.T) {
	s := signer(t)
	now := time.Now().Truncate(time.Second)
	raw, expires, err := s.Telemetry("current", testNode, testOrchestrator, 3, time.Hour, now)
	if err != nil || !expires.Equal(now.Add(time.Hour)) {
		t.Fatal("telemetry token refused", err, expires)
	}
	claims, err := VerifyTelemetry(s.Keys, raw, now)
	if err != nil || claims.Subject != testNode || claims.Orchestrator != testOrchestrator || claims.CredentialVersion != 3 {
		t.Fatal("telemetry claims", claims, err)
	}
	if _, err := VerifyTelemetry(s.Keys, raw, now.Add(time.Hour+ClockTolerance)); err == nil {
		t.Fatal("expired telemetry token accepted")
	}
	// Scope separation: each verifier refuses the other token kind.
	if Verify(s.Keys, raw, testNode, now) == nil {
		t.Fatal("ingress accepted a telemetry token")
	}
	discovery, _ := s.Discovery("current", testNode, now)
	if _, err := VerifyTelemetry(s.Keys, discovery, now); err == nil {
		t.Fatal("telemetry ingest accepted a discovery token")
	}
	h, _ := Handler(s.Keys, testNode)
	r := httptest.NewRequest("GET", "/authorize", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("ForwardAuth accepted a telemetry token", w.Code)
	}
	for name, args := range map[string]struct {
		node, orchestrator string
		version            int64
		lifetime           time.Duration
	}{
		"node":           {"short", testOrchestrator, 1, time.Hour},
		"orchestrator":   {testNode, "0xABC", 1, time.Hour},
		"uppercase orch": {testNode, strings.ToUpper(testOrchestrator), 1, time.Hour},
		"version":        {testNode, testOrchestrator, 0, time.Hour},
		"lifetime":       {testNode, testOrchestrator, 1, MaxTelemetryLifetime + time.Second},
		"no lifetime":    {testNode, testOrchestrator, 1, 0},
	} {
		if _, _, err := s.Telemetry("current", args.node, args.orchestrator, args.version, args.lifetime, now); err == nil {
			t.Fatal("invalid telemetry identity minted", name)
		}
	}
	base := TelemetryClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: Issuer, Subject: testNode, Audience: jwt.ClaimStrings{TelemetryAudience}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}, Scope: TelemetryScope, Orchestrator: testOrchestrator, CredentialVersion: 1}
	for name, mutate := range map[string]func(*TelemetryClaims){
		"issuer":             func(c *TelemetryClaims) { c.Issuer = "other" },
		"audience":           func(c *TelemetryClaims) { c.Audience = jwt.ClaimStrings{Audience} },
		"multiple audiences": func(c *TelemetryClaims) { c.Audience = jwt.ClaimStrings{TelemetryAudience, Audience} },
		"scope":              func(c *TelemetryClaims) { c.Scope = Scope },
		"subject":            func(c *TelemetryClaims) { c.Subject = "not-a-node" },
		"orchestrator":       func(c *TelemetryClaims) { c.Orchestrator = "" },
		"credential version": func(c *TelemetryClaims) { c.CredentialVersion = 0 },
		"missing issuance":   func(c *TelemetryClaims) { c.IssuedAt = nil },
		"missing expiration": func(c *TelemetryClaims) { c.ExpiresAt = nil },
		"excess lifetime": func(c *TelemetryClaims) {
			c.ExpiresAt = jwt.NewNumericDate(now.Add(MaxTelemetryLifetime + time.Second))
		},
		"negative lifetime": func(c *TelemetryClaims) { c.ExpiresAt = c.IssuedAt },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			raw, _ := s.Sign("current", c)
			if _, err := VerifyTelemetry(s.Keys, raw, now); err == nil {
				t.Fatal("invalid telemetry claims accepted")
			}
		})
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, base)
	token.Header["kid"] = "current"
	hmacRaw, _ := token.SignedString([]byte(s.Keys["current"]))
	if _, err := VerifyTelemetry(s.Keys, hmacRaw, now); err == nil {
		t.Fatal("symmetric telemetry token accepted")
	}
}
