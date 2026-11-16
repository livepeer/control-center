package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/livepeer/control-center/runtime/ingressauth"
)

func testJWTKey(seed byte) *ingressauth.Signer {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return &ingressauth.Signer{Private: key, Keys: ingressauth.Keys{"1": key.Public().(ed25519.PublicKey)}}
}

func testJWTPem() string {
	data, _ := x509.MarshalPKCS8PrivateKey(testJWTKey(1).Private)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}))
}

func testRotateJWT(p *Params, seed byte, id string) {
	keys := p.jwtKey.Keys
	next := testJWTKey(seed)
	next.Keys = ingressauth.Keys{}
	for id, public := range keys {
		next.Keys[id] = public
	}
	next.Keys[id] = next.Private.Public().(ed25519.PublicKey)
	p.jwtKey, p.JWTSigningKeyID = next, id
}

func testVerifyEnrollment(p Params, raw string) (string, error) {
	c, err := p.enrollmentGrant(raw, time.Now(), false)
	if err != nil {
		return "", err
	}
	return c.Subject, nil
}

func TestJWTFamiliesAreIsolatedAndRejectHMAC(t *testing.T) {
	p := testParams()
	s := New(nil, p, nil)
	now := time.Now().Truncate(time.Second)
	s.now = func() time.Time { return now }
	enrollment, _, _ := p.signEnrollment(ownerA, orchA, now)
	claim, _, _ := s.signOrchestratorClaim(ownerA, orchA)
	invitation, _, _ := s.signInvitation(ownerA, orchA)
	node := "vkvkvkvkvkvkuaaaaaaaaaaaaa"
	discovery, _ := s.signDiscovery(node)
	tokens := []string{enrollment, claim, invitation, discovery}
	checks := []func(string) error{
		func(raw string) error { _, err := p.enrollmentGrant(raw, now, false); return err },
		func(raw string) error { _, err := s.verifyOrchestratorClaim(raw, ownerA); return err },
		func(raw string) error { _, err := s.verifyInvitation(raw); return err },
		func(raw string) error { return ingressauth.Verify(p.jwtKey.Keys, raw, node, now) },
	}
	for i, token := range tokens {
		for j, check := range checks {
			if err := check(token); (err == nil) != (i == j) {
				t.Fatalf("token family %d accepted by %d: %v", i, j, err)
			}
		}
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
			t.Fatal(err)
		}
		legacy := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		legacy.Header["kid"] = p.signingKeyID()
		raw, _ := legacy.SignedString([]byte("previous HMAC signing key"))
		if checks[i](raw) == nil {
			t.Fatalf("family %d accepted HMAC", i)
		}
	}
}
