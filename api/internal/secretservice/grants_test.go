package secretservice

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	protocol "github.com/livepeer/control-center/secrets"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestIssuanceHasNoStorageOrVaultDependency(t *testing.T) {
	s := New(nil, Config{SigningKey: strings.Repeat("k", 32), SigningKeyID: "v1", SupabaseURL: "https://auth.example"})
	now := time.Date(2026, 11, 12, 1, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	s.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/auth/v1/user" {
			t.Fatal("unexpected request")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"11111111-1111-4111-8111-111111111111"}`)), Header: http.Header{}}, nil
	})
	seen := map[string]bool{}
	for range 100 {
		req := httptest.NewRequest("POST", "/v1/enrollment-grants", nil)
		req.Header.Set("Authorization", "Bearer operator-session")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var v struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &v)
		c, e := s.grant(v.Token, false)
		if e != nil || seen[c.ID] || c.ExpiresAt.Sub(now) != time.Hour {
			t.Fatal("invalid repeated grant", e)
		}
		seen[c.ID] = true
	}
	if s.DB != nil {
		t.Fatal("issuance must not allocate storage")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Body.String() != "secrets_setup_grants_issued_total 100\nsecrets_setup_grants_rejected_total 0\n" {
		t.Fatal("issuance metrics must have fixed cardinality", w.Body.String())
	}
}
func TestGrantExpiryAudienceScopeAndRollover(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := New(nil, Config{SigningKey: strings.Repeat("a", 32), SigningKeyID: "a"})
	s.Now = func() time.Time { return now }
	raw, _, e := s.Grant("11111111-1111-4111-8111-111111111111")
	if e != nil {
		t.Fatal(e)
	}
	s.Config.SigningKeys = map[string]string{"a": s.Config.SigningKey}
	s.Config.SigningKeyID = "b"
	s.Config.SigningKey = strings.Repeat("b", 32)
	if _, e = s.grant(raw, false); e != nil {
		t.Fatal("old key rejected", e)
	}
	now = now.Add(time.Hour)
	if _, e = s.grant(raw, false); e == nil {
		t.Fatal("expired grant accepted")
	}
	if _, e = s.grant(raw, true); e != nil {
		t.Fatal("revocation cannot inspect signed expiry", e)
	}
	c := claims{jwt.RegisteredClaims{Issuer: issuer, Subject: "11111111-1111-4111-8111-111111111111", Audience: jwt.ClaimStrings{"other"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)), IssuedAt: jwt.NewNumericDate(now), ID: ident()}, "machines:enroll"}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	token.Header["kid"] = "b"
	bad, _ := token.SignedString([]byte(s.Config.SigningKey))
	if _, e = s.grant(bad, true); e == nil {
		t.Fatal("wrong audience accepted")
	}
}
func TestMalformedAndCredentialBearingBodiesAreNotEchoed(t *testing.T) {
	s := New(nil, Config{})
	req := httptest.NewRequest("POST", "/v1/machines/enroll", bytes.NewBufferString(`{"secret":"credential-sentinel"}`))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if strings.Contains(w.Body.String(), "credential-sentinel") {
		t.Fatal("credential echoed")
	}
}

func TestDatabaseOutageMustBeUnavailable(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://unused@127.0.0.1:1/unused")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	s := New(db, Config{})
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "test-node"}, URIs: []*url.URL{{Scheme: "lpcc", Host: "test-node", Path: "/1"}}}
	w := call(t, s, "/v1/runtime/batch", "POST", "", map[string]any{"assignments": []any{}}, cert)
	if w.Code != 503 {
		t.Fatalf("database failure returned %d %s; runtime interprets this as a permanent denial", w.Code, w.Body.String())
	}
}

func TestMetadataAvailabilityAndExplicitEligibility(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{403, `{"error":"metadata principal required"}`, protocol.ErrUnavailable},
		{404, `{"error":"not found"}`, protocol.ErrUnavailable},
		{200, `{"node_id":"node"}`, protocol.ErrUnavailable},
		{200, `{"node_id":"wrong","active":false}`, protocol.ErrUnavailable},
		{200, `not JSON`, protocol.ErrUnavailable},
		{200, `{"node_id":"node","active":false}`, protocol.ErrDenied},
	} {
		s := New(nil, Config{ControlURL: "https://control.invalid"})
		s.HTTP.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: http.Header{}}, nil
		})
		if _, e := s.Metadata.Machine(context.Background(), "node", nil); !errors.Is(e, tc.want) {
			t.Fatal(tc.status, tc.body, e)
		}
	}
}
