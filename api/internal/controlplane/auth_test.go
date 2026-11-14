package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustedIdentityAndAuthenticationFailures(t *testing.T) {
	requireStatus(t, request(t, New(nil, testParams(), nil), "GET", "/api/operator/config", "", nil), http.StatusUnauthorized)
	for _, tc := range []struct {
		name, body       string
		upstream, status int
		confirmed        bool
		email            string
	}{
		{"verified", `{"id":"` + ownerA + `","email":"A@example.invalid","email_confirmed_at":"2026-11-06T00:00:00Z","app_metadata":{"provider":"google"}}`, 200, 200, true, "a@example.invalid"},
		{"phone_and_metadata", `{"id":"` + ownerA + `","confirmed_at":"2026-11-06T00:00:00Z","new_email":"a@example.invalid","user_metadata":{"email":"a@example.invalid","email_verified":true,"role":"admin"}}`, 200, 200, false, ""},
		{"unconfirmed", `{"id":"` + ownerA + `","email":"a@example.invalid","email_confirmed_at":null}`, 200, 200, false, "a@example.invalid"},
		{"provisioning_ineligible_email", `{"id":"` + ownerA + `","email":"a..b@example.invalid","email_confirmed_at":"2026-11-06T00:00:00Z"}`, 200, 200, false, ""},
		{"malformed_confirmation", `{"id":"` + ownerA + `","email_confirmed_at":"not-a-time"}`, 200, 503, false, ""},
		{"invalid_identity", `{"id":"not-a-uuid"}`, 200, 503, false, ""},
		{"malformed_json", `{`, 200, 503, false, ""},
		{"expired", `{}`, 401, 401, false, ""},
		{"forbidden", `{}`, 403, 401, false, ""},
		{"rate_limit", `{}`, 429, 503, false, ""},
		{"outage", `{}`, 500, 503, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("apikey") != "public-test" {
					t.Error("missing publishable key")
				}
				w.WriteHeader(tc.upstream)
				io.WriteString(w, tc.body)
			}))
			defer auth.Close()
			p := testParams()
			p.SupabaseURL, p.SecretsURL = auth.URL, "https://secrets.example"
			s := New(nil, p, slog.New(slog.NewTextHandler(io.Discard, nil)))
			user, err := s.user(t.Context(), "session")
			if tc.status != 200 {
				if err == nil || errorDetails(err).status != tc.status {
					t.Fatalf("identity status: %v", err)
				}
			} else if err != nil || user.EmailConfirmed != tc.confirmed || user.Email != tc.email {
				t.Fatalf("identity %+v: %v", user, err)
			}
			if tc.status == 200 {
				w := request(t, s, "GET", "/api/operator/config", "session", nil)
				requireStatus(t, w, http.StatusOK)
				var settings map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &settings); err != nil || !maps.Equal(settings, map[string]string{"public_api_url": p.PublicAPIURL, "secrets_url": p.SecretsURL, "mode": "offchain"}) {
					t.Fatal("operator config", w.Body.String(), err)
				}
			} else {
				for _, path := range []string{"/api/bootstrap-token", "/api/machines", "/api/me", "/api/operator/config", "/api/admin/machines"} {
					method := "GET"
					if path == "/api/bootstrap-token" {
						method = "POST"
					}
					requireStatus(t, request(t, s, method, path, "session", nil), tc.status)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := s.user(ctx, "session"); err == nil || errorDetails(err).status != 503 {
				t.Fatal("cancellation treated as invalid session", err)
			}
		})
	}
}

func TestEmailNormalization(t *testing.T) {
	for _, raw := range []string{" Admin+ops@Example.COM ", "admin+ops@example.com"} {
		email, err := normalizeEmail(raw)
		if err != nil || email != "admin+ops@example.com" {
			t.Fatal(email, err)
		}
	}
	for _, raw := range []string{"", "Name <admin@example.com>", "a@example.com,b@example.com", "a@example.com\nBcc: b@example.com"} {
		if _, err := normalizeEmail(raw); err == nil {
			t.Fatal("accepted", raw)
		}
	}
}
