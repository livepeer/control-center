package controlplane

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestBrowserPreview is an opt-in UI harness backed by disposable PostgreSQL.
// It never connects to the configured Supabase project or sends emails.
func TestBrowserPreview(t *testing.T) {
	if os.Getenv("CONTROL_CENTER_BROWSER_PREVIEW") != "1" {
		t.Skip("manual browser preview is opt-in")
	}
	s := newTestServer(t)
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": ownerA, "aud": "authenticated", "role": "authenticated", "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte("browser-fixture-only"))
	if err != nil {
		t.Fatal(err)
	}
	user := map[string]any{"id": ownerA, "email": "preview@example.invalid", "aud": "authenticated", "role": "authenticated", "created_at": time.Now().UTC()}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		w.Header().Set("Access-Control-Allow-Headers", r.Header.Get("Access-Control-Request-Headers"))
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		switch r.URL.Path {
		case "/auth/v1/authorize":
			http.Redirect(w, r, "http://localhost:5173/auth/callback?code=expired-code", http.StatusFound)
		case "/auth/v1/token":
			if r.URL.Query().Get("grant_type") == "pkce" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "Authorization code has expired"})
				return
			}
			var body struct {
				Email        string
				Password     string
				RefreshToken string `json:"refresh_token"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if (body.Email != "preview@example.invalid" || body.Password != "browser-preview") && body.RefreshToken != "preview-refresh" {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]string{"msg": "Invalid login credentials"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": accessToken, "token_type": "bearer", "expires_in": 3600, "refresh_token": "preview-refresh", "user": user})
		case "/auth/v1/user":
			if r.Header.Get("Authorization") != "Bearer "+accessToken {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(user)
		case "/auth/v1/logout":
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer auth.Close()
	s.params.SupabaseURL = auth.URL
	stop := make(chan struct{})
	handler := s.Handler()
	listener, err := net.Listen("tcp", "localhost:41932")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__preview/stop":
			w.WriteHeader(200)
			select {
			case <-stop:
			default:
				close(stop)
			}
		case "/__preview/enroll":
			enroll(t, s, ownerA, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
			w.WriteHeader(200)
		default:
			handler.ServeHTTP(w, r)
		}
	})}
	defer server.Close()
	go server.Serve(listener)
	t.Log("Browser preview ready at localhost:41932; POST /__preview/stop when finished")
	select {
	case <-stop:
	case <-time.After(15 * time.Minute):
		t.Fatal("browser preview timed out")
	}
}
