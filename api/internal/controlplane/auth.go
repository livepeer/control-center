package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
)

const enrollmentIssuer = "livepeer-control-center"
const enrollmentAudience = "livepeer-enrollment"

type enrollmentClaims struct {
	jwt.RegisteredClaims
	Scope string `json:"scope"`
}

func signEnrollment(secret, owner string, now time.Time) (string, time.Time, error) {
	expires := now.Add(time.Hour).Truncate(time.Second)
	claims := enrollmentClaims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: enrollmentIssuer, Subject: owner, Audience: jwt.ClaimStrings{enrollmentAudience},
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(expires),
	}, Scope: "machines:register"}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	return token, expires, err
}

func verifyEnrollment(secret, raw string) (string, error) {
	claims := new(enrollmentClaims)
	_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return []byte(secret), nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(enrollmentIssuer), jwt.WithAudience(enrollmentAudience),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || claims.Scope != "machines:register" {
		return "", errors.New("invalid or expired enrollment token")
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return "", errors.New("invalid enrollment subject")
	}
	return id.String(), nil
}

func machineToken(secret, owner, nodeID string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("config:v1:" + owner + ":" + nodeID))
	return hex.EncodeToString(mac.Sum(nil))
}

func bearer(r *http.Request) string {
	kind, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(kind, "Bearer") || strings.ContainsAny(token, " \t\r\n") {
		return ""
	}
	return token
}

// Ask Auth for the user; never trust a client-decoded Supabase session.
func (s *Server) user(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", errors.New("sign in to continue")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.params.SupabaseURL, "/")+"/auth/v1/user", nil)
	if err != nil {
		return "", errors.New("authentication unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("apikey", s.params.SupabasePublishableKey)
	response, err := s.client.Do(req)
	if err != nil {
		return "", errors.New("authentication unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("session expired; sign in again")
	}
	var user struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&user); err != nil {
		return "", errors.New("authentication unavailable")
	}
	id, err := uuid.Parse(user.ID)
	if err != nil {
		return "", errors.New("invalid authenticated user")
	}
	return id.String(), nil
}
