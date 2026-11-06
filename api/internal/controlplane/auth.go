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
	"net/mail"
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

// UserIdentity comes only from Auth's verified response, never browser metadata.
type UserIdentity struct {
	ID             string `json:"user_id"`
	Email          string `json:"email"`
	EmailConfirmed bool   `json:"-"`
}

func normalizeEmail(raw string) (string, error) {
	email := strings.TrimSpace(raw)
	address, err := mail.ParseAddress(email)
	if err != nil || address.Name != "" || address.Address != email || len(email) > 254 {
		return "", errors.New("invalid email address")
	}
	return strings.ToLower(email), nil
}

// Ask Auth for the user; never trust a client-decoded Supabase session.
func (s *Server) user(ctx context.Context, token string) (UserIdentity, error) {
	if token == "" {
		return UserIdentity{}, problem(401, "authentication_required", "Sign in to continue.")
	}
	var raw struct {
		ID               string     `json:"id"`
		Email            string     `json:"email"`
		EmailConfirmedAt *time.Time `json:"email_confirmed_at"`
	}
	if err := s.authJSON(ctx, "/user", token, &raw); err != nil {
		return UserIdentity{}, err
	}
	id, err := uuid.Parse(raw.ID)
	if err != nil || id == (uuid.UUID{}) {
		return UserIdentity{}, problem(503, "authentication_unavailable", "Authentication is temporarily unavailable.")
	}
	identity := UserIdentity{ID: id.String()}
	if raw.Email != "" {
		identity.Email, err = normalizeEmail(raw.Email)
		if err != nil {
			// Provisioning syntax is stricter than Auth's accepted account emails.
			// UUID authentication and previously bound grants remain valid.
			return identity, nil
		}
	}
	identity.EmailConfirmed = raw.EmailConfirmedAt != nil && !raw.EmailConfirmedAt.IsZero()
	return identity, nil
}

func (s *Server) authJSON(ctx context.Context, path, token string, value any) error {
	unavailable := problem(503, "authentication_unavailable", "Authentication is temporarily unavailable.")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.params.SupabaseURL, "/")+"/auth/v1"+path, nil)
	if err != nil {
		return unavailable
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("apikey", s.params.SupabasePublishableKey)
	response, err := s.client.Do(req)
	if err != nil {
		return unavailable
	}
	defer response.Body.Close()
	if token != "" && (response.StatusCode == 401 || response.StatusCode == 403) {
		return problem(401, "invalid_session", "Session expired; sign in again.")
	}
	if response.StatusCode != http.StatusOK {
		return unavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || json.Unmarshal(data, value) != nil {
		return unavailable
	}
	return nil
}

func (s *Server) emailProvisioning(ctx context.Context) error {
	var settings struct {
		AutoConfirm *bool `json:"mailer_autoconfirm"`
	}
	if err := s.authJSON(ctx, "/settings", "", &settings); err != nil {
		return err
	}
	if settings.AutoConfirm == nil || *settings.AutoConfirm {
		return problem(503, "email_verification_unavailable", "Administrator provisioning requires verified email. Contact the operator.")
	}
	return nil
}
