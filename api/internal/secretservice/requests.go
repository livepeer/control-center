package secretservice

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	protocol "github.com/livepeer/control-center/secrets"
)

type requestIdentityKey struct{}

type requestIdentity struct {
	protocol.RequestClaims
	PublicKey string
}

func (s *Service) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, e := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
		if e != nil || len(body) > 2<<20 {
			fail(w, 400, "invalid_request")
			return
		}
		var id requestIdentity
		c := &id.RequestClaims
		_, e = jwt.ParseWithClaims(bearer(r), c, func(t *jwt.Token) (any, error) {
			if s.Config.PublicURL == "" || c.Subject == "" || c.Generation < 1 || len(c.ID) < 26 || len(c.ID) > 128 || len(c.Audience) != 1 ||
				c.IssuedAt == nil || c.ExpiresAt == nil || c.ExpiresAt.Sub(c.IssuedAt.Time) != protocol.RequestLifetime ||
				c.IssuedAt.After(s.Now().Add(30*time.Second)) || c.Digest != protocol.RequestDigest(r, body) {
				return nil, protocol.ErrDenied
			}
			kid, ok := t.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, protocol.ErrDenied
			}
			e := s.DB.QueryRowContext(r.Context(), `SELECT public_key FROM lpsecrets.identities WHERE node_id=$1 AND public_key=$2
UNION SELECT public_key FROM lpsecrets.retired_keys WHERE node_id=$1 AND public_key=$2`, c.Subject, kid).Scan(&id.PublicKey)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return nil, protocol.ErrUnavailable
			}
			return protocol.PublicKey(id.PublicKey)
		}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(protocol.RequestIssuer), jwt.WithAudience(s.Config.PublicURL), jwt.WithExpirationRequired(), jwt.WithTimeFunc(s.Now))
		if e != nil {
			failAuthorization(w, e, 401, "proof_refused")
			return
		}
		// Commit consumption before executing the request, including failed requests.
		// A shared unique constraint fences simultaneous replays and process restarts.
		res, e := s.DB.ExecContext(r.Context(), `INSERT INTO lpsecrets.request_nonces(node_id,nonce,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, c.Subject, c.ID, c.ExpiresAt.Time)
		if e != nil {
			fail(w, 503, "unavailable")
			return
		}
		if n, _ := res.RowsAffected(); n != 1 || !s.Now().Before(c.ExpiresAt.Time) {
			fail(w, 401, "proof_refused")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next(w, r.WithContext(context.WithValue(r.Context(), requestIdentityKey{}, id)))
	}
}

func failAuthorization(w http.ResponseWriter, e error, status int, code string) {
	if errors.Is(e, protocol.ErrUnavailable) {
		status, code = 503, "unavailable"
	}
	fail(w, status, code)
}
