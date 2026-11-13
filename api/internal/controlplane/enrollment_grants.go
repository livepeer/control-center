package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

func (p Params) signingKeyID() string {
	if p.JWTSigningKeyID == "" {
		return "1"
	}
	return p.JWTSigningKeyID
}

func (p Params) enrollmentKeys() (map[string]string, error) {
	keys := map[string]string{}
	if p.JWTVerificationKeys != "" && json.Unmarshal([]byte(p.JWTVerificationKeys), &keys) != nil {
		return nil, errors.New("invalid enrollment verification keyring")
	}
	if keys == nil {
		return nil, errors.New("invalid enrollment verification keyring")
	}
	if len(p.signingKeyID()) > 64 {
		return nil, errors.New("enrollment signing key ID exceeds 64 bytes")
	}
	if len(keys) > 16 {
		return nil, errors.New("enrollment verification keyring exceeds 16 keys")
	}
	for id, key := range keys {
		if id == "" || len(id) > 64 || len(key) < 32 {
			return nil, errors.New("enrollment verification keys require an ID and at least 32 bytes")
		}
	}
	keys[p.signingKeyID()] = p.JWTSigningSecret
	return keys, nil
}

func signEnrollment(secret, owner string, now time.Time) (string, time.Time, error) {
	return (Params{JWTSigningSecret: secret}).signEnrollment(owner, now)
}
func (p Params) signEnrollment(owner string, now time.Time) (string, time.Time, error) {
	expires := now.Add(time.Hour).Truncate(time.Second)
	c := enrollmentClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: enrollmentIssuer, Subject: owner, Audience: jwt.ClaimStrings{enrollmentAudience}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(expires), ID: uuid.New().String()}, Scope: "machines:register"}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	token.Header["kid"] = p.signingKeyID()
	raw, e := token.SignedString([]byte(p.JWTSigningSecret))
	return raw, expires, e
}
func verifyEnrollment(secret, raw string) (string, error) {
	c, e := (Params{JWTSigningSecret: secret}).enrollmentGrant(raw, time.Now(), false)
	if e != nil {
		return "", e
	}
	return c.Subject, nil
}
func (p Params) enrollmentGrant(raw string, now time.Time, expired bool) (*enrollmentClaims, error) {
	keys, e := p.enrollmentKeys()
	if e != nil {
		return nil, e
	}
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(enrollmentIssuer), jwt.WithAudience(enrollmentAudience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(func() time.Time { return now })}
	if expired {
		opts = append(opts, jwt.WithoutClaimsValidation())
	}
	// Tokens issued before key IDs were introduced remain valid for their
	// original hour. They can also be explicitly revoked by their signed hash.
	for _, legacyKey := range keys {
		c := new(enrollmentClaims)
		_, e = jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
			if value, ok := t.Header["kid"]; ok {
				id, ok := value.(string)
				if !ok || id == "" || keys[id] == "" {
					return nil, errors.New("unknown enrollment key")
				}
				return []byte(keys[id]), nil
			}
			return []byte(legacyKey), nil
		}, opts...)
		if e != nil {
			continue
		}
		if c.Issuer != enrollmentIssuer || len(c.Audience) != 1 || c.Audience[0] != enrollmentAudience || c.Scope != "machines:register" || c.ExpiresAt == nil || c.IssuedAt == nil || c.IssuedAt.After(now) || !c.ExpiresAt.After(c.IssuedAt.Time) || c.ExpiresAt.Sub(c.IssuedAt.Time) > time.Hour {
			break
		}
		id, e := uuid.Parse(c.Subject)
		if e != nil || id == uuid.Nil() {
			break
		}
		c.Subject = id.String()
		if c.ID == "" {
			// Signature encodings can vary without changing the verified MAC.
			// Identity comes from the authenticated signing input, never its alias.
			digest := sha256.Sum256([]byte(raw[:strings.LastIndexByte(raw, '.')]))
			c.ID = "legacy-" + hex.EncodeToString(digest[:])
		}
		return c, nil
	}
	return nil, errors.New("invalid or expired enrollment token")
}

func (s *Server) currentTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}
func lockEnrollmentGrant(ctx context.Context, tx *sql.Tx, id string) error {
	_, e := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,17240))`, id)
	return e
}
func (s *Server) acceptEnrollmentGrant(ctx context.Context, tx *sql.Tx, c *enrollmentClaims) error {
	if e := lockEnrollmentGrant(ctx, tx, c.ID); e != nil {
		return e
	}
	if !s.currentTime().Before(c.ExpiresAt.Time) {
		return problem(401, "grant_refused", "Enrollment grant expired or revoked.")
	}
	var revoked bool
	if e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.revoked_enrollment_grants WHERE jti=$1)`, c.ID).Scan(&revoked); e != nil {
		return e
	}
	if revoked {
		return problem(401, "grant_refused", "Enrollment grant expired or revoked.")
	}
	return nil
}
func (s *Server) revokeEnrollmentGrant(w http.ResponseWriter, r *http.Request) {
	owner, e := s.user(r.Context(), bearer(r))
	if e != nil {
		s.respondError(w, e)
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	if boundedInput(r, &in, 16384) != nil {
		fail(w, 400, "invalid grant")
		return
	}
	c, e := s.params.enrollmentGrant(in.Token, s.currentTime(), true)
	if e != nil || c.Subject != owner.ID {
		fail(w, 403, "grant refused")
		return
	}
	if !s.currentTime().Before(c.ExpiresAt.Time) {
		respond(w, 200, map[string]bool{"changed": false})
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	defer tx.Rollback()
	if e = lockEnrollmentGrant(r.Context(), tx, c.ID); e != nil {
		s.databaseError(w, e)
		return
	}
	if !s.currentTime().Before(c.ExpiresAt.Time) {
		respond(w, 200, map[string]bool{"changed": false})
		return
	}
	res, e := tx.ExecContext(r.Context(), `INSERT INTO lpcc.revoked_enrollment_grants(jti,owner_id,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, c.ID, owner.ID, c.ExpiresAt.Time)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		_, e = tx.ExecContext(r.Context(), `INSERT INTO lpcc.enrollment_audit(owner_id,action,target) VALUES($1,'grant.revoke',$2)`, owner.ID, c.ID)
	}
	if e != nil {
		s.databaseError(w, e)
		return
	}
	if e = tx.Commit(); e != nil {
		s.databaseError(w, e)
		return
	}
	respond(w, 200, map[string]bool{"changed": n > 0})
}

func (s *Server) enrollmentMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "control_enrollment_grants_issued_total %d\ncontrol_enrollment_grants_rejected_total %d\n", s.grantsIssued.Load(), s.grantsRejected.Load())
}
