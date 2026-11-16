package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/livepeer/control-center/runtime/ingressauth"
	protocol "github.com/livepeer/control-center/secrets"
	"net/http"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
)

const enrollmentIssuer = "livepeer-control-center"
const enrollmentAudience = "livepeer-enrollment"

type enrollmentClaims struct {
	jwt.RegisteredClaims
	Scope               string `json:"scope"`
	OrchestratorAddress string `json:"orchestrator_address"`
}

func (p Params) signingKeyID() string {
	if p.JWTSigningKeyID == "" {
		return "1"
	}
	return p.JWTSigningKeyID
}

func (p *Params) loadJWTKeys() error {
	if p.jwtKey != nil {
		return nil
	}
	key, err := ingressauth.Load(p.JWTSigningPrivateKeyFile, p.JWTVerificationPublicKeysFile, p.signingKeyID())
	if err == nil {
		p.jwtKey = key
	}
	return err
}
func (p Params) enrollmentKeys() (ingressauth.Keys, error) {
	if err := p.loadJWTKeys(); err != nil {
		return nil, err
	}
	return p.jwtKey.Keys, nil
}
func (p Params) signJWT(claims jwt.Claims) (string, error) {
	if err := p.loadJWTKeys(); err != nil {
		return "", err
	}
	return p.jwtKey.Sign(p.signingKeyID(), claims)
}
func (p Params) signEnrollment(owner, address string, now time.Time) (string, time.Time, error) {
	expires := now.Add(time.Hour).Truncate(time.Second)
	c := enrollmentClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: enrollmentIssuer, Subject: owner, Audience: jwt.ClaimStrings{enrollmentAudience}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(expires), ID: uuid.New().String()}, Scope: "machines:register", OrchestratorAddress: address}
	raw, e := p.signJWT(c)
	return raw, expires, e
}
func (p Params) enrollmentGrant(raw string, now time.Time, expired bool) (*enrollmentClaims, error) {
	keys, e := p.enrollmentKeys()
	if e != nil {
		return nil, e
	}
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(enrollmentIssuer), jwt.WithAudience(enrollmentAudience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(func() time.Time { return now })}
	if expired {
		opts = append(opts, jwt.WithoutClaimsValidation())
	}
	c := new(enrollmentClaims)
	_, e = jwt.ParseWithClaims(raw, c, keys.Key, opts...)
	invalid := errors.New("invalid or expired enrollment token")
	if e != nil || c.Issuer != enrollmentIssuer || len(c.Audience) != 1 || c.Audience[0] != enrollmentAudience || c.Scope != "machines:register" || c.ID == "" || c.ExpiresAt == nil || c.IssuedAt == nil || c.IssuedAt.After(now) || !c.ExpiresAt.After(c.IssuedAt.Time) || c.ExpiresAt.Sub(c.IssuedAt.Time) > time.Hour {
		return nil, invalid
	}
	id, e := uuid.Parse(c.Subject)
	if e != nil || id == uuid.Nil() {
		return nil, invalid
	}
	c.Subject = id.String()
	address, e := protocol.OrchestratorAddress(c.OrchestratorAddress)
	if e != nil {
		return nil, invalid
	}
	c.OrchestratorAddress = address
	return c, nil
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
	if e := lockMembership(ctx, tx, c.Subject, c.OrchestratorAddress); e != nil {
		return e
	}
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
	if e = lockMembership(r.Context(), tx, owner.ID, c.OrchestratorAddress); e != nil {
		s.respondError(w, e)
		return
	}
	if e = lockEnrollmentGrant(r.Context(), tx, c.ID); e != nil {
		s.databaseError(w, e)
		return
	}
	if !s.currentTime().Before(c.ExpiresAt.Time) {
		respond(w, 200, map[string]bool{"changed": false})
		return
	}
	res, e := tx.ExecContext(r.Context(), `INSERT INTO lpcc.revoked_enrollment_grants(jti,actor_user_id,orchestrator_address,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, c.ID, owner.ID, c.OrchestratorAddress, c.ExpiresAt.Time)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		_, e = tx.ExecContext(r.Context(), `INSERT INTO lpcc.enrollment_audit(actor_user_id,orchestrator_address,action,target) VALUES($1,$2,'grant.revoke',$3)`, owner.ID, c.OrchestratorAddress, c.ID)
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
