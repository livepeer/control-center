// Package secretservice is deployed independently of Control Center. It never
// decrypts application values; Vault handles wrapping keys and runtime DEKs.
package secretservice

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	protocol "github.com/livepeer/control-center/secrets"
)

type Config struct {
	SigningKey                                                                              string
	SigningKeys                                                                             map[string]string
	SigningKeyID                                                                            string
	SupabaseURL, SupabaseKey, ControlURL, ControlToken, VaultURL, VaultToken, AllowedOrigin string
	PublicURL                                                                               string
}
type Metadata interface {
	Machine(context.Context, string, *protocol.MachineBinding) (protocol.Machine, error)
}
type Transit interface {
	Wrap(context.Context, string, []byte) (string, error)
	Unwrap(context.Context, string, string) ([]byte, error)
}
type Service struct {
	issued           atomic.Uint64
	issuanceRejected atomic.Uint64
	DB               *sql.DB
	Config           Config
	HTTP             *http.Client
	Metadata         Metadata
	Transit          Transit
	Now              func() time.Time
}

func New(db *sql.DB, c Config) *Service {
	s := &Service{DB: db, Config: c, HTTP: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Now: time.Now}
	s.Metadata = &controlMetadata{s}
	s.Transit = &vaultTransit{s}
	return s
}

const ddl = `CREATE SCHEMA IF NOT EXISTS lpsecrets;
CREATE TABLE IF NOT EXISTS lpsecrets.revoked_grants(jti text PRIMARY KEY,owner_id uuid NOT NULL,expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS lpsecrets.identities(node_id text PRIMARY KEY,owner_id uuid NOT NULL,public_key text NOT NULL,generation bigint NOT NULL DEFAULT 1,revoked boolean NOT NULL DEFAULT false);
ALTER TABLE lpsecrets.identities ADD COLUMN IF NOT EXISTS reset_pending boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS lpsecrets.retired_keys(node_id text NOT NULL REFERENCES lpsecrets.identities,public_key text NOT NULL,PRIMARY KEY(node_id,public_key));
DROP TABLE IF EXISTS lpsecrets.challenges;
CREATE TABLE IF NOT EXISTS lpsecrets.request_nonces(node_id text NOT NULL REFERENCES lpsecrets.identities,nonce text NOT NULL,expires_at timestamptz NOT NULL,PRIMARY KEY(node_id,nonce));
CREATE INDEX IF NOT EXISTS request_nonce_expiry ON lpsecrets.request_nonces(expires_at);
CREATE TABLE IF NOT EXISTS lpsecrets.secrets(id uuid PRIMARY KEY,owner_id uuid NOT NULL,name text NOT NULL,key text NOT NULL,head uuid,revision bigint NOT NULL DEFAULT 1,deleted boolean NOT NULL DEFAULT false,updated_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX IF NOT EXISTS active_secret_reference ON lpsecrets.secrets(owner_id,name,key) WHERE NOT deleted;
CREATE TABLE IF NOT EXISTS lpsecrets.versions(id uuid PRIMARY KEY,secret_id uuid NOT NULL REFERENCES lpsecrets.secrets,base_revision bigint NOT NULL,nonce bytea,ciphertext bytea,wrapped_key text,created_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE lpsecrets.versions ADD COLUMN IF NOT EXISTS superseded_at timestamptz;
CREATE TABLE IF NOT EXISTS lpsecrets.audit(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,owner_id uuid NOT NULL,action text NOT NULL,target text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
REVOKE ALL ON SCHEMA lpsecrets FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA lpsecrets FROM PUBLIC;`

func (s *Service) Migrate(ctx context.Context) error { _, e := s.DB.ExecContext(ctx, ddl); return e }
func (s *Service) Collect(ctx context.Context) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	now := s.Now()
	// Keep nonces for an extra minute so small clock differences between replicas
	// cannot let a collector remove a credential another replica still accepts.
	for _, q := range []string{`DELETE FROM lpsecrets.revoked_grants WHERE expires_at<=$1`, `DELETE FROM lpsecrets.request_nonces WHERE expires_at<=$1::timestamptz - interval '1 minute'`} {
		if _, e = tx.ExecContext(ctx, q, now); e != nil {
			return e
		}
	}
	_, e = tx.ExecContext(ctx, `DELETE FROM lpsecrets.versions v USING lpsecrets.secrets s WHERE v.secret_id=s.id AND v.id IS DISTINCT FROM s.head AND COALESCE(v.superseded_at,v.created_at)<=$1`, now.Add(-7*24*time.Hour))
	if e != nil {
		return e
	}
	return tx.Commit()
}

func ident() string { return uuid.New().String() }
func decode(r *http.Request, v any) error {
	raw, e := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
	if e != nil || len(raw) > 2<<20 {
		return protocol.ErrInvalid
	}
	return jsonv2.Unmarshal(raw, v, jsontext.AllowDuplicateNames(false), jsonv2.RejectUnknownMembers(true))
}

func response(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, reason string) {
	response(w, status, map[string]string{"error": reason, "code": reason})
}
func bearer(r *http.Request) string {
	v := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if v == r.Header.Get("Authorization") || strings.ContainsAny(v, " \r\n\t") {
		return ""
	}
	return v
}
func (s *Service) owner(r *http.Request) (string, error) {
	token := bearer(r)
	if token == "" {
		return "", protocol.ErrDenied
	}
	req, e := http.NewRequestWithContext(r.Context(), "GET", strings.TrimRight(s.Config.SupabaseURL, "/")+"/auth/v1/user", nil)
	if e != nil {
		return "", protocol.ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("apikey", s.Config.SupabaseKey)
	res, e := s.HTTP.Do(req)
	if e != nil {
		return "", protocol.ErrUnavailable
	}
	defer res.Body.Close()
	var v struct {
		ID string `json:"id"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&v) != nil {
		return "", protocol.ErrDenied
	}
	id, e := uuid.Parse(v.ID)
	if e != nil || id == uuid.Nil() {
		return "", protocol.ErrDenied
	}
	return id.String(), nil
}

type claims struct {
	jwt.RegisteredClaims
	Scope string `json:"scope"`
}

const issuer = "livepeer-secrets"
const audience = "livepeer-secrets-enrollment"

func (s *Service) Grant(owner string) (string, time.Time, error) {
	now := s.Now().UTC()
	exp := now.Add(time.Hour).Truncate(time.Second)
	c := claims{jwt.RegisteredClaims{Issuer: issuer, Subject: owner, Audience: jwt.ClaimStrings{audience}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(exp), ID: ident()}, "machines:enroll"}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	t.Header["kid"] = s.Config.SigningKeyID
	v, e := t.SignedString([]byte(s.Config.SigningKey))
	return v, exp, e
}
func (s *Service) grant(raw string, expired bool) (*claims, error) {
	c := new(claims)
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(s.Now)}
	if expired {
		opts = append(opts, jwt.WithoutClaimsValidation())
	}
	_, e := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == s.Config.SigningKeyID {
			return []byte(s.Config.SigningKey), nil
		}
		k := s.Config.SigningKeys[kid]
		if k == "" {
			return nil, protocol.ErrDenied
		}
		return []byte(k), nil
	}, opts...)
	if e != nil || c.Issuer != issuer || len(c.Audience) != 1 || c.Audience[0] != audience || c.Scope != "machines:enroll" || c.ID == "" || c.ExpiresAt == nil || c.IssuedAt == nil || c.ExpiresAt.Sub(c.IssuedAt.Time) > time.Hour {
		return nil, protocol.ErrDenied
	}
	id, e := uuid.Parse(c.Subject)
	if e != nil || id == uuid.Nil() {
		return nil, protocol.ErrDenied
	}
	return c, nil
}
func lockGrant(ctx context.Context, tx *sql.Tx, id string) error {
	_, e := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,17019))`, id)
	return e
}
func lockIdentity(ctx context.Context, tx *sql.Tx, node string) error {
	_, e := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,17020))`, node)
	return e
}
func audit(ctx context.Context, tx *sql.Tx, owner, action, target string) error {
	_, e := tx.ExecContext(ctx, `INSERT INTO lpsecrets.audit(owner_id,action,target) VALUES($1,$2,$3)`, owner, action, target)
	return e
}
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "secrets_setup_grants_issued_total %d\nsecrets_setup_grants_rejected_total %d\n", s.issued.Load(), s.issuanceRejected.Load())
	})
	mux.HandleFunc("POST /v1/enrollment-grants", s.issue)
	mux.HandleFunc("POST /v1/enrollment-grants/revoke", s.revokeGrant)
	mux.HandleFunc("POST /v1/machines/enroll", s.enroll)
	mux.HandleFunc("GET /v1/machines", s.listIdentities)
	mux.HandleFunc("POST /v1/machines/activate", s.authenticated(s.activate))
	mux.HandleFunc("POST /v1/machines/{node}/revoke", s.revokeIdentity)
	mux.HandleFunc("POST /v1/machines/{node}/reset", s.resetIdentity)
	mux.HandleFunc("POST /v1/runtime/resolve", s.authenticated(s.resolve))
	mux.HandleFunc("POST /v1/runtime/versions", s.authenticated(s.versions))
	mux.HandleFunc("POST /v1/runtime/batch", s.authenticated(s.batchVersions))
	mux.HandleFunc("GET /v1/secrets", s.list)
	mux.HandleFunc("POST /v1/secrets/reserve", s.reserve)
	mux.HandleFunc("POST /v1/secrets/{id}/wrap", s.wrap)
	mux.HandleFunc("PUT /v1/secrets/{id}", s.upload)
	mux.HandleFunc("DELETE /v1/secrets/{id}", s.deleteSecret)
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.DB.PingContext(r.Context()) != nil {
			fail(w, 503, "unavailable")
			return
		}
		response(w, 200, map[string]bool{"ready": true})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if origin := r.Header.Get("Origin"); origin != "" {
			if origin != s.Config.AllowedOrigin {
				fail(w, 403, "origin_refused")
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (s *Service) issue(w http.ResponseWriter, r *http.Request) {
	owner, e := s.owner(r)
	if e != nil {
		s.issuanceRejected.Add(1)
		fail(w, 401, "authentication_required")
		return
	}
	raw, exp, e := s.Grant(owner)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	s.issued.Add(1)
	response(w, 200, map[string]any{"token": raw, "expires_at": exp})
}
func (s *Service) revokeGrant(w http.ResponseWriter, r *http.Request) {
	owner, e := s.owner(r)
	var in struct {
		Token string `json:"token"`
	}
	if e != nil {
		fail(w, 401, "authentication_required")
		return
	}
	if decode(r, &in) != nil {
		fail(w, 400, "invalid_grant")
		return
	}
	c, e := s.grant(in.Token, true)
	if e != nil || c.Subject != owner {
		fail(w, 403, "grant_refused")
		return
	}
	if !s.Now().Before(c.ExpiresAt.Time) {
		response(w, 200, map[string]bool{"changed": false})
		return
	}
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer tx.Rollback()
	if lockGrant(r.Context(), tx, c.ID) != nil {
		fail(w, 503, "unavailable")
		return
	}
	if !s.Now().Before(c.ExpiresAt.Time) {
		response(w, 200, map[string]bool{"changed": false})
		return
	}
	res, e := tx.ExecContext(r.Context(), `INSERT INTO lpsecrets.revoked_grants VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, c.ID, owner, c.ExpiresAt.Time)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		e = audit(r.Context(), tx, owner, "grant.revoke", c.ID)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 503, "unavailable")
		return
	}
	response(w, 200, map[string]bool{"changed": n > 0})
}

type controlMetadata struct{ s *Service }

func (c *controlMetadata) Machine(ctx context.Context, node string, in *protocol.MachineBinding) (protocol.Machine, error) {
	var v protocol.Machine
	method := "GET"
	var body io.Reader
	if in != nil {
		method = "POST"
		b, _ := json.Marshal(in)
		body = strings.NewReader(string(b))
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.s.Config.ControlURL, "/")+"/internal/secrets/nodes/"+url.PathEscape(node), body)
	if e != nil {
		return v, protocol.ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+c.s.Config.ControlToken)
	req.Header.Set("Content-Type", "application/json")
	res, e := c.s.HTTP.Do(req)
	if e != nil {
		return v, protocol.ErrUnavailable
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	var eligibility struct {
		Active *bool `json:"active"`
	}
	if res.StatusCode != 200 || err != nil || len(raw) > 2<<20 || json.Unmarshal(raw, &eligibility) != nil || eligibility.Active == nil || json.Unmarshal(raw, &v) != nil || v.NodeID != node || (v.Active && v.Owner == "") {
		return v, protocol.ErrUnavailable
	}
	if !v.Active {
		return v, protocol.ErrDenied
	}
	return v, nil
}

type vaultTransit struct{ s *Service }

func (v *vaultTransit) call(ctx context.Context, owner, op string, in, out any) error {
	b, _ := json.Marshal(in)
	id, e := uuid.Parse(owner)
	if e != nil {
		return protocol.ErrDenied
	}
	req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(v.s.Config.VaultURL, "/")+"/v1/transit/"+op+"/operator-"+id.String(), strings.NewReader(string(b)))
	if e != nil {
		return protocol.ErrUnavailable
	}
	req.Header.Set("X-Vault-Token", v.s.Config.VaultToken)
	req.Header.Set("Content-Type", "application/json")
	res, e := v.s.HTTP.Do(req)
	if e != nil {
		return protocol.ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return protocol.ErrUnavailable
	}
	if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out) != nil {
		return protocol.ErrUnavailable
	}
	return nil
}
func (v *vaultTransit) Wrap(ctx context.Context, owner string, key []byte) (string, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	e := v.call(ctx, owner, "encrypt", map[string]string{"plaintext": base64.StdEncoding.EncodeToString(key)}, &out)
	if out.Data.Ciphertext == "" {
		return "", protocol.ErrUnavailable
	}
	return out.Data.Ciphertext, e
}
func (v *vaultTransit) Unwrap(ctx context.Context, owner, wrapped string) ([]byte, error) {
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if e := v.call(ctx, owner, "decrypt", map[string]string{"ciphertext": wrapped}, &out); e != nil {
		return nil, e
	}
	key, e := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if e != nil || len(key) != 32 {
		return nil, protocol.ErrUnavailable
	}
	return key, nil
}

// Keep credential comparison independent of normal string equality.
func equal(a, b string) bool { return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
