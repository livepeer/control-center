package controlplane

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
)

func TestEnrollmentIssuanceHasNoStorageDependency(t *testing.T) {
	s := New(nil, testParams(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"id":"` + ownerA + `"}`))}, nil
	})
	seen := map[string]bool{}
	for range 100 {
		w := request(t, s, "POST", "/api/bootstrap-token", "operator", nil)
		requireStatus(t, w, 200)
		var out struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		c, e := s.params.enrollmentGrant(out.Token, s.currentTime(), false)
		if e != nil || seen[c.ID] {
			t.Fatal("grant was not fresh", e)
		}
		seen[c.ID] = true
	}
	w := request(t, s, "GET", "/metrics", "", nil)
	if w.Body.String() != "control_enrollment_grants_issued_total 100\ncontrol_enrollment_grants_rejected_total 0\n" {
		t.Fatal("issuance metric cardinality", w.Body.String())
	}
}

func TestControlGrantRevocationRolloverAndExpiry(t *testing.T) {
	s := newTestServer(t)
	var token string
	for range 10 {
		w := request(t, s, "POST", "/api/bootstrap-token", "session-a", nil)
		requireStatus(t, w, 200)
		var out struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if token == "" {
			token = out.Token
		}
	}
	for _, table := range []string{"enrollments", "revoked_enrollment_grants", "enrollment_audit", "secret_machines"} {
		if n := count(t, s, "SELECT count(*) FROM lpcc."+table); n != 0 {
			t.Fatal("issuance persisted state", table, n)
		}
	}
	oldKey := s.params.JWTSigningSecret
	s.params.JWTSigningKeyID = "next"
	s.params.JWTSigningSecret = strings.Repeat("z", 32)
	retained, _ := json.Marshal(map[string]string{"1": oldKey})
	s.params.JWTVerificationKeys = string(retained)
	// A previously issued grant survives rollover and remains reusable.
	for _, fingerprint := range []string{strings.Repeat("1", 64), strings.Repeat("2", 64)} {
		requireStatus(t, request(t, s, "POST", "/v1/nodes/register", token, registrationBody(ownerA, fingerprint, token)), 200)
	}
	requireStatus(t, request(t, s, "POST", "/api/bootstrap-token/revoke", "session-b", map[string]string{"token": token}), 403)
	for range 2 {
		requireStatus(t, request(t, s, "POST", "/api/bootstrap-token/revoke", "session-a", map[string]string{"token": token}), 200)
	}
	if n := count(t, s, `SELECT count(*) FROM lpcc.enrollment_audit WHERE action='grant.revoke'`); n != 1 {
		t.Fatal("revocation retry duplicated audit", n)
	}
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", token, registrationBody(ownerA, strings.Repeat("3", 64), token)), 401)
	// Legacy grants without key IDs remain verifiable and explicitly revocable.
	c := enrollmentClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: enrollmentIssuer, Subject: ownerA, Audience: jwt.ClaimStrings{enrollmentAudience}, IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}, Scope: "machines:register"}
	legacy, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(oldKey))
	if _, e := s.params.enrollmentGrant(legacy, s.currentTime(), false); e != nil {
		t.Fatal("legacy rollover", e)
	}
	requireStatus(t, request(t, s, "POST", "/api/bootstrap-token/revoke", "session-a", map[string]string{"token": legacy}), 200)
	future := time.Now().Add(2 * time.Hour)
	s.now = func() time.Time { return future }
	requireStatus(t, request(t, s, "POST", "/api/bootstrap-token/revoke", "session-a", map[string]string{"token": token}), 200)
	if e := s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	if n := count(t, s, `SELECT count(*) FROM lpcc.revoked_enrollment_grants`); n != 0 {
		t.Fatal("expired revocations retained", n)
	}
}

func TestControlGrantAcceptanceAndRevocationSerialize(t *testing.T) {
	s := newTestServer(t)
	for n := 0; n < 5; n++ {
		token, _, _ := s.params.signEnrollment(ownerA, s.currentTime())
		start := make(chan struct{})
		enrolled, revoked := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
		body := registrationBody(ownerA, fmt.Sprintf("%064x", n+1), token)
		go func() { <-start; enrolled <- request(t, s, "POST", "/v1/nodes/register", token, body) }()
		go func() {
			<-start
			revoked <- request(t, s, "POST", "/api/bootstrap-token/revoke", "session-a", map[string]string{"token": token})
		}()
		close(start)
		a, b := <-enrolled, <-revoked
		if (a.Code != 200 && a.Code != 401) || b.Code != 200 {
			t.Fatal(a.Code, a.Body.String(), b.Code, b.Body.String())
		}
		requireStatus(t, request(t, s, "POST", "/v1/nodes/register", token, body), 401)
	}
}

func TestControlGrantExpiryIsRecheckedAfterLockWait(t *testing.T) {
	s := newTestServer(t)
	var clock atomic.Int64
	clock.Store(time.Now().Unix())
	s.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	for _, operation := range []string{"enroll", "revoke"} {
		token, _, _ := s.params.signEnrollment(ownerA, s.currentTime())
		c, _ := s.params.enrollmentGrant(token, s.currentTime(), false)
		tx, e := s.db.Begin()
		if e != nil {
			t.Fatal(e)
		}
		if e = lockEnrollmentGrant(t.Context(), tx, c.ID); e != nil {
			t.Fatal(e)
		}
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			if operation == "enroll" {
				done <- request(t, s, "POST", "/v1/nodes/register", token, registrationBody(ownerA, strings.Repeat("4", 64), token))
			} else {
				done <- request(t, s, "POST", "/api/bootstrap-token/revoke", "session-a", map[string]string{"token": token})
			}
		}()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var waiting bool
			e = s.db.QueryRow(`SELECT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))`).Scan(&waiting)
			if e != nil || time.Now().After(deadline) {
				_ = tx.Rollback()
				<-done
				t.Fatal("grant did not reach acceptance lock", e)
			}
			if waiting {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		clock.Add(3600)
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
		w := <-done
		if operation == "enroll" {
			requireStatus(t, w, 401)
		} else {
			requireStatus(t, w, 200)
		}
	}
	if count(t, s, `SELECT count(*) FROM lpcc.enrollments`)+count(t, s, `SELECT count(*) FROM lpcc.revoked_enrollment_grants`) != 0 {
		t.Fatal("expired acceptance persisted state")
	}
}

func TestCredentialRefreshRetryRequiresPreviousOrCurrentPossession(t *testing.T) {
	s := newTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("5", 64))
	token, _, _ := s.params.signEnrollment(ownerA, s.currentTime())
	body := map[string]any{"fingerprint": strings.Repeat("5", 64), "install_dir": "/opt/livepeer", "operation_id": uuid.New().String(), "expected_credential_version": 1, "management_proof": c["token"]}
	path := "/v1/nodes/" + c["node_id"] + "/credentials/refresh"
	w := request(t, s, "POST", path, token, body)
	requireStatus(t, w, 200)
	current := credentials(t, w.Body.Bytes())
	for _, proof := range []string{"", strings.Repeat("x", 64), c["token"], current["token"]} {
		body["management_proof"] = proof
		status := 403
		if proof == c["token"] || proof == current["token"] {
			status = 200
		}
		requireStatus(t, request(t, s, "POST", path, token, body), status)
	}
}

func TestLegacyRevocationIdentityIsCanonical(t *testing.T) {
	now := time.Now()
	p := testParams()
	c := enrollmentClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: enrollmentIssuer, Subject: ownerA, Audience: jwt.ClaimStrings{enrollmentAudience}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}, Scope: "machines:register"}
	raw, e := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(p.JWTSigningSecret))
	if e != nil {
		t.Fatal(e)
	}
	first, e := p.enrollmentGrant(raw, now, false)
	if e != nil {
		t.Fatal(e)
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	n := strings.IndexByte(alphabet, raw[len(raw)-1])
	alias := raw[:len(raw)-1] + string(alphabet[n+1])
	second, e := p.enrollmentGrant(alias, now, false)
	if e == nil && first.ID != second.ID {
		t.Fatalf("same authenticated grant has different revocation/acceptance lock identities: %s vs %s", first.ID, second.ID)
	}
}

func TestRevokedLegacyAliasMustNotEnroll(t *testing.T) {
	s := newTestServer(t)
	now := s.currentTime()
	c := enrollmentClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: enrollmentIssuer, Subject: ownerA, Audience: jwt.ClaimStrings{enrollmentAudience}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}, Scope: "machines:register"}
	raw, e := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(s.params.JWTSigningSecret))
	if e != nil {
		t.Fatal(e)
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	n := strings.IndexByte(alphabet, raw[len(raw)-1])
	alias := raw[:len(raw)-1] + string(alphabet[n+1])
	requireStatus(t, request(t, s, "POST", "/api/bootstrap-token/revoke", "session-a", map[string]string{"token": raw}), 200)
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", raw, registrationBody(ownerA, strings.Repeat("9", 64), raw)), 401)
	w := request(t, s, "POST", "/v1/nodes/register", alias, registrationBody(ownerA, strings.Repeat("9", 64), raw))
	if w.Code == 200 {
		t.Fatal("alternate signature encoding bypassed legacy grant revocation and enrolled a machine")
	}
}
