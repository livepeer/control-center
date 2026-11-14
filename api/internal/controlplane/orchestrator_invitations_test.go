package controlplane

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/livepeer/control-center/api/internal/migrations"
)

func invitation(t *testing.T, s *Server, session, address string) string {
	t.Helper()
	w := request(t, s, "POST", "/api/orchestrators/"+address+"/invitations", session, nil)
	requireStatus(t, w, 200)
	var result struct {
		Token     string
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Token == "" {
		t.Fatal(w.Body.String(), err)
	}
	return result.Token
}

func TestInvitationTokenValidation(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s := &Server{params: testParams(), now: func() time.Time { return now }}
	raw, expires, err := s.signInvitation(ownerA, orchA)
	if err != nil || !expires.Equal(now.Add(24*time.Hour)) {
		t.Fatal(expires, err)
	}
	base, err := s.verifyInvitation(raw)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*invitationClaims){
		"scope":            func(c *invitationClaims) { c.Scope = "machines:register" },
		"issuer":           func(c *invitationClaims) { c.Issuer = "another-service" },
		"audience":         func(c *invitationClaims) { c.Audience = jwt.ClaimStrings{enrollmentAudience} },
		"extra audience":   func(c *invitationClaims) { c.Audience = jwt.ClaimStrings{invitationAudience, enrollmentAudience} },
		"deployment":       func(c *invitationClaims) { c.ControlCenter = "https://another.example" },
		"missing issuance": func(c *invitationClaims) { c.IssuedAt = nil },
		"future issuance":  func(c *invitationClaims) { c.IssuedAt = jwt.NewNumericDate(now.Add(time.Second)) },
		"missing expiry":   func(c *invitationClaims) { c.ExpiresAt = nil },
		"expired":          func(c *invitationClaims) { c.ExpiresAt = jwt.NewNumericDate(now) },
		"excess lifetime":  func(c *invitationClaims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(24*time.Hour + time.Second)) },
		"missing user":     func(c *invitationClaims) { c.Subject = "" },
		"nil user":         func(c *invitationClaims) { c.Subject = uuid.Nil().String() },
		"invalid id":       func(c *invitationClaims) { c.ID = "invalid" },
		"nil id":           func(c *invitationClaims) { c.ID = uuid.Nil().String() },
		"invalid address":  func(c *invitationClaims) { c.OrchestratorAddress = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			c := *base
			mutate(&c)
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
			token.Header["kid"] = s.params.signingKeyID()
			raw, err := token.SignedString([]byte(s.params.JWTSigningSecret))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.verifyInvitation(raw); err == nil {
				t.Fatal("invalid invitation accepted")
			}
		})
	}
	for _, kind := range []string{"signature", "kid", "missing kid", "algorithm"} {
		t.Run(kind, func(t *testing.T) {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, base)
			token.Header["kid"] = s.params.signingKeyID()
			secret := s.params.JWTSigningSecret
			switch kind {
			case "signature":
				secret = strings.Repeat("x", 32)
			case "kid":
				token.Header["kid"] = "unknown"
			case "missing kid":
				delete(token.Header, "kid")
			case "algorithm":
				token = jwt.NewWithClaims(jwt.SigningMethodHS384, base)
				token.Header["kid"] = s.params.signingKeyID()
			}
			bad, _ := token.SignedString([]byte(secret))
			if _, err := s.verifyInvitation(bad); err == nil {
				t.Fatal("invalid signature accepted")
			}
		})
	}
	s.now = func() time.Time { return expires.Add(-time.Nanosecond) }
	if _, err := s.verifyInvitation(raw); err != nil {
		t.Fatal("expired early", err)
	}
	s.now = func() time.Time { return expires }
	if _, err := s.verifyInvitation(raw); err == nil {
		t.Fatal("accepted at expiry")
	}
	s.now = func() time.Time { return now }
	if _, err := s.params.enrollmentGrant(raw, now, false); err == nil {
		t.Fatal("invitation used for enrollment")
	}
	if _, err := s.verifyOrchestratorClaim(raw, ownerA); err == nil {
		t.Fatal("invitation used for claim")
	}
	grant, _, _ := s.params.signEnrollment(ownerA, orchA, now)
	claim, _, _ := s.signOrchestratorClaim(ownerA, orchA)
	for _, other := range []string{grant, claim} {
		if _, err := s.verifyInvitation(other); err == nil {
			t.Fatal("other token used for invitation")
		}
	}
	oldKey := s.params.JWTSigningSecret
	s.params.JWTSigningKeyID, s.params.JWTSigningSecret = "next", strings.Repeat("n", 32)
	s.params.JWTVerificationKeys = `{"1":"` + oldKey + `"}`
	if _, err := s.verifyInvitation(raw); err != nil {
		t.Fatal("retained key refused", err)
	}
}

func TestInvitationLifecycleAndEqualPermissions(t *testing.T) {
	s := newTestServer(t)
	path := "/api/orchestrators/" + orchA
	proof := uuid.New().String()
	execSQL(t, s.db, `UPDATE lpcc.orchestrators SET proof_jti=$1 WHERE address=$2`, proof, orchA)
	machine := enroll(t, s, ownerA, strings.Repeat("e", 64))
	grant, _, _ := s.params.signEnrollment(ownerA, orchA, s.currentTime())
	token := invitation(t, s, "session-a", orchA)
	if token == invitation(t, s, "session-a", orchA) {
		t.Fatal("invitation identifiers reused")
	}
	if count(t, s, `SELECT count(*) FROM lpcc.orchestrator_invitation_acceptances`) != 0 || count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`) != 0 {
		t.Fatal("issuance persisted invitation state")
	}
	body := map[string]string{"token": token}
	for _, endpoint := range []string{path + "/members", path + "/invitations"} {
		method := "GET"
		if strings.HasSuffix(endpoint, "invitations") {
			method = "POST"
		}
		requireStatus(t, request(t, s, method, endpoint, "session-b", nil), 403)
	}
	requireStatus(t, request(t, s, "POST", "/api/orchestrator-invitations/preview", "", body), 401)
	requireStatus(t, request(t, s, "POST", "/api/orchestrator-invitations/preview", "session-b", body), 200)
	requireStatus(t, request(t, s, "POST", "/api/orchestrator-invitations/accept", "session-b", body), 200)
	for _, session := range []string{"session-a", "session-b"} {
		requireStatus(t, request(t, s, "POST", "/api/orchestrator-invitations/accept", session, body), 409)
	}
	w := request(t, s, "GET", path+"/members", "session-b", nil)
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), ownerA) || !strings.Contains(w.Body.String(), ownerB) {
		t.Fatal(w.Body.String())
	}
	pending := invitation(t, s, "session-a", orchA)
	invitation(t, s, "session-b", orchA)
	requireStatus(t, request(t, s, "DELETE", path+"/members/"+ownerA, "session-b", nil), 204)
	requireStatus(t, request(t, s, "GET", path+"/members", "session-a", nil), 403)
	requireStatus(t, request(t, s, "POST", "/api/bootstrap-token", "session-a", map[string]string{"orchestrator_address": orchA}), 403)
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", grant, registrationBody(ownerA, strings.Repeat("f", 64), grant)), 403)
	s.params.SecretsMetadataToken = "test-metadata-token"
	requireStatus(t, request(t, s, "GET", "/internal/users/"+ownerA+"/orchestrators/"+orchA, s.params.SecretsMetadataToken, nil), 403)
	requireStatus(t, request(t, s, "GET", "/v1/nodes/"+machine["node_id"]+"/config", machine["token"], nil), 200)
	if count(t, s, `SELECT count(*) FROM lpcc.orchestrators WHERE address=$1 AND claimed_by_user_id=$2 AND proof_jti=$3`, orchA, ownerA, proof) != 1 {
		t.Fatal("claim record changed")
	}
	if count(t, s, `SELECT count(*) FROM lpcc.orchestrator_invitation_acceptances WHERE inviter_user_id=$1 AND accepted_by_user_id=$2 AND orchestrator_address=$3`, ownerA, ownerB, orchA) != 1 {
		t.Fatal("acceptance identities missing")
	}
	if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE actor_id=$1 AND action IN ('orchestrator.invitation.accept','orchestrator.member.remove')`, ownerB) != 2 {
		t.Fatal("audit actors missing")
	}
	requireStatus(t, request(t, s, "POST", "/api/orchestrator-invitations/accept", "session-b", map[string]string{"token": pending}), 403)
	w = request(t, s, "DELETE", path+"/members/"+ownerB, "session-b", nil)
	requireStatus(t, w, 409)
	if !strings.Contains(w.Body.String(), `"code":"last_member"`) {
		t.Fatal(w.Body.String())
	}
}

func TestInvitationConsumptionAndRollback(t *testing.T) {
	s := newTestServer(t)
	body := map[string]string{"token": invitation(t, s, "session-a", orchA)}
	execSQL(t, s.db, `ALTER TABLE lpcc.admin_audit_events ADD CONSTRAINT reject_acceptance CHECK(action<>'orchestrator.invitation.accept') NOT VALID`)
	requireStatus(t, request(t, s, "POST", "/api/orchestrator-invitations/accept", "session-b", body), 503)
	if count(t, s, `SELECT count(*) FROM lpcc.orchestrator_invitation_acceptances`) != 0 || count(t, s, `SELECT count(*) FROM lpcc.orchestrator_memberships WHERE user_id=$1 AND orchestrator_address=$2`, ownerB, orchA) != 0 {
		t.Fatal("failed acceptance partially committed")
	}
	execSQL(t, s.db, `ALTER TABLE lpcc.admin_audit_events DROP CONSTRAINT reject_acceptance`)
	requireStatus(t, request(t, s, "POST", "/api/orchestrator-invitations/accept", "session-b", body), 200)
	requireStatus(t, request(t, s, "DELETE", "/api/orchestrators/"+orchA+"/members/"+ownerB, "session-a", nil), 204)
	requireStatus(t, request(t, s, "POST", "/api/orchestrator-invitations/accept", "session-b", body), 409)
	// Even an existing member explicitly accepting consumes the link.
	self := map[string]string{"token": invitation(t, s, "session-a", orchA)}
	requireStatus(t, request(t, s, "POST", "/api/orchestrator-invitations/accept", "session-a", self), 200)
	requireStatus(t, request(t, s, "POST", "/api/orchestrator-invitations/accept", "session-b", self), 409)
}

func TestConcurrentInvitationAcceptance(t *testing.T) {
	for _, sameLink := range []bool{true, false} {
		t.Run(map[bool]string{true: "same link", false: "independent links"}[sameLink], func(t *testing.T) {
			s := newTestServer(t)
			execSQL(t, s.db, `INSERT INTO auth.users(id,email) VALUES($1,'c@example.invalid')`, ownerC)
			one := invitation(t, s, "session-a", orchA)
			two := one
			if !sameLink {
				two = invitation(t, s, "session-a", orchA)
			}
			start := make(chan struct{})
			done := make(chan *httptest.ResponseRecorder, 2)
			for _, in := range []struct{ session, token string }{{"session-b", one}, {"session-c", two}} {
				go func() {
					<-start
					done <- request(t, s, "POST", "/api/orchestrator-invitations/accept", in.session, map[string]string{"token": in.token})
				}()
			}
			close(start)
			statuses := map[int]int{}
			for range 2 {
				w := <-done
				statuses[w.Code]++
			}
			want := 2
			if sameLink {
				want = 1
				if statuses[409] != 1 {
					t.Fatal(statuses)
				}
			}
			if statuses[200] != want || count(t, s, `SELECT count(*) FROM lpcc.orchestrator_invitation_acceptances`) != want {
				t.Fatal(statuses)
			}
		})
	}
}

func TestConcurrentMemberRemoval(t *testing.T) {
	for _, cross := range []bool{false, true} {
		t.Run(map[bool]string{false: "departures", true: "cross removals"}[cross], func(t *testing.T) {
			s := newTestServer(t)
			execSQL(t, s.db, `INSERT INTO lpcc.orchestrator_memberships VALUES($1,$2)`, ownerB, orchA)
			start := make(chan struct{})
			done := make(chan *httptest.ResponseRecorder, 2)
			a, b := ownerA, ownerB
			if cross {
				a, b = b, a
			}
			for _, in := range []struct{ session, target string }{{"session-a", a}, {"session-b", b}} {
				go func() {
					<-start
					done <- request(t, s, "DELETE", "/api/orchestrators/"+orchA+"/members/"+in.target, in.session, nil)
				}()
			}
			close(start)
			statuses := map[int]int{}
			for range 2 {
				w := <-done
				statuses[w.Code]++
			}
			if statuses[204] != 1 || count(t, s, `SELECT count(*) FROM lpcc.orchestrator_memberships WHERE orchestrator_address=$1`, orchA) != 1 {
				t.Fatal(statuses)
			}
			if cross && statuses[403] != 1 || !cross && statuses[409] != 1 {
				t.Fatal(statuses)
			}
		})
	}
}

func TestInviterRemovalSerializesAcceptance(t *testing.T) {
	for _, removeFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "removal first", false: "acceptance first"}[removeFirst], func(t *testing.T) {
			s := newTestServer(t)
			execSQL(t, s.db, `INSERT INTO lpcc.orchestrator_memberships VALUES($1,$2)`, ownerB, orchA)
			execSQL(t, s.db, `INSERT INTO auth.users(id) VALUES($1)`, ownerC)
			token := invitation(t, s, "session-a", orchA)
			block, err := s.membershipTx(t.Context(), orchA)
			if err != nil {
				t.Fatal(err)
			}
			defer block.Rollback()
			remove := func() *httptest.ResponseRecorder {
				return request(t, s, "DELETE", "/api/orchestrators/"+orchA+"/members/"+ownerA, "session-b", nil)
			}
			accept := func() *httptest.ResponseRecorder {
				return request(t, s, "POST", "/api/orchestrator-invitations/accept", "session-c", map[string]string{"token": token})
			}
			first, second := remove, accept
			if !removeFirst {
				first, second = accept, remove
			}
			done1, done2 := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
			go func() { done1 <- first() }()
			waitMembershipWriters(t, s, 1)
			go func() { done2 <- second() }()
			waitMembershipWriters(t, s, 2)
			if err = block.Commit(); err != nil {
				t.Fatal(err)
			}
			w1, w2 := <-done1, <-done2
			if removeFirst {
				requireStatus(t, w1, 204)
				requireStatus(t, w2, 403)
			} else {
				requireStatus(t, w1, 200)
				requireStatus(t, w2, 204)
			}
		})
	}
}

func waitMembershipWriters(t *testing.T, s *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for count(t, s, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%17241%'`) < want {
		if time.Now().After(deadline) {
			t.Fatal("membership writer did not wait")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestBootstrapRechecksMembershipAfterChainLookup(t *testing.T) {
	s := newTestServer(t)
	onchainSettings(t, s)
	execSQL(t, s.db, `INSERT INTO lpcc.orchestrator_memberships VALUES($1,$2)`, ownerB, orchA)
	entered, release := make(chan struct{}), make(chan struct{})
	s.activeCheck = func(ctx context.Context, _ string) (bool, error) {
		close(entered)
		select {
		case <-release:
			return true, nil
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- request(t, s, "POST", "/api/bootstrap-token", "session-a", map[string]string{"orchestrator_address": orchA})
	}()
	<-entered
	w := request(t, s, "DELETE", "/api/orchestrators/"+orchA+"/members/"+ownerA, "session-b", nil)
	close(release)
	requireStatus(t, w, 204)
	requireStatus(t, <-done, 403)
	if s.grantsIssued.Load() != 0 {
		t.Fatal("token issued after membership removal")
	}
}

func TestDeletedMembersDoNotPermitLastDeparture(t *testing.T) {
	s := newTestServer(t)
	execSQL(t, s.db, `INSERT INTO lpcc.orchestrator_memberships VALUES($1,$2)`, ownerB, orchA)
	execSQL(t, s.db, `UPDATE auth.users SET deleted_at=now() WHERE id=$1`, ownerB)
	invitation(t, s, "session-a", orchA)
	requireStatus(t, request(t, s, "DELETE", "/api/orchestrators/"+orchA+"/members/"+ownerA, "session-a", nil), 409)
}

func TestInvitationExpiryIsRecheckedAfterWaiting(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().Truncate(time.Second)
	var clock atomic.Int64
	clock.Store(now.Unix())
	s.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	token := invitation(t, s, "session-a", orchA)
	block, err := s.membershipTx(t.Context(), orchA)
	if err != nil {
		t.Fatal(err)
	}
	defer block.Rollback()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- request(t, s, "POST", "/api/orchestrator-invitations/accept", "session-b", map[string]string{"token": token})
	}()
	waitMembershipWriters(t, s, 1)
	clock.Store(now.Add(24 * time.Hour).Unix())
	if err = block.Commit(); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, <-done, 400)
	if count(t, s, `SELECT count(*) FROM lpcc.orchestrator_invitation_acceptances`) != 0 {
		t.Fatal("expired invitation consumed")
	}
}

func TestInvitationMigrationPreservesExistingData(t *testing.T) {
	s := newTestServer(t)
	m := enroll(t, s, ownerA, strings.Repeat("a", 64))
	files, err := fs.Sub(MigrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if err = migrations.Down(t.Context(), s.db, files); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(t.Context(), s.db); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.orchestrator_memberships`) != 2 {
		t.Fatal("membership migration lost data")
	}
	requireStatus(t, request(t, s, "GET", "/v1/nodes/"+m["node_id"]+"/config", m["token"], nil), 200)
}

func TestInvitationAccountsMustRemainLive(t *testing.T) {
	for _, actor := range []string{"inviter", "recipient"} {
		for _, deletion := range []string{"soft", "hard"} {
			t.Run(actor+"/"+deletion, func(t *testing.T) {
				s := newTestServer(t)
				token := invitation(t, s, "session-a", orchA)
				id := ownerA
				if actor == "recipient" {
					id = ownerB
				}
				remove := func() {
					query := `UPDATE auth.users SET deleted_at=now() WHERE id=$1`
					if deletion == "hard" {
						query = `DELETE FROM auth.users WHERE id=$1`
					}
					execSQL(t, s.db, query, id)
				}
				if actor == "inviter" {
					remove()
				} else {
					// Auth can return a valid identity just before account deletion.
					s.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
						res, err := http.DefaultTransport.RoundTrip(r)
						if err == nil {
							remove()
						}
						return res, err
					})
				}
				requireStatus(t, request(t, s, "POST", "/api/orchestrator-invitations/accept", "session-b", map[string]string{"token": token}), 403)
				if count(t, s, `SELECT count(*) FROM lpcc.orchestrator_invitation_acceptances`) != 0 {
					t.Fatal("deleted account consumed invitation")
				}
			})
		}
	}
}

func TestMemberRemovalWaitsForEnrollment(t *testing.T) {
	s := newTestServer(t)
	execSQL(t, s.db, `INSERT INTO lpcc.orchestrator_memberships VALUES($1,$2)`, ownerB, orchA)
	token, _, _ := s.params.signEnrollment(ownerA, orchA, s.currentTime())
	c, err := s.params.enrollmentGrant(token, s.currentTime(), false)
	if err != nil {
		t.Fatal(err)
	}
	block, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer block.Rollback()
	if err = lockEnrollmentGrant(t.Context(), block, c.ID); err != nil {
		t.Fatal(err)
	}
	enrolled := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		enrolled <- request(t, s, "POST", "/v1/nodes/register", token, registrationBody(ownerA, strings.Repeat("b", 64), token))
	}()
	waitForAuthorizationLock(t, s)
	removed := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		removed <- request(t, s, "DELETE", "/api/orchestrators/"+orchA+"/members/"+ownerA, "session-b", nil)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for count(t, s, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'DELETE FROM lpcc.orchestrator_memberships%'`) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("removal did not wait for enrollment")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = block.Commit(); err != nil {
		t.Fatal(err)
	}
	w := <-enrolled
	requireStatus(t, w, 200)
	requireStatus(t, <-removed, 204)
	m := credentials(t, w.Body.Bytes())
	requireStatus(t, request(t, s, "GET", "/v1/nodes/"+m["node_id"]+"/config", m["token"], nil), 200)
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", token, registrationBody(ownerA, strings.Repeat("c", 64), token)), 403)
}
