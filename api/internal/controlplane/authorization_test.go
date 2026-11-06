package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func requireStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status %d, want %d: %s", w.Code, want, w.Body.String())
	}
}
func execSQL(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, s *Server, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func adminA(t *testing.T, s *Server) string {
	t.Helper()
	s.params.DefaultAdminEmail = " A@example.invalid "
	if err := s.BootstrapAdmin(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, request(t, s, "GET", "/api/me", "session-a", nil), 200)
	var id string
	if err := s.db.QueryRow(`SELECT grant_id::text FROM lpcc.administrator_grants WHERE bound_user_id=$1 AND revoked_at IS NULL`, ownerA).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAdministratorLifecycleAndCredentialBoundaries(t *testing.T) {
	s := newTestServer(t)
	a := enroll(t, s, ownerA, strings.Repeat("a", 64))
	b := enroll(t, s, ownerB, strings.Repeat("b", 64))
	me := request(t, s, "GET", "/api/me", "session-a", nil)
	requireStatus(t, me, 200)
	if strings.Contains(me.Body.String(), `"is_admin":true`) {
		t.Fatal("editable role metadata elevated user")
	}
	for _, token := range []string{"", "invalid", a["token"]} {
		requireStatus(t, request(t, s, "POST", "/api/admin/administrators", token, map[string]string{"email": "b@example.invalid"}), 401)
	}
	requireStatus(t, request(t, s, "POST", "/api/admin/administrators", "session-a", map[string]string{"email": "b@example.invalid"}), 403)
	s.params.DefaultAdminEmail = "a@example.invalid"
	if err := s.BootstrapAdmin(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Direct admin API access must claim without a preliminary /api/me call.
	fleet := request(t, s, "GET", "/api/admin/machines", "session-a", nil)
	requireStatus(t, fleet, 200)
	if !strings.Contains(fleet.Body.String(), ownerB) {
		t.Fatal("admin cannot see another owner's inventory")
	}
	for _, secret := range []string{"fingerprint", "install_dir", "bundle", a["token"], b["token"]} {
		if strings.Contains(fleet.Body.String(), secret) {
			t.Fatal("fleet leaked", secret)
		}
	}
	var grantA string
	if err := s.db.QueryRow(`SELECT grant_id::text FROM lpcc.administrator_grants WHERE bound_user_id=$1`, ownerA).Scan(&grantA); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, request(t, s, "DELETE", "/api/admin/administrators/"+grantA, "session-a", nil), 409)
	created := request(t, s, "POST", "/api/admin/administrators", "session-a", map[string]string{"email": " B@Example.invalid "})
	requireStatus(t, created, 201)
	var grantB AdministratorGrant
	if err := json.Unmarshal(created.Body.Bytes(), &grantB); err != nil {
		t.Fatal(err)
	}
	before := count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`)
	repeated := request(t, s, "POST", "/api/admin/administrators", "session-a", map[string]string{"email": "b@example.invalid"})
	requireStatus(t, repeated, 200)
	if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`) != before {
		t.Fatal("no-op grant wrote state-change audit")
	}
	if !strings.Contains(repeated.Body.String(), grantB.GrantID) {
		t.Fatal("no-op changed identity")
	}
	requireStatus(t, request(t, s, "DELETE", "/api/admin/administrators/"+grantA, "session-b", nil), 204)
	for _, path := range []string{"/api/admin/administrators", "/api/admin/machines"} {
		requireStatus(t, request(t, s, "GET", path, "session-a", nil), 403)
	}
	requireStatus(t, request(t, s, "POST", "/api/admin/administrators", "session-a", map[string]string{"email": "b@example.invalid"}), 403)
	requireStatus(t, request(t, s, "GET", "/api/machines", "session-a", nil), 200)
	requireStatus(t, request(t, s, "POST", "/api/bootstrap-token", "session-a", nil), 200)
	if err := s.BootstrapAdmin(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.administrator_grants WHERE revoked_at IS NULL`) != 1 {
		t.Fatal("restart restored revoked default")
	}
	for _, token := range []string{"session-a", "session-b", b["token"]} {
		requireStatus(t, request(t, s, "GET", "/v1/nodes/"+a["node_id"]+"/config", token, nil), 401)
	}
	requireStatus(t, request(t, s, "GET", "/v1/nodes/"+a["node_id"]+"/config", a["token"], nil), 200)
	requireStatus(t, request(t, s, "GET", "/api/admin/machines", b["token"], nil), 401)
	var own struct {
		Machines []Machine `json:"machines"`
	}
	if err := json.Unmarshal(request(t, s, "GET", "/api/machines", "session-b", nil).Body.Bytes(), &own); err != nil || len(own.Machines) != 1 {
		t.Fatal("administrator bypassed owner scope", err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE actor_id=$1 AND action='administrator.revoke' AND target_id=$2 AND revision='3' AND outcome='success'`, ownerB, grantA) != 1 {
		t.Fatal("missing actor/revision audit")
	}
	var audit string
	if err := s.db.QueryRow(`SELECT json_agg(e)::text FROM lpcc.admin_audit_events e`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{a["token"], b["token"], "session-a", "session-b", s.params.JWTSigningSecret, s.params.MachineTokenSecret} {
		if strings.Contains(audit, credential) {
			t.Fatal("credential recorded in audit")
		}
	}
}

func TestBootstrapConcurrencyDeletionAndRecovery(t *testing.T) {
	s := newTestServer(t)
	execSQL(t, s.db, `DELETE FROM auth.users WHERE id=$1`, ownerA)
	s.params.DefaultAdminEmail = "a@example.invalid"
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errors <- s.BootstrapAdmin(t.Context()) })
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if count(t, s, `SELECT count(*) FROM lpcc.administrator_grants`) != 1 || count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`) != 1 {
		t.Fatal("concurrent bootstrap duplicated state")
	}
	s.params.DefaultAdminEmail = "typo-fixed@example.invalid"
	if err := s.BootstrapAdmin(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.administrator_grants WHERE email='a@example.invalid'`) != 1 {
		t.Fatal("config replaced pending grant")
	}
	execSQL(t, s.db, `INSERT INTO auth.users(id,email,email_confirmed_at) VALUES($1,'a@example.invalid',now())`, ownerA)
	requireStatus(t, request(t, s, "GET", "/api/me", "session-a", nil), 200)
	execSQL(t, s.db, `DELETE FROM auth.users WHERE id=$1;`, ownerA)
	execSQL(t, s.db, `INSERT INTO auth.users(id,email,email_confirmed_at) VALUES($1,'a@example.invalid',now())`, ownerC)
	if err := s.BootstrapAdmin(t.Context()); err != nil {
		t.Fatal(err)
	}
	me := request(t, s, "GET", "/api/me", "session-c", nil)
	requireStatus(t, me, 200)
	if strings.Contains(me.Body.String(), `"is_admin":true`) || count(t, s, `SELECT count(*) FROM lpcc.administrator_grants`) != 1 {
		t.Fatal("deleted account grant transferred/reseeded")
	}
	// Same transaction/lock as the documented recovery procedure.
	tx, err := s.policyTx(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var target AdminTarget
	target.Kind = "administrator_grant"
	if err := tx.QueryRow(`UPDATE lpcc.administrator_grants SET revoked_at=now(),revision=revision+1 WHERE revoked_at IS NULL RETURNING grant_id::text,revision::text`).Scan(&target.ID, &target.Revision); err != nil {
		t.Fatal(err)
	}
	if err := writeAudit(t.Context(), tx, "system", "operator-recovery", "administrator.revoke", target, "success", "recovery"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.BootstrapAdmin(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.administrator_grants WHERE email='typo-fixed@example.invalid' AND bound_user_id IS NULL AND revoked_at IS NULL`) != 1 {
		t.Fatal("explicit recovery did not permit seeding")
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func mockSettings(s *Server, body string, status int) {
	s.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/auth/v1/settings" {
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		return http.DefaultTransport.RoundTrip(r)
	})
}

func TestProvisioningEligibility(t *testing.T) {
	s := newTestServer(t)
	s.params.DefaultAdminEmail = "a@example.invalid"
	if err := s.BootstrapAdmin(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"mailer_autoconfirm":true}`, `{}`, `{"mailer_autoconfirm":null}`, `{"mailer_autoconfirm":"false"}`, `invalid`} {
		mockSettings(s, body, 200)
		requireStatus(t, request(t, s, "GET", "/api/me", "session-a", nil), 503)
		if count(t, s, `SELECT count(*) FROM lpcc.administrator_grants WHERE bound_user_id IS NOT NULL`) != 0 {
			t.Fatal("unsafe settings bound grant")
		}
	}
	mockSettings(s, `{}`, 500)
	requireStatus(t, request(t, s, "GET", "/api/me", "session-a", nil), 503)
	s.client.Transport = nil
	execSQL(t, s.db, `UPDATE auth.users SET email_confirmed_at=NULL WHERE id=$1`, ownerA)
	me := request(t, s, "GET", "/api/me", "session-a", nil)
	requireStatus(t, me, 200)
	if strings.Contains(me.Body.String(), `"is_admin":true`) {
		t.Fatal("unconfirmed bootstrap claimed")
	}
	execSQL(t, s.db, `UPDATE auth.users SET email_confirmed_at=now() WHERE id=$1`, ownerA)
	execSQL(t, s.db, `INSERT INTO auth.users(id,email,email_confirmed_at) VALUES($1,'A@example.invalid',now())`, ownerC)
	requireStatus(t, request(t, s, "GET", "/api/me", "session-a", nil), 409)
	execSQL(t, s.db, `DELETE FROM auth.users WHERE id=$1`, ownerC)
	requireStatus(t, request(t, s, "GET", "/api/me", "session-a", nil), 200)
	for _, field := range []string{"email_confirmed_at=NULL", "deleted_at=now()", "is_anonymous=true"} {
		execSQL(t, s.db, `UPDATE auth.users SET `+field+` WHERE id=$1`, ownerB)
		requireStatus(t, request(t, s, "POST", "/api/admin/administrators", "session-a", map[string]string{"email": "b@example.invalid"}), 404)
		execSQL(t, s.db, `UPDATE auth.users SET email_confirmed_at=now(),deleted_at=NULL,is_anonymous=false WHERE id=$1`, ownerB)
	}
	mockSettings(s, `{"mailer_autoconfirm":true}`, 200)
	requireStatus(t, request(t, s, "POST", "/api/admin/administrators", "session-a", map[string]string{"email": "b@example.invalid"}), 503)
	if count(t, s, `SELECT count(*) FROM lpcc.administrator_grants WHERE bound_user_id=$1`, ownerB) != 0 || count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE action='administrator.grant' AND outcome='success'`) != 0 {
		t.Fatal("unsafe grant settings changed authority")
	}
	requireStatus(t, request(t, s, "GET", "/api/admin/machines", "session-a", nil), 200)
}

func invoke(handler http.Handler, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/test/assignment", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func waitForPolicyWaiters(t *testing.T, s *Server, want int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1129073483 AND objid=2 AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n >= want {
			return
		}
	}
	t.Fatal("mutation did not wait for policy lock")
}

func TestQueuedMutationSeesCommittedRevocation(t *testing.T) {
	s := newTestServer(t)
	id := adminA(t, s)
	var database string
	if err := s.db.QueryRow(`SELECT current_database()`).Scan(&database); err != nil {
		t.Fatal(err)
	}
	execSQL(t, s.db, fmt.Sprintf(`ALTER DATABASE %q SET default_transaction_isolation='repeatable read'`, database))
	s.db.SetMaxIdleConns(0) // New connections inherit the stronger default.
	tx, err := s.policyTx(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE lpcc.administrator_grants SET revoked_at=now(),revision=revision+1 WHERE grant_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	var applied atomic.Bool
	handler := s.adminMutation("assignment.create", func(*http.Request, UserIdentity) (AdminApply, error) {
		return func(ctx context.Context, tx *sql.Tx, _ UserIdentity) (AdminChange, error) {
			applied.Store(true)
			return AdminChange{AdminTarget{"machine_assignment", "probe", "1"}, true, 200, map[string]bool{"ok": true}}, nil
		}, nil
	})
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- invoke(handler, "session-a") }()
	waitForPolicyWaiters(t, s, 1)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case w := <-result:
		requireStatus(t, w, 403)
	case <-time.After(3 * time.Second):
		t.Fatal("queued mutation stuck")
	}
	if applied.Load() {
		t.Fatal("revoked actor executed callback")
	}
}

func TestConcurrentMutualRevocation(t *testing.T) {
	s := newTestServer(t)
	a := adminA(t, s)
	w := request(t, s, "POST", "/api/admin/administrators", "session-a", map[string]string{"email": "b@example.invalid"})
	requireStatus(t, w, 201)
	var b AdministratorGrant
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	tx, err := s.policyTx(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	result := make(chan *httptest.ResponseRecorder, 2)
	go func() { result <- request(t, s, "DELETE", "/api/admin/administrators/"+b.GrantID, "session-a", nil) }()
	go func() { result <- request(t, s, "DELETE", "/api/admin/administrators/"+a, "session-b", nil) }()
	waitForPolicyWaiters(t, s, 2)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	codes := map[int]int{}
	for range 2 {
		select {
		case w := <-result:
			codes[w.Code]++
		case <-time.After(3 * time.Second):
			t.Fatal("revocation stuck")
		}
	}
	if codes[204] != 1 || codes[403] != 1 || count(t, s, `SELECT count(*) FROM lpcc.administrator_grants WHERE revoked_at IS NULL`) != 1 {
		t.Fatal("mutual revocation removed all admins", codes)
	}
}

func TestAuditRollbackAndDeniedTraffic(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	var logs bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&logs, nil))
	before := count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`)
	for range 100 {
		requireStatus(t, request(t, s, "POST", "/api/admin/administrators", "", nil), 401)
		requireStatus(t, request(t, s, "POST", "/api/admin/administrators", "session-b", nil), 403)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`) != before || strings.Count(logs.String(), "administrator request denied") != 1 {
		t.Fatal("untrusted denials amplified audit writes/logs")
	}
	execSQL(t, s.db, `ALTER TABLE lpcc.admin_audit_events ADD CONSTRAINT reject_success CHECK(outcome<>'success') NOT VALID`)
	requireStatus(t, request(t, s, "POST", "/api/admin/administrators", "session-a", map[string]string{"email": "b@example.invalid"}), 503)
	if count(t, s, `SELECT count(*) FROM lpcc.administrator_grants WHERE bound_user_id=$1`, ownerB) != 0 {
		t.Fatal("audit failure committed grant")
	}
	if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE outcome='failure'`) != 1 {
		t.Fatal("authorized failure was not recorded after rollback")
	}
	execSQL(t, s.db, `ALTER TABLE lpcc.admin_audit_events DROP CONSTRAINT reject_success`)
	// A deferred trigger fails at commit, after apply and success-audit insertion.
	execSQL(t, s.db, `CREATE FUNCTION lpcc.reject_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$;
 CREATE CONSTRAINT TRIGGER reject_commit AFTER INSERT ON lpcc.administrator_grants DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION lpcc.reject_commit()`)
	w := request(t, s, "POST", "/api/admin/administrators", "session-a", map[string]string{"email": "b@example.invalid"})
	requireStatus(t, w, 503)
	if strings.Contains(w.Body.String(), `"grant_id"`) || count(t, s, `SELECT count(*) FROM lpcc.administrator_grants WHERE bound_user_id=$1`, ownerB) != 0 {
		t.Fatal("commit failure leaked success/committed grant")
	}
}

func TestBootstrapAuditFailureAndLockTimeout(t *testing.T) {
	s := newTestServer(t)
	s.params.DefaultAdminEmail = "a@example.invalid"
	execSQL(t, s.db, `ALTER TABLE lpcc.admin_audit_events ADD CONSTRAINT reject_bootstrap CHECK(action<>'administrator.bootstrap')`)
	if err := s.BootstrapAdmin(t.Context()); err == nil {
		t.Fatal("bootstrap swallowed audit failure")
	}
	if count(t, s, `SELECT count(*) FROM lpcc.administrator_grants`) != 0 {
		t.Fatal("failed bootstrap persisted grant")
	}
	execSQL(t, s.db, `ALTER TABLE lpcc.admin_audit_events DROP CONSTRAINT reject_bootstrap`)
	adminA(t, s)
	tx, err := s.policyTx(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	start := time.Now()
	requireStatus(t, request(t, s, "POST", "/api/admin/administrators", "session-a", map[string]string{"email": "b@example.invalid"}), 503)
	if time.Since(start) > 4*time.Second {
		t.Fatal("policy lock wait was unbounded")
	}
	// Ordinary /me polls do not wait on the policy lock.
	requireStatus(t, request(t, s, "GET", "/api/me", "session-b", nil), 200)
}

func TestBindingAtomicityAndConcurrentClaims(t *testing.T) {
	s := newTestServer(t)
	s.params.DefaultAdminEmail = "a@example.invalid"
	if err := s.BootstrapAdmin(t.Context()); err != nil {
		t.Fatal(err)
	}
	execSQL(t, s.db, `ALTER TABLE lpcc.admin_audit_events ADD CONSTRAINT reject_binding CHECK(action<>'administrator.bind') NOT VALID`)
	requireStatus(t, request(t, s, "GET", "/api/me", "session-a", nil), 503)
	if count(t, s, `SELECT count(*) FROM lpcc.administrator_grants WHERE bound_user_id IS NOT NULL`) != 0 {
		t.Fatal("audit failure committed binding")
	}
	execSQL(t, s.db, `ALTER TABLE lpcc.admin_audit_events DROP CONSTRAINT reject_binding`)
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 8)
	for range 8 {
		wg.Go(func() { results <- request(t, s, "GET", "/api/me", "session-a", nil) })
	}
	wg.Wait()
	close(results)
	for result := range results {
		requireStatus(t, result, 200)
		if !strings.Contains(result.Body.String(), `"is_admin":true`) {
			t.Fatal("claim did not converge")
		}
	}
	if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE action='administrator.bind'`) != 1 {
		t.Fatal("concurrent claims duplicated binding audit")
	}
}

func TestAdminMutationContract(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	execSQL(t, s.db, `CREATE TABLE lpcc.assignment_probe (id TEXT PRIMARY KEY)`)
	for _, status := range []int{200, 400, 404, 409, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			handler := s.adminMutation("assignment.create", func(*http.Request, UserIdentity) (AdminApply, error) {
				return func(ctx context.Context, tx *sql.Tx, _ UserIdentity) (AdminChange, error) {
					change := AdminChange{AdminTarget{"machine_assignment", "probe", "7"}, true, 200, map[string]bool{"ok": true}}
					if _, err := tx.ExecContext(ctx, `INSERT INTO lpcc.assignment_probe VALUES('probe')`); err != nil {
						return change, err
					}
					if status == 503 {
						return change, fmt.Errorf("private error must not escape")
					}
					if status != 200 {
						return change, problem(status, "fixture_rejection", "Requested change rejected.")
					}
					return change, nil
				}, nil
			})
			w := invoke(handler, "session-a")
			requireStatus(t, w, status)
			want := 0
			if status == 200 {
				want = 1
			}
			if count(t, s, `SELECT count(*) FROM lpcc.assignment_probe`) != want || strings.Contains(w.Body.String(), "private error") {
				t.Fatal("callback error leaked or committed side effects")
			}
			execSQL(t, s.db, `DELETE FROM lpcc.assignment_probe`)
		})
	}
	// A malformed/oversized request is rejected before taking the policy lock.
	for _, body := range []string{`{"email":"b@example.invalid","role":"admin"}`, `{"email":"b@example.invalid"}` + strings.Repeat(" ", 5000)} {
		r := httptest.NewRequest("POST", "/api/admin/administrators", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer session-a")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		requireStatus(t, w, 400)
	}
}

func TestAccountEmailChangedBeforeBinding(t *testing.T) {
	s := newTestServer(t)
	s.params.DefaultAdminEmail = "a@example.invalid"
	if err := s.BootstrapAdmin(t.Context()); err != nil {
		t.Fatal(err)
	}
	var changed atomic.Bool
	s.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		response, err := http.DefaultTransport.RoundTrip(r)
		if err == nil && r.URL.Path == "/auth/v1/user" && changed.CompareAndSwap(false, true) {
			if _, err := s.db.Exec(`UPDATE auth.users SET email='changed@example.invalid' WHERE id=$1`, ownerA); err != nil {
				t.Error(err)
			}
		}
		return response, err
	})
	requireStatus(t, request(t, s, "GET", "/api/me", "session-a", nil), 404)
	if count(t, s, `SELECT count(*) FROM lpcc.administrator_grants WHERE bound_user_id IS NOT NULL`) != 0 {
		t.Fatal("stale Auth response bound grant")
	}
}

func TestMembershipRecheckFailureAudited(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	var logs bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&logs, nil))
	lock, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	var applied bool
	handler := s.adminMutation("assignment.create", func(*http.Request, UserIdentity) (AdminApply, error) {
		// Initial authorization has completed. Simulate a temporarily unavailable
		// policy table while leaving the independent audit table writable.
		if _, err := lock.Exec(`LOCK TABLE lpcc.administrator_grants IN ACCESS EXCLUSIVE MODE`); err != nil {
			return nil, err
		}
		return func(context.Context, *sql.Tx, UserIdentity) (AdminChange, error) {
			applied = true
			return AdminChange{}, nil
		}, nil
	})
	requireStatus(t, invoke(handler, "session-a"), 503)
	if applied {
		t.Fatal("callback ran after failed membership recheck")
	}
	if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE actor_id=$1 AND action='assignment.create' AND outcome='failure'`, ownerA) != 1 {
		t.Fatal("authorized recheck failure was not audited")
	}
	if !strings.Contains(logs.String(), "postgres_55P03") || strings.Contains(logs.String(), "session-a") {
		t.Fatal("missing safe lock-timeout diagnostic", logs.String())
	}
}

func TestProvisioningEmailDoesNotGateUUIDAuthority(t *testing.T) {
	s := newTestServer(t)
	for _, bound := range []bool{false, true} {
		if bound {
			execSQL(t, s.db, `UPDATE auth.users SET email='a@example.invalid' WHERE id=$1`, ownerA)
			adminA(t, s)
		}
		execSQL(t, s.db, `UPDATE auth.users SET email='a..b@example.invalid' WHERE id=$1`, ownerA)
		for _, path := range []string{"/api/machines", "/api/bootstrap-token"} {
			method := "GET"
			if path == "/api/bootstrap-token" {
				method = "POST"
			}
			requireStatus(t, request(t, s, method, path, "session-a", nil), 200)
		}
		me := request(t, s, "GET", "/api/me", "session-a", nil)
		requireStatus(t, me, 200)
		if strings.Contains(me.Body.String(), `"is_admin":true`) != bound {
			t.Fatal("email syntax changed UUID authority")
		}
		if bound {
			requireStatus(t, request(t, s, "GET", "/api/admin/machines", "session-a", nil), 200)
			requireStatus(t, request(t, s, "POST", "/api/admin/administrators", "session-a", map[string]string{"email": "a..b@example.invalid"}), 400)
		}
	}
}

func TestDeletedAdministratorListAndRevocation(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	w := request(t, s, "POST", "/api/admin/administrators", "session-a", map[string]string{"email": "b@example.invalid"})
	requireStatus(t, w, 201)
	var grant AdministratorGrant
	if err := json.Unmarshal(w.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	for _, deleted := range []bool{false, true} {
		query := `UPDATE auth.users SET email='renamed@example.invalid' WHERE id=$1`
		if deleted {
			query = `DELETE FROM auth.users WHERE id=$1`
		}
		execSQL(t, s.db, query, ownerB)
		w := request(t, s, "GET", "/api/admin/administrators", "session-a", nil)
		requireStatus(t, w, 200)
		var result struct {
			Administrators []AdministratorGrant `json:"administrators"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, g := range result.Administrators {
			if g.GrantID == grant.GrantID {
				found = true
				if g.UserID == nil || *g.UserID != ownerB {
					t.Fatal("bound UUID lost")
				}
				if deleted {
					if g.State != "account_missing" || g.CurrentEmail != nil {
						t.Fatal("missing-account state", g)
					}
				} else if g.State != "bound" || g.CurrentEmail == nil || *g.CurrentEmail != "renamed@example.invalid" {
					t.Fatal("renamed account state", g)
				}
			}
		}
		if !found {
			t.Fatal("grant lost after Auth change")
		}
	}
	requireStatus(t, request(t, s, "DELETE", "/api/admin/administrators/"+grant.GrantID, "session-a", nil), 204)
	requireStatus(t, request(t, s, "DELETE", "/api/admin/administrators/"+grant.GrantID, "session-a", nil), 404)
}

func TestUnexpectedErrorDiagnosticsDoNotLeak(t *testing.T) {
	var logs bytes.Buffer
	s := New(nil, testParams(), slog.New(slog.NewTextHandler(&logs, nil)))
	err := &pgconn.PgError{Code: "42501", Message: "sentinel-secret", Detail: "Bearer sensitive-token", InternalQuery: "request-body-secret"}
	for range 3 {
		w := httptest.NewRecorder()
		s.respondError(w, err)
		requireStatus(t, w, 503)
		if strings.Contains(w.Body.String(), "sentinel") {
			t.Fatal("error response exposed details")
		}
	}
	if !strings.Contains(logs.String(), "postgres_42501") || strings.Count(logs.String(), "control plane operation failed") != 1 {
		t.Fatal("missing or unbounded diagnostics", logs.String())
	}
	for _, secret := range []string{"sentinel-secret", "sensitive-token", "request-body-secret"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("error detail leaked", secret)
		}
	}
}
