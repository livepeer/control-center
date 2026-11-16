package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type administrationResult struct {
	UserIdentity
	IsAdmin        bool                     `json:"is_admin"`
	Administrators []AdministratorGrant     `json:"administrators"`
	Machines       []observedMachineSummary `json:"machines"`
}

func decodeAdministration(t *testing.T, w *httptest.ResponseRecorder) administrationResult {
	t.Helper()
	requireStatus(t, w, 200)
	var result administrationResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

type administrationQueryCounter struct{ n atomic.Int64 }

func (c *administrationQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.n.Add(1)
	return ctx
}
func (*administrationQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestAdministrationBoundPoll(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	a := enroll(t, s, ownerA, strings.Repeat("a", 64))
	b := enroll(t, s, ownerB, strings.Repeat("b", 64))
	// Include the terminal cleanup projection and a deleted grant holder.
	execSQL(t, s.db, `UPDATE lpcc.enrollments SET retired_at=now() WHERE node_id=$1`, b["node_id"])
	execSQL(t, s.db, `DELETE FROM lpcc.machines WHERE node_id=$1`, b["node_id"])
	requireStatus(t, request(t, s, "POST", "/api/admin/administrators", "session-a", map[string]string{"email": "b@example.invalid"}), 201)
	execSQL(t, s.db, `DELETE FROM auth.users WHERE id=$1`, ownerB)
	grants := request(t, s, "GET", "/api/admin/administrators", "session-a", nil)
	requireStatus(t, grants, 200)
	fleet := request(t, s, "GET", "/api/admin/machines", "session-a", nil)
	requireStatus(t, fleet, 200)
	var expected administrationResult
	if err := json.Unmarshal(grants.Body.Bytes(), &expected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fleet.Body.Bytes(), &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected.Machines) != 2 || !expected.Machines[0].Terminal {
		t.Fatal("terminal fleet fixture missing")
	}
	if len(expected.Administrators) != 2 || expected.Administrators[1].State != "account_missing" {
		t.Fatal("deleted administrator fixture missing")
	}
	// Count only server SQL; the Auth fixture retains its own database pool.
	var database string
	if err := s.db.QueryRow(`SELECT current_database()`).Scan(&database); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = database
	cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
	queries := &administrationQueryCounter{}
	cfg.Tracer = queries
	s.db = stdlib.OpenDB(*cfg)
	t.Cleanup(func() { s.db.Close() })
	var calls atomic.Int64
	s.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return http.DefaultTransport.RoundTrip(r)
	})
	w := request(t, s, "GET", "/api/admin/overview", "session-a", nil)
	got := decodeAdministration(t, w)
	if calls.Load() != 1 || queries.n.Load() != 3 {
		t.Fatalf("poll used %d Auth calls and %d SQL statements; want 1 and 3", calls.Load(), queries.n.Load())
	}
	if !got.IsAdmin || got.ID != ownerA || !reflect.DeepEqual(got.Administrators, expected.Administrators) || !reflect.DeepEqual(got.Machines, expected.Machines) {
		t.Fatal("overview differs from existing projections")
	}
	for _, secret := range []string{"fingerprint", "install_dir", "bundle", "credential_version", a["token"], b["token"]} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("overview leaked private machine data")
		}
	}
}

func TestAdministrationAuthority(t *testing.T) {
	s := newTestServer(t)
	grant := adminA(t, s)
	enroll(t, s, ownerA, strings.Repeat("a", 64))
	ordinary := decodeAdministration(t, request(t, s, "GET", "/api/admin/overview", "session-b", nil))
	if ordinary.ID != ownerB || ordinary.IsAdmin || ordinary.Administrators == nil || ordinary.Machines == nil || len(ordinary.Administrators) != 0 || len(ordinary.Machines) != 0 {
		t.Fatal("ordinary account received privileged data or missing lists")
	}
	execSQL(t, s.db, `UPDATE lpcc.administrator_grants SET revoked_at=now(),revision=revision+1 WHERE grant_id=$1`, grant)
	revoked := decodeAdministration(t, request(t, s, "GET", "/api/admin/overview", "session-a", nil))
	if revoked.IsAdmin || len(revoked.Administrators) != 0 || len(revoked.Machines) != 0 {
		t.Fatal("revoked account retained authority")
	}
	execSQL(t, s.db, `DELETE FROM auth.users WHERE id=$1`, ownerA)
	requireStatus(t, request(t, s, "GET", "/api/admin/overview", "session-a", nil), 401)
	for _, token := range []string{"", "invalid"} {
		requireStatus(t, request(t, s, "GET", "/api/admin/overview", token, nil), 401)
	}
	s.client.Transport = transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
	})
	requireStatus(t, request(t, s, "GET", "/api/admin/overview", "session-b", nil), 503)
}

func TestAdministrationBootstrap(t *testing.T) {
	for _, failedRead := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "inventory unavailable"}[failedRead], func(t *testing.T) {
			s := newTestServer(t)
			s.params.DefaultAdminEmail = "a@example.invalid"
			if err := s.BootstrapAdmin(t.Context()); err != nil {
				t.Fatal(err)
			}
			if failedRead {
				execSQL(t, s.db, `ALTER TABLE lpcc.machines RENAME TO unavailable_machines`)
			}
			w := request(t, s, "GET", "/api/admin/overview", "session-a", nil)
			if failedRead {
				requireStatus(t, w, 503)
				if strings.Contains(w.Body.String(), `"administrators"`) || strings.Contains(w.Body.String(), `"is_admin"`) {
					t.Fatal("partial success escaped")
				}
			} else if got := decodeAdministration(t, w); !got.IsAdmin || len(got.Administrators) != 1 || got.Administrators[0].UserID == nil || *got.Administrators[0].UserID != ownerA {
				t.Fatal("direct overview did not claim bootstrap grant")
			}
			if count(t, s, `SELECT count(*) FROM lpcc.administrator_grants WHERE bound_user_id=$1`, ownerA) != 1 || count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE action='administrator.bind'`) != 1 {
				t.Fatal("binding and audit did not commit independently")
			}
		})
	}
}
