package controlplane

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"uuid"
)

func TestSharedOrchestratorLifecycle(t *testing.T) {
	s := newTestServer(t)
	execSQL(t, s.db, `INSERT INTO lpcc.orchestrator_memberships VALUES($1,$2),($3,$4)`, ownerA, orchB, ownerB, orchA)
	w := request(t, s, "GET", "/api/orchestrators", "session-a", nil)
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), orchA) || !strings.Contains(w.Body.String(), orchB) {
		t.Fatal(w.Body.String())
	}
	fingerprint := strings.Repeat("a", 64)
	a := enroll(t, s, ownerA, fingerprint)
	b := enroll(t, s, ownerB, strings.Repeat("b", 64))
	w = request(t, s, "GET", "/api/machines?orchestrator_address="+orchB, "session-a", nil)
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), b["node_id"]) || strings.Contains(w.Body.String(), a["node_id"]) {
		t.Fatal("orchestrator inventory was mixed", w.Body.String())
	}
	requireStatus(t, request(t, s, "GET", "/api/machines/"+a["node_id"]+"/status", "session-b", nil), 200)
	grant, _, _ := s.params.signEnrollment(ownerB, orchA, s.currentTime())
	// Membership alone cannot claim the saved installation or replace its key.
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", grant, registrationBody(ownerB, fingerprint, grant)), 409)
	body := registrationBody(ownerA, fingerprint, grant)
	w = request(t, s, "POST", "/v1/nodes/register", grant, body)
	requireStatus(t, w, 200)
	if c := credentials(t, w.Body.Bytes()); c["node_id"] != a["node_id"] || c["token"] != a["token"] {
		t.Fatal("shared retry changed machine identity")
	}
	refresh := map[string]any{"fingerprint": fingerprint, "install_dir": "/opt/livepeer", "operation_id": uuid.New().String(), "expected_credential_version": 1, "management_proof": a["token"]}
	w = request(t, s, "POST", "/v1/nodes/"+a["node_id"]+"/credentials/refresh", grant, refresh)
	requireStatus(t, w, 200)
	current := credentials(t, w.Body.Bytes())
	execSQL(t, s.db, `DELETE FROM lpcc.orchestrator_memberships WHERE user_id=$1 AND orchestrator_address=$2`, ownerB, orchA)
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", grant, body), 403)
	// Current-membership semantics allow an unexpired grant after rejoining.
	execSQL(t, s.db, `INSERT INTO lpcc.orchestrator_memberships VALUES($1,$2)`, ownerB, orchA)
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", grant, body), 200)
	execSQL(t, s.db, `DELETE FROM lpcc.orchestrator_memberships WHERE user_id=$1 AND orchestrator_address=$2`, ownerB, orchA)
	execSQL(t, s.db, `DELETE FROM auth.users WHERE id=$1`, ownerA)
	if count(t, s, `SELECT count(*) FROM lpcc.machines WHERE node_id=$1`, a["node_id"]) != 1 {
		t.Fatal("last member departure retired a shared machine")
	}
	requireStatus(t, request(t, s, "GET", "/v1/nodes/"+a["node_id"]+"/config", current["token"], nil), 200)
	if _, err := s.db.Exec(`DELETE FROM lpcc.orchestrators WHERE address=$1`, orchA); err == nil {
		t.Fatal("resource owner was deleted while machine/cleanup state still references it")
	}
}

func TestOrchestratorScopeAndMetadata(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	for _, address := range []string{"", "not-an-address", "0x0000000000000000000000000000000000000000"} {
		requireStatus(t, request(t, s, "GET", "/api/machines?orchestrator_address="+address, "session-a", nil), 400)
		requireStatus(t, request(t, s, "POST", "/api/bootstrap-token", "session-a", map[string]string{"orchestrator_address": address}), 400)
	}
	requireStatus(t, request(t, s, "GET", "/api/machines?orchestrator_address="+orchB, "session-a", nil), 403)
	// Hex case is normalized before authorization.
	address := "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	execSQL(t, s.db, `INSERT INTO lpcc.orchestrators(address) VALUES($1)`, address)
	execSQL(t, s.db, `INSERT INTO lpcc.orchestrator_memberships VALUES($1,$2)`, ownerA, address)
	requireStatus(t, request(t, s, "GET", "/api/machines?orchestrator_address=0x"+strings.ToUpper(address[2:]), "session-a", nil), 200)
	s.params.SecretsMetadataToken = "independent-metadata-principal"
	path := "/internal/users/" + ownerA + "/orchestrators/" + orchA
	requireStatus(t, request(t, s, "GET", path, "session-a", nil), 403)
	requireStatus(t, request(t, s, "GET", path, s.params.SecretsMetadataToken, nil), 200)
	execSQL(t, s.db, `DELETE FROM lpcc.orchestrator_memberships WHERE user_id=$1`, ownerA)
	requireStatus(t, request(t, s, "GET", path, s.params.SecretsMetadataToken, nil), 403)
	requireStatus(t, request(t, s, "GET", "/api/admin/machines", "session-a", nil), 200)
	requireStatus(t, request(t, s, "GET", "/api/machines?orchestrator_address="+orchA, "session-a", nil), 403)
	requireStatus(t, request(t, s, "POST", "/api/bootstrap-token", "session-a", map[string]string{"orchestrator_address": orchA}), 403)
	w := request(t, s, "GET", "/api/orchestrators", "session-a", nil)
	var result struct {
		Orchestrators []any `json:"orchestrators"`
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Orchestrators) != 0 {
		t.Fatal(w.Body.String())
	}
}

func TestMembershipChangesSerializeEnrollmentAndRefresh(t *testing.T) {
	for _, operation := range []string{"register", "refresh"} {
		for _, change := range []string{"membership", "soft-delete", "hard-delete"} {
			for _, first := range []string{"revocation", "consumption"} {
				t.Run(operation+"/"+change+"/"+first, func(t *testing.T) {
					s := newTestServer(t)
					fingerprint := strings.Repeat("c", 64)
					grant, _, _ := s.params.signEnrollment(ownerA, orchA, s.currentTime())
					path := "/v1/nodes/register"
					var body any = registrationBody(ownerA, fingerprint, grant)
					var saved map[string]string
					if operation == "refresh" {
						saved = enroll(t, s, ownerA, fingerprint)
						path = "/v1/nodes/" + saved["node_id"] + "/credentials/refresh"
						body = map[string]any{"fingerprint": fingerprint, "install_dir": "/opt/livepeer", "operation_id": uuid.New().String(), "expected_credential_version": 1, "management_proof": saved["token"]}
					}
					query := `DELETE FROM lpcc.orchestrator_memberships WHERE user_id=$1`
					if change == "soft-delete" {
						query = `UPDATE auth.users SET deleted_at=now() WHERE id=$1`
					}
					if change == "hard-delete" {
						query = `DELETE FROM auth.users WHERE id=$1`
					}
					block, err := s.db.Begin()
					if err != nil {
						t.Fatal(err)
					}
					defer block.Rollback()
					if first == "revocation" {
						if _, err = block.Exec(query, ownerA); err != nil {
							t.Fatal(err)
						}
					} else {
						c, _ := s.params.enrollmentGrant(grant, s.currentTime(), false)
						if err = lockEnrollmentGrant(t.Context(), block, c.ID); err != nil {
							t.Fatal(err)
						}
					}
					done := make(chan *httptest.ResponseRecorder, 1)
					go func() { done <- request(t, s, "POST", path, grant, body) }()
					waitForAuthorizationLock(t, s)
					var revoked chan error
					if first == "consumption" {
						revoked = make(chan error, 1)
						go func() { _, e := s.db.Exec(query, ownerA); revoked <- e }()
						deadline := time.Now().Add(5 * time.Second)
						for count(t, s, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query=$1`, query) == 0 {
							if time.Now().After(deadline) {
								t.Fatal("revocation did not wait for authorization")
							}
							time.Sleep(10 * time.Millisecond)
						}
					}
					if err = block.Commit(); err != nil {
						t.Fatal(err)
					}
					w := <-done
					want := 403
					if first == "consumption" {
						want = 200
						if err = <-revoked; err != nil {
							t.Fatal(err)
						}
					}
					requireStatus(t, w, want)
					requireStatus(t, request(t, s, "POST", path, grant, body), 403)
					if first == "consumption" {
						saved = credentials(t, w.Body.Bytes())
					}
					if saved != nil {
						requireStatus(t, request(t, s, "GET", "/v1/nodes/"+saved["node_id"]+"/config", saved["token"], nil), 200)
					}
				})
			}
		}
	}
}

func waitForAuthorizationLock(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for count(t, s, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'`) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("enrollment did not reach authorization lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
