package controlplane

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/livepeer/control-center/schema"
)

func registryFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../../runtime/tests/fixtures/whoami.toml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func revisionResponse(t *testing.T, s *Server, source, head string, create bool) (CatalogRevision, int) {
	t.Helper()
	path := "/api/admin/apps"
	input := map[string]any{"source_toml": source}
	if !create {
		path += "/whoami/revisions"
		input["expected_head_revision_id"] = head
	}
	w := request(t, s, "POST", path, "session-a", input)
	var body struct {
		Revision CatalogRevision `json:"revision"`
	}
	if w.Code == 200 || w.Code == 201 {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Log(w.Body.String())
	}
	return body.Revision, w.Code
}
func TestRegistryLifecycleAndRoundTrip(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	source := registryFixture(t)
	validate := request(t, s, "POST", "/api/admin/apps/validate", "session-a", map[string]string{"source_toml": source})
	requireStatus(t, validate, 200)
	if count(t, s, `SELECT count(*) FROM lpcc.apps`) != 0 {
		t.Fatal("dry run persisted app data")
	}
	first, status := revisionResponse(t, s, source, "", true)
	if status != 201 {
		t.Fatal(status)
	}
	wire, _ := json.Marshal(first.ResolvedRevision)
	if _, err := schema.DecodeRevision(wire); err != nil {
		t.Fatal(err)
	}
	initialAudit := count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`)
	same, status := revisionResponse(t, s, source+"\n# formatting only\n", "", true)
	if status != 200 || same.RevisionID != first.RevisionID || same.SourceTOML != first.SourceTOML || count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`) != initialAudit {
		t.Fatal("duplicate changed publication")
	}
	secondSource := strings.Replace(source, "replicas = 2", "replicas = 3", 1)
	second, status := revisionResponse(t, s, secondSource, first.RevisionID, false)
	if status != 201 || second.Revision != 2 || second.AppVersion != "1" {
		t.Fatal(status, second.Revision)
	}
	_, status = revisionResponse(t, s, strings.Replace(source, "replicas = 2", "replicas = 4", 1), first.RevisionID, false)
	if status != 409 {
		t.Fatal("stale publication accepted", status)
	}
	_, status = revisionResponse(t, s, source, first.RevisionID, false)
	if status != 200 {
		t.Fatal("duplicate lost to stale head", status)
	}
	invalid := request(t, s, "POST", "/api/admin/apps/whoami/revisions", "session-a", map[string]any{"source_toml": strings.Replace(source, "amount = \"0.001\"", "amount = 0.001", 1), "expected_head_revision_id": second.RevisionID})
	requireStatus(t, invalid, 400)
	if !strings.Contains(invalid.Body.String(), `"path":"price.amount"`) {
		t.Fatal(invalid.Body.String())
	}
	requireStatus(t, request(t, s, "POST", "/api/admin/apps/whoami/revisions/"+first.RevisionID+"/retire", "session-a", map[string]int{"expected_state_version": 1}), 200)
	before := count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`)
	requireStatus(t, request(t, s, "POST", "/api/admin/apps/whoami/revisions/"+first.RevisionID+"/retire", "session-a", map[string]int{"expected_state_version": 1}), 200)
	if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`) != before {
		t.Fatal("retirement retry audited as change")
	}
	requireStatus(t, request(t, s, "GET", "/api/admin/apps/other/revisions/"+first.RevisionID, "session-a", nil), 404)
	history := request(t, s, "GET", "/api/admin/apps/whoami?limit=1", "session-a", nil)
	requireStatus(t, history, 200)
	var page struct {
		App       AppSummary        `json:"app"`
		Revisions []RevisionSummary `json:"revisions"`
		Next      *int64            `json:"next_before_revision"`
	}
	json.Unmarshal(history.Body.Bytes(), &page)
	if len(page.Revisions) != 1 || page.Revisions[0].Revision != 2 || page.Next == nil {
		t.Fatal(history.Body.String())
	}
	if page.App.Head.RevisionID != second.RevisionID || page.App.RevisionCount != 2 || page.App.ActiveRevisionCount != 1 {
		t.Fatal("incorrect app summary", page.App)
	}
	history = request(t, s, "GET", fmt.Sprintf("/api/admin/apps/whoami?limit=1&before_revision=%d", *page.Next), "session-a", nil)
	requireStatus(t, history, 200)
	if !strings.Contains(history.Body.String(), first.RevisionID) {
		t.Fatal(history.Body.String())
	}
	var head string
	if err := s.db.QueryRow(`SELECT head_revision_id::text FROM lpcc.apps WHERE name='whoami'`).Scan(&head); err != nil || head != second.RevisionID {
		t.Fatal(head, err)
	}
	for _, sql := range []string{`UPDATE lpcc.app_revisions SET source_toml='changed' WHERE revision_id='` + first.RevisionID + `'`, `DELETE FROM lpcc.app_revisions WHERE revision_id='` + first.RevisionID + `'`, `UPDATE lpcc.app_revision_state SET version=1,retired_at=NULL,retired_by=NULL WHERE revision_id='` + first.RevisionID + `'`} {
		if _, err := s.db.Exec(sql); err == nil {
			t.Fatal("database allowed immutable mutation")
		}
	}
	for _, name := range []string{"zeta", "alpha", "Alpha"} {
		if _, status := revisionResponse(t, s, strings.Replace(source, `name = "whoami"`, `name = "`+name+`"`, 1), "", true); status != 201 {
			t.Fatal(status)
		}
	}
	var apps struct {
		Apps []AppSummary `json:"apps"`
		Next *string      `json:"next_after_name"`
	}
	for i, path := range []string{"/api/admin/apps?limit=2", "/api/admin/apps?limit=2&after_name=alpha"} {
		response := request(t, s, "GET", path, "session-a", nil)
		requireStatus(t, response, 200)
		if err := json.Unmarshal(response.Body.Bytes(), &apps); err != nil {
			t.Fatal(err)
		}
		if len(apps.Apps) != 2 {
			t.Fatal(response.Body.String())
		}
		if i == 0 {
			if apps.Apps[0].Name != "Alpha" || apps.Apps[1].Name != "alpha" || apps.Next == nil || *apps.Next != "alpha" {
				t.Fatal(response.Body.String())
			}
		} else if apps.Next != nil || apps.Apps[0].Name != "whoami" || apps.Apps[1].Name != "zeta" || apps.Apps[0].Head.RevisionID != second.RevisionID || apps.Apps[0].Head.Digest != second.Digest || apps.Apps[0].ActiveRevisionCount != 1 {
			t.Fatal(response.Body.String())
		}
	}
}
func TestRegistryPolicyAndBindingSeam(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	source := strings.Replace(registryFixture(t), "amount = \"0.001\"", "amount = '0'", 1)
	first, status := revisionResponse(t, s, source, "", true)
	if status != 201 {
		t.Fatal(status)
	}
	requireStatus(t, request(t, s, "POST", "/api/admin/apps/whoami/revisions/"+first.RevisionID+"/retire", "session-a", map[string]int{"expected_state_version": 1}), 200)
	s.params.RegistryPaymentMode = "onchain"
	requireStatus(t, request(t, s, "POST", "/api/admin/apps/validate", "session-a", map[string]string{"source_toml": source}), 400)
	same, status := revisionResponse(t, s, source, uuid.New().String(), false)
	if status != 200 || same.RevisionID != first.RevisionID || same.Lifecycle.RetiredAt == nil {
		t.Fatal("retired retry lost to policy/precondition")
	}
	_, status = revisionResponse(t, s, strings.Replace(source, "replicas = 2", "replicas = 3", 1), first.RevisionID, false)
	if status != 400 {
		t.Fatal("new free onchain revision accepted")
	}
	testBinding := func(current *schema.RevisionRef, ref schema.RevisionRef, want int) {
		t.Helper()
		tx, err := s.policyTx(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		_, err = revisionForBinding(t.Context(), tx, current, ref, s.registryMode())
		if want == 200 && err != nil {
			t.Fatal(err)
		}
		if want != 200 && (err == nil || errorDetails(err).status != want) {
			t.Fatal(want, err)
		}
	}
	testBinding(&first.RevisionRef, first.RevisionRef, 200)
	testBinding(nil, first.RevisionRef, 409)
	s.params.RegistryPaymentMode = "offchain"
	active, status := revisionResponse(t, s, strings.Replace(source, "replicas = 2", "replicas = 3", 1), first.RevisionID, false)
	if status != 201 {
		t.Fatal(status)
	}
	s.params.RegistryPaymentMode = "onchain"
	testBinding(nil, active.RevisionRef, 400)
	testBinding(&active.RevisionRef, active.RevisionRef, 200)
	testBinding(&active.RevisionRef, first.RevisionRef, 409)
	testBinding(nil, schema.RevisionRef{RevisionID: uuid.New().String(), Digest: active.Digest}, 404)
	testBinding(nil, schema.RevisionRef{RevisionID: active.RevisionID, Digest: "sha256:" + strings.Repeat("0", 64)}, 409)
}

func TestPinnedRevisionRejectsMalformedIDsBeforeLookup(t *testing.T) {
	for _, id := range []string{"", "abc", "00000000-0000-0000-0000-000000000000", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		_, err := loadPinnedRevision(t.Context(), nil, schema.RevisionRef{RevisionID: id})
		if err == nil || errorDetails(err).status != 400 || errorDetails(err).reason != "invalid_revision_id" {
			t.Fatal(id, err)
		}
	}
}

func TestConcurrentRegistryPublications(t *testing.T) {
	for _, identical := range []bool{false, true} {
		t.Run(fmt.Sprintf("identical=%v", identical), func(t *testing.T) {
			s := newTestServer(t)
			adminA(t, s)
			source := registryFixture(t)
			first, status := revisionResponse(t, s, source, "", true)
			if status != 201 {
				t.Fatal(status)
			}
			before := count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE action='app.publish' AND outcome='success'`)
			type result struct {
				revision CatalogRevision
				status   int
			}
			start := make(chan struct{})
			done := make(chan result, 2)
			for i := range 2 {
				replicas := 3 + i
				if identical {
					replicas = 3
				}
				updated := strings.Replace(source, "replicas = 2", fmt.Sprintf("replicas = %d", replicas), 1)
				go func() {
					<-start
					r, status := revisionResponse(t, s, updated, first.RevisionID, false)
					done <- result{r, status}
				}()
			}
			close(start)
			a, b := <-done, <-done
			statuses := map[int]int{}
			statuses[a.status]++
			statuses[b.status]++
			other := 409
			if identical {
				other = 200
				if a.revision.RevisionID != b.revision.RevisionID {
					t.Fatal("duplicate publications have different UUIDs")
				}
			}
			if statuses[201] != 1 || statuses[other] != 1 || count(t, s, `SELECT count(*) FROM lpcc.app_revisions`) != 2 || count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE action='app.publish' AND outcome='success'`) != before+1 {
				t.Fatal(a.status, b.status)
			}
		})
	}
}
func TestRegistryAuthorizationAndAtomicAudit(t *testing.T) {
	s := newTestServer(t)
	source := registryFixture(t)
	machine := enroll(t, s, ownerB, strings.Repeat("c", 64))
	for _, tc := range []struct {
		token  string
		status int
	}{{"", 401}, {"session-b", 403}, {machine["token"], 401}} {
		for _, route := range []struct{ method, path string }{
			{"GET", "/api/admin/apps"}, {"GET", "/api/admin/apps/whoami"}, {"GET", "/api/admin/apps/whoami/revisions/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
			{"POST", "/api/admin/apps"}, {"POST", "/api/admin/apps/validate"}, {"POST", "/api/admin/apps/whoami/revisions"}, {"POST", "/api/admin/apps/whoami/revisions/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/retire"},
		} {
			requireStatus(t, request(t, s, route.method, route.path, tc.token, map[string]string{"source_toml": source}), tc.status)
		}
	}
	grant := adminA(t, s)
	execSQL(t, s.db, `CREATE FUNCTION lpcc.fail_app_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='app.create' THEN RAISE EXCEPTION 'injected failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER app_audit_failure BEFORE INSERT ON lpcc.admin_audit_events FOR EACH ROW EXECUTE FUNCTION lpcc.fail_app_audit()`)
	_, status := revisionResponse(t, s, source, "", true)
	if status != 503 || count(t, s, `SELECT count(*) FROM lpcc.apps`) != 0 {
		t.Fatal("audit failure did not roll back catalog")
	}
	execSQL(t, s.db, `DROP TRIGGER app_audit_failure ON lpcc.admin_audit_events; DROP FUNCTION lpcc.fail_app_audit()`)
	execSQL(t, s.db, `CREATE FUNCTION lpcc.fail_app_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected commit failure'; END $$; CREATE CONSTRAINT TRIGGER app_commit_failure AFTER INSERT ON lpcc.app_revisions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION lpcc.fail_app_commit()`)
	_, status = revisionResponse(t, s, source, "", true)
	if status != 503 || count(t, s, `SELECT count(*) FROM lpcc.apps`) != 0 {
		t.Fatal("commit failure did not roll back catalog")
	}
	execSQL(t, s.db, `DROP TRIGGER app_commit_failure ON lpcc.app_revisions; DROP FUNCTION lpcc.fail_app_commit()`)
	// Queue the actual registry route behind revocation, not a surrogate callback.
	tx, err := s.policyTx(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	execSQL(t, s.db, `SELECT 1`)
	if _, err = tx.Exec(`UPDATE lpcc.administrator_grants SET revoked_at=now(),revision=revision+1 WHERE grant_id=$1`, grant); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() {
		w := request(t, s, "POST", "/api/admin/apps", "session-a", map[string]string{"source_toml": source})
		done <- w.Code
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		err = s.db.QueryRow(`SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory')`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("publication did not queue behind revocation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case status := <-done:
		if status != 403 {
			t.Fatal(status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued publication did not finish")
	}
	if count(t, s, `SELECT count(*) FROM lpcc.apps`) != 0 {
		t.Fatal("revoked writer changed catalog")
	}
}
