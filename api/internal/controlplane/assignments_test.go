package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/api/internal/migrations"
	"github.com/livepeer/control-center/schema"
)

func publishAssignmentRevision(t *testing.T, s *Server, source, parent string) CatalogRevision {
	t.Helper()
	r, status := revisionResponse(t, s, source, parent, parent == "")
	if status != 201 {
		t.Fatal(status)
	}
	return r
}
func appPath(c map[string]string, r CatalogRevision) string {
	return "/api/admin/machines/" + c["node_id"] + "/apps/" + r.RevisionID
}
func putApp(t *testing.T, s *Server, c map[string]string, r CatalogRevision, g int64, n int) *httptest.ResponseRecorder {
	t.Helper()
	return request(t, s, "PUT", appPath(c, r), "session-a", map[string]any{"epoch": c["epoch"], "digest": r.Digest, "expected_generation": g, "replicas": n})
}
func appBundle(t *testing.T, s *Server, c map[string]string) (schema.AppAssignmentSetV1, string, map[string]string) {
	t.Helper()
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, "GET", "/v1/nodes/"+c["node_id"]+"/config", c["token"], nil)
	requireStatus(t, w, 200)
	files := archiveFiles(t, w.Body.Bytes())
	var manifest struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(files[schema.AppAssignmentsFile]), &manifest); err != nil {
		t.Fatal(err)
	}
	set, err := schema.DecodeAssignmentSet([]byte(manifest.Data["desired.json"]))
	if err != nil {
		t.Fatal(err)
	}
	return set, schema.Digest([]byte(manifest.Data["desired.json"])), files
}
func appReport(t *testing.T, s *Server, c map[string]string, a schema.AppAssignment, digest, phase string) *httptest.ResponseRecorder {
	t.Helper()
	reason := ""
	if phase == "failed" {
		reason = "reconcile_failed"
	}
	return request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/apps/"+a.RevisionID+"/status", c["token"], assignmentReport{Epoch: c["epoch"], CredentialVersion: 1, Generation: a.Generation, ActivationGeneration: a.ActivationGeneration, AppsDigest: digest, Phase: phase, Reason: reason})
}
func findApp(t *testing.T, set schema.AppAssignmentSetV1, id string) schema.AppAssignment {
	t.Helper()
	for _, a := range set.Entries {
		if a.RevisionID == id {
			return a
		}
	}
	t.Fatal("assignment missing", id)
	return schema.AppAssignment{}
}
func TestMachineAssignmentsDeliveryAndSequentialReplacement(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("a", 64))
	other := enroll(t, s, ownerB, strings.Repeat("b", 64))
	before := request(t, s, "GET", "/v1/nodes/"+other["node_id"]+"/config", other["token"], nil).Header().Get("ETag")
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	requireStatus(t, putApp(t, s, c, r, 0, 2), 202)
	set, digest, files := appBundle(t, s, c)
	initial := findApp(t, set, r.RevisionID)
	var runtime machineconfig.Runtime
	json.Unmarshal([]byte(files["runtime.json"]), &runtime)
	if runtime.Generation != 1 || initial.Generation != 1 || initial.ActivationGeneration != 1 || !initial.StartAllowed {
		t.Fatal("invalid initial generation")
	}
	unchanged := request(t, s, "GET", "/v1/nodes/"+other["node_id"]+"/config", other["token"], nil).Header().Get("ETag")
	if unchanged != before {
		t.Fatal("cross-machine config changed")
	}
	audits := count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`)
	requireStatus(t, putApp(t, s, c, r, 0, 2), 200)
	if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`) != audits {
		t.Fatal("retry audited twice")
	}
	next := publishAssignmentRevision(t, s, strings.Replace(registryFixture(t), `app_version = "1"`, `app_version = "2"`, 1), r.RevisionID)
	_, sameDigest, _ := appBundle(t, s, c)
	if sameDigest != digest {
		t.Fatal("catalog publish mutated placement")
	}
	beta := publishAssignmentRevision(t, s, strings.Replace(registryFixture(t), `name = "whoami"`, `name = "beta"`, 1), "")
	requireStatus(t, putApp(t, s, c, beta, 0, 1), 202)
	replace := map[string]any{"epoch": c["epoch"], "expected_generation": 1, "target": map[string]any{"revision_id": next.RevisionID, "digest": next.Digest, "expected_generation": 0, "replicas": 3}}
	requireStatus(t, request(t, s, "POST", appPath(c, r)+"/replace", "session-a", replace), 202)
	requireStatus(t, request(t, s, "POST", appPath(c, r)+"/replace", "session-a", replace), 200)
	implicitRetry := map[string]any{"epoch": c["epoch"], "expected_generation": 1, "target": map[string]any{"revision_id": next.RevisionID, "digest": next.Digest, "expected_generation": 0}}
	requireStatus(t, request(t, s, "POST", appPath(c, r)+"/replace", "session-a", implicitRetry), 409)
	currentReplacement := map[string]any{"epoch": c["epoch"], "expected_generation": 2, "target": map[string]any{"revision_id": next.RevisionID, "digest": next.Digest, "expected_generation": 1}}
	auditsBeforeNoop := count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`)
	requireStatus(t, request(t, s, "POST", appPath(c, r)+"/replace", "session-a", currentReplacement), 200)
	if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events`) != auditsBeforeNoop {
		t.Fatal("replacement no-op changed audit history")
	}
	blocked, blockedDigest, _ := appBundle(t, s, c)
	target := findApp(t, blocked, next.RevisionID)
	source := findApp(t, blocked, r.RevisionID)
	if target.StartAllowed || target.StartAfter == nil || source.Desired != "absent" || source.Generation != 2 {
		t.Fatal("replacement not sequential")
	}
	requireStatus(t, appReport(t, s, c, target, blockedDigest, "applied"), 409)
	requireStatus(t, putApp(t, s, c, r, 2, 2), 409)
	requireStatus(t, appReport(t, s, c, source, blockedDigest, "removed"), 200)
	unblocked, unblockedDigest, afterFiles := appBundle(t, s, c)
	target = findApp(t, unblocked, next.RevisionID)
	if !target.StartAllowed || target.Generation != 1 || target.ActivationGeneration != 1 {
		t.Fatal("cleanup did not release target")
	}
	if files["orchestrator.yaml"] != afterFiles["orchestrator.yaml"] {
		t.Fatal("assignment edit replaced Node")
	}
	requireStatus(t, appReport(t, s, c, source, blockedDigest, "removed"), 200)
	requireStatus(t, putApp(t, s, c, beta, 1, 2), 202)
	appBundle(t, s, c)
	requireStatus(t, appReport(t, s, c, target, unblockedDigest, "applied"), 200)
	requireStatus(t, appReport(t, s, c, target, unblockedDigest, "failed"), 200)
	requireStatus(t, putApp(t, s, c, r, 2, 2), 202)
	requireStatus(t, appReport(t, s, c, source, blockedDigest, "removed"), 200)
	requireStatus(t, putApp(t, s, c, r, 3, 3), 202)
	requireStatus(t, putApp(t, s, c, r, 3, 3), 200)
	head, err := machineapps.Head(t.Context(), s.db, c["node_id"], c["epoch"], r.RevisionID)
	if err != nil || head.Generation != 4 || head.ActivationGeneration != 3 {
		t.Fatal(head, err)
	}
	requireStatus(t, putApp(t, s, c, r, 4, 2), 202)
	requireStatus(t, putApp(t, s, c, r, 3, 3), 409)
	requireStatus(t, appReport(t, s, c, initial, digest, "applied"), 409)
	requireStatus(t, request(t, s, "GET", appPath(c, r), "session-a", nil), 200)
	s.db.SetMaxOpenConns(1)
	defer s.db.SetMaxOpenConns(0)
	listing := request(t, s, "GET", "/api/admin/machines/"+c["node_id"]+"/apps?limit=1", "session-a", nil)
	requireStatus(t, listing, 200)
	var page struct {
		Assignments []machineapps.Version `json:"assignments"`
		Next        *string               `json:"next_after_revision_id"`
	}
	if err := json.Unmarshal(listing.Body.Bytes(), &page); err != nil || len(page.Assignments) != 1 || page.Next == nil {
		t.Fatal("assignment pagination", err, listing.Body.String())
	}
	requireStatus(t, request(t, s, "GET", appPath(c, r)+"?epoch=bad", "session-a", nil), 400)
}
func TestAssignmentAuthorizationPolicyAndInvalidChanges(t *testing.T) {
	s := newTestServer(t)
	grant := adminA(t, s)
	c := enroll(t, s, ownerB, strings.Repeat("c", 64))
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	body := map[string]any{"epoch": c["epoch"], "digest": r.Digest, "expected_generation": 0}
	for _, token := range []string{"", "invalid", c["token"]} {
		requireStatus(t, request(t, s, "PUT", appPath(c, r), token, body), 401)
	}
	requireStatus(t, request(t, s, "PUT", appPath(c, r), "session-b", body), 403)
	requireStatus(t, putApp(t, s, c, r, 0, 0), 400)
	requireStatus(t, putApp(t, s, c, r, 0, 101), 400)
	bad := r
	bad.Digest = "sha256:" + strings.Repeat("0", 64)
	requireStatus(t, putApp(t, s, c, bad, 0, 1), 409)
	requireStatus(t, putApp(t, s, c, r, 0, 1), 202)
	requireStatus(t, request(t, s, "POST", "/api/admin/apps/whoami/revisions/"+r.RevisionID+"/retire", "session-a", map[string]int{"expected_state_version": 1}), 200)
	requireStatus(t, putApp(t, s, c, r, 1, 2), 202)
	set, digest, _ := appBundle(t, s, c)
	a := findApp(t, set, r.RevisionID)
	requireStatus(t, request(t, s, "DELETE", appPath(c, r), "session-a", map[string]any{"epoch": c["epoch"], "expected_generation": 2}), 202)
	set, digest, _ = appBundle(t, s, c)
	a = findApp(t, set, r.RevisionID)
	requireStatus(t, appReport(t, s, c, a, digest, "removed"), 200)
	requireStatus(t, putApp(t, s, c, r, 3, 1), 409)
	execSQL(t, s.db, `UPDATE lpcc.administrator_grants SET revoked_at=now(),revision=revision+1 WHERE grant_id=$1`, grant)
	requireStatus(t, putApp(t, s, c, r, 3, 1), 403)
}
func TestAssignmentGenerationFailureAndPublicationFence(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("d", 64))
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	requireStatus(t, putApp(t, s, c, r, 0, 1), 202)
	_, first, _ := appBundle(t, s, c)
	requireStatus(t, putApp(t, s, c, r, 1, 2), 202)
	s.build = func(machineconfig.Desired) ([]byte, string, error) { return nil, "", errors.New("private error") }
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, "GET", "/v1/nodes/"+c["node_id"]+"/config", c["token"], nil)
	if !strings.Contains(archiveFiles(t, w.Body.Bytes())["runtime.json"], first) {
		t.Fatal("failure replaced previous bundle")
	}
	s.build = func(d machineconfig.Desired) ([]byte, string, error) {
		// A committed edit while rendering makes this candidate obsolete.
		requireStatus(t, putApp(t, s, c, r, 2, 3), 202)
		return machineconfig.Build(d)
	}
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.machine_app_deliveries WHERE node_id=$1 AND apps_generation>1`, c["node_id"]) != 0 {
		t.Fatal("stale render published")
	}
	s.build = machineconfig.Build
	latest, _, _ := appBundle(t, s, c)
	if latest.Entries[0].Generation != 3 || latest.Entries[0].Replicas != 3 {
		t.Fatal("did not recover latest intent")
	}
}
func TestMachineRemovalWaitsForAppsAndRetainsTerminalCleanup(t *testing.T) {
	for _, mode := range []string{"normal", "forced", "owner-delete"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestServer(t)
			adminA(t, s)
			s.params.TunnelDrainTimeout = time.Minute
			s.configs = s.newConfigurationManager()
			c := enroll(t, s, ownerB, fmt.Sprintf("%064x", 21))
			r := publishAssignmentRevision(t, s, registryFixture(t), "")
			requireStatus(t, putApp(t, s, c, r, 0, 1), 202)
			appBundle(t, s, c)
			if mode == "owner-delete" {
				execSQL(t, s.db, `DELETE FROM auth.users WHERE id=$1`, ownerB)
			} else {
				requireStatus(t, request(t, s, "DELETE", "/api/admin/machines/"+c["node_id"], "session-a", map[string]any{"epoch": c["epoch"], "force": mode == "forced"}), 202)
			}
			if mode == "normal" {
				reportRuntime(t, s, c, "runner", true)
				set, digest, _ := appBundle(t, s, c)
				if count(t, s, `SELECT count(*) FROM lpcc.machines WHERE node_id=$1`, c["node_id"]) != 1 {
					t.Fatal("retired before app cleanup")
				}
				var state machineconfig.State
				var raw []byte
				if err := s.db.QueryRow(`SELECT rollout FROM lpcc.machine_states WHERE node_id=$1`, c["node_id"]).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(raw, &state); err != nil || state.DrainedGeneration != state.Generation || state.RolloutReason != "app_cleanup_pending" {
					t.Fatal("timely drain was not retained while waiting for apps", state, err)
				}
				// Cleanup outlasts both the Node deadline and the runner report TTL.
				execSQL(t, s.db, `UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{drain_started_at}',to_jsonb($1::text))`, time.Now().Add(-time.Hour).Format(time.RFC3339Nano))
				execSQL(t, s.db, `UPDATE lpcc.machine_reports SET received_at=now()-interval '1 hour'`)
				head, err := machineapps.Head(t.Context(), s.db, c["node_id"], c["epoch"], r.RevisionID)
				if err != nil || head.Revision != nil || head.AppName != "whoami" || head.RevisionNumber != 1 {
					t.Fatal("compact removal lost administrative identity", head, err)
				}
				requireStatus(t, appReport(t, s, c, set.Entries[0], digest, "removed"), 200)
				if err := s.reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else {
				set, digest, _ := appBundle(t, s, c)
				a := set.Entries[0]
				requireStatus(t, appReport(t, s, c, a, digest, "applied"), 403)
				requireStatus(t, appReport(t, s, c, a, digest, "removed"), 200)
				requireStatus(t, appReport(t, s, c, a, digest, "removed"), 200)
			}
			if count(t, s, `SELECT count(*) FROM lpcc.machines WHERE node_id=$1`, c["node_id"]) != 0 {
				t.Fatal("machine still active")
			}
			if count(t, s, `SELECT count(*) FROM lpcc.machine_app_versions WHERE node_id=$1`, c["node_id"]) != 2 {
				t.Fatal("lost history")
			}
		})
	}
}

func TestAssignmentConcurrentEditsAndAuditFailure(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("e", 64))
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	results := make(chan int, 2)
	for _, n := range []int{2, 3} {
		go func(n int) { results <- putApp(t, s, c, r, 0, n).Code }(n)
	}
	first, second := <-results, <-results
	if first+second != 202+409 {
		t.Fatal(first, second)
	}
	before := count(t, s, `SELECT count(*) FROM lpcc.machine_app_versions`)
	execSQL(t, s.db, `CREATE FUNCTION lpcc.fail_assignment_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='assignment.put' AND NEW.outcome='success' THEN RAISE EXCEPTION 'audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_assignment_audit BEFORE INSERT ON lpcc.admin_audit_events FOR EACH ROW EXECUTE FUNCTION lpcc.fail_assignment_audit()`)
	requireStatus(t, putApp(t, s, c, r, 1, 5), 503)
	if count(t, s, `SELECT count(*) FROM lpcc.machine_app_versions`) != before {
		t.Fatal("audit failure committed intent")
	}
}
func TestAssignmentSizeAdmissionStillAllowsRemoval(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("f", 64))
	args := []string{}
	for i := 0; i < 15; i++ {
		args = append(args, `"`+strings.Repeat("<", 4000)+`"`)
	}
	var first CatalogRevision
	for i := 0; i < 3; i++ {
		source := strings.Replace(registryFixture(t), `name = "whoami"`, fmt.Sprintf(`name = "large%d"`, i), 1)
		source = strings.Replace(source, "[container]\n", "[container]\nentrypoint = ["+strings.Join(args, ",")+"]\n", 1)
		r := publishAssignmentRevision(t, s, source, "")
		expected := 202
		if i == 2 {
			expected = 400
		}
		requireStatus(t, putApp(t, s, c, r, 0, 1), expected)
		if i == 0 {
			first = r
		}
	}
	if count(t, s, `SELECT count(*) FROM lpcc.machine_app_versions`) != 2 {
		t.Fatal("oversized intent persisted")
	}
	appBundle(t, s, c)
	requireStatus(t, request(t, s, "DELETE", appPath(c, first), "session-a", map[string]any{"epoch": c["epoch"], "expected_generation": 1}), 202)
	set, _, _ := appBundle(t, s, c)
	if findApp(t, set, first.RevisionID).Desired != "absent" {
		t.Fatal("removal failed at boundary")
	}
}
func TestAssignmentTerminalCleanupCannotAffectReenrollment(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	fingerprint := fmt.Sprintf("%064x", 31)
	old := enroll(t, s, ownerA, fingerprint)
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	requireStatus(t, putApp(t, s, old, r, 0, 1), 202)
	appBundle(t, s, old)
	requireStatus(t, request(t, s, "DELETE", "/api/admin/machines/"+old["node_id"], "session-a", map[string]any{"epoch": old["epoch"], "force": true}), 202)
	terminal, oldDigest, _ := appBundle(t, s, old)
	removal := terminal.Entries[0]
	fresh := enroll(t, s, ownerA, fingerprint)
	if old["epoch"] == fresh["epoch"] {
		t.Fatal("epoch reused")
	}
	requireStatus(t, putApp(t, s, fresh, r, 0, 1), 202)
	appBundle(t, s, fresh)
	requireStatus(t, appReport(t, s, old, removal, oldDigest, "removed"), 200)
	requireStatus(t, appReport(t, s, old, removal, oldDigest, "removed"), 200)
	head, err := machineapps.Head(t.Context(), s.db, fresh["node_id"], fresh["epoch"], r.RevisionID)
	if err != nil || head.CompletedAt != nil || head.Generation != 1 {
		t.Fatal("old cleanup modified new assignment", head, err)
	}
}
func TestAssignmentsPreserveTunnelReadiness(t *testing.T) {
	s, _ := tunnelTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, fmt.Sprintf("%064x", 32))
	ready := readyTunnel(t, s, c)
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	requireStatus(t, putApp(t, s, c, r, 0, 2), 202)
	_, _, files := appBundle(t, s, c)
	after, _, err := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if err != nil || !after.Ready || after.Generation != ready.Generation || after.SourceGeneration != ready.SourceGeneration {
		t.Fatal("app assignment invalidated tunnel", after, err)
	}
	if strings.Contains(files["tunnel.yaml"], "apps_generation") {
		t.Fatal("app metadata leaked into connector config")
	}
	sources, err := s.tunnels.DiscoverySources(t.Context())
	if err != nil || len(sources) != 1 || !sources[0].Ready {
		t.Fatal("app edit invalidated discovery", sources, err)
	}
}

func TestAssignmentBlockedTargetEditsAndCancellation(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, fmt.Sprintf("%064x", 33))
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	next := publishAssignmentRevision(t, s, strings.Replace(registryFixture(t), `app_version = "1"`, `app_version = "2"`, 1), r.RevisionID)
	requireStatus(t, putApp(t, s, c, r, 0, 1), 202)
	replace := map[string]any{"epoch": c["epoch"], "expected_generation": 1, "target": map[string]any{"revision_id": next.RevisionID, "digest": next.Digest, "expected_generation": 0}}
	requireStatus(t, request(t, s, "POST", appPath(c, r)+"/replace", "session-a", replace), 202)
	requireStatus(t, request(t, s, "PUT", appPath(c, next), "session-a", map[string]any{"epoch": c["epoch"], "digest": next.Digest, "expected_generation": 0}), 409)
	requireStatus(t, putApp(t, s, c, next, 1, 3), 202)
	impossibleRetry := map[string]any{"epoch": c["epoch"], "expected_generation": 1, "target": map[string]any{"revision_id": next.RevisionID, "digest": next.Digest, "expected_generation": 1, "replicas": 3}}
	requireStatus(t, request(t, s, "POST", appPath(c, r)+"/replace", "session-a", impossibleRetry), 409)
	currentNoop := map[string]any{"epoch": c["epoch"], "expected_generation": 2, "target": map[string]any{"revision_id": next.RevisionID, "digest": next.Digest, "expected_generation": 2}}
	requireStatus(t, request(t, s, "POST", appPath(c, r)+"/replace", "session-a", currentNoop), 200)
	set, digest, _ := appBundle(t, s, c)
	target := findApp(t, set, next.RevisionID)
	if target.StartAllowed || target.StartAfter == nil || target.Generation != 2 || target.ActivationGeneration != 1 {
		t.Fatal("replica edit cleared prerequisite")
	}
	chain := map[string]any{"epoch": c["epoch"], "expected_generation": 2, "target": map[string]any{"revision_id": r.RevisionID, "digest": r.Digest, "expected_generation": 2}}
	requireStatus(t, request(t, s, "POST", appPath(c, next)+"/replace", "session-a", chain), 409)
	requireStatus(t, request(t, s, "DELETE", appPath(c, next), "session-a", map[string]any{"epoch": c["epoch"], "expected_generation": 2}), 202)
	set, digest, _ = appBundle(t, s, c)
	requireStatus(t, appReport(t, s, c, findApp(t, set, r.RevisionID), digest, "removed"), 200)
	requireStatus(t, appReport(t, s, c, findApp(t, set, next.RevisionID), digest, "removed"), 200)
	empty, _, _ := appBundle(t, s, c)
	if len(empty.Entries) != 0 {
		t.Fatal("cancelled replacement started")
	}
}

func TestAssignmentOmittedReplicasUseExpectedIntent(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, fmt.Sprintf("%064x", 41))
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	implicit := func(expected int64) *httptest.ResponseRecorder {
		return request(t, s, "PUT", appPath(c, r), "session-a", map[string]any{"epoch": c["epoch"], "digest": r.Digest, "expected_generation": expected})
	}
	requireStatus(t, putApp(t, s, c, r, 0, 3), 202)
	requireStatus(t, implicit(0), 409) // Creation requested the definition default, two.
	requireStatus(t, putApp(t, s, c, r, 0, 3), 200)
	requireStatus(t, implicit(1), 200) // Current-version omission retains three.
	requireStatus(t, putApp(t, s, c, r, 1, 4), 202)
	requireStatus(t, implicit(1), 409) // A stale omission retains the expected version's three.
	requireStatus(t, putApp(t, s, c, r, 1, 4), 200)
	requireStatus(t, implicit(2), 200)
	head, err := machineapps.Head(t.Context(), s.db, c["node_id"], c["epoch"], r.RevisionID)
	if err != nil || head.Generation != 2 || head.Replicas != 4 || head.ActivationGeneration != 1 {
		t.Fatal(head, err)
	}
}

func TestAssignmentCompletionRetriesSurviveRetirementAndDeliveryChanges(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, fmt.Sprintf("%064x", 42))
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	requireStatus(t, putApp(t, s, c, r, 0, 2), 202)
	set, firstDigest, _ := appBundle(t, s, c)
	applied := findApp(t, set, r.RevisionID)
	requireStatus(t, appReport(t, s, c, applied, firstDigest, "applied"), 200)
	beta := publishAssignmentRevision(t, s, strings.Replace(registryFixture(t), `name = "whoami"`, `name = "beta"`, 1), "")
	requireStatus(t, putApp(t, s, c, beta, 0, 1), 202)
	_, secondDigest, _ := appBundle(t, s, c)
	requireStatus(t, appReport(t, s, c, applied, secondDigest, "applied"), 200)
	requireStatus(t, request(t, s, "DELETE", "/api/admin/machines/"+c["node_id"], "session-a", map[string]any{"epoch": c["epoch"], "force": true}), 202)
	terminal, terminalDigest, _ := appBundle(t, s, c)
	for _, digest := range []string{firstDigest, secondDigest} {
		requireStatus(t, appReport(t, s, c, applied, digest, "applied"), 200)
	}
	requireStatus(t, appReport(t, s, c, findApp(t, terminal, r.RevisionID), terminalDigest, "applied"), 403)
	requireStatus(t, appReport(t, s, c, findApp(t, terminal, r.RevisionID), terminalDigest, "failed"), 403)
	requireStatus(t, appReport(t, s, c, findApp(t, terminal, r.RevisionID), terminalDigest, "removed"), 200)
	if count(t, s, `SELECT count(*) FROM lpcc.machine_app_completions WHERE phase='applied'`) != 1 {
		t.Fatal("completion retries wrote new state")
	}
}

func TestAssignmentReportValidationAndProviderBackoff(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, fmt.Sprintf("%064x", 43))
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET next_attempt_at=now()+interval '1 hour',failures=3`)
	requireStatus(t, putApp(t, s, c, r, 0, 2), 202)
	set, digest, _ := appBundle(t, s, c)
	a := set.Entries[0]
	for _, phase := range []string{"applied", "removed", "failed"} {
		reasons := []string{"free form diagnostics", strings.Repeat("x", 100), "reconcile_failed"}
		if phase == "failed" {
			reasons[2] = ""
		}
		for _, reason := range reasons {
			report := assignmentReport{Epoch: c["epoch"], CredentialVersion: 1, Generation: a.Generation, ActivationGeneration: a.ActivationGeneration, AppsDigest: digest, Phase: phase, Reason: reason}
			path := "/v1/nodes/" + c["node_id"] + "/apps/" + r.RevisionID + "/status"
			requireStatus(t, request(t, s, "POST", path, c["token"], report), 400)
		}
	}
	wrongVersion := assignmentReport{Epoch: c["epoch"], CredentialVersion: 2, Generation: a.Generation, ActivationGeneration: a.ActivationGeneration, AppsDigest: digest, Phase: "applied"}
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/apps/"+r.RevisionID+"/status", c["token"], wrongVersion), 409)
	requireStatus(t, appReport(t, s, c, a, digest, "failed"), 200)
	requireStatus(t, appReport(t, s, c, a, digest, "applied"), 200)
	requireStatus(t, request(t, s, "DELETE", appPath(c, r), "session-a", map[string]any{"epoch": c["epoch"], "expected_generation": 1}), 202)
	set, digest, _ = appBundle(t, s, c)
	// A provider write holds state before checking its enrollment foreign key.
	// The receipt must not take a conflicting enrollment key lock while waiting.
	provider, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Rollback()
	if _, err := provider.Exec(`SELECT 1 FROM lpcc.machine_states FOR UPDATE; SET LOCAL lock_timeout='1s'`); err != nil {
		t.Fatal(err)
	}
	receipt := make(chan *httptest.ResponseRecorder, 1)
	go func() { receipt <- appReport(t, s, c, set.Entries[0], digest, "removed") }()
	deadline := time.Now().Add(5 * time.Second)
	for count(t, s, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'UPDATE lpcc.machine_states SET apps_generation=%'`) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("receipt did not reach state lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := provider.Exec(`INSERT INTO lpcc.access_credentials(node_id,epoch,version,provider_id,key_id,ciphertext,expires_at) VALUES($1,$2,1,'fixture','fixture',decode('00','hex'),now()+interval '1 hour')`, c["node_id"], c["epoch"]); err != nil {
		t.Fatal("receipt blocked credential foreign-key check", err)
	}
	if err := provider.Commit(); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, <-receipt, 200)
	if count(t, s, `SELECT count(*) FROM lpcc.machine_states WHERE failures=3 AND next_attempt_at>now()+interval '55 minutes'`) != 1 {
		t.Fatal("app changes reset provider backoff")
	}
	files, err := fs.Sub(MigrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrations.Down(t.Context(), s.db, files); err == nil || !strings.Contains(err.Error(), "retain assignment schema") {
		t.Fatal("rollback did not protect assignment history", err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.machine_app_versions`) != 2 {
		t.Fatal("rollback changed history")
	}
}
