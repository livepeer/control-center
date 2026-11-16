package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/schema"
	protocol "github.com/livepeer/control-center/secrets"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestOwnerDenialRetainsIntentAndReallowWaitsForCleanup(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("a", 64))
	other := enroll(t, s, ownerB, strings.Repeat("b", 64))
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	requireStatus(t, putApp(t, s, c, r, 0, 2), 202)
	requireStatus(t, putApp(t, s, other, r, 0, 1), 202)
	path := "/api/operator/apps/" + r.Name + "/policy?orchestrator_address=" + orchA
	requireStatus(t, request(t, s, "PUT", path, "session-a", map[string]any{"denied": true, "expected_generation": 0}), 200)
	head, e := machineapps.Head(t.Context(), s.db, c["node_id"], r.RevisionID)
	if e != nil || head.Desired != "absent" || head.Generation != 2 {
		t.Fatal(head, e)
	}
	foreign, e := machineapps.Head(t.Context(), s.db, other["node_id"], r.RevisionID)
	if e != nil || foreign.Desired != "present" {
		t.Fatal("owner isolation", e)
	}
	var raw []byte
	if e = s.db.QueryRow(`SELECT intent FROM lpcc.machine_app_requests WHERE node_id=$1 AND revision_id=$2`, c["node_id"], r.RevisionID).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	var wanted map[string]any
	_ = json.Unmarshal(raw, &wanted)
	if wanted["desired"] != "present" {
		t.Fatal("denial erased administrator intent")
	}
	requireStatus(t, request(t, s, "PUT", path, "session-a", map[string]any{"denied": false, "expected_generation": 1}), 200)
	head, _ = machineapps.Head(t.Context(), s.db, c["node_id"], r.RevisionID)
	if head.Desired != "absent" {
		t.Fatal("reallow reversed pending withdrawal")
	}
	set, digest, _ := appBundle(t, s, c)
	removal := findApp(t, set, r.RevisionID)
	requireStatus(t, appReport(t, s, c, removal, digest, "removed"), 200)
	if e = s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	head, e = machineapps.Head(t.Context(), s.db, c["node_id"], r.RevisionID)
	if e != nil || head.Desired != "present" || head.ActivationGeneration != head.Generation || head.Generation != 3 {
		t.Fatal("fresh activation missing", head, e)
	}
}
func TestStolenEnrollmentGrantCannotReissueExistingMachineCredential(t *testing.T) {
	s := newTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("d", 64))
	token, _, _ := s.params.signEnrollment(ownerA, testOrchestrator(ownerA), time.Now())
	w := request(t, s, "POST", "/v1/nodes/register", token, registrationBody(ownerB, strings.Repeat("d", 64), token))
	requireStatus(t, w, 409)
	w = request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/credentials/refresh", token, map[string]any{"fingerprint": strings.Repeat("d", 64), "install_dir": "/opt/livepeer", "operation_id": uuid.New().String(), "expected_credential_version": 1})
	requireStatus(t, w, 403)
}

func TestSharedPolicyAuditRecordsMemberWithoutMachines(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	execSQL(t, s.db, `INSERT INTO lpcc.orchestrator_memberships VALUES($1,$2)`, ownerB, orchA)
	path := "/api/operator/apps/" + r.Name + "/policy?orchestrator_address=" + orchA
	for _, change := range []struct {
		denied     bool
		generation int64
	}{{true, 0}, {true, 1}, {false, 1}} {
		requireStatus(t, request(t, s, "PUT", path, "session-b", map[string]any{"denied": change.denied, "expected_generation": change.generation}), 200)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.machines`) != 0 {
		t.Fatal("fixture unexpectedly has machines")
	}
	if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE actor_kind='user' AND actor_id=$1 AND target_kind='orchestrator_policy' AND target_id=$2 AND ((action='orchestrator.policy.deny' AND revision='1') OR (action='orchestrator.policy.allow' AND revision='2'))`, ownerB, orchA+"/"+r.Name) != 2 {
		t.Fatal("policy audit lost actor/scope/change/generation or duplicated a no-op")
	}
}

func TestReallowWaitsForEveryReplacementRemoval(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("6", 64))
	first := publishAssignmentRevision(t, s, registryFixture(t), "")
	requireStatus(t, putApp(t, s, c, first, 0, 2), 202)
	second := publishAssignmentRevision(t, s, strings.Replace(registryFixture(t), `app_version = "1"`, `app_version = "2"`, 1), first.RevisionID)
	requireStatus(t, request(t, s, "POST", appPath(c, first)+"/replace", "session-a", map[string]any{"expected_generation": 1, "target": map[string]any{"revision_id": second.RevisionID, "digest": second.Digest, "expected_generation": 0, "replicas": 1}}), 202)
	policy := "/api/operator/apps/" + first.Name + "/policy?orchestrator_address=" + orchA
	requireStatus(t, request(t, s, "PUT", policy, "session-a", map[string]any{"denied": true, "expected_generation": 0}), 200)
	set, digest, _ := appBundle(t, s, c)
	requireStatus(t, appReport(t, s, c, findApp(t, set, second.RevisionID), digest, "removed"), 200)
	requireStatus(t, request(t, s, "PUT", policy, "session-a", map[string]any{"denied": false, "expected_generation": 1}), 200)
	head, e := machineapps.Head(t.Context(), s.db, c["node_id"], second.RevisionID)
	if e != nil || head.Desired != "absent" {
		t.Fatal("target restarted while source still draining", head, e)
	}
	set, digest, _ = appBundle(t, s, c)
	requireStatus(t, appReport(t, s, c, findApp(t, set, first.RevisionID), digest, "removed"), 200)
	if e = s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	head, e = machineapps.Head(t.Context(), s.db, c["node_id"], second.RevisionID)
	if e != nil || head.Desired != "present" || head.ActivationGeneration != 3 {
		t.Fatal("cleaned replacement did not receive fresh activation", head, e)
	}
}

func TestRenderRepairAdvancesBeyondDeniedFallback(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("7", 64))
	first := publishAssignmentRevision(t, s, registryFixture(t), "")
	requireStatus(t, putApp(t, s, c, first, 0, 1), 202)
	_, _, _ = appBundle(t, s, c)
	second := publishAssignmentRevision(t, s, strings.Replace(registryFixture(t), `name = "whoami"`, `name = "other"`, 1), "")
	requireStatus(t, putApp(t, s, c, second, 0, 1), 202)
	requireStatus(t, request(t, s, "PUT", "/api/operator/apps/"+first.Name+"/policy?orchestrator_address="+orchA, "session-a", map[string]any{"denied": true, "expected_generation": 0}), 200)
	s.params.AppStopSignals = false
	s.configs = s.newConfigurationManager()
	fallback, _, _ := appBundle(t, s, c)
	if findApp(t, fallback, first.RevisionID).Desired != "absent" {
		t.Fatal("fallback restored denied app")
	}
	s.params.AppStopSignals = true
	s.configs = s.newConfigurationManager()
	repaired, _, _ := appBundle(t, s, c)
	if repaired.Generation <= fallback.Generation || findApp(t, repaired, first.RevisionID).Desired != "absent" || findApp(t, repaired, second.RevisionID).Desired != "present" {
		t.Fatal("render repair did not converge with a fresh identity")
	}
	again, _, _ := appBundle(t, s, c)
	if again.Generation != repaired.Generation {
		t.Fatal("unchanged repair kept allocating generations")
	}
}

type operatorQueryCount struct{ atomic.Int64 }

func (c *operatorQueryCount) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.Add(1)
	return ctx
}
func (*operatorQueryCount) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestOperatorAppsBatchesOwnerUsage(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	conn, err := s.db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var config *pgx.ConnConfig
	err = conn.Raw(func(raw any) error {
		config = raw.(*stdlib.Conn).Conn().Config()
		return nil
	})
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	queries := &operatorQueryCount{}
	config.Tracer = queries
	// Auth's fixture keeps its original pool; count only the handler's SQL reads.
	s.db = stdlib.OpenDB(*config)
	t.Cleanup(func() { s.db.Close() })
	s.db.SetMaxOpenConns(1)
	type appView struct {
		Name      string                     `json:"name"`
		Machines  []string                   `json:"machines"`
		Requested []string                   `json:"requested_machines"`
		Aliases   []schema.App               `json:"aliases"`
		Secrets   []schema.SecretEnvironment `json:"secrets"`
		Catalog   []schema.SecretEnvironment `json:"catalog_secrets"`
	}
	read := func(wantQueries int64, wantApps int) []appView {
		t.Helper()
		queries.Store(0)
		w := request(t, s, "GET", "/api/operator/apps?orchestrator_address="+orchA, "session-a", nil)
		requireStatus(t, w, 200)
		if got := queries.Load(); got != wantQueries {
			t.Fatalf("catalog SQL reads = %d, want %d", got, wantQueries)
		}
		var view struct {
			Apps []appView `json:"apps"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		if view.Apps == nil || len(view.Apps) != wantApps {
			t.Fatal("unexpected catalog", w.Body.String())
		}
		return view.Apps
	}
	read(2, 0)
	source := func(version, secret, alias string) string {
		return strings.Replace(registryFixture(t), `app_version = "1"`, `app_version = "`+version+`"`, 1) +
			"\n[[container.secrets]]\nname = \"TOKEN\"\nsecret = \"" + secret + "\"\nkey = \"token\"\n" +
			"\n[[apps]]\nname = \"" + alias + "\"\npath = \"/alias\"\n"
	}
	foreign := publishAssignmentRevision(t, s, source("1", "lp-app-foreign", "foreign"), "")
	view := read(3, 1)
	if len(view[0].Secrets) != 1 || view[0].Secrets[0].Secret != "lp-app-foreign" || len(view[0].Machines) != 0 {
		t.Fatal("unused app lost catalog declarations", view)
	}
	other := enroll(t, s, ownerB, strings.Repeat("a", 64))
	requireStatus(t, putApp(t, s, other, foreign, 0, 1), 202)
	pinned := publishAssignmentRevision(t, s, source("2", "lp-app-pinned", "pinned"), foreign.RevisionID)
	a := enroll(t, s, ownerA, strings.Repeat("b", 64))
	b := enroll(t, s, ownerA, strings.Repeat("c", 64))
	requireStatus(t, putApp(t, s, a, pinned, 0, 1), 202)
	requireStatus(t, putApp(t, s, b, pinned, 0, 1), 202)
	_ = publishAssignmentRevision(t, s, source("3", "lp-app-head", "head"), pinned.RevisionID)
	_ = publishAssignmentRevision(t, s, strings.Replace(source("1", "lp-app-unused", "unused"), `name = "whoami"`, `name = "aaa-unused"`, 1), "")
	view = read(3, 2)
	if view[0].Name != "aaa-unused" || len(view[0].Machines) != 0 || len(view[0].Requested) != 0 || len(view[0].Secrets) != 1 || view[0].Secrets[0].Secret != "lp-app-unused" {
		t.Fatal("catalog order or unused declarations changed", view)
	}
	app := view[1]
	wantMachines := []string{a["node_id"], b["node_id"]}
	slices.Sort(wantMachines)
	if app.Name != "whoami" || !slices.Equal(app.Machines, wantMachines) || !slices.Equal(app.Requested, wantMachines) || len(app.Secrets) != 1 || app.Secrets[0].Secret != "lp-app-pinned" || len(app.Catalog) != 1 || app.Catalog[0].Secret != "lp-app-head" || len(app.Aliases) != 2 || app.Aliases[0].Name != "head" || app.Aliases[1].Name != "pinned" {
		t.Fatal("owner usage, pinned declarations, or deduplication changed", app)
	}
	queries.Store(0)
	requireStatus(t, request(t, s, "GET", "/api/operator/apps?orchestrator_address="+orchA, "session-b", nil), 403)
	if queries.Load() != 1 {
		t.Fatal("unauthorized catalog queried usage")
	}
}

func TestOwnerReferencesDescribePinnedAndCleanupRevisions(t *testing.T) {
	s := newTestServer(t)

	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("8", 64))
	decl := func(name string) string {
		return "\n[[container.secrets]]\nname = \"TOKEN\"\nsecret = \"" + name + "\"\nkey = \"token\"\n"
	}
	first := publishAssignmentRevision(t, s, registryFixture(t)+decl("lp-app-old"), "")
	requireStatus(t, putApp(t, s, c, first, 0, 1), 202)
	second := publishAssignmentRevision(t, s, strings.Replace(registryFixture(t), `app_version = "1"`, `app_version = "2"`, 1)+decl("lp-app-new"), first.RevisionID)
	s.db.SetMaxOpenConns(1)
	w := request(t, s, "GET", "/api/operator/apps?orchestrator_address="+orchA, "session-a", nil)
	s.db.SetMaxOpenConns(10)
	requireStatus(t, w, 200)
	var view struct {
		Apps []struct {
			Secrets []struct {
				Secret string `json:"secret"`
			} `json:"secrets"`
			Catalog []struct {
				Secret string `json:"secret"`
			} `json:"catalog_secrets"`
		} `json:"apps"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &view); e != nil {
		t.Fatal(e)
	}
	if len(view.Apps) != 1 || len(view.Apps[0].Secrets) != 1 || view.Apps[0].Secrets[0].Secret != "lp-app-old" || view.Apps[0].Catalog[0].Secret != "lp-app-new" {
		t.Fatal("catalog head obscured pinned declarations", w.Body.String())
	}
	requireStatus(t, request(t, s, "POST", appPath(c, first)+"/replace", "session-a", map[string]any{"expected_generation": 1, "target": map[string]any{"revision_id": second.RevisionID, "digest": second.Digest, "expected_generation": 0}}), 202)
	w = request(t, s, "GET", "/api/operator/apps?orchestrator_address="+orchA, "session-a", nil)
	requireStatus(t, w, 200)
	if e := json.Unmarshal(w.Body.Bytes(), &view); e != nil {
		t.Fatal(e)
	}
	if len(view.Apps) != 1 || len(view.Apps[0].Secrets) != 2 {
		t.Fatal("pending cleanup lost pinned declarations", w.Body.String())
	}
	s.params.SecretsMetadataToken = strings.Repeat("m", 32)
	w = request(t, s, "GET", "/internal/secrets/nodes/"+c["node_id"], s.params.SecretsMetadataToken, nil)
	requireStatus(t, w, 200)
	var metadata struct {
		Consumers []struct {
			References []struct {
				Secret string `json:"secret"`
			} `json:"references"`
		} `json:"cleanup_consumers"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &metadata); e != nil {
		t.Fatal(e)
	}
	if len(metadata.Consumers) != 1 || metadata.Consumers[0].References[0].Secret != "lp-app-old" {
		t.Fatal("cleanup consumer lost pinned declaration", w.Body.String())
	}
}

func TestPendingSecretBindingOwnerActivationAndConditionalReset(t *testing.T) {
	s := newTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("f", 64))
	node := c["node_id"]
	s.params.SecretsMetadataToken = strings.Repeat("m", 32)
	body := registrationBody(ownerA, strings.Repeat("f", 64), "unused")
	public := body["public_key"].(string)
	seed := sha256.Sum256([]byte(ownerA + strings.Repeat("f", 64)))
	key := ed25519.NewKeyFromSeed(seed[:])
	if _, e := s.db.Exec(`UPDATE lpcc.secret_machines SET public_key='' WHERE node_id=$1`, node); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(`INSERT INTO lpcc.machine_reports(node_id,component,generation,credential_version,report) VALUES($1,'runner',1,1,'{"apps":{"secrets_protocol":1}}')`, node); e != nil {
		t.Fatal(e)
	}
	nonce := strings.Repeat("a", 64)
	in := protocol.MachineBinding{EnrollRequest: protocol.EnrollRequest{NodeID: node, PublicKey: public, Nonce: nonce, Signature: ed25519.Sign(key, protocol.Proof(node, public)), ManagementProof: protocol.EnrollmentProof(c["token"], node, public, nonce), EncryptionReady: true}, Owner: orchB}
	path := "/internal/secrets/nodes/" + node
	requireStatus(t, request(t, s, "POST", path, s.params.SecretsMetadataToken, in), 400)
	var bound string
	var managed bool
	_ = s.db.QueryRow(`SELECT public_key,managed FROM lpcc.secret_machines WHERE node_id=$1`, node).Scan(&bound, &managed)
	if bound != "" || managed {
		t.Fatal("mixed owner mutated binding")
	}
	in.Owner = orchA
	for name, change := range map[string]func(*protocol.MachineBinding){
		"missing proof":      func(b *protocol.MachineBinding) { b.ManagementProof = "" },
		"raw credential":     func(b *protocol.MachineBinding) { b.ManagementProof = c["token"] },
		"missing nonce":      func(b *protocol.MachineBinding) { b.Nonce = "" },
		"short nonce":        func(b *protocol.MachineBinding) { b.Nonce = "abcd" },
		"noncanonical nonce": func(b *protocol.MachineBinding) { b.Nonce = strings.Repeat("A", 64) },
		"changed nonce":      func(b *protocol.MachineBinding) { b.Nonce = strings.Repeat("b", 64) },
		"other node": func(b *protocol.MachineBinding) {
			b.ManagementProof = protocol.EnrollmentProof(c["token"], "other-node", public, nonce)
		},
		"other key": func(b *protocol.MachineBinding) {
			b.ManagementProof = protocol.EnrollmentProof(c["token"], node, "other-public", nonce)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := in
			change(&changed)
			requireStatus(t, request(t, s, "POST", path, s.params.SecretsMetadataToken, changed), 403)
		})
	}
	requireStatus(t, request(t, s, "GET", "/v1/nodes/"+node+"/config", in.ManagementProof, nil), 401)
	requireStatus(t, request(t, s, "POST", path, in.ManagementProof, in), 403)
	// A retry of the exact binding remains idempotent.
	requireStatus(t, request(t, s, "POST", path, s.params.SecretsMetadataToken, in), 200)
	requireStatus(t, request(t, s, "POST", path, s.params.SecretsMetadataToken, in), 200)
	_ = s.db.QueryRow(`SELECT managed FROM lpcc.secret_machines WHERE node_id=$1`, node).Scan(&managed)
	if managed {
		t.Fatal("pending binding activated")
	}
	in.Activate = true
	in.AdmissionReady = true
	requireStatus(t, request(t, s, "POST", path, s.params.SecretsMetadataToken, in), 200)
	in.ResetKey = "a-different-retired-key"
	requireStatus(t, request(t, s, "POST", path, s.params.SecretsMetadataToken, in), 200)
	_ = s.db.QueryRow(`SELECT public_key,managed FROM lpcc.secret_machines WHERE node_id=$1`, node).Scan(&bound, &managed)
	if bound != public || !managed {
		t.Fatal("late clear erased new binding")
	}
	// Credential refresh invalidates the old proof even for the same binding.
	grant, _, _ := s.params.signEnrollment(ownerA, orchA, s.currentTime())
	w := request(t, s, "POST", "/v1/nodes/"+node+"/credentials/refresh", grant, map[string]any{"management_proof": c["token"], "fingerprint": strings.Repeat("f", 64), "install_dir": "/opt/livepeer", "operation_id": uuid.New().String(), "expected_credential_version": 1})
	requireStatus(t, w, 200)
	fresh := credentials(t, w.Body.Bytes())
	in.Activate, in.AdmissionReady, in.ResetKey = false, false, ""
	requireStatus(t, request(t, s, "POST", path, s.params.SecretsMetadataToken, in), 403)
	if _, err := s.db.Exec(`UPDATE lpcc.machine_reports SET credential_version=2 WHERE node_id=$1`, node); err != nil {
		t.Fatal(err)
	}
	in.ManagementProof = protocol.EnrollmentProof(fresh["token"], node, public, nonce)
	requireStatus(t, request(t, s, "POST", path, s.params.SecretsMetadataToken, in), 200)
}

func TestRegistrationProofCannotBeReplayedWithAnotherGrantOrRequest(t *testing.T) {
	s := newTestServer(t)
	token, _, _ := s.params.signEnrollment(ownerA, testOrchestrator(ownerA), s.currentTime())
	body := registrationBody(ownerA, strings.Repeat("e", 64), token)
	unsigned := registrationBody(ownerA, strings.Repeat("e", 64), token)
	delete(unsigned, "public_key")
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", token, unsigned), 403)
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", token, body), 200)
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", token, body), 200)
	next, _, _ := s.params.signEnrollment(ownerA, testOrchestrator(ownerA), s.currentTime())
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", next, body), 403)
	body["hostname"] = "changed-host"
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", token, body), 403)
}

func TestReallowDoesNotReactivateDrainingMachine(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("9", 64))
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	requireStatus(t, putApp(t, s, c, r, 0, 2), 202)
	policy := "/api/operator/apps/" + r.Name + "/policy?orchestrator_address=" + orchA
	requireStatus(t, request(t, s, "PUT", policy, "session-a", map[string]any{"denied": true, "expected_generation": 0}), 200)
	set, digest, _ := appBundle(t, s, c)
	requireStatus(t, appReport(t, s, c, findApp(t, set, r.RevisionID), digest, "removed"), 200)
	if _, e := s.db.Exec(`UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{lifecycle}','"draining"') WHERE node_id=$1`, c["node_id"]); e != nil {
		t.Fatal(e)
	}
	requireStatus(t, request(t, s, "PUT", policy, "session-a", map[string]any{"denied": false, "expected_generation": 1}), 200)
	if e := s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	h, e := machineapps.Head(t.Context(), s.db, c["node_id"], r.RevisionID)
	if e != nil || h.Desired != "absent" {
		t.Fatal("reallow resurrected draining machine", h, e)
	}
}

func TestDeniedAssignmentRetriesReserveRequestedBudget(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("c", 64))
	r := publishAssignmentRevision(t, s, registryFixture(t), "")
	policy := "/api/operator/apps/" + r.Name + "/policy?orchestrator_address=" + orchA
	requireStatus(t, request(t, s, "PUT", policy, "session-a", map[string]any{"denied": true, "expected_generation": 0}), 200)
	requireStatus(t, putApp(t, s, c, r, 0, 100), 202)
	requireStatus(t, putApp(t, s, c, r, 0, 100), 200)
	for n := 0; n < 5; n++ {
		second := publishAssignmentRevision(t, s, strings.Replace(registryFixture(t), `name = "whoami"`, fmt.Sprintf(`name = "other%d"`, n), 1), "")
		requireStatus(t, request(t, s, "PUT", "/api/operator/apps/"+second.Name+"/policy?orchestrator_address="+orchA, "session-a", map[string]any{"denied": true, "expected_generation": 0}), 200)
		want := 202
		if n == 4 {
			want = 400
		}
		requireStatus(t, putApp(t, s, c, second, 0, 100), want)
	}
}

func TestDeniedCleanedAssignmentKeepsRequestedDeclarations(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("0", 64))
	decl := func(name string) string {
		return "\n[[container.secrets]]\nname = \"TOKEN\"\nsecret = \"" + name + "\"\nkey = \"token\"\n"
	}
	first := publishAssignmentRevision(t, s, registryFixture(t)+decl("lp-app-pinned"), "")
	requireStatus(t, putApp(t, s, c, first, 0, 1), 202)
	_ = publishAssignmentRevision(t, s, strings.Replace(registryFixture(t), `app_version = "1"`, `app_version = "2"`, 1)+decl("lp-app-new-head"), first.RevisionID)
	requireStatus(t, request(t, s, "PUT", "/api/operator/apps/"+first.Name+"/policy?orchestrator_address="+orchA, "session-a", map[string]any{"denied": true, "expected_generation": 0}), 200)
	set, digest, _ := appBundle(t, s, c)
	requireStatus(t, appReport(t, s, c, findApp(t, set, first.RevisionID), digest, "removed"), 200)
	w := request(t, s, "GET", "/api/operator/apps?orchestrator_address="+orchA, "session-a", nil)
	requireStatus(t, w, 200)
	var view struct {
		Apps []struct {
			Machines  []string                   `json:"machines"`
			Requested []string                   `json:"requested_machines"`
			Secrets   []schema.SecretEnvironment `json:"secrets"`
		} `json:"apps"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &view); e != nil {
		t.Fatal(e)
	}
	if len(view.Apps) != 1 || len(view.Apps[0].Machines) != 0 || len(view.Apps[0].Requested) != 1 || len(view.Apps[0].Secrets) != 1 || view.Apps[0].Secrets[0].Secret != "lp-app-pinned" {
		t.Fatal("cleaned denial hid retained requested declaration", w.Body.String())
	}
}

func TestManagedStateQueryFailurePreservesPreviousBundle(t *testing.T) {
	s := newTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("1", 64))
	if _, e := s.db.Exec(`UPDATE lpcc.secret_machines SET managed=true,encryption_ready=true WHERE node_id=$1`, c["node_id"]); e != nil {
		t.Fatal(e)
	}
	if e := s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	var before string
	if e := s.db.QueryRow(`SELECT sha256 FROM lpcc.machine_configs WHERE node_id=$1`, c["node_id"]).Scan(&before); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(`ALTER TABLE lpcc.secret_machines RENAME TO unavailable_secret_machines`); e != nil {
		t.Fatal(e)
	}
	defer s.db.Exec(`ALTER TABLE lpcc.unavailable_secret_machines RENAME TO secret_machines`)
	if e := s.reconcile(t.Context()); e == nil {
		t.Fatal("managed-state query failure ignored")
	}
	var after string
	_ = s.db.QueryRow(`SELECT sha256 FROM lpcc.machine_configs WHERE node_id=$1`, c["node_id"]).Scan(&after)
	if after != before {
		t.Fatal("storage outage published regressing metadata")
	}
}
