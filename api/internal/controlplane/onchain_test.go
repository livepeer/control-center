package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/consumer"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/onchain"
)

func onchainSettings(t *testing.T, s *Server) onchain.Config {
	t.Helper()
	dir := t.TempDir()
	s.params.OnchainSecretsDir = dir
	s.params.OnchainWebhookSecret = strings.Repeat("w", 32)
	ref := rpcSecret(t, s, "https://rpc.example/private-token")
	s.params.Mode = "onchain"
	c := onchain.Config{Version: 1, CredentialRevision: 1, Mode: "onchain", Network: "arbitrum-one-mainnet", ChainID: 42161, Controller: mainnetController, Recipient: orchA, RPCSecret: ref, RedeemerURL: "https://api.example/redemption", WeiPerUSD: "1000000000000000", TicketFaceValue: "1000", TicketWinProb: "100", MaxPendingTickets: 100, MaxTicketsPerRecipient: 10}
	template := c
	template.Recipient = ""
	template.CredentialRevision = 0
	s.params.OnchainConfigFile = filepath.Join(t.TempDir(), "onchain.json")
	if err := os.WriteFile(s.params.OnchainConfigFile, onchainTemplateJSON(t, template), 0600); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOnchainCredentialsRequireBoundRuntimeProofWhileSecretsUnavailable(t *testing.T) {
	s, _, machine := onchainMachine(t)
	s.params.SecretsURL = "https://127.0.0.1:1"
	node := machine["node_id"]
	path := "/v1/nodes/" + node + "/onchain/credentials"
	in := signedOnchainRequest(t, s, node, consumer.Launch{PodName: "orchestrator", PodUID: "pod", LaunchID: strings.Repeat("a", 32), ProcessID: strings.Repeat("b", 64)})
	seed := sha256.Sum256([]byte(ownerA + installationFingerprint(t, s, node)))
	key, endpoint := ed25519.NewKeyFromSeed(seed[:]), s.params.PublicAPIURL+path
	for name, mutate := range map[string]func(*consumer.Request){
		"unsigned":   func(r *consumer.Request) { r.Signature = nil },
		"pod-name":   func(r *consumer.Request) { r.PodName += "x" },
		"pod-uid":    func(r *consumer.Request) { r.PodUID += "x" },
		"launch":     func(r *consumer.Request) { r.LaunchID = strings.Repeat("c", 32) },
		"process":    func(r *consumer.Request) { r.ProcessID = strings.Repeat("c", 64) },
		"generation": func(r *consumer.Request) { r.OnchainGeneration++ },
		"config":     func(r *consumer.Request) { r.ConfigDigest = strings.Repeat("c", 64) },
		"node":       func(r *consumer.Request) { r.Sign(key, node+"x", 1, endpoint, s.currentTime()) },
		"credential": func(r *consumer.Request) { r.Sign(key, node, 2, endpoint, s.currentTime()) },
		"endpoint":   func(r *consumer.Request) { r.Sign(key, node, 1, endpoint+"x", s.currentTime()) },
		"expired":    func(r *consumer.Request) { r.Sign(key, node, 1, endpoint, s.currentTime().Add(-time.Minute)) },
		"future":     func(r *consumer.Request) { r.Sign(key, node, 1, endpoint, s.currentTime().Add(time.Minute)) },
		"wrong-key": func(r *consumer.Request) {
			r.Sign(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), node, 1, endpoint, s.currentTime())
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := in
			mutate(&bad)
			requireStatus(t, request(t, s, "POST", path, machine["token"], bad), 403)
			if count(t, s, `SELECT count(*) FROM lpcc.onchain_grants`) != 0 {
				t.Fatal("invalid proof created a grant")
			}
		})
	}
	for range 2 {
		requireStatus(t, request(t, s, "POST", path, machine["token"], in), 200)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.onchain_grants`) != 1 {
		t.Fatal("replay minted another grant")
	}
	execSQL(t, s.db, `UPDATE lpcc.secret_machines SET public_key='' WHERE node_id=$1`, node)
	requireStatus(t, request(t, s, "POST", path, machine["token"], in), 403)
	execSQL(t, s.db, `DELETE FROM lpcc.secret_machines WHERE node_id=$1`, node)
	requireStatus(t, request(t, s, "POST", path, machine["token"], in), 409)
}

func TestAutomaticOnchainConfigurationAndUpdates(t *testing.T) {
	s := newTestServer(t)
	c := onchainSettings(t, s)
	s.params.Mode = ""
	machine := enroll(t, s, ownerA, strings.Repeat("a", 64))
	node := machine["node_id"]
	loaded, err := loadOnchain(t.Context(), s.db, node)
	if err != nil || loaded.Recipient != c.Recipient || loaded.Generation != 1 {
		t.Fatal(loaded, err)
	}
	if delivered := onchainMetadata(t, s, node).Onchain; !delivered.Onchain() || delivered.Recipient != c.Recipient || delivered.Generation != 1 {
		t.Fatal("first boot did not receive the claimed recipient", delivered)
	}
	var initiator string
	if err = s.db.QueryRow(`SELECT enrolled_by_user_id FROM lpcc.machines WHERE node_id=$1`, node).Scan(&initiator); err != nil || initiator != ownerA {
		t.Fatal(initiator, err)
	}
	next, err := s.loadOnchainTemplate()
	if err != nil {
		t.Fatal(err)
	}
	next.TicketFaceValue = "2000"
	if err = os.WriteFile(s.params.OnchainConfigFile, onchainTemplateJSON(t, next), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	loaded, err = loadOnchain(t.Context(), s.db, node)
	if err != nil || loaded.Generation != 2 || loaded.TicketFaceValue != "2000" {
		t.Fatal(loaded, err)
	}
	if delivered := onchainMetadata(t, s, node).Onchain; delivered.Generation != 2 || delivered.TicketFaceValue != "2000" {
		t.Fatal("template update was not delivered", delivered)
	}
}

type onchainQueryTrace func(string)

func (f onchainQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	f(q.SQL)
	return ctx
}
func (onchainQueryTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestOnchainReconcileSkipsUnchangedMachines(t *testing.T) {
	s, _, a := onchainMachine(t)
	b := enroll(t, s, ownerB, strings.Repeat("b", 64))
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	var database string
	if err := s.db.QueryRow(`SELECT current_database()`).Scan(&database); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database, cfg.DefaultQueryExecMode = database, pgx.QueryExecModeExec
	var queries []string
	cfg.Tracer = onchainQueryTrace(func(q string) { queries = append(queries, q) })
	s.db = stdlib.OpenDB(*cfg)
	t.Cleanup(func() { s.db.Close() })
	if err = s.reconcileOnchain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 1 || !strings.HasPrefix(queries[0], "SELECT m.fingerprint") {
		t.Fatalf("unchanged pass issued %d commands: %v", len(queries), queries)
	}
	next, err := s.loadOnchainTemplate()
	if err != nil {
		t.Fatal(err)
	}
	next.TicketFaceValue = "2000"
	writeOnchainTemplate(t, s, next)
	// Align one machine first: only the other should enter a transaction.
	tx, err := s.policyTx(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, _, err = s.syncOnchainConfig(t.Context(), tx, strings.Repeat("b", 64), orchB); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	beforeA := count(t, s, `SELECT revision FROM lpcc.machine_states WHERE node_id=$1`, a["node_id"])
	beforeB := count(t, s, `SELECT revision FROM lpcc.machine_states WHERE node_id=$1`, b["node_id"])
	queries = nil
	if err = s.reconcileOnchain(t.Context()); err != nil {
		t.Fatal(err)
	}
	begins := 0
	for _, q := range queries {
		if strings.HasPrefix(q, "begin") {
			begins++
		}
	}
	if begins != 1 {
		t.Fatalf("mixed pass opened %d transactions: %v", begins, queries)
	}
	if count(t, s, `SELECT revision FROM lpcc.machine_states WHERE node_id=$1`, a["node_id"]) != beforeA+1 || count(t, s, `SELECT revision FROM lpcc.machine_states WHERE node_id=$1`, b["node_id"]) != beforeB {
		t.Fatal("mixed pass changed the wrong machine revisions")
	}
	for _, m := range []map[string]string{a, b} {
		c, err := loadOnchain(t.Context(), s.db, m["node_id"])
		if err != nil || c.Generation != 2 || c.CredentialRevision != 2 || c.TicketFaceValue != "2000" {
			t.Fatal("wrong reconciled configuration", c, err)
		}
	}
	queries = nil
	if err = os.WriteFile(s.params.OnchainConfigFile, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.reconcileOnchain(t.Context()); err == nil || len(queries) != 1 || !strings.HasPrefix(queries[0], "SELECT m.fingerprint") {
		t.Fatal("invalid template was not rejected before transactional work", err, queries)
	}
}

func writeOnchainTemplate(t *testing.T, s *Server, c onchain.Config) {
	t.Helper()
	if err := os.WriteFile(s.params.OnchainConfigFile, onchainTemplateJSON(t, c), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestOnchainReconcileRechecksCandidates(t *testing.T) {
	for _, race := range []string{"already-updated", "newer-settings", "retired", "refreshed", "identity", "incompatible-app", "template"} {
		t.Run(race, func(t *testing.T) {
			s, _, m := onchainMachine(t)
			if err := s.reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			node, fingerprint := m["node_id"], strings.Repeat("a", 64)
			var revision CatalogRevision
			if race == "incompatible-app" {
				adminA(t, s)
				revision = publishAssignmentRevision(t, s, registryFixture(t), "")
				requireStatus(t, putApp(t, s, m, revision, 0, 1), 202)
			}
			next, err := s.loadOnchainTemplate()
			if err != nil {
				t.Fatal(err)
			}
			next.TicketFaceValue = "2000"
			writeOnchainTemplate(t, s, next)
			plain := race == "retired" || race == "refreshed" || race == "newer-settings"
			begin := s.policyTx
			if plain {
				begin = func(ctx context.Context) (*sql.Tx, error) { return s.db.BeginTx(ctx, nil) }
			}
			tx, err := begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if plain {
				var present int
				if err = tx.QueryRow(`SELECT 1 FROM lpcc.machines WHERE node_id=$1 FOR UPDATE`, node).Scan(&present); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() { done <- s.reconcileOnchain(t.Context()) }()
			query := "SELECT pg_advisory_xact_lock(1129073483, 2)"
			if plain {
				query = "SELECT 1 FROM lpcc.machines%"
			}
			waitForStateLock(t, s, query, 1)
			switch race {
			case "already-updated", "newer-settings":
				if race == "newer-settings" {
					next.TicketFaceValue = "3000"
					writeOnchainTemplate(t, s, next)
				}
				if _, changed, err := s.syncOnchainConfig(t.Context(), tx, fingerprint, orchA); err != nil || !changed {
					t.Fatal(changed, err)
				}
			case "retired":
				_, err = tx.Exec(`DELETE FROM lpcc.machines WHERE node_id=$1`, node)
			case "refreshed":
				_, err = tx.Exec(`UPDATE lpcc.machines SET credential_version=credential_version+1 WHERE node_id=$1`, node)
			case "identity":
				_, err = tx.Exec(`UPDATE lpcc.onchain_state SET recipient=$1 WHERE fingerprint=$2`, orchB, fingerprint)
			case "incompatible-app":
				// Simulate incompatible policy committed while inventory waited.
				var head machineapps.Version
				head, err = machineapps.Head(t.Context(), tx, node, revision.RevisionID)
				if err == nil {
					head.Generation++
					head.Revision.Definition.Price.Amount = "0"
					err = machineapps.AppendEffective(t.Context(), tx, node, ownerA, head.AppAssignment)
				}
			case "template":
				next.TicketFaceValue = "3000"
				writeOnchainTemplate(t, s, next)
			}
			if err != nil {
				t.Fatal(err)
			}
			var wantRevision int
			if err = tx.QueryRow(`SELECT revision FROM lpcc.machine_states WHERE node_id=$1`, node).Scan(&wantRevision); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("queued reconciliation did not finish")
			}
			wantError := race == "identity" || race == "incompatible-app"
			if (err != nil) != wantError {
				t.Fatal("unexpected reconciliation result", err)
			}
			generation := 1
			if race == "already-updated" || race == "newer-settings" || race == "template" {
				generation = 2
			}
			if race == "template" {
				wantRevision++
			}
			if count(t, s, `SELECT count(*) FROM lpcc.onchain_configs WHERE fingerprint=$1`, fingerprint) != generation || count(t, s, `SELECT generation FROM lpcc.onchain_state WHERE fingerprint=$1`, fingerprint) != generation || count(t, s, `SELECT revision FROM lpcc.machine_states WHERE node_id=$1`, node) != wantRevision {
				t.Fatal("stale candidate changed generation or machine revision")
			}
			if race == "newer-settings" {
				c, err := loadOnchain(t.Context(), s.db, node)
				if err != nil || c.TicketFaceValue != "3000" || c.CredentialRevision != 2 {
					t.Fatal("cached template overwrote newer settings", c, err)
				}
			}
			if race == "template" {
				c, err := loadOnchain(t.Context(), s.db, node)
				if err != nil || c.TicketFaceValue != "2000" {
					t.Fatal("pass did not retain its template snapshot", c, err)
				}
				if err = s.reconcileOnchain(t.Context()); err != nil {
					t.Fatal(err)
				}
				c, err = loadOnchain(t.Context(), s.db, node)
				if err != nil || c.TicketFaceValue != "3000" || c.Generation != 3 || c.CredentialRevision != 3 {
					t.Fatal("next pass did not pick up the changed template", c, err)
				}
			}
		})
	}
}

func TestOnchainReconcileRejectsChangedIdentity(t *testing.T) {
	s, _, m := onchainMachine(t)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	before := count(t, s, `SELECT revision FROM lpcc.machine_states WHERE node_id=$1`, m["node_id"])
	for _, set := range []string{"recipient='" + orchB + "'", "chain_id=1", "controller='" + orchB + "'"} {
		t.Run(set, func(t *testing.T) {
			execSQL(t, s.db, `UPDATE lpcc.onchain_state SET `+set)
			if err := s.reconcileOnchain(t.Context()); err == nil {
				t.Fatal("unchanged template hid an immutable identity change")
			}
			if count(t, s, `SELECT count(*) FROM lpcc.onchain_configs`) != 1 || count(t, s, `SELECT revision FROM lpcc.machine_states WHERE node_id=$1`, m["node_id"]) != before {
				t.Fatal("identity rejection changed configuration or revision")
			}
			execSQL(t, s.db, `UPDATE lpcc.onchain_state SET recipient=$1,chain_id=42161,controller=$2`, orchA, mainnetController)
		})
	}
}

func TestOnchainReconcileEmptyInventoryAllowsRetiredCleanup(t *testing.T) {
	s, _, m := onchainMachine(t)
	execSQL(t, s.db, `DELETE FROM lpcc.machines WHERE node_id=$1`, m["node_id"])
	if err := os.WriteFile(s.params.OnchainConfigFile, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.enrollments WHERE node_id=$1 AND terminal_bundle IS NOT NULL`, m["node_id"]) != 1 {
		t.Fatal("invalid template prevented retired cleanup publication")
	}
}

func TestControlCenterModeCannotChange(t *testing.T) {
	s := newTestServer(t)
	if err := s.ConfigureMode(t.Context()); err != nil {
		t.Fatal(err)
	}
	onchainSettings(t, s)
	if err := s.ConfigureMode(t.Context()); err == nil {
		t.Fatal("deployment mode changed")
	}
}

func TestOnchainTemplateRejectsMachineFieldsAndUnknownSettings(t *testing.T) {
	s := &Server{params: testParams()}
	onchainSettings(t, s)
	raw, err := os.ReadFile(s.params.OnchainConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(s.params.OnchainConfigFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.loadOnchainTemplate(); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"recipient":"0x1111111111111111111111111111111111111111",`, `"generation":1,`, `"unrecognized":true,`} {
		bad := append([]byte("{"+field), raw[1:]...)
		if err = os.WriteFile(s.params.OnchainConfigFile, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = s.loadOnchainTemplate(); err == nil {
			t.Fatal("accepted machine or unknown field", field)
		}
	}
}

func onchainTemplateJSON(t *testing.T, c onchain.Config) []byte {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "generation")
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestOnchainCredentialsWebhookAndRevocation(t *testing.T) {
	s, c, machine := onchainMachine(t)
	node := machine["node_id"]
	fingerprint := installationFingerprint(t, s, node)
	cfg, err := loadOnchain(t.Context(), s.db, node)
	if err != nil {
		t.Fatal(err)
	}
	var e error
	launch := consumer.Launch{PodName: "orchestrator-test", PodUID: "uid-test", LaunchID: strings.Repeat("a", 32), ProcessID: strings.Repeat("b", 64)}
	in := signedOnchainRequest(t, s, node, launch)
	path := "/v1/nodes/" + node + "/onchain/credentials"
	requireStatus(t, request(t, s, "POST", path, "session-a", in), 401)
	w := request(t, s, "POST", path, machine["token"], in)
	requireStatus(t, w, 200)
	var g consumer.Grant
	if json.Unmarshal(w.Body.Bytes(), &g) != nil || g.RPCURL == "" || g.Headers == "" {
		t.Fatal(w.Body.String())
	}
	retry := request(t, s, "POST", path, machine["token"], in)
	requireStatus(t, retry, 200)
	if retry.Body.String() != w.Body.String() {
		t.Fatal("credential retry changed")
	}
	// Even a newline change must not reuse an existing content address.
	rpcPath := filepath.Join(s.params.OnchainSecretsDir, c.RPCSecret)
	if e = os.WriteFile(rpcPath, []byte(g.RPCURL+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	requireStatus(t, request(t, s, "POST", path, machine["token"], in), 503)
	if e = os.WriteFile(rpcPath, []byte(g.RPCURL), 0600); e != nil {
		t.Fatal(e)
	}
	webhook := func(recipient string, headers map[string][]string, secret string) int {
		w := request(t, s, "POST", "/internal/redemption/authorize", secret, map[string]any{"headers": headers, "ticket": map[string]string{"recipient": recipient}})
		if w.Code != 200 {
			return w.Code
		}
		var d struct {
			Status int `json:"status"`
		}
		json.Unmarshal(w.Body.Bytes(), &d)
		return d.Status
	}
	h := map[string][]string{"Authorization": {strings.TrimPrefix(g.Headers, "Authorization: ")}}
	if webhook(c.Recipient, h, s.params.OnchainWebhookSecret) != 200 {
		t.Fatal("valid submission denied")
	}
	if webhook("0x"+strings.Repeat("3", 40), h, s.params.OnchainWebhookSecret) != 403 {
		t.Fatal("cross recipient allowed")
	}
	if webhook(c.Recipient, h, "wrong-service-secret") != 401 {
		t.Fatal("service authentication bypass")
	}
	h["authorization"] = h["Authorization"]
	if webhook(c.Recipient, h, s.params.OnchainWebhookSecret) != 403 {
		t.Fatal("duplicate authorization allowed")
	}
	delete(h, "authorization")
	// Management refresh does not silently revoke the loaded submission bearer.
	if _, e = s.db.Exec(`UPDATE lpcc.machines SET credential_version=credential_version+1 WHERE node_id=$1`, node); e != nil {
		t.Fatal(e)
	}
	if webhook(c.Recipient, h, s.params.OnchainWebhookSecret) != 200 {
		t.Fatal("refresh revoked retained grant")
	}
	if _, e = s.db.Exec(`UPDATE lpcc.onchain_state SET initialized=true WHERE fingerprint=$1`, fingerprint); e != nil {
		t.Fatal(e)
	}
	if e = s.RetireMachine(t.Context(), node); e != nil {
		t.Fatal(e)
	}
	var initiator string
	if e = s.db.QueryRow(`SELECT enrolled_by_user_id FROM lpcc.enrollments WHERE node_id=$1`, node).Scan(&initiator); e != nil || initiator != ownerA {
		t.Fatal("retained enrollment lost its initiator", initiator, e)
	}
	if webhook(c.Recipient, h, s.params.OnchainWebhookSecret) != 403 {
		t.Fatal("forced retirement did not revoke")
	}
	fresh := enroll(t, s, ownerA, fingerprint)
	if fresh["node_id"] == machine["node_id"] {
		t.Fatal("enrollment not replaced")
	}
	inherited, err := loadOnchain(t.Context(), s.db, fresh["node_id"])
	inheritedJSON, _ := json.Marshal(inherited)
	configJSON, _ := json.Marshal(cfg)
	if err != nil || string(inheritedJSON) != string(configJSON) {
		t.Fatal("re-enrollment lost onchain configuration", inherited, err)
	}
	var initialized bool
	if err = s.db.QueryRow(`SELECT initialized FROM lpcc.onchain_state WHERE fingerprint=$1`, fingerprint).Scan(&initialized); err != nil || !initialized {
		t.Fatal("re-enrollment lost storage identity", err)
	}

}

func reportOnchainReady(t *testing.T, s *Server, c map[string]string) {
	t.Helper()
	node := c["node_id"]
	m := onchainMetadata(t, s, node)
	launch := consumer.Launch{PodName: "orchestrator-test", PodUID: "node-pod", LaunchID: strings.Repeat("a", 32), ProcessID: strings.Repeat("b", 64)}
	grant := onchainGrant(t, s, c, launch)
	r := currentReport(t, s, node, machineconfig.Report{NodeID: node, CredentialVersion: 1, Component: "runtime", Generation: m.Generation, ConfigDigest: m.ConfigDigest, K3sVersion: "v1.37.2+k3s1", Ready: true, Reason: "ready", Onchain: &onchain.Observation{Generation: m.Onchain.Generation, Mode: "onchain", PodUID: "node-pod", GrantID: grant.GrantID, Applied: true, Ready: true, Handoff: "unverified"}})
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+node+"/status", c["token"], r), 200)
}

func TestOnchainActivationAndNormalDrain(t *testing.T) {
	s, _, c := onchainMachine(t)
	node := c["node_id"]
	if onchainMetadata(t, s, node).OnchainActive {
		t.Fatal("saved setting treated as active onchain operation")
	}
	reportOnchainReady(t, s, c)
	if e := s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	if !onchainMetadata(t, s, node).OnchainActive {
		t.Fatal("fresh applied Node did not activate")
	}
	adminA(t, s)
	requireStatus(t, request(t, s, "DELETE", "/api/admin/machines/"+node, "session-a", map[string]any{}), 202)
	if e := s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	reportRuntime(t, s, c, "runner", true)
	if e := s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.machines`) != 0 {
		t.Fatal("ordinary removal did not complete")
	}

}

func TestSupersedingUnreadyOnchainForceNeedsNewDrain(t *testing.T) {
	s, _, c := onchainMachine(t)
	node := c["node_id"]
	reconcile := func() {
		t.Helper()
		if err := s.reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	reportOnchainReady(t, s, c)
	reconcile()
	if !onchainMetadata(t, s, node).OnchainActive {
		t.Fatal("original workload was not ready")
	}
	adminA(t, s)
	setImage := func(image string) {
		s.params.RuntimeNodeImage = "registry.invalid/node@sha256:" + strings.Repeat(image, 64)
		s.configs = s.newConfigurationManager()
	}
	setImage("d")
	pending := pendingWorkloadDrain(t, s, node)
	requireStatus(t, request(t, s, "POST", "/api/admin/machines/"+node+"/drain/force", "session-a", map[string]int64{"generation": pending.Generation}), 202)
	reconcile()
	reconcile()
	forced := onchainMetadata(t, s, node)
	if forced.ConfigDigest != pending.PendingConfigDigest || !forced.DrainRequested {
		t.Fatal("expected forced replacement to be published with admission closed")
	}

	generation := forced.Generation
	for _, image := range []string{"c", "d", "c"} {
		setImage(image)
		reconcile()
		m := onchainMetadata(t, s, node)
		if m.ConfigDigest != forced.ConfigDigest || m.Generation <= generation || !m.DrainRequested {
			t.Fatal("image change bypassed the drain", image)
		}
		generation = m.Generation
	}

	reportRuntime(t, s, c, "runner", true)
	reconcile()
	drained := onchainMetadata(t, s, node)
	if drained.ConfigDigest == forced.ConfigDigest || drained.Generation != generation {
		t.Fatal("a fresh drain should release the superseding workload")
	}
	// The previously forced digest can now be published as a normal startup repair.
	for _, image := range []string{"d", "e"} {
		setImage(image)
		reconcile()
		m, manifest := publishedMachineConfiguration(t, s, node)
		if !strings.Contains(manifest, s.params.RuntimeNodeImage) || m.Generation != generation || !m.DrainRequested {
			t.Fatal("a past force blocked startup repair after the fresh drain", image)
		}
	}
}

func TestOnchainStartupRepairSupersedesDrain(t *testing.T) {
	s, _, c := onchainMachine(t)
	node := c["node_id"]
	settings, err := s.loadOnchainTemplate()
	if err != nil {
		t.Fatal(err)
	}
	redeemer := settings.RedeemerURL
	settings.RedeemerURL = "https://api.example/other"
	writeOnchainTemplate(t, s, settings)
	pendingWorkloadDrain(t, s, node)
	settings.RedeemerURL = redeemer
	writeOnchainTemplate(t, s, settings)
	s.params.RuntimeNodeImage = "registry.invalid/node@sha256:" + strings.Repeat("d", 64)
	s.configs = s.newConfigurationManager()
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	meta, manifest := publishedMachineConfiguration(t, s, node)
	if !strings.Contains(manifest, s.params.RuntimeNodeImage) || meta.OnchainActive {
		t.Fatal("a never-ready workload should allow repair while keeping admission closed")
	}
}

func TestObservedGrantCannotRevokeANewerProcessGrant(t *testing.T) {
	s, _, c := onchainMachine(t)
	node := c["node_id"]
	m := onchainMetadata(t, s, node)
	issue := func(nonce string) consumer.Grant {
		return onchainGrant(t, s, c, consumer.Launch{PodName: "orchestrator-test", PodUID: "same-pod", LaunchID: strings.Repeat(nonce, 32), ProcessID: strings.Repeat(nonce, 64)})
	}
	old := issue("a")
	newer := issue("b")
	observe := func(p *onchain.Observation, digest string, at ...time.Time) *httptest.ResponseRecorder {
		t.Helper()
		r := currentReport(t, s, node, machineconfig.Report{NodeID: c["node_id"], CredentialVersion: 1, Generation: m.Generation, Component: "runtime", ConfigDigest: digest, Onchain: p})
		if len(at) > 0 {
			r.ObservedAt = at[0]
		}
		return request(t, s, "POST", "/v1/nodes/"+node+"/status", c["token"], r)
	}
	admission := func(g consumer.Grant) *onchain.Observation {
		return &onchain.Observation{Generation: m.Onchain.Generation, Mode: "onchain", PodUID: "same-pod", GrantID: g.GrantID, Applied: true, Ready: true, Handoff: "unverified"}
	}
	requireStatus(t, observe(admission(newer), m.ConfigDigest, time.Now().Add(time.Hour)), 200)
	if count(t, s, `SELECT count(*) FROM lpcc.onchain_grants WHERE revoked_at IS NOT NULL OR ready_at IS NOT NULL`) != 0 {
		t.Fatal("uncertain clock changed submission authority or initialized storage")
	}

	requireStatus(t, observe(admission(old), m.ConfigDigest), 200)
	var revoked bool
	if e := s.db.QueryRow(`SELECT revoked_at IS NOT NULL FROM lpcc.onchain_grants WHERE grant_id=$1`, newer.GrantID).Scan(&revoked); e != nil || revoked {
		t.Fatal("old observation revoked an applying grant", e)
	}
	requireStatus(t, observe(admission(newer), m.ConfigDigest), 200)
	requireStatus(t, observe(admission(old), m.ConfigDigest), 409)
	if e := s.db.QueryRow(`SELECT revoked_at IS NOT NULL FROM lpcc.onchain_grants WHERE grant_id=$1`, old.GrantID).Scan(&revoked); e != nil || !revoked {
		t.Fatal("replacement did not retire predecessor", e)
	}
	reset := currentReport(t, s, node, machineconfig.Report{NodeID: c["node_id"], CredentialVersion: 1, Generation: m.Generation, Component: "runtime", ConfigDigest: m.ConfigDigest, Onchain: admission(old)})
	reset.Sequence = 1
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+node+"/status", c["token"], reset), 412)
	third := issue("c")
	if !third.RequireState {
		t.Fatal("initialized onchain database can be silently recreated")
	}
	off := onchain.Offchain()
	off.Generation = m.Onchain.Generation + 1
	desired := machineconfig.Desired{Machine: machineconfig.Machine{NodeID: node, CredentialVersion: 1, InstallDir: "/srv/livepeer", K3sVersion: "v1.37.2+k3s1"}, Onchain: off, RuntimeImage: s.params.RuntimeImage, NodeImage: s.params.RuntimeNodeImage}
	b, digest, e := machineconfig.Build(desired)
	if e != nil {
		t.Fatal(e)
	}
	files, _ := artifact.Read(b)
	var replacement contract.Metadata
	json.Unmarshal(files["runtime.json"], &replacement)
	o := &onchain.Observation{Generation: off.Generation, Mode: "offchain", PodUID: "offchain-pod", Applied: true, Handoff: "unverified"}
	requireStatus(t, observe(o, m.ConfigDigest), 409)
	if e = s.db.QueryRow(`SELECT revoked_at IS NOT NULL FROM lpcc.onchain_grants WHERE grant_id=$1`, third.GrantID).Scan(&revoked); e != nil || revoked {
		t.Fatal("offchain observation revoked a still-held onchain grant", e)
	}
	if _, e = s.db.Exec(`UPDATE lpcc.machine_configs SET bundle=$2,sha256=$3 WHERE node_id=$1`, node, b, digest); e != nil {
		t.Fatal(e)
	}
	requireStatus(t, observe(o, replacement.ConfigDigest), 200)
	if count(t, s, `SELECT count(*) FROM lpcc.onchain_grants WHERE revoked_at IS NULL`) != 0 {
		t.Fatal("applied offchain replacement retained submission grants")
	}
}

func TestConcurrentReportsNormalizeClocksBeforeRetiringGrants(t *testing.T) {
	s, _, c := onchainMachine(t)
	m := onchainMetadata(t, s, c["node_id"])
	issue := func(n string) consumer.Grant {
		return onchainGrant(t, s, c, consumer.Launch{PodName: "node", PodUID: "pod", LaunchID: strings.Repeat(n, 32), ProcessID: strings.Repeat(n, 64)})
	}
	lower, higher := issue("a"), issue("b")
	gate, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	var id string
	if err = gate.QueryRow(`SELECT grant_id::text FROM lpcc.onchain_grants WHERE grant_id=$1 FOR UPDATE`, lower.GrantID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	post := func(sequence uint64, g consumer.Grant, at time.Time) int {
		r := machineconfig.Report{ReportVersion: 1, Sequence: sequence, ObservedAt: at, NodeID: c["node_id"], CredentialVersion: 1, Generation: m.Generation, Component: "runtime", ConfigDigest: m.ConfigDigest, Onchain: &onchain.Observation{Generation: m.Onchain.Generation, Mode: "onchain", PodUID: "pod", GrantID: g.GrantID, Applied: true, Ready: true, Handoff: "unverified"}}
		return request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/status", c["token"], r).Code
	}
	done := make(chan int, 2)
	go func() { done <- post(2, lower, start.Add(2*time.Second)) }()
	waitForStateLock(t, s, "%", 1)
	go func() { done <- post(3, higher, start.Add(time.Second)) }()
	waitForStateLock(t, s, "%", 2)
	if err = gate.Commit(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if code := <-done; code != 200 {
			t.Fatal("concurrent report refused", code)
		}
	}
	var uncertain bool
	if err = s.db.QueryRow(`SELECT (report->>'clock_uncertain')::boolean FROM lpcc.machine_reports WHERE node_id=$1 AND component='runtime'`, c["node_id"]).Scan(&uncertain); err != nil {
		t.Fatal(err)
	}
	if !uncertain || count(t, s, `SELECT count(*) FROM lpcc.onchain_grants WHERE ready_at IS NOT NULL`) != 1 || count(t, s, `SELECT count(*) FROM lpcc.onchain_grants WHERE revoked_at IS NOT NULL`) != 0 {
		t.Fatal("backward concurrent report changed submission authority")
	}
}

func rpcSecret(t *testing.T, s *Server, value string) string {
	t.Helper()
	hash := sha256.Sum256([]byte(value))
	ref := hex.EncodeToString(hash[:])
	if err := os.WriteFile(filepath.Join(s.params.OnchainSecretsDir, ref), []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return ref
}

func onchainMachine(t *testing.T) (*Server, onchain.Config, map[string]string) {
	t.Helper()
	s := newTestServer(t)
	c := onchainSettings(t, s)
	return s, c, enroll(t, s, ownerA, strings.Repeat("a", 64))
}
func onchainMetadata(t *testing.T, s *Server, node string) contract.Metadata {
	t.Helper()
	m, _ := publishedMachineConfiguration(t, s, node)
	return m
}
func onchainGrant(t *testing.T, s *Server, c map[string]string, launch consumer.Launch) consumer.Grant {
	t.Helper()
	w := request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/onchain/credentials", c["token"], signedOnchainRequest(t, s, c["node_id"], launch))
	requireStatus(t, w, 200)
	var g consumer.Grant
	if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func signedOnchainRequest(t *testing.T, s *Server, node string, launch consumer.Launch) consumer.Request {
	t.Helper()
	m := onchainMetadata(t, s, node)
	var owner string
	if e := s.db.QueryRow(`SELECT actor_user_id::text FROM lpcc.enrollment_audit WHERE action='machine.enroll' AND target=$1`, node).Scan(&owner); e != nil {
		t.Fatal(e)
	}
	seed := sha256.Sum256([]byte(owner + installationFingerprint(t, s, node)))
	in := consumer.Request{Launch: launch, OnchainGeneration: m.Onchain.Generation, ConfigDigest: m.ConfigDigest}
	in.Sign(ed25519.NewKeyFromSeed(seed[:]), node, m.CredentialVersion, s.params.PublicAPIURL+"/v1/nodes/"+node+"/onchain/credentials", s.currentTime())
	return in
}

func installationFingerprint(t *testing.T, s *Server, node string) string {
	t.Helper()
	if fingerprintPattern.MatchString(node) {
		return node
	}
	var fingerprint string
	if err := s.db.QueryRow(`SELECT fingerprint FROM lpcc.enrollments WHERE node_id=$1`, node).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	return fingerprint
}
