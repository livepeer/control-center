package controlplane

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	return onchain.Config{Version: 1, CredentialRevision: 1, Mode: "onchain", Network: "custom", ChainID: 123, Controller: "0x" + strings.Repeat("1", 40), Recipient: "0x" + strings.Repeat("2", 40), RPCSecret: ref, RedeemerURL: "https://api.example/redemption", WeiPerUSD: "1000000000000000", TicketFaceValue: "1000", TicketWinProb: "100", MaxPendingTickets: 100, MaxTicketsPerRecipient: 10}
}

func TestOnchainCredentialsRequireBoundRuntimeProofWithoutSecretsService(t *testing.T) {
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

func TestOnchainApplyAtomicBindingAndSecretVersions(t *testing.T) {
	s := newTestServer(t)
	c := onchainSettings(t, s)
	fingerprint := strings.Repeat("a", 64)
	in := onchainInput{Version: 1, Machines: map[string]onchain.Config{fingerprint: c}}
	if rev, e := s.applyOnchain(t.Context(), in, 0); e != nil || rev != 1 {
		t.Fatal(rev, e)
	}
	if rev, e := s.applyOnchain(t.Context(), in, 1); e != nil || rev != 1 {
		t.Fatal("retry", rev, e)
	}
	if rev, e := s.applyOnchain(t.Context(), in, 0); e != nil || rev != 1 {
		t.Fatal("lost response retry", rev, e)
	}
	stale := c
	stale.CredentialRevision++
	if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{fingerprint: stale}}, 0); e == nil {
		t.Fatal("stale edit accepted")
	}
	var n int
	if e := s.db.QueryRow(`SELECT count(*) FROM lpcc.admin_audit_events WHERE action='onchain.apply'`).Scan(&n); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	// Omission and immutable bindings fail without committing another audit event.
	other := onchain.Offchain()
	if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{strings.Repeat("b", 64): other}}, 1); e == nil {
		t.Fatal("omission disabled onchain machine")
	}
	for _, mutate := range []func(*onchain.Config){func(c *onchain.Config) { c.Recipient = "0x" + strings.Repeat("3", 40) }, func(c *onchain.Config) { c.ChainID++ }, func(c *onchain.Config) { c.TicketWinProb = "0" }} {
		next := c
		mutate(&next)
		if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{fingerprint: next}}, 1); e == nil {
			t.Fatal("invalid change accepted")
		}
	}
	if e := os.WriteFile(filepath.Join(s.params.OnchainSecretsDir, c.RPCSecret), []byte("https://rpc.example/changed-secret"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.applyOnchain(t.Context(), in, 1); e == nil {
		t.Fatal("overwritten secret version accepted")
	}
	if e := s.db.QueryRow(`SELECT count(*) FROM lpcc.admin_audit_events WHERE action='onchain.apply'`).Scan(&n); e != nil || n != 1 {
		t.Fatal("partial commit", n, e)
	}
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
	c.Recipient = "0x" + strings.Repeat("3", 40)
	if _, e = s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{fingerprint: c}}, 1); e == nil {
		t.Fatal("re-enrollment reset pinned recipient")
	}
}

func TestOnchainActivationAndNormalDrain(t *testing.T) {
	s, _, c := onchainMachine(t)
	node := c["node_id"]
	metadata := func() contract.Metadata { return onchainMetadata(t, s, node) }
	if metadata().OnchainActive {
		t.Fatal("saved setting treated as active onchain operation")
	}
	launch := consumer.Launch{PodName: "orchestrator-test", PodUID: "node-pod", LaunchID: strings.Repeat("a", 32), ProcessID: strings.Repeat("b", 64)}
	grant := onchainGrant(t, s, c, launch)
	report := func() {
		t.Helper()
		m := metadata()
		r := currentReport(t, s, node, machineconfig.Report{NodeID: c["node_id"], CredentialVersion: 1, Component: "runtime", Generation: m.Generation, ConfigDigest: m.ConfigDigest, K3sVersion: "v1.37.2+k3s1", Ready: true, Reason: "ready", Onchain: &onchain.Observation{Generation: m.Onchain.Generation, Mode: "onchain", PodUID: "node-pod", GrantID: grant.GrantID, Applied: true, Ready: true, Handoff: "unverified"}})
		requireStatus(t, request(t, s, "POST", "/v1/nodes/"+node+"/status", c["token"], r), 200)
	}
	report()
	if e := s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	if !metadata().OnchainActive {
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

func TestOnchainIsolationAndGenericCatalogCompatibility(t *testing.T) {
	s := newTestServer(t)
	cfg := onchainSettings(t, s)
	fingerprint := strings.Repeat("a", 64)
	if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{fingerprint: cfg}}, 0); e != nil {
		t.Fatal(e)
	}
	a := enroll(t, s, ownerA, fingerprint)
	b := enroll(t, s, ownerB, strings.Repeat("b", 64))
	adminA(t, s)
	freeSource := strings.Replace(registryFixture(t), `amount = "0.001"`, `amount = "0"`, 1)
	free, status := revisionResponse(t, s, freeSource, "", true)
	if status != 201 {
		t.Fatal("catalog applied machine policy", status)
	}
	requireStatus(t, putApp(t, s, a, free, 0, 1), 400)
	requireStatus(t, putApp(t, s, b, free, 0, 1), 202)
	w := request(t, s, "GET", "/v1/nodes/"+b["node_id"]+"/config", b["token"], nil)
	requireStatus(t, w, 200)
	files, e := artifact.Read(w.Body.Bytes())
	if e != nil {
		t.Fatal(e)
	}
	var meta contract.Metadata
	json.Unmarshal(files["runtime.json"], &meta)
	if meta.Onchain.Onchain() || strings.Contains(string(files["runtime.json"]), cfg.Recipient) {
		t.Fatal("cross-machine onchain delivery")
	}
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+a["node_id"]+"/onchain/credentials", b["token"], map[string]any{}), 401)
	// Browser administration has no onchain-settings mutation interface.
	requireStatus(t, request(t, s, "PUT", "/api/admin/machines/"+a["node_id"]+"/onchain", "session-a", cfg), 404)
}

func TestConcurrentOnchainApplyCannotCommitTwoDifferentTargets(t *testing.T) {
	s := newTestServer(t)
	c := onchainSettings(t, s)
	fingerprint := strings.Repeat("a", 64)
	errors := make(chan error, 2)
	for n := range 2 {
		copy := c
		copy.CredentialRevision = uint64(n + 1)
		go func() {
			_, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{fingerprint: copy}}, 0)
			errors <- e
		}()
	}
	successes := 0
	for range 2 {
		if <-errors == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("concurrent edits both committed", successes)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.onchain_configs`) != 1 || count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE action='onchain.apply'`) != 1 {
		t.Fatal("configuration and audit diverged")
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

func TestUnapprovedOnchainStartupCanRepairItsImageButCannotDisable(t *testing.T) {
	s, cfg, c := onchainMachine(t)
	node := c["node_id"]
	read := func() contract.Metadata { return onchainMetadata(t, s, node) }
	before := read()
	s.params.RuntimeNodeImage = "registry.invalid/node@sha256:" + strings.Repeat("f", 64)
	s.configs = s.newConfigurationManager()
	if e := s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	after := read()
	if after.ConfigDigest == before.ConfigDigest || !after.Onchain.Onchain() || after.OnchainActive || after.Onchain.Generation != before.Onchain.Generation {
		t.Fatal("unapproved onchain target could not repair its image under the same onchain binding", after)
	}
	// A syntactically valid but unusable RPC can prevent Node's listener from
	// starting. Repair its credentials without asking that failed process to drain.
	cfg.RPCSecret = rpcSecret(t, s, "https://rpc.example/corrected\n")
	if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{installationFingerprint(t, s, node): cfg}}, 1); e != nil {
		t.Fatal(e)
	}
	if e := s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	if fixed := read(); fixed.Onchain.RPCSecret != cfg.RPCSecret || fixed.OnchainActive {
		t.Fatal("RPC repair stalled or opened admission", fixed)
	}
	fixed := read()
	report := currentReport(t, s, node, machineconfig.Report{NodeID: c["node_id"], CredentialVersion: 1, Component: "runtime", Generation: fixed.Generation, ConfigDigest: fixed.ConfigDigest, K3sVersion: "v1.37.2+k3s1", Ready: true})
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+node+"/status", c["token"], report), 200)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.machine_states WHERE rollout->>'applying_config_digest'<>'' AND COALESCE(rollout->>'approved_config_digest','')<>$1`, fixed.ConfigDigest) != 1 || read().OnchainActive {
		t.Fatal("generic readiness approved an onchain repair without admission evidence")
	}
	for ref, want := range map[string]string{before.Onchain.RPCSecret: "https://rpc.example/private-token", cfg.RPCSecret: "https://rpc.example/corrected"} {
		if value, err := s.readOnchainRPC(ref); err != nil || string(value) != want {
			t.Fatal("rotated or retained RPC input unavailable", err)
		}
	}
	if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{installationFingerprint(t, s, node): onchain.Offchain()}}, 2); e != nil {
		t.Fatal(e)
	}
	if e := s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	if !read().Onchain.Onchain() {
		t.Fatal("failed onchain startup bypassed normal drain to offchain")
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
	if _, err := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{strings.Repeat("a", 64): c}}, 0); err != nil {
		t.Fatal(err)
	}
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
