package controlplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/connector"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/onchain"
	"github.com/livepeer/control-center/runtime/orchestrator"
)

func onchainSettings(t *testing.T, s *Server) onchain.Config {
	t.Helper()
	dir := t.TempDir()
	s.params.OnchainSecretsDir = dir
	s.params.OnchainWebhookSecret = strings.Repeat("w", 32)
	if e := os.WriteFile(filepath.Join(dir, "rpc-v1"), []byte("https://rpc.example/private-token"), 0600); e != nil {
		t.Fatal(e)
	}
	return onchain.Config{Version: 1, CredentialRevision: 1, Mode: "onchain", Network: "custom", ChainID: 123, Controller: "0x" + strings.Repeat("1", 40), Recipient: "0x" + strings.Repeat("2", 40), RPCSecret: "rpc-v1", RedeemerURL: "https://api.example/redemption", WeiPerUSD: "1000000000000000", TicketFaceValue: "1000", TicketWinProb: "100", MaxPendingTickets: 100, MaxTicketsPerRecipient: 10}
}
func TestOnchainApplyAtomicBindingAndSecretVersions(t *testing.T) {
	s := newTestServer(t)
	c := onchainSettings(t, s)
	node := strings.Repeat("a", 64)
	in := onchainInput{Version: 1, Machines: map[string]onchain.Config{installationFingerprint(t, s, node): c}}
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
	if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{installationFingerprint(t, s, node): stale}}, 0); e == nil {
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
		if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{installationFingerprint(t, s, node): next}}, 1); e == nil {
			t.Fatal("invalid change accepted")
		}
	}
	if e := os.WriteFile(filepath.Join(s.params.OnchainSecretsDir, "rpc-v1"), []byte("https://rpc.example/changed-secret"), 0600); e != nil {
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
	s := newTestServer(t)
	c := onchainSettings(t, s)
	machine := enroll(t, s, ownerA, strings.Repeat("a", 64))
	node := machine["node_id"]
	if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{installationFingerprint(t, s, node): c}}, 0); e != nil {
		t.Fatal(e)
	}
	cfg, e := loadOnchain(t.Context(), s.db, node)
	if e != nil {
		t.Fatal(e)
	}
	// Install an applying bundle; this test exercises the real API boundary, not
	// Kubernetes attestation (covered by the Runtime consumer tests).
	desired := machineconfig.Desired{Machine: machineconfig.Machine{NodeID: node, CredentialVersion: 1, InstallDir: "/srv/livepeer", K3sVersion: "v1.37.2+k3s1"}, Onchain: cfg, RuntimeImage: s.params.RuntimeImage, NodeImage: s.params.RuntimeNodeImage}
	b, digest, e := machineconfig.Build(desired)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec(`UPDATE lpcc.machine_configs SET bundle=$2,sha256=$3 WHERE node_id=$1`, node, b, digest); e != nil {
		t.Fatal(e)
	}
	files, _ := artifact.Read(b)
	var meta contract.Metadata
	json.Unmarshal(files["runtime.json"], &meta)
	launch := connector.Launch{PodName: "orchestrator-test", PodUID: "uid-test", LaunchID: strings.Repeat("a", 32), ProcessID: strings.Repeat("b", 64)}
	in := orchestrator.Request{Launch: launch, OnchainGeneration: cfg.Generation, ConfigDigest: meta.ConfigDigest}
	path := "/v1/nodes/" + node + "/onchain/credentials"
	requireStatus(t, request(t, s, "POST", path, "session-a", in), 401)
	w := request(t, s, "POST", path, machine["token"], in)
	requireStatus(t, w, 200)
	var g orchestrator.Grant
	if json.Unmarshal(w.Body.Bytes(), &g) != nil || g.RPCURL == "" || g.Headers == "" {
		t.Fatal(w.Body.String())
	}
	retry := request(t, s, "POST", path, machine["token"], in)
	requireStatus(t, retry, 200)
	if retry.Body.String() != w.Body.String() {
		t.Fatal("credential retry changed")
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
	if e = s.RetireMachine(t.Context(), node); e != nil {
		t.Fatal(e)
	}
	if webhook(c.Recipient, h, s.params.OnchainWebhookSecret) != 403 {
		t.Fatal("forced retirement did not revoke")
	}
	fresh := enroll(t, s, ownerA, strings.Repeat("a", 64))
	if fresh["node_id"] == machine["node_id"] {
		t.Fatal("enrollment not replaced")
	}
	c.Recipient = "0x" + strings.Repeat("3", 40)
	if _, e = s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{installationFingerprint(t, s, node): c}}, 1); e == nil {
		t.Fatal("re-enrollment reset pinned recipient")
	}
}

func TestOnchainActivationAndNormalDrain(t *testing.T) {
	s := newTestServer(t)
	cfg := onchainSettings(t, s)
	node := strings.Repeat("a", 64)
	if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{installationFingerprint(t, s, node): cfg}}, 0); e != nil {
		t.Fatal(e)
	}
	c := enroll(t, s, ownerA, strings.Repeat("a", 64))
	node = c["node_id"]
	node = c["node_id"]
	if e := s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	metadata := func() contract.Metadata {
		t.Helper()
		var b []byte
		if e := s.db.QueryRow(`SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, node).Scan(&b); e != nil {
			t.Fatal(e)
		}
		f, e := artifact.Read(b)
		if e != nil {
			t.Fatal(e)
		}
		var m contract.Metadata
		if json.Unmarshal(f["runtime.json"], &m) != nil {
			t.Fatal("metadata")
		}
		return m
	}
	if metadata().OnchainActive {
		t.Fatal("saved setting treated as active onchain operation")
	}
	m0 := metadata()
	launch := orchestrator.Launch{PodName: "orchestrator-test", PodUID: "node-pod", LaunchID: strings.Repeat("a", 32), ProcessID: strings.Repeat("b", 64)}
	w := request(t, s, "POST", "/v1/nodes/"+node+"/onchain/credentials", c["token"], orchestrator.Request{Launch: launch, OnchainGeneration: m0.Onchain.Generation, ConfigDigest: m0.ConfigDigest})
	requireStatus(t, w, 200)
	var grant orchestrator.Grant
	json.Unmarshal(w.Body.Bytes(), &grant)
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
	s := newTestServer(t)
	cfg := onchainSettings(t, s)
	node := strings.Repeat("a", 64)
	if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{installationFingerprint(t, s, node): cfg}}, 0); e != nil {
		t.Fatal(e)
	}
	c := enroll(t, s, ownerA, strings.Repeat("a", 64))
	node = c["node_id"]
	node = c["node_id"]
	var b []byte
	if e := s.db.QueryRow(`SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, node).Scan(&b); e != nil {
		t.Fatal(e)
	}
	files, _ := artifact.Read(b)
	var m contract.Metadata
	json.Unmarshal(files["runtime.json"], &m)
	issue := func(nonce string) orchestrator.Grant {
		t.Helper()
		l := orchestrator.Launch{PodName: "orchestrator-test", PodUID: "same-pod", LaunchID: strings.Repeat(nonce, 32), ProcessID: strings.Repeat(nonce, 64)}
		w := request(t, s, "POST", "/v1/nodes/"+node+"/onchain/credentials", c["token"], orchestrator.Request{Launch: l, OnchainGeneration: m.Onchain.Generation, ConfigDigest: m.ConfigDigest})
		requireStatus(t, w, 200)
		var g orchestrator.Grant
		if e := json.Unmarshal(w.Body.Bytes(), &g); e != nil {
			t.Fatal(e)
		}
		return g
	}
	old := issue("a")
	newer := issue("b")
	machine, e := s.authenticateMachine(t.Context(), node, c["token"], false)
	if e != nil {
		t.Fatal(e)
	}
	observe := func(g orchestrator.Grant) {
		t.Helper()
		if e := s.observeOnchainGrant(t.Context(), machine, &onchain.Observation{Generation: m.Onchain.Generation, Mode: "onchain", PodUID: "same-pod", GrantID: g.GrantID, Applied: true, Ready: true}, m.ConfigDigest); e != nil {
			t.Fatal(e)
		}
	}
	observe(old)
	var revoked bool
	if e := s.db.QueryRow(`SELECT revoked_at IS NOT NULL FROM lpcc.onchain_grants WHERE grant_id=$1`, newer.GrantID).Scan(&revoked); e != nil || revoked {
		t.Fatal("old observation revoked an applying grant", e)
	}
	observe(newer)
	observe(old)
	if e := s.db.QueryRow(`SELECT revoked_at IS NOT NULL FROM lpcc.onchain_grants WHERE grant_id=$1`, old.GrantID).Scan(&revoked); e != nil || !revoked {
		t.Fatal("replacement did not retire predecessor", e)
	}
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
	files, _ = artifact.Read(b)
	var replacement contract.Metadata
	json.Unmarshal(files["runtime.json"], &replacement)
	o := &onchain.Observation{Generation: off.Generation, Mode: "offchain", PodUID: "offchain-pod", Applied: true}
	if e = s.observeOnchainGrant(t.Context(), machine, o, m.ConfigDigest); e != nil {
		t.Fatal(e)
	}
	if e = s.db.QueryRow(`SELECT revoked_at IS NOT NULL FROM lpcc.onchain_grants WHERE grant_id=$1`, third.GrantID).Scan(&revoked); e != nil || revoked {
		t.Fatal("offchain observation revoked a still-held onchain grant", e)
	}
	if _, e = s.db.Exec(`UPDATE lpcc.machine_configs SET bundle=$2,sha256=$3 WHERE node_id=$1`, node, b, digest); e != nil {
		t.Fatal(e)
	}
	if e = s.observeOnchainGrant(t.Context(), machine, o, replacement.ConfigDigest); e != nil {
		t.Fatal(e)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.onchain_grants WHERE revoked_at IS NULL`) != 0 {
		t.Fatal("applied offchain replacement retained submission grants")
	}
}

func TestOnchainIsolationAndGenericCatalogCompatibility(t *testing.T) {
	s := newTestServer(t)
	cfg := onchainSettings(t, s)
	onchainNode := strings.Repeat("a", 64)
	if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{onchainNode: cfg}}, 0); e != nil {
		t.Fatal(e)
	}
	a := enroll(t, s, ownerA, strings.Repeat("a", 64))
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
	node := strings.Repeat("a", 64)
	errors := make(chan error, 2)
	for n := range 2 {
		copy := c
		copy.CredentialRevision = uint64(n + 1)
		go func() {
			_, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{installationFingerprint(t, s, node): copy}}, 0)
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

func TestUnapprovedOnchainStartupCanRepairItsImageButCannotDisable(t *testing.T) {
	s := newTestServer(t)
	cfg := onchainSettings(t, s)
	node := strings.Repeat("a", 64)
	if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{installationFingerprint(t, s, node): cfg}}, 0); e != nil {
		t.Fatal(e)
	}
	node = enroll(t, s, ownerA, strings.Repeat("a", 64))["node_id"]
	read := func() contract.Metadata {
		t.Helper()
		var b []byte
		if e := s.db.QueryRow(`SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, node).Scan(&b); e != nil {
			t.Fatal(e)
		}
		files, _ := artifact.Read(b)
		var m contract.Metadata
		if e := json.Unmarshal(files["runtime.json"], &m); e != nil {
			t.Fatal(e)
		}
		return m
	}
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
	if _, e := s.applyOnchain(t.Context(), onchainInput{Version: 1, Machines: map[string]onchain.Config{installationFingerprint(t, s, node): onchain.Offchain()}}, 1); e != nil {
		t.Fatal(e)
	}
	if e := s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	if !read().Onchain.Onchain() {
		t.Fatal("failed onchain startup bypassed normal drain to offchain")
	}
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
