package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
	"github.com/livepeer/control-center/runtime/contract"
)

type simulatedCloudflare struct {
	certificatePacks  map[string]tunnel.CertificatePack
	certificateStatus string
	mu                sync.Mutex
	resources         map[string]tunnel.CFResource
	configurations    map[string][]tunnel.IngressRule
	versions          map[string]int64
	tokens            map[string]string
	creates           map[string]int
	lostKind          string
	disconnected      int
	policies          map[string][]string
}

func newSimulatedCloudflare() *simulatedCloudflare {
	return &simulatedCloudflare{certificatePacks: map[string]tunnel.CertificatePack{}, resources: map[string]tunnel.CFResource{}, configurations: map[string][]tunnel.IngressRule{}, versions: map[string]int64{}, tokens: map[string]string{}, creates: map[string]int{}, policies: map[string][]string{}}
}
func (f *simulatedCloudflare) Find(_ context.Context, r tunnel.CFResource) ([]tunnel.CFResource, error) {
	return f.find(r, false)
}
func (f *simulatedCloudflare) FindOwned(_ context.Context, r tunnel.CFResource) ([]tunnel.CFResource, error) {
	return f.find(r, true)
}
func (f *simulatedCloudflare) find(r tunnel.CFResource, ownedOnly bool) ([]tunnel.CFResource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var found []tunnel.CFResource
	if r.ID != "" {
		v, ok := f.resources[r.ID]
		if ok && (v.Kind != r.Kind || v.Name != r.Name || v.Host != r.Host) {
			return nil, tunnel.ErrResourceConflict
		}
		if !r.Watch {
			if ok {
				r.Audience = v.Audience
				r.Target = v.Target
				r.Proxied = v.Proxied
				r.Pending = false
				return []tunnel.CFResource{r}, nil
			}
			return nil, nil
		}
	}
	for _, v := range f.resources {
		if !ownedOnly && r.ID == "" && (r.Kind == "app" || r.Kind == "dns") && v.Kind == r.Kind && v.Host == r.Host && v.Name != r.Name {
			return nil, tunnel.ErrResourceConflict
		}
		if v.Kind == r.Kind && v.Name == r.Name && v.Host == r.Host {
			copy := r
			copy.ID = v.ID
			copy.Audience = v.Audience
			copy.Target = v.Target
			copy.Proxied = v.Proxied
			copy.Pending = false
			found = append(found, copy)
		}
	}
	return found, nil
}
func (f *simulatedCloudflare) Create(_ context.Context, r tunnel.CFResource, target string) (tunnel.CFResource, *tunnel.AccessCredential, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r.ID = uuid.New().String()
	r.Pending = false
	f.creates[r.Kind]++
	if r.Kind == "app" {
		r.Audience = "aud-" + r.ID
	}
	if r.Kind == "dns" {
		r.Target = target + ".cfargotunnel.com"
		r.Proxied = true
	}
	f.resources[r.ID] = r
	if r.Kind == "tunnel" {
		f.tokens[r.ID] = "opaque-tunnel-token-" + r.ID
	}
	if r.Kind == f.lostKind {
		f.lostKind = ""
		return tunnel.CFResource{}, nil, time.Time{}, &tunnel.ProviderError{Status: 503, Ambiguous: true}
	}
	if r.Kind == "token" {
		return r, &tunnel.AccessCredential{ClientID: "client-" + r.ID, ClientSecret: "secret-" + r.ID}, time.Now().Add(24 * time.Hour), nil
	}
	return r, nil, time.Time{}, nil
}
func (f *simulatedCloudflare) Configure(_ context.Context, id string, rules []tunnel.IngressRule) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ingressHash(rules) != ingressHash(f.configurations[id]) {
		f.versions[id]++
		f.configurations[id] = rules
	}
	return f.versions[id], nil
}
func (f *simulatedCloudflare) Protect(_ context.Context, r tunnel.CFResource, ids []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policies[r.ID] = append([]string(nil), ids...)
	if len(ids) == 0 {
		return errors.New("empty service-auth policy")
	}
	return nil
}
func (f *simulatedCloudflare) ConnectorToken(_ context.Context, id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens[id], nil
}
func (f *simulatedCloudflare) RotateConnector(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[id] = "rotated-tunnel-token-" + uuid.New().String()
	return nil
}
func (f *simulatedCloudflare) Delete(_ context.Context, r tunnel.CFResource, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.resources, r.ID)
	return nil
}
func (f *simulatedCloudflare) Disconnect(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnected++
	return nil
}
func (f *simulatedCloudflare) Route(_ context.Context, r tunnel.CFResource, target string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r.Target = target + ".cfargotunnel.com"
	r.Proxied = true
	f.resources[r.ID] = r
	return nil
}

func tunnelTestServer(t *testing.T) (*Server, *simulatedCloudflare) {
	t.Helper()
	s := newTestServer(t)
	t.Cleanup(func() { testTunnelDependencies.Delete(s) })
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	s.params.TunnelParams = TunnelParams{CloudflareEnabled: true, CloudflareIngressApproved: true, CloudflareAccountID: strings.Repeat("a", 32), CloudflareZoneID: strings.Repeat("b", 32), CloudflareBaseDomain: "fleet.example.invalid", CloudflareTeamName: "test-team", CloudflareAPIToken: "backend-provisioning-only", CloudflareKeyring: `{"current":"one","keys":{"one":"` + key + `"}}`, CloudflareAccessLifetime: 24 * time.Hour, CloudflareRotateBefore: 6 * time.Hour, TunnelStatusTTL: 5 * time.Minute, TunnelDrainTimeout: time.Minute}
	s.params.TunnelNodeAddresses = []string{"198.51.100.10/32"}
	s.params.RuntimeImage = "registry.example.invalid/runtime@sha256:" + strings.Repeat("d", 64)
	s.params.RuntimeConnectorImage = "registry.example.invalid/connector@sha256:" + strings.Repeat("c", 64)
	if e := s.ConfigureTunnels(); e != nil {
		t.Fatal(e)
	}
	fake := newSimulatedCloudflare()
	testTunnelDeps(s).Provider = fake
	testTunnelDeps(s).VerifyEndpoints = func(_ context.Context, r tunnel.RoutingState, c tunnel.AccessCredential) error {
		if r.ServiceURL == tunnel.PrivateOrchestrator || c.ClientSecret == "" {
			t.Error("invalid simulated source")
		}
		return nil
	}
	configureTestTunnels(t, s)
	return s, fake
}

var testTunnelDependencies sync.Map

func testTunnelDeps(s *Server) *tunnel.Dependencies {
	d, _ := testTunnelDependencies.LoadOrStore(s, &tunnel.Dependencies{})
	return d.(*tunnel.Dependencies)
}

func configureTestTunnels(t *testing.T, s *Server) {
	t.Helper()
	s.configs = s.newConfigurationManager()
	s.tunnels = s.newTunnelManager(*testTunnelDeps(s))
	if err := s.tunnels.Configure(s.params.PublicAPIURL); err != nil {
		t.Fatal(err)
	}
}

func ingressHash(r []tunnel.IngressRule) string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func credentialRef(node string, version int64) string {
	return "access/" + node + "/" + strconv.FormatInt(version, 10)
}

func driveTunnels(t *testing.T, s *Server) {
	t.Helper()
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, e := s.db.Exec(`UPDATE lpcc.machine_states SET next_attempt_at=now()`); e != nil {
		t.Fatal(e)
	}
	if e := s.tunnels.Reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	if e := s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
}
func reportRuntime(t *testing.T, s *Server, c map[string]string, component string, ready bool) {
	t.Helper()
	m, e := s.authenticateMachine(t.Context(), c["node_id"], c["token"], false)
	if e != nil {
		t.Fatal(e)
	}
	state, _, e := s.loadTunnel(t.Context(), m.NodeID)
	gen := int64(1)
	if e == nil {
		gen = state.Generation
	}
	r := tunnel.MachineReport{NodeID: m.NodeID, CredentialVersion: m.CredentialVersion, Component: component, Generation: gen, K3sVersion: m.K3sVersion, ConfigDigest: machineconfig.Digest(desiredConfiguration(s, m, &state)), HTTPS: true, Ready: ready, ProviderVersion: state.ProviderVersion, TokenGeneration: state.CredentialGeneration, Reason: "ready"}
	if component == "connector" {
		r.ConnectorObservedAt = time.Now().UTC()
		r.ConnectorExpiresAt = r.ConnectorObservedAt.Add(time.Minute)
	}
	if component == "runner" {
		r.BundleFormat = contract.BundleFormat
		r.Apps = &contract.AppStatus{Instances: []contract.InstanceStatus{}}
		rollout, err := (machineconfig.Store{DB: s.db}).Load(t.Context(), m.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		if ready && rollout.DrainRequested {
			now := time.Now().UTC()
			r.Drained = true
			r.Evidence = &contract.Evidence{Kind: "no_owner", Target: machineconfig.DrainTarget(m.NodeID, rollout.State), WithdrawalID: "withdrawal", ObservedAt: now, ExpiresAt: now.Add(30 * time.Second)}
		}
	}
	r = currentReport(t, s, m.NodeID, r)
	if w := request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/status", c["token"], r); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}
func readyTunnel(t *testing.T, s *Server, c map[string]string) tunnel.Snapshot {
	t.Helper()
	reportRuntime(t, s, c, "runtime", false)
	driveTunnels(t, s)
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	reportRuntime(t, s, c, "runtime", true)
	reportRuntime(t, s, c, "connector", true)
	driveTunnels(t, s)
	state, _, e := s.loadTunnel(t.Context(), c["node_id"])
	if e != nil || !state.Ready {
		m, _ := s.authenticateMachine(t.Context(), c["node_id"], c["token"], false)
		report, at, err := (machineconfig.Store{DB: s.db}).Report(t.Context(), configurationMachine(m), "runtime")
		t.Fatalf("not ready: reason=%s generation=%d runtime=%+v observed=%v err=%v desired=%s", state.Reason, state.Generation, report, at, err, machineconfig.Digest(desiredConfiguration(s, m, &state)))
	}
	return state
}

func TestTunnelDurabilityPartialFailureAndIsolation(t *testing.T) {
	s, f := tunnelTestServer(t)
	a := enroll(t, s, ownerA, strings.Repeat("a", 64))
	b := enroll(t, s, ownerB, strings.Repeat("b", 64))
	f.lostKind = "tunnel"
	reportRuntime(t, s, a, "runtime", false)
	driveTunnels(t, s)
	first, _, e := s.loadTunnel(t.Context(), a["node_id"])
	if e != nil || !first.Resources["tunnel"].Pending {
		t.Fatal("create intent not retained", e)
	}
	stateA := readyTunnel(t, s, a)
	stateB := readyTunnel(t, s, b)
	if stateA.TunnelID == stateB.TunnelID || f.creates["tunnel"] != 2 {
		t.Fatal("duplicate/shared tunnel")
	}
	oldID := stateA.TunnelID
	for i := 0; i < 3; i++ {
		driveTunnels(t, s)
	}
	current, _, _ := s.loadTunnel(t.Context(), a["node_id"])
	if current.TunnelID != oldID || f.creates["tunnel"] != 2 {
		t.Fatal("restart/retry replaced tunnel")
	}
	path := "/v1/nodes/" + a["node_id"] + "/tunnel/connector-token"
	if w := request(t, s, "POST", path, b["token"], map[string]any{}); w.Code != 401 {
		t.Fatal("cross-machine connector access", w.Code)
	}
	w := request(t, s, "POST", path, a["token"], map[string]any{})
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), "opaque-tunnel-token") {
		t.Fatal(w.Code, w.Body.String())
	}
	sources, e := s.tunnels.DiscoverySources(t.Context())
	if e != nil || len(sources) != 2 {
		t.Fatal(e, len(sources))
	}
	var pair [2]tunnel.AccessCredential
	for i, v := range sources {
		pair[i], e = s.tunnels.ResolveAccessCredential(t.Context(), v.CredentialRef)
		if e != nil {
			t.Fatal(e)
		}
	}
	if pair[0] == pair[1] {
		t.Fatal("shared Access credentials")
	}
	bundle := request(t, s, "GET", "/v1/nodes/"+a["node_id"]+"/config", a["token"], nil)
	files := archiveFiles(t, bundle.Body.Bytes())
	joined := ""
	for _, v := range files {
		joined += v
	}
	for _, secret := range []string{a["token"], s.params.CloudflareAPIToken, pair[0].ClientSecret, pair[1].ClientSecret} {
		if strings.Contains(joined, secret) {
			t.Fatal("secret in bundle")
		}
	}
	if !strings.Contains(files["system/node/orchestrator.yaml"], stateA.ServiceURL) || !strings.Contains(files["system/node/orchestrator.yaml"], "RunnerServiceURL = \""+tunnel.PrivateOrchestrator+"\"") {
		t.Fatal("incorrect Node routing")
	}
	if strings.Contains(files["system/connector/tunnel.yaml"], "mountPath: /credentials") || !strings.Contains(files["system/connector/tunnel.yaml"], "medium: Memory") {
		t.Fatal("connector credential isolation")
	}
}
func TestLostAccessSecretIsReplacedWithoutOrphan(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("c", 64))
	f.lostKind = "token"
	reportRuntime(t, s, c, "runtime", false)
	driveTunnels(t, s)
	state := readyTunnel(t, s, c)
	count := 0
	for _, r := range f.resources {
		if r.Kind == "token" {
			count++
		}
	}
	if count != 1 || f.creates["token"] != 2 || state.AccessVersion != 1 {
		t.Fatal("stranded Access token", count, f.creates)
	}
}
func TestNodeIdentityRetirementAndRefresh(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("d", 64))
	state := readyTunnel(t, s, c)
	jwt, _, _ := signEnrollment(s.params.JWTSigningSecret, ownerA, testOrchestrator(ownerA), time.Now())
	in := map[string]any{"management_proof": c["token"], "fingerprint": strings.Repeat("d", 64), "install_dir": "/opt/livepeer", "operation_id": uuid.New().String(), "expected_credential_version": 1}
	refreshPath := "/v1/nodes/" + c["node_id"] + "/credentials/refresh"
	w := request(t, s, "POST", refreshPath, jwt, in)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var fresh map[string]string
	json.Unmarshal(w.Body.Bytes(), &fresh)
	repeated := request(t, s, "POST", refreshPath, jwt, in)
	if repeated.Code != 200 || repeated.Body.String() != w.Body.String() {
		t.Fatal("refresh retry changed credential")
	}
	if fresh["node_id"] != c["node_id"] || fresh["token"] == c["token"] {
		t.Fatal("refresh changed node or reused credential")
	}
	if w = request(t, s, "GET", "/v1/nodes/"+c["node_id"]+"/config", c["token"], nil); w.Code != 401 {
		t.Fatal("old credential still works")
	}
	var version string
	s.db.QueryRow(`SELECT k3s_version FROM lpcc.machines WHERE node_id=$1`, c["node_id"]).Scan(&version)
	if version != "v1.37.2+k3s1" {
		t.Fatal("credential refresh changed K3s")
	}
	if e := s.RetireMachine(t.Context(), c["node_id"]); e != nil {
		t.Fatal(e)
	}
	driveTunnels(t, s)
	terminal := request(t, s, "GET", "/v1/nodes/"+c["node_id"]+"/config", fresh["token"], nil)
	if terminal.Code != 200 || terminal.Header().Get("X-Livepeer-Terminal") != "true" {
		t.Fatal(terminal.Code, terminal.Body.String())
	}
	terminalFiles := archiveFiles(t, terminal.Body.Bytes())
	if strings.Contains(terminalFiles["terminal-cleanup/system/node/orchestrator.yaml"], "kind: Deployment") || !strings.Contains(terminalFiles["terminal-cleanup/system/node/orchestrator.yaml"], "kind: PersistentVolumeClaim") || !strings.Contains(terminalFiles["terminal-cleanup/upgrade-plan/kustomization.yaml"], "resources: []") {
		t.Fatal("terminal cleanup storage/upgrade inventory")
	}
	newer := enroll(t, s, ownerA, strings.Repeat("d", 64))
	if newer["node_id"] == fresh["node_id"] || newer["token"] == fresh["token"] {
		t.Fatal("new enrollment reused identity")
	}
	old := request(t, s, "GET", "/v1/nodes/"+c["node_id"]+"/config", fresh["token"], nil)
	active := request(t, s, "GET", "/v1/nodes/"+newer["node_id"]+"/config", newer["token"], nil)
	if old.Header().Get("X-Livepeer-Terminal") != "true" || active.Header().Get("X-Livepeer-Terminal") != "false" {
		t.Fatal("node artifacts crossed")
	}
	if w = request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/tunnel/connector-token", fresh["token"], map[string]any{}); w.Code != 401 {
		t.Fatal("retired credential got new tunnel token")
	}
	if _, e := s.tunnels.ResolveAccessCredential(t.Context(), credentialRef(c["node_id"], state.AccessVersion)); e == nil {
		t.Fatal("retired source secret resolved")
	}
	digest := sha256.Sum256(terminal.Body.Bytes())
	ack := request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/removal-ack", fresh["token"], map[string]any{"node_id": c["node_id"], "digest": hex.EncodeToString(digest[:]), "connector_absent": true})
	if ack.Code != 200 {
		t.Fatal(ack.Code, ack.Body.String())
	}
}
func TestTunnelRotationNeedsConsumerAcknowledgement(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("e", 64))
	initial := readyTunnel(t, s, c)
	if _, e := s.db.Exec(`UPDATE lpcc.access_credentials SET expires_at=now()+interval '1 hour' WHERE node_id=$1`, c["node_id"]); e != nil {
		t.Fatal(e)
	}
	driveTunnels(t, s)
	next, _, _ := s.loadTunnel(t.Context(), c["node_id"])
	if next.AccessVersion != 2 || next.SourceGeneration != 2 || next.TunnelID != initial.TunnelID {
		t.Fatal("incorrect Access rotation", next)
	}
	var count int
	s.db.QueryRow(`SELECT count(*) FROM lpcc.access_credentials WHERE node_id=$1 AND revoked_at IS NULL`, c["node_id"]).Scan(&count)
	if count != 2 {
		t.Fatal("old token revoked before acknowledgement")
	}
	sources, _ := s.tunnels.DiscoverySources(t.Context())
	if e := s.tunnels.AcknowledgeDiscovery(t.Context(), sources[0]); e != nil {
		t.Fatal(e)
	}
	driveTunnels(t, s)
	s.db.QueryRow(`SELECT count(*) FROM lpcc.access_credentials WHERE node_id=$1 AND revoked_at IS NULL`, c["node_id"]).Scan(&count)
	if count != 1 {
		t.Fatal("old Access token not retired")
	}
	adminA(t, s)
	requireStatus(t, request(t, s, "POST", "/api/admin/machines/"+c["node_id"]+"/tunnel/rotate", "session-a", map[string]any{"kind": "connector"}), 202)
	driveTunnels(t, s)
	rotated, _, _ := s.loadTunnel(t.Context(), c["node_id"])
	if rotated.TunnelID != initial.TunnelID || rotated.CredentialGeneration != 2 || f.creates["tunnel"] != 1 {
		t.Fatal("connector rotation replaced tunnel")
	}
}

func TestMemberDeletionPreservesTunnelsAndExplicitRetirementCleansUp(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("f", 64))
	readyTunnel(t, s, c)
	if _, e := s.db.Exec(`DELETE FROM auth.users WHERE id=$1`, ownerA); e != nil {
		t.Fatal(e)
	}
	if _, err := s.authenticateMachine(t.Context(), c["node_id"], c["token"], false); err != nil {
		t.Fatal("member deletion revoked shared machine", err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.machines WHERE node_id=$1`, c["node_id"]) != 1 {
		t.Fatal("member deletion retired machine")
	}
	if err := s.RetireMachine(t.Context(), c["node_id"]); err != nil {
		t.Fatal(err)
	}
	driveTunnels(t, s)
	var retired, complete bool
	e := s.db.QueryRow(`SELECT e.retired_at IS NOT NULL,(t.state->>'cleanup_complete')::boolean FROM lpcc.enrollments e JOIN lpcc.machine_states t USING(node_id) WHERE e.node_id=$1`, c["node_id"]).Scan(&retired, &complete)
	if e != nil || !retired || !complete || len(f.resources) != 0 {
		t.Fatal("cascade lost cleanup", retired, complete, e, len(f.resources))
	}
}

func TestTunnelDrainRolloutAndObservationExpiry(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("7", 64))
	path := "/v1/nodes/" + c["node_id"] + "/config"
	old := archiveFiles(t, request(t, s, "GET", path, c["token"], nil).Body.Bytes())["system/node/orchestrator.yaml"]
	m, e := s.authenticateMachine(t.Context(), c["node_id"], c["token"], false)
	if e != nil {
		t.Fatal(e)
	}
	stateBefore := tunnel.RoutingFor(m.NodeID, s.params.CloudflareBaseDomain)
	stateBefore.IngressDigest = "configured-before-drain-intent"
	raw, _ := json.Marshal(stateBefore.RoutingState)
	rollout, _ := json.Marshal(stateBefore.State)
	execSQL(t, s.db, `INSERT INTO lpcc.machine_states(node_id,state,rollout) VALUES($1,$2,$3)`, m.NodeID, string(raw), string(rollout))
	if e = s.reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	if current := archiveFiles(t, request(t, s, "GET", path, c["token"], nil).Body.Bytes())["system/node/orchestrator.yaml"]; current != old {
		t.Fatal("publisher replaced workload ahead of drain worker")
	}
	reportRuntime(t, s, c, "runtime", false)
	driveTunnels(t, s)
	state, _, _ := s.loadTunnel(t.Context(), c["node_id"])
	if !state.DrainRequested || state.HeldOrchestrator != old {
		t.Fatal("Node replacement not drain gated")
	}
	held := archiveFiles(t, request(t, s, "GET", path, c["token"], nil).Body.Bytes())
	if held["system/node/orchestrator.yaml"] != old {
		t.Fatal("workload changed before drain")
	}
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	updated := archiveFiles(t, request(t, s, "GET", path, c["token"], nil).Body.Bytes())["system/node/orchestrator.yaml"]
	if updated == old || !strings.Contains(updated, state.ServiceURL) {
		t.Fatal("drained configuration not released")
	}
	reportRuntime(t, s, c, "runtime", true)
	reportRuntime(t, s, c, "connector", true)
	driveTunnels(t, s)
	stable := request(t, s, "GET", path, c["token"], nil).Body.Bytes()
	driveTunnels(t, s)
	if !bytes.Equal(stable, request(t, s, "GET", path, c["token"], nil).Body.Bytes()) {
		t.Fatal("unchanged desired state changed bundle")
	}
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=jsonb_set(state,'{verified_at}',to_jsonb($1::text))`, time.Now().Add(-time.Hour).Format(time.RFC3339Nano))
	sources, e := s.tunnels.DiscoverySources(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	if sources[0].Ready || sources[0].Reason != "observation_expired" {
		t.Fatal("stale readiness remained advertised", sources)
	}
}

func TestTunnelAdministrativeDrainAndRotation(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("8", 64))
	state := readyTunnel(t, s, c)
	path := "/api/admin/machines/" + c["node_id"]
	in := map[string]any{"kind": "connector", "compromised": true}
	requireStatus(t, request(t, s, "POST", path+"/tunnel/rotate", "session-a", in), 403)
	adminA(t, s)
	requireStatus(t, request(t, s, "POST", path+"/tunnel/rotate", "session-a", in), 202)
	driveTunnels(t, s)
	rotated, _, _ := s.loadTunnel(t.Context(), c["node_id"])
	if rotated.TunnelID != state.TunnelID || rotated.CredentialGeneration != 2 || f.disconnected != 1 {
		t.Fatal("compromise rotation failed", rotated, f.disconnected)
	}
	requireStatus(t, request(t, s, "DELETE", "/api/admin/machines/"+strings.Repeat("z", 26), "session-a", map[string]any{}), 404)
	requireStatus(t, request(t, s, "DELETE", path, "session-a", map[string]any{}), 202)
	driveTunnels(t, s)
	if count(t, s, `SELECT count(*) FROM lpcc.machines`) != 1 {
		t.Fatal("removal skipped drain")
	}
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	driveTunnels(t, s)
	if count(t, s, `SELECT count(*) FROM lpcc.machines`) != 0 || len(f.resources) != 0 {
		t.Fatal("drained removal not completed")
	}
	if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE action IN ('machine.remove','tunnel.rotate') AND outcome='success'`) != 2 {
		t.Fatal("missing administration audit")
	}
}

func TestEndpointReplacementRequiresCurrentSourceAcknowledgement(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("9", 64))
	initial := readyTunnel(t, s, c)
	sources, _ := s.tunnels.DiscoverySources(t.Context())
	if e := s.tunnels.AcknowledgeDiscovery(t.Context(), sources[0]); e != nil {
		t.Fatal(e)
	}
	s.params.CloudflareBaseDomain = "replacement.example.invalid"
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	reportRuntime(t, s, c, "runtime", true)
	reportRuntime(t, s, c, "connector", true)
	driveTunnels(t, s)
	current, _, _ := s.loadTunnel(t.Context(), c["node_id"])
	if current.TunnelID != initial.TunnelID || current.SourceGeneration != 2 || current.AccessVersion != initial.AccessVersion {
		t.Fatal("endpoint update changed identity", current)
	}
	apps := 0
	for _, r := range f.resources {
		if r.Kind == "app" {
			apps++
		}
	}
	if apps != 2 {
		t.Fatal("old source acknowledgement retired replacement protection", apps)
	}
	if e := s.tunnels.AcknowledgeDiscovery(t.Context(), sources[0]); e == nil {
		t.Fatal("accepted old endpoint acknowledgement")
	}
	sources, _ = s.tunnels.DiscoverySources(t.Context())
	if e := s.tunnels.AcknowledgeDiscovery(t.Context(), sources[0]); e != nil {
		t.Fatal(e)
	}
	driveTunnels(t, s)
	apps = 0
	for _, r := range f.resources {
		if r.Kind == "app" {
			apps++
		}
	}
	if apps != 1 {
		t.Fatal("predecessor protection not cleaned up", apps)
	}
}

func TestPrivateWorkloadUpdatePolicy(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint("managed-enable-", enabled), func(t *testing.T) {
			s := newTestServer(t)
			s.params.CloudflareEnabled = enabled
			s.configs = s.newConfigurationManager()
			c := enroll(t, s, ownerA, strings.Repeat("4", 64))
			m, e := s.authenticateMachine(t.Context(), c["node_id"], c["token"], false)
			if e != nil {
				t.Fatal(e)
			}
			desired := desiredConfiguration(s, m, nil)
			data, _, e := machineconfig.Build(desired)
			if e != nil {
				t.Fatal(e)
			}
			previous := strings.Replace(archiveFiles(t, data)["system/node/orchestrator.yaml"], `Network = "offchain"`, `Network = "previous"`, 1)
			desired.State.HeldOrchestrator = previous
			data, digest, e := machineconfig.Build(desired)
			if e != nil {
				t.Fatal(e)
			}
			execSQL(t, s.db, `UPDATE lpcc.machine_configs SET bundle=$2,sha256=$3 WHERE node_id=$1`, m.NodeID, data, digest)
			if e = s.reconcile(t.Context()); e != nil {
				t.Fatal(e)
			}
			w := request(t, s, "GET", "/v1/nodes/"+m.NodeID+"/config", c["token"], nil)
			requireStatus(t, w, 200)
			same := archiveFiles(t, w.Body.Bytes())["system/node/orchestrator.yaml"] == previous
			if !same {
				t.Fatal("workload replacement bypassed the drain")
			}
		})
	}
}

func TestAccessCredentialReencryption(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("5", 64))
	readyTunnel(t, s, c)
	ref := credentialRef(c["node_id"], 1)
	before, e := s.tunnels.ResolveAccessCredential(t.Context(), ref)
	if e != nil {
		t.Fatal(e)
	}
	oldKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
	s.params.CloudflareKeyring = `{"current":"two","keys":{"one":"` + oldKey + `","two":"` + newKey + `"}}`
	configureTestTunnels(t, s)
	if e = s.tunnels.ReencryptAccessCredentials(t.Context()); e != nil {
		t.Fatal(e)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.access_credentials WHERE key_id='two'`) != 1 {
		t.Fatal("ciphertext was not reencrypted")
	}
	s.params.CloudflareKeyring = `{"current":"two","keys":{"two":"` + newKey + `"}}`
	configureTestTunnels(t, s)
	after, e := s.tunnels.ResolveAccessCredential(t.Context(), ref)
	if e != nil || before != after {
		t.Fatal("key rotation changed credential", e)
	}
}
