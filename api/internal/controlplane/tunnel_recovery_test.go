package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
	protocol "github.com/livepeer/control-center/secrets"
)

func TestArtifactPublicationFencesAfterLockWait(t *testing.T) {
	for _, credentialChange := range []bool{false, true} {
		name := "routing"
		if credentialChange {
			name = "credential"
		}
		t.Run(name, func(t *testing.T) {
			s := newTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("3", 64))
			m, e := s.authenticateMachine(t.Context(), c["node_id"], c["token"], false)
			if e != nil {
				t.Fatal(e)
			}
			old := tunnel.RoutingFor(m.NodeID, "example.invalid")
			raw, _ := json.Marshal(old.RoutingState)
			rollout, _ := json.Marshal(old.State)
			execSQL(t, s.db, `INSERT INTO lpcc.machine_states(node_id,state,rollout) VALUES($1,$2,$3)`, m.NodeID, string(raw), string(rollout))
			if e = s.reconcile(t.Context()); e != nil {
				t.Fatal(e)
			}
			newer := old
			if credentialChange {
				m.CredentialVersion++
			} else {
				newer.Generation++
			}
			bundle, digest, e := machineconfig.Build(desiredConfiguration(s, m, &newer))
			if e != nil {
				t.Fatal(e)
			}
			tx, e := s.db.Begin()
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			if _, e = tx.Exec(`SELECT FROM lpcc.machine_configs WHERE node_id=$1 FOR UPDATE`, m.NodeID); e != nil {
				t.Fatal(e)
			}
			if credentialChange {
				if _, e = tx.Exec(`UPDATE lpcc.machines SET credential_version=$2 WHERE node_id=$1`, m.NodeID, m.CredentialVersion); e != nil {
					t.Fatal(e)
				}
				if _, e = tx.Exec(`UPDATE lpcc.enrollments SET credential_version=$2 WHERE node_id=$1`, m.NodeID, m.CredentialVersion); e != nil {
					t.Fatal(e)
				}
			} else {
				raw, _ = json.Marshal(newer.RoutingState)
				rollout, _ = json.Marshal(newer.State)
				if _, e = tx.Exec(`UPDATE lpcc.machine_states SET state=$2,rollout=$3,revision=revision+1 WHERE node_id=$1`, m.NodeID, string(raw), string(rollout)); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = tx.Exec(`UPDATE lpcc.machine_configs SET bundle=$2,sha256=$3 WHERE node_id=$1`, m.NodeID, bundle, digest); e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- s.reconcile(t.Context()) }()
			deadline := time.Now().Add(5 * time.Second)
			blocked := false
			for time.Now().Before(deadline) {
				if e = s.db.QueryRow(`SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock')`).Scan(&blocked); e != nil {
					t.Fatal(e)
				}
				if blocked {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !blocked {
				t.Fatal("publisher did not wait behind concurrent commit")
			}
			if e = tx.Commit(); e != nil {
				t.Fatal(e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			var data []byte
			if e = s.db.QueryRow(`SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, m.NodeID).Scan(&data); e != nil {
				t.Fatal(e)
			}
			var desired machineconfig.Runtime
			if e = json.Unmarshal([]byte(archiveFiles(t, data)["runtime.json"]), &desired); e != nil {
				t.Fatal(e)
			}
			if desired.Generation != newer.Generation || desired.CredentialVersion != m.CredentialVersion {
				t.Fatalf("stale publisher replaced newer committed artifact: generation=%d credential=%d", desired.Generation, desired.CredentialVersion)
			}
		})
	}
}

type rotationFailures struct {
	*simulatedCloudflare
	reject int
	lose   bool
	calls  int
}

func (f *rotationFailures) RotateConnector(ctx context.Context, id string) error {
	f.calls++
	if f.reject > 0 {
		f.reject--
		return &tunnel.ProviderError{Status: 429}
	}
	if e := f.simulatedCloudflare.RotateConnector(ctx, id); e != nil {
		return e
	}
	if f.lose {
		f.lose = false
		return &tunnel.ProviderError{Ambiguous: true}
	}
	return nil
}

func TestOfflineSecurityMaintenanceAndRotationRecovery(t *testing.T) {
	for _, lose := range []bool{false, true} {
		t.Run(fmt.Sprint("lost-response-", lose), func(t *testing.T) {
			s, base := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("7", 64))
			initial := readyTunnel(t, s, c)
			f := &rotationFailures{simulatedCloudflare: base, lose: lose}
			if !lose {
				f.reject = 1
			}
			testTunnelDeps(s).Provider = f
			configureTestTunnels(t, s)
			adminA(t, s)
			path := "/api/admin/machines/" + c["node_id"] + "/tunnel/rotate"
			for _, kind := range []string{"connector"} {
				requireStatus(t, request(t, s, "POST", path, "session-a", map[string]any{"kind": kind, "compromised": true}), 202)
			}
			execSQL(t, s.db, `UPDATE lpcc.machine_reports SET received_at=now()-interval '1 hour'`)
			driveTunnels(t, s)
			driveTunnels(t, s)
			current, _, e := s.loadTunnel(t.Context(), c["node_id"])
			if e != nil || current.CredentialGeneration != initial.CredentialGeneration+1 || current.Ready || current.RotationReason != "" || base.disconnected != 1 {
				t.Fatal(current, base.disconnected, e)
			}
			if f.calls != map[bool]int{false: 2, true: 1}[lose] {
				t.Fatal("rotation replayed after success", f.calls)
			}

			requireStatus(t, request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/tunnel/connector-token", c["token"], map[string]any{}), 409)
		})
	}
}

type endpointCreateFailure struct{ *simulatedCloudflare }

func (f *endpointCreateFailure) Configure(ctx context.Context, id string, rules []tunnel.IngressRule) (int64, error) {
	for _, rule := range rules {
		if strings.Contains(rule.Hostname, "replacement.example.invalid") {
			return 0, &tunnel.ProviderError{Status: 429}
		}
	}
	return f.simulatedCloudflare.Configure(ctx, id, rules)
}
func TestEndpointFailurePreservesConnectorAndRollbackReusesOwnership(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("4", 64))
	initial := readyTunnel(t, s, c)
	dnsID := initial.Resources["g1-dns-0"].ID
	s.params.CloudflareBaseDomain = "replacement.example.invalid"
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	reportRuntime(t, s, c, "runner", true)
	testTunnelDeps(s).Provider = &endpointCreateFailure{f}
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	driveTunnels(t, s)
	if _, exists := f.certificatePacks[initial.CertificatePackID]; !exists {
		t.Fatal("failed replacement deleted predecessor certificate coverage")
	}
	state, _, _ := s.loadTunnel(t.Context(), c["node_id"])
	bundle := request(t, s, "GET", "/v1/nodes/"+c["node_id"]+"/config", c["token"], nil)
	files := archiveFiles(t, bundle.Body.Bytes())
	if !strings.Contains(files["system/node/orchestrator.yaml"], initial.ProxyURLTemplate) || !strings.Contains(files["system/node/orchestrator.yaml"], initial.ServiceURL) {
		t.Fatal("failed replacement changed held Node routing")
	}
	if state.IngressDigest != initial.IngressDigest || files["system/connector/tunnel.yaml"] == "" || files["system/connector/network.yaml"] == "" {
		t.Fatal("failed replacement pruned last connector", state, files["kustomization.yaml"])
	}
	testTunnelDeps(s).Provider = f
	testTunnelDeps(s).VerifyEndpoints = func(context.Context, tunnel.RoutingState, string) error {
		return errors.New("TLS pending")
	}
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	reportRuntime(t, s, c, "runtime", true)
	reportRuntime(t, s, c, "connector", true)
	driveTunnels(t, s)
	s.params.CloudflareBaseDomain = "fleet.example.invalid"
	testTunnelDeps(s).VerifyEndpoints = func(context.Context, tunnel.RoutingState, string) error { return nil }
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	restored := readyTunnel(t, s, c)
	key := fmt.Sprintf("g%d-dns-0", restored.EndpointGeneration)
	if restored.Resources[key].ID != dnsID || restored.TunnelID != initial.TunnelID || f.creates["dns"] != 6 {
		t.Fatal("rollback recreated or conflicted with owned predecessor", restored, f.creates)
	}
}

func TestLateDrainReportNeedsAuditedRetry(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("2", 64))
	readyTunnel(t, s, c)
	adminA(t, s)
	path := "/api/admin/machines/" + c["node_id"]
	requireStatus(t, request(t, s, "DELETE", path, "session-a", map[string]any{}), 202)
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{drain_started_at}',to_jsonb($1::text))`, time.Now().Add(-time.Hour).Format(time.RFC3339Nano))
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	state, _, _ := s.loadTunnel(t.Context(), c["node_id"])
	if state.Reason != "drain_timeout" || count(t, s, `SELECT count(*) FROM lpcc.machines`) != 1 {
		t.Fatal("late report crossed drain deadline", state)
	}
	requireStatus(t, request(t, s, "POST", path+"/drain/retry", "session-a", map[string]any{"generation": state.Generation - 1}), 409)
	requireStatus(t, request(t, s, "POST", path+"/drain/retry", "session-a", map[string]any{"generation": state.Generation}), 202)
	driveTunnels(t, s)
	if count(t, s, `SELECT count(*) FROM lpcc.machines`) != 1 {
		t.Fatal("old drain report satisfied new generation")
	}
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	driveTunnels(t, s)
	if count(t, s, `SELECT count(*) FROM lpcc.machines`) != 0 || count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE action='machine.drain.retry' AND outcome='success'`) != 1 {
		t.Fatal("audited retry did not finish removal")
	}
}

func TestDevelopmentEnrollmentNeedsExplicitRefresh(t *testing.T) {
	s, _ := tunnelTestServer(t)
	jwt, _, _ := s.params.signEnrollment(ownerA, testOrchestrator(ownerA), time.Now())
	fp := strings.Repeat("1", 64)
	body := registrationBody(ownerA, fp, jwt)
	body["development_http"] = true
	seed := sha256.Sum256([]byte(ownerA + fp))
	body["signature"] = ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), protocol.RegistrationProof(jwt, fp, "worker-01", "/opt/livepeer", "v1.37.2+k3s1", body["public_key"].(string), true))
	w := request(t, s, "POST", "/v1/nodes/register", jwt, body)
	requireStatus(t, w, 200)
	c := credentials(t, w.Body.Bytes())
	reportRuntime(t, s, c, "runtime", false)
	driveTunnels(t, s)
	// An ordinary enrollment retry over the production URL must not upgrade a
	// credential previously released to development HTTP consumers.
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", jwt, registrationBody(ownerA, fp, jwt)), 200)
	driveTunnels(t, s)
	if count(t, s, `SELECT count(*) FROM lpcc.machines WHERE tunnel_eligible`) != 0 || count(t, s, `SELECT count(*) FROM lpcc.machine_states WHERE state->>'tunnel_id' IS NOT NULL AND state->>'tunnel_id'<>''`) != 0 {
		t.Fatal("development enrollment became live")
	}
	w = request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/credentials/refresh", jwt, map[string]any{"management_proof": c["token"], "fingerprint": fp, "install_dir": "/opt/livepeer", "operation_id": uuid.New().String(), "expected_credential_version": 1})
	requireStatus(t, w, 200)
	if count(t, s, `SELECT count(*) FROM lpcc.machines WHERE tunnel_eligible AND credential_version=2`) != 1 {
		t.Fatal("explicit refresh did not enable secure enrollment")
	}
}

type dnsDeleteFailure struct{ *simulatedCloudflare }

func (f *dnsDeleteFailure) Delete(ctx context.Context, r tunnel.CFResource, target string) error {
	if r.Kind == "dns" {
		return &tunnel.ProviderError{Status: 503, Ambiguous: true}
	}
	return f.simulatedCloudflare.Delete(ctx, r, target)
}
func TestLateRetiredResultCannotAffectReplacementReadiness(t *testing.T) {
	s, base := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("c", 64))
	old := readyTunnel(t, s, c)
	late := old.Resources["g1-dns-0"]
	// Only ambiguous operations need periodic late-result inventories.
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=jsonb_set(state,'{resources,g1-dns-0,watch}','true')`)
	if e := s.RetireMachine(t.Context(), c["node_id"]); e != nil {
		t.Fatal(e)
	}
	driveTunnels(t, s)
	newC := enroll(t, s, ownerA, strings.Repeat("c", 64))
	readyTunnel(t, s, newC)
	late.ID = "late-old-dns"
	base.resources[late.ID] = late
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=jsonb_set(state,'{resources,g1-dns-0,audit_after}',to_jsonb($1::text)) WHERE node_id=$2`, time.Now().Add(-time.Hour).Format(time.RFC3339Nano), c["node_id"])
	testTunnelDeps(s).Provider = &dnsDeleteFailure{base}
	configureTestTunnels(t, s)
	// Two passes remove dependence on enrollment row enumeration order.
	driveTunnels(t, s)
	driveTunnels(t, s)
	sources, e := s.tunnels.DiscoverySources(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, source := range sources {
		if source.NodeID == newC["node_id"] {
			found = true
			if !source.Ready {
				t.Fatal("retired node cleanup changed replacement readiness", source)
			}
		}
	}
	if !found {
		t.Fatal("replacement source was removed by old cleanup")
	}
	testTunnelDeps(s).Provider = base
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	driveTunnels(t, s)
	readyTunnel(t, s, newC)
}

func TestSecureEnrollmentBeforeEnablementCanProvision(t *testing.T) {
	s, f := tunnelTestServer(t)
	s.params.CloudflareEnabled = false
	testTunnelDeps(s).Provider = nil
	configureTestTunnels(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("d", 64))
	if count(t, s, `SELECT count(*) FROM lpcc.machines WHERE tunnel_eligible`) != 1 || count(t, s, `SELECT count(*) FROM lpcc.machine_states`) != 0 {
		t.Fatal("secure issuance coupled to enablement")
	}
	s.params.CloudflareEnabled = true
	testTunnelDeps(s).Provider = f
	configureTestTunnels(t, s)
	readyTunnel(t, s, c)
}

func TestEndpointDrainCancellationAndFailedStageRollback(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(fmt.Sprint("completed-", completed), func(t *testing.T) {
			s, f := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("a", 64))
			initial := readyTunnel(t, s, c)
			s.params.CloudflareBaseDomain = "replacement.example.invalid"
			configureTestTunnels(t, s)
			driveTunnels(t, s)
			if completed {
				reportRuntime(t, s, c, "runner", true)
				testTunnelDeps(s).Provider = &endpointCreateFailure{f}
				configureTestTunnels(t, s)
				driveTunnels(t, s)
			}
			execSQL(t, s.db, `UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{drain_started_at}',to_jsonb($1::text))`, time.Now().Add(-time.Hour).Format(time.RFC3339Nano))
			s.params.CloudflareBaseDomain = "fleet.example.invalid"
			testTunnelDeps(s).Provider = f
			configureTestTunnels(t, s)
			driveTunnels(t, s)
			current, _, _ := s.loadTunnel(t.Context(), c["node_id"])
			if current.DrainRequested || current.Target != "" || current.ServiceURL != initial.ServiceURL {
				t.Fatal("obsolete endpoint drain survived rollback", current)
			}
			// No fresh runner report is needed to retain the already applied A workload.
			reportRuntime(t, s, c, "runtime", true)
			reportRuntime(t, s, c, "connector", true)
			driveTunnels(t, s)
			current, _, _ = s.loadTunnel(t.Context(), c["node_id"])
			if !current.Ready {
				t.Fatal("rollback to applied workload imposed another drain", current)
			}
		})
	}
}
func stageEndpointChange(t *testing.T, s *Server, node string) tunnel.Snapshot {
	t.Helper()
	s.params.CloudflareBaseDomain = "replacement.example.invalid"
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	pending, _, err := s.loadTunnel(t.Context(), node)
	requireNoError(t, err)
	return pending
}

func TestExpiredEndpointDrainForcesReplacement(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("b", 64))
	initial := readyTunnel(t, s, c)
	pending := stageEndpointChange(t, s, c["node_id"])
	if pending.Target == "" || pending.ServiceURL != initial.ServiceURL {
		t.Fatal("endpoint replacement did not wait for the drain deadline", pending)
	}
	backdateWorkloadDrain(t, s, c["node_id"])
	driveTunnels(t, s)
	runtime, _ := publishedMachineConfiguration(t, s, c["node_id"])
	if runtime.ServiceURL != pending.Target || runtime.ConfigDigest != pending.PendingConfigDigest || !runtime.DrainRequested {
		t.Fatal("deadline did not release the endpoint replacement with admission closed", runtime)
	}
}

func TestForcedEndpointChangeStillRequiresRouteReadiness(t *testing.T) {
	s, provider := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("a", 64))
	node := c["node_id"]
	initial := readyTunnel(t, s, c)
	_, original := publishedMachineConfiguration(t, s, node)
	pending := stageEndpointChange(t, s, node)
	if pending.Target == "" || pending.ServiceURL != initial.ServiceURL {
		t.Fatal("endpoint change did not wait for the drain", pending)
	}
	adminA(t, s)
	force := "/api/admin/machines/" + node + "/drain/force"
	requireStatus(t, request(t, s, "POST", force, "session-a", map[string]int64{"generation": pending.Generation}), 202)

	testTunnelDeps(s).Provider = &endpointCreateFailure{provider}
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	current, _, err := s.loadTunnel(t.Context(), node)
	requireNoError(t, err)
	beforeIngress, held := publishedMachineConfiguration(t, s, node)
	if held != original || beforeIngress.ServiceURL != initial.ServiceURL ||
		current.ServiceURL != initial.ServiceURL || current.Reason != "provisioning_pending" {
		t.Fatal("force changed the published route before provider ingress succeeded", current)
	}

	testTunnelDeps(s).Provider = provider
	testTunnelDeps(s).VerifyEndpoints = func(context.Context, tunnel.RoutingState, string) error {
		return errors.New("route verification pending")
	}
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	current, _, err = s.loadTunnel(t.Context(), node)
	requireNoError(t, err)
	runtime, manifest := publishedMachineConfiguration(t, s, node)
	if current.ServiceURL != pending.Target || current.Ready || !runtime.DrainRequested ||
		!strings.Contains(manifest, current.ServiceURL) || !strings.Contains(manifest, current.ProxyURLTemplate) {
		t.Fatal("force did not release the replacement while keeping admission closed", current, runtime)
	}
	reportRuntime(t, s, c, "runtime", true)
	driveTunnels(t, s)
	current, _, err = s.loadTunnel(t.Context(), node)
	requireNoError(t, err)
	if current.Ready || current.Reason != "runtime_pending" {
		t.Fatal("missing connector report allowed the new route", current)
	}
	reportRuntime(t, s, c, "connector", true)
	driveTunnels(t, s)
	current, _, err = s.loadTunnel(t.Context(), node)
	requireNoError(t, err)
	if current.Ready || current.Reason != "tls_or_route_pending" {
		t.Fatal("unverified route became ready", current)
	}
	testTunnelDeps(s).VerifyEndpoints = func(context.Context, tunnel.RoutingState, string) error { return nil }
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	current, _, err = s.loadTunnel(t.Context(), node)
	requireNoError(t, err)
	if !current.Ready || current.DrainRequested || current.ServiceURL != pending.Target {
		t.Fatal("forced endpoint change did not become ready", current)
	}
}

func TestForcedEndpointChangeDoesNotReleaseSupersedingWorkload(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("b", 64))
	node := c["node_id"]
	initial := readyTunnel(t, s, c)
	_, original := publishedMachineConfiguration(t, s, node)
	pending := stageEndpointChange(t, s, node)
	adminA(t, s)
	force := "/api/admin/machines/" + node + "/drain/force"
	requireStatus(t, request(t, s, "POST", force, "session-a", map[string]int64{"generation": pending.Generation}), 202)

	s.params.RuntimeNodeImage = "registry.invalid/node@sha256:" + strings.Repeat("c", 64)
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	current, _, err := s.loadTunnel(t.Context(), node)
	requireNoError(t, err)
	_, held := publishedMachineConfiguration(t, s, node)
	if current.Target != pending.Target || current.ServiceURL != initial.ServiceURL || held != original ||
		current.Generation <= pending.Generation+1 || current.PendingConfigDigest == pending.PendingConfigDigest ||
		!current.DrainStartedAt.Equal(pending.DrainStartedAt) {
		t.Fatal("force crossed a change to the pending workload", current)
	}
	requireStatus(t, request(t, s, "POST", force, "session-a", map[string]int64{"generation": current.Generation}), 202)
	driveTunnels(t, s)
	_, manifest := publishedMachineConfiguration(t, s, node)
	if !strings.Contains(manifest, s.params.RuntimeNodeImage) || !strings.Contains(manifest, pending.Target) {
		t.Fatal("fresh force did not release the superseding workload")
	}
}

func TestOneForceReleasesFirstPublicEndpointAfterDomainChange(t *testing.T) {
	s, provider := tunnelTestServer(t)
	provider.certificateStatus = "pending_validation"
	c := enroll(t, s, ownerA, strings.Repeat("a", 64))
	node := c["node_id"]
	reportRuntime(t, s, c, "runtime", false)
	driveTunnels(t, s)
	initial, _, err := s.loadTunnel(t.Context(), node)
	requireNoError(t, err)
	if initial.Reason != "certificate_pending" || initial.IngressDigest != "" {
		t.Fatal("expected the first certificate to be pending", initial)
	}

	s.params.CloudflareBaseDomain = "replacement.example.invalid"
	s.params.RuntimeNodeImage = "registry.invalid/node@sha256:" + strings.Repeat("c", 64)
	provider.certificateStatus = "active"
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	pending, _, err := s.loadTunnel(t.Context(), node)
	requireNoError(t, err)
	adminA(t, s)
	path := "/api/admin/machines/" + node + "/drain/force"
	requireStatus(t, request(t, s, "POST", path, "session-a", map[string]int64{"generation": pending.Generation}), 202)
	driveTunnels(t, s)
	runtime, manifest := publishedMachineConfiguration(t, s, node)
	if runtime.ConfigDigest != pending.PendingConfigDigest ||
		!strings.Contains(manifest, "replacement.example.invalid") || !strings.Contains(manifest, s.params.RuntimeNodeImage) {
		t.Fatal("one force did not release the first public workload", runtime)
	}
}

func TestProxyOnlyEndpointChangeRequiresDrainOrForce(t *testing.T) {
	s, provider := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("a", 64))
	node := c["node_id"]
	initial := readyTunnel(t, s, c)
	prior := initial
	prior.ProxyURLTemplate = strings.Replace(initial.ProxyURLTemplate, "fleet.example.invalid", "prior.example.invalid", 1)
	rules := append([]tunnel.IngressRule(nil), provider.configurations[prior.TunnelID]...)
	for i := range rules {
		if strings.HasPrefix(rules[i].Hostname, "*.") {
			rules[i].Hostname = strings.Replace(rules[i].Hostname, "fleet.example.invalid", "prior.example.invalid", 1)
		}
	}
	version, err := provider.Configure(t.Context(), prior.TunnelID, rules)
	requireNoError(t, err)
	prior.IngressDigest = ingressHash(rules)
	raw, err := json.Marshal(rules)
	requireNoError(t, err)
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=state || jsonb_build_object('proxy_url_template',$2::text,'applied_ingress',$3::jsonb,'ingress_digest',$4::text,'provider_version',$5::bigint) WHERE node_id=$1`, node, prior.ProxyURLTemplate, string(raw), prior.IngressDigest, version)
	priorMachineConfiguration(t, s, c, &prior)

	driveTunnels(t, s)
	pending, _, err := s.loadTunnel(t.Context(), node)
	requireNoError(t, err)
	if pending.Target == "" || pending.ServiceURL != initial.ServiceURL || pending.ProxyURLTemplate != prior.ProxyURLTemplate {
		t.Fatal("proxy-only change did not wait for the drain", pending)
	}
	adminA(t, s)
	force := "/api/admin/machines/" + node + "/drain/force"
	requireStatus(t, request(t, s, "POST", force, "session-a", map[string]int64{"generation": pending.Generation}), 202)
	driveTunnels(t, s)
	runtime, _ := publishedMachineConfiguration(t, s, node)
	if runtime.ProxyURLTemplate != initial.ProxyURLTemplate || runtime.ServiceURL != initial.ServiceURL {
		t.Fatal("force did not release the proxy-only change", runtime)
	}
}

func TestConnectorRotationRevokesStagedEndpointForce(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("b", 64))
	node := c["node_id"]
	initial := readyTunnel(t, s, c)
	pending := stageEndpointChange(t, s, node)
	adminA(t, s)
	path := "/api/admin/machines/" + node
	force := func(generation int64, status int) {
		t.Helper()
		requireStatus(t, request(t, s, "POST", path+"/drain/force", "session-a", map[string]int64{"generation": generation}), status)
	}
	force(pending.Generation, 202)
	requireStatus(t, request(t, s, "POST", path+"/tunnel/rotate", "session-a", map[string]string{"kind": "connector"}), 202)
	driveTunnels(t, s)
	rotated, _, err := s.loadTunnel(t.Context(), node)
	requireNoError(t, err)
	if rotated.CredentialGeneration == initial.CredentialGeneration || rotated.ServiceURL != initial.ServiceURL {
		t.Fatal("connector rotation did not leave the endpoint change waiting", rotated)
	}
	force(rotated.Generation, 202)
	driveTunnels(t, s)
	runtime, _ := publishedMachineConfiguration(t, s, node)
	if runtime.ConfigDigest != pending.PendingConfigDigest {
		t.Fatal("a fresh force did not release the staged replacement")
	}
}

type reconnectingConnector struct {
	*rotationFailures
	original string
}

func (f *reconnectingConnector) Delete(ctx context.Context, r tunnel.CFResource, target string) error {
	if r.Kind == "tunnel" && f.tokens[r.ID] == f.original {
		return &tunnel.ProviderError{Status: 409}
	}
	return f.simulatedCloudflare.Delete(ctx, r, target)
}
func TestRemovalRevokesReconnectingConnectorAndResumesLostResponse(t *testing.T) {
	for _, alreadyAbsent := range []bool{false, true} {
		t.Run(fmt.Sprint("already-absent-", alreadyAbsent), func(t *testing.T) {
			s, base := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("d", 64))
			initial := readyTunnel(t, s, c)
			f := &reconnectingConnector{rotationFailures: &rotationFailures{simulatedCloudflare: base, lose: true}, original: base.tokens[initial.TunnelID]}
			testTunnelDeps(s).Provider = f
			configureTestTunnels(t, s)
			if alreadyAbsent {
				delete(base.resources, initial.TunnelID)
			} else {
				// An interrupted old cleanup may already have persisted an absent intent.
				execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=jsonb_set(state,'{resources,tunnel,absent}','true')`)
			}
			if e := s.RetireMachine(t.Context(), c["node_id"]); e != nil {
				t.Fatal(e)
			}
			driveTunnels(t, s)
			driveTunnels(t, s)
			state, _, _ := s.loadTunnel(t.Context(), c["node_id"])
			if !state.CleanupComplete || len(base.resources) != 0 {
				t.Fatal("connector could reauthenticate during deletion", state, base.resources)
			}
			if !alreadyAbsent && (f.calls != 1 || !state.ConnectorRevoked || base.tokens[initial.TunnelID] == f.original) {
				t.Fatal("lost rotation response did not converge", state, f.calls)
			}
			if alreadyAbsent && f.calls != 0 {
				t.Fatal("rotation required an already deleted tunnel")
			}
		})
	}
}
func TestModernIneligibleMachineCanCompleteRemoval(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("e", 64))
	execSQL(t, s.db, `UPDATE lpcc.machines SET tunnel_eligible=false`)
	adminA(t, s)
	requireStatus(t, request(t, s, "DELETE", "/api/admin/machines/"+c["node_id"], "session-a", map[string]any{}), 202)
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	driveTunnels(t, s)
	if count(t, s, `SELECT count(*) FROM lpcc.machines`) != 0 || f.creates["tunnel"] != 0 {
		t.Fatal("removal depended on provisioning eligibility")
	}
}

type cleanupAudits struct {
	*simulatedCloudflare
	inventories, rotations int
	selected, lateToken    string
	failDelete             bool
}

func (f *cleanupAudits) FindOwned(ctx context.Context, r tunnel.CFResource) ([]tunnel.CFResource, error) {
	f.inventories++
	return f.simulatedCloudflare.FindOwned(ctx, r)
}
func (f *cleanupAudits) RotateConnector(ctx context.Context, id string) error {
	f.rotations++
	return f.simulatedCloudflare.RotateConnector(ctx, id)
}
func (f *cleanupAudits) Delete(ctx context.Context, r tunnel.CFResource, target string) error {
	if r.Kind == "tunnel" && r.ID == f.selected {
		if f.tokens[r.ID] == f.lateToken {
			return errors.New("late connector was not revoked before deletion")
		}
		if f.failDelete {
			f.failDelete = false
			return &tunnel.ProviderError{Status: 503}
		}
	}
	return f.simulatedCloudflare.Delete(ctx, r, target)
}
func TestCompletedCleanupAuditsDueWatchesBeforeDeletingLateTunnel(t *testing.T) {
	s, base := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("1", 64))
	initial := readyTunnel(t, s, c)
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=jsonb_set(state,'{resources,tunnel,watch}','true')`)
	if e := s.RetireMachine(t.Context(), c["node_id"]); e != nil {
		t.Fatal(e)
	}
	driveTunnels(t, s)
	state, revision, e := s.loadTunnel(t.Context(), c["node_id"])
	if e != nil || !state.CleanupComplete {
		t.Fatal(state, e)
	}
	f := &cleanupAudits{simulatedCloudflare: base, selected: initial.TunnelID}
	testTunnelDeps(s).Provider = f
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	_, after, _ := s.loadTunnel(t.Context(), c["node_id"])
	if f.inventories != 0 || after != revision {
		t.Fatal("completed retirement ignored audit interval", f.inventories, revision, after)
	}
	overdue := time.Now().Add(-time.Hour).Format(time.RFC3339Nano)
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=jsonb_set(state,'{resources,tunnel,audit_after}',to_jsonb($1::text))`, overdue)
	driveTunnels(t, s)
	if f.inventories == 0 {
		t.Fatal("due watch was never inventoried")
	}
	state, _, _ = s.loadTunnel(t.Context(), c["node_id"])
	if !state.CleanupComplete || !time.Now().Before(state.Resources["tunnel"].AuditAfter) {
		t.Fatal("empty audit did not reschedule", state)
	}
	// A selected tunnel reappears with usable authentication. Audit must reopen
	// cleanup, not delete it before revocation; a failed delete must then resume.
	base.resources[initial.TunnelID] = initial.Resources["tunnel"]
	f.lateToken = "late-usable-connector-token"
	base.tokens[initial.TunnelID] = f.lateToken
	f.failDelete = true
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=jsonb_set(state,'{resources,tunnel,audit_after}',to_jsonb($1::text))`, overdue)
	driveTunnels(t, s)
	state, _, _ = s.loadTunnel(t.Context(), c["node_id"])
	if state.CleanupComplete || !state.ConnectorRevoked || f.rotations != 1 {
		t.Fatal("late tunnel bypassed revocation", state, f.rotations)
	}
	driveTunnels(t, s)
	state, _, _ = s.loadTunnel(t.Context(), c["node_id"])
	if !state.CleanupComplete || len(base.resources) != 0 || f.rotations != 1 {
		t.Fatal("reopened cleanup did not resume", state, f.rotations)
	}
}

// The API-level retirement test injects a lost deletion response.
