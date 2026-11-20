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

func TestDevelopmentEnrollmentStaysPrivate(t *testing.T) {
	s := newTestServer(t)
	jwt, _, _ := s.params.signEnrollment(ownerA, testOrchestrator(ownerA), time.Now())
	fp := strings.Repeat("1", 64)
	secure := registrationBody(ownerA, fp, jwt)
	dev := registrationBody(ownerA, fp, jwt)
	dev["development_http"] = true
	seed := sha256.Sum256([]byte(ownerA + fp))
	dev["signature"] = ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), protocol.RegistrationProof(jwt, fp, "worker-01", "/opt/livepeer", "v1.37.2+k3s1", dev["public_key"].(string), true))
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", jwt, dev), 403)

	s.params.DevelopmentHTTP, s.params.PublicAPIURL = true, "http://api.example"
	s.configs = s.newConfigurationManager()
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", jwt, secure), 403)
	w := request(t, s, "POST", "/v1/nodes/register", jwt, dev)
	requireStatus(t, w, 200)
	c := credentials(t, w.Body.Bytes())
	path := "/v1/nodes/" + c["node_id"]
	if c["config_url"] != s.params.PublicAPIURL+path+"/config" {
		t.Fatal("development config URL is not bound to the HTTP origin")
	}
	requireStatus(t, request(t, s, "GET", path+"/config", c["token"], nil), 200)
	requireStatus(t, request(t, s, "POST", path+"/tunnel/connector-token", c["token"], nil), 403)

	s.params.DevelopmentHTTP, s.params.PublicAPIURL = false, "https://api.example"
	requireStatus(t, request(t, s, "GET", path+"/config", c["token"], nil), 401)
	requireStatus(t, request(t, s, "POST", "/v1/nodes/register", jwt, secure), 409)
	requireStatus(t, request(t, s, "POST", path+"/credentials/refresh", jwt, map[string]any{
		"management_proof": c["token"], "fingerprint": fp, "install_dir": "/opt/livepeer",
		"operation_id": uuid.New().String(), "expected_credential_version": 1,
	}), 404)
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
func TestUnfinishedEndpointDrainCannotResetItsDeadline(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("b", 64))
	initial := readyTunnel(t, s, c)
	s.params.CloudflareBaseDomain = "replacement.example.invalid"
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	old := time.Now().UTC().Add(-time.Hour)
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{drain_started_at}',to_jsonb($1::text))`, old.Format(time.RFC3339Nano))
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	state, _, _ := s.loadTunnel(t.Context(), c["node_id"])
	if state.Reason != "drain_timeout" || state.ServiceURL != initial.ServiceURL || !state.DrainStartedAt.Equal(old) {
		t.Fatal("same-target retry revived expired drain", state)
	}
	adminA(t, s)
	requireStatus(t, request(t, s, "POST", "/api/admin/machines/"+c["node_id"]+"/drain/retry", "session-a", map[string]any{"generation": state.Generation}), 202)
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	state, _, _ = s.loadTunnel(t.Context(), c["node_id"])
	if state.ServiceURL == initial.ServiceURL {
		t.Fatal("audited endpoint retry did not proceed", state)
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
