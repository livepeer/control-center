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
			for _, kind := range []string{"connector", "access"} {
				requireStatus(t, request(t, s, "POST", path, "session-a", map[string]any{"kind": kind, "compromised": true}), 202)
			}
			execSQL(t, s.db, `UPDATE lpcc.machine_reports SET received_at=now()-interval '1 hour'`)
			driveTunnels(t, s)
			driveTunnels(t, s)
			current, _, e := s.loadTunnel(t.Context(), c["node_id"])
			if e != nil || current.CredentialGeneration != initial.CredentialGeneration+1 || current.AccessVersion != initial.AccessVersion+1 || current.Ready || base.disconnected != 1 {
				t.Fatal(current, base.disconnected, e)
			}
			if f.calls != map[bool]int{false: 2, true: 1}[lose] {
				t.Fatal("rotation replayed after success", f.calls)
			}
			if _, e = s.tunnels.ResolveAccessCredential(t.Context(), credentialRef(c["node_id"], initial.AccessVersion)); e == nil {
				t.Fatal("compromised credential still resolves")
			}
			requireStatus(t, request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/tunnel/connector-token", c["token"], map[string]any{}), 409)
		})
	}
}

func TestExpiredUnacknowledgedAccessVersionsRecover(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("5", 64))
	initial := readyTunnel(t, s, c)
	adminA(t, s)
	requireStatus(t, request(t, s, "POST", "/api/admin/machines/"+c["node_id"]+"/tunnel/rotate", "session-a", map[string]any{"kind": "access"}), 202)
	driveTunnels(t, s)
	if n := count(t, s, `SELECT count(*) FROM lpcc.access_credentials WHERE revoked_at IS NULL`); n != 2 {
		t.Fatal(n)
	}
	execSQL(t, s.db, `UPDATE lpcc.access_credentials SET expires_at=now()-interval '1 minute'`)
	driveTunnels(t, s)
	current, _, _ := s.loadTunnel(t.Context(), c["node_id"])
	if current.AccessVersion != initial.AccessVersion+2 {
		t.Fatal(current)
	}
	if _, e := s.tunnels.ResolveAccessCredential(t.Context(), credentialRef(c["node_id"], current.AccessVersion)); e != nil {
		t.Fatal(e)
	}
	sources, e := s.tunnels.DiscoverySources(t.Context())
	if e != nil || len(sources) != 1 {
		t.Fatal(e, sources)
	}
	if e = s.tunnels.AcknowledgeDiscovery(t.Context(), sources[0]); e != nil {
		t.Fatal(e)
	}
	if n := count(t, s, `SELECT count(*) FROM lpcc.access_credentials WHERE revoked_at IS NULL`); n != 1 {
		t.Fatal(n)
	}
}

type appCreateFailure struct{ *simulatedCloudflare }

func (f *appCreateFailure) Create(ctx context.Context, r tunnel.CFResource, target string) (tunnel.CFResource, *tunnel.AccessCredential, time.Time, error) {
	if r.Kind == "app" {
		return r, nil, time.Time{}, &tunnel.ProviderError{Status: 403}
	}
	return f.simulatedCloudflare.Create(ctx, r, target)
}
func TestEndpointFailurePreservesConnectorAndRollbackReusesOwnership(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("4", 64))
	initial := readyTunnel(t, s, c)
	appID := initial.Resources["g1-app"].ID
	s.params.CloudflareBaseDomain = "replacement.example.invalid"
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	reportRuntime(t, s, c, "runner", true)
	testTunnelDeps(s).Provider = &appCreateFailure{f}
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
	testTunnelDeps(s).VerifyEndpoints = func(context.Context, tunnel.RoutingState, tunnel.AccessCredential) error {
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
	testTunnelDeps(s).VerifyEndpoints = func(context.Context, tunnel.RoutingState, tunnel.AccessCredential) error { return nil }
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	restored := readyTunnel(t, s, c)
	key := fmt.Sprintf("g%d-app", restored.EndpointGeneration)
	if restored.Resources[key].ID != appID || restored.TunnelID != initial.TunnelID || f.creates["app"] != 2 {
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
	jwt, _, _ := signEnrollment(s.params.JWTSigningSecret, ownerA, time.Now())
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

type tokenCreateFailure struct {
	*simulatedCloudflare
	fail bool
}

func (f *tokenCreateFailure) Create(ctx context.Context, r tunnel.CFResource, target string) (tunnel.CFResource, *tunnel.AccessCredential, time.Time, error) {
	if r.Kind == "token" && f.fail {
		return r, nil, time.Time{}, &tunnel.ProviderError{Status: 503, Ambiguous: true}
	}
	return f.simulatedCloudflare.Create(ctx, r, target)
}
func TestOfflineAccessReplacementStatusSurvivesFailure(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint("expired-", expired), func(t *testing.T) {
			s, base := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("b", 64))
			initial := readyTunnel(t, s, c)
			f := &tokenCreateFailure{simulatedCloudflare: base, fail: true}
			testTunnelDeps(s).Provider = f
			configureTestTunnels(t, s)
			execSQL(t, s.db, `UPDATE lpcc.machine_reports SET received_at=now()-interval '1 hour'`)
			reason, recovered := "access_rotation_failed", "rotation_ack_pending"
			if expired {
				execSQL(t, s.db, `UPDATE lpcc.access_credentials SET expires_at=now()-interval '1 minute'`)
				reason, recovered = "access_credential_expired", ""
			} else {
				adminA(t, s)
				requireStatus(t, request(t, s, "POST", "/api/admin/machines/"+c["node_id"]+"/tunnel/rotate", "session-a", map[string]any{"kind": "access"}), 202)
			}
			for i := 0; i < 2; i++ {
				driveTunnels(t, s)
				state, _, _ := s.loadTunnel(t.Context(), c["node_id"])
				if state.AccessVersion != initial.AccessVersion+1 || state.Reason != "runtime_offline" || state.RotationReason != reason {
					t.Fatal("lost credential failure cause", state)
				}
			}
			f.fail = false
			// Allow the persisted retry deadline without waiting in the test.
			execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=jsonb_set(state,'{resources,token-2,attempt_at}',to_jsonb($1::text))`, time.Now().Add(-time.Hour).Format(time.RFC3339Nano))
			driveTunnels(t, s)
			state, _, _ := s.loadTunnel(t.Context(), c["node_id"])
			if state.Reason != "runtime_offline" || state.RotationReason != recovered || state.Ready {
				t.Fatal("recovery lost independent Runtime state", state)
			}
		})
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

func TestOfflineAcknowledgementRetiresOverlapAndPermitsNextRotation(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("e", 64))
	readyTunnel(t, s, c)
	adminA(t, s)
	path := "/api/admin/machines/" + c["node_id"] + "/tunnel/rotate"
	rotate := map[string]any{"kind": "access"}
	requireStatus(t, request(t, s, "POST", path, "session-a", rotate), 202)
	driveTunnels(t, s)
	sources, e := s.tunnels.DiscoverySources(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	if e = s.tunnels.AcknowledgeDiscovery(t.Context(), sources[0]); e != nil {
		t.Fatal(e)
	}
	execSQL(t, s.db, `UPDATE lpcc.machine_reports SET received_at=now()-interval '1 hour'`)
	driveTunnels(t, s)
	state, _, _ := s.loadTunnel(t.Context(), c["node_id"])
	current := state.Resources["token-2"].ID
	if count(t, s, `SELECT count(*) FROM lpcc.access_credentials WHERE revoked_at IS NULL`) != 1 {
		t.Fatal("acknowledged predecessor retained offline")
	}
	for _, ids := range f.policies {
		if len(ids) != 1 || ids[0] != current {
			t.Fatal("policy overlap survived acknowledgement", ids)
		}
	}
	requireStatus(t, request(t, s, "POST", path, "session-a", rotate), 202)
	driveTunnels(t, s)
	state, _, _ = s.loadTunnel(t.Context(), c["node_id"])
	if state.AccessVersion != 3 {
		t.Fatal("acknowledged overlap blocked next rotation", state)
	}
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
				testTunnelDeps(s).Provider = &appCreateFailure{f}
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

type protectFailure struct {
	*simulatedCloudflare
	failure error
}

func (f *protectFailure) Protect(ctx context.Context, r tunnel.CFResource, ids []string) error {
	if f.failure != nil {
		return f.failure
	}
	return f.simulatedCloudflare.Protect(ctx, r, ids)
}
func TestProtectionFailuresPreserveOrRestoreAppliedIngressOffline(t *testing.T) {
	s, base := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("c", 64))
	initial := readyTunnel(t, s, c)
	f := &protectFailure{simulatedCloudflare: base}
	testTunnelDeps(s).Provider = f
	configureTestTunnels(t, s)
	execSQL(t, s.db, `UPDATE lpcc.machine_reports SET received_at=now()-interval '1 hour'`)
	for _, code := range []int{503, 429} {
		f.failure = &tunnel.ProviderError{Status: code}
		driveTunnels(t, s)
		if ingressHash(base.configurations[initial.TunnelID]) != initial.IngressDigest {
			t.Fatal("transient failure erased working ingress")
		}
	}
	f.failure = tunnel.ErrUnsafeProtection
	driveTunnels(t, s)
	state, _, _ := s.loadTunnel(t.Context(), c["node_id"])
	if !state.Quarantined || len(base.configurations[initial.TunnelID]) != 1 {
		t.Fatal("unsafe policy left routes exposed", state)
	}
	f.failure = nil
	driveTunnels(t, s)
	state, _, _ = s.loadTunnel(t.Context(), c["node_id"])
	if state.Quarantined || state.Reason != "runtime_offline" || ingressHash(base.configurations[initial.TunnelID]) != initial.IngressDigest {
		t.Fatal("verified offline protection did not restore applied ingress", state)
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

func TestAcknowledgedRetirementCheckpointCanResumeReplacement(t *testing.T) {
	for _, compromised := range []bool{false, true} {
		t.Run(fmt.Sprint("compromised-", compromised), func(t *testing.T) {
			s, base := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("f", 64))
			initial := readyTunnel(t, s, c)
			sources, e := s.tunnels.DiscoverySources(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			if e = s.tunnels.AcknowledgeDiscovery(t.Context(), sources[0]); e != nil {
				t.Fatal(e)
			}
			if compromised {
				adminA(t, s)
				requireStatus(t, request(t, s, "POST", "/api/admin/machines/"+c["node_id"]+"/tunnel/rotate", "session-a", map[string]any{"kind": "access", "compromised": true}), 202)
			} else {
				execSQL(t, s.db, `UPDATE lpcc.access_credentials SET expires_at=now()-interval '1 minute'`)
			}
			testTunnelDeps(s).Provider = &lostTokenCheckpoint{simulatedCloudflare: base, lostDelete: true}
			configureTestTunnels(t, s)
			driveTunnels(t, s)
			checkpoint, _, _ := s.loadTunnel(t.Context(), c["node_id"])
			if checkpoint.AccessVersion != initial.AccessVersion || !checkpoint.Resources["token-1"].Absent || count(t, s, `SELECT count(*) FROM lpcc.access_credentials WHERE revoked_at IS NOT NULL AND acknowledged_at IS NOT NULL`) != 1 {
				t.Fatal("retirement checkpoint was not reached", checkpoint)
			}
			// driveTunnels reloads the lease and JSON, including the retained old ack.
			driveTunnels(t, s)
			recovered, _, _ := s.loadTunnel(t.Context(), c["node_id"])
			if recovered.AccessVersion != initial.AccessVersion+1 {
				t.Fatal("old acknowledgement blocked replacement", recovered)
			}
			if _, e = s.tunnels.ResolveAccessCredential(t.Context(), credentialRef(c["node_id"], recovered.AccessVersion)); e != nil {
				t.Fatal(e)
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
type lostTokenCheckpoint struct {
	*simulatedCloudflare
	lostDelete bool
}

func (f *lostTokenCheckpoint) Delete(ctx context.Context, r tunnel.CFResource, target string) error {
	if err := f.simulatedCloudflare.Delete(ctx, r, target); err != nil {
		return err
	}
	if r.Kind == "token" && f.lostDelete {
		f.lostDelete = false
		return &tunnel.ProviderError{Ambiguous: true}
	}
	return nil
}
