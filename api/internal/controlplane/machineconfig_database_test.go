package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
	"github.com/livepeer/control-center/runtime/contract"
)

func TestUnchangedRenderingAllowsProviderProgress(t *testing.T) {
	s, provider := tunnelTestServer(t)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	c := enroll(t, s, ownerA, strings.Repeat("2", 64))
	reportRuntime(t, s, c, "runtime", false)
	original := s.build
	s.build = func(d machineconfig.Desired) ([]byte, string, error) {
		if err := s.tunnels.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
		return original(d)
	}
	for i := 0; i < 5; i++ {
		if err := s.reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if len(provider.resources) == 0 {
		t.Fatal("aligned provider passes made no progress during configuration rendering")
	}
}

func waitForStateLock(t *testing.T, s *Server, query string, minimum int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var blocked int
		if err := s.db.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1`, query).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked >= minimum {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("expected state operation did not wait on lock", query)
}

func TestCredentialRefreshSerializesWithBlockedStateWrite(t *testing.T) {
	s := newTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("3", 64))
	m, err := s.authenticateMachine(t.Context(), c["node_id"], c["token"], false)
	if err != nil {
		t.Fatal(err)
	}
	store := machineconfig.Store{DB: s.db}
	lease, err := store.Claim(t.Context(), configurationMachine(m), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release(t.Context())
	revision := lease.Revision
	blocking, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer blocking.Rollback()
	if _, err = blocking.Exec(`SELECT FROM lpcc.machine_states WHERE node_id=$1 FOR UPDATE`, m.NodeID); err != nil {
		t.Fatal(err)
	}
	lease.State.ApprovedConfigDigest = "approval"
	written := make(chan error, 1)
	go func() { written <- lease.Save(t.Context()) }()
	waitForStateLock(t, s, "UPDATE lpcc.machine_states SET state=%", 1)
	jwt, _, _ := signEnrollment(s.params.JWTSigningSecret, ownerA, time.Now())
	refreshed := make(chan int, 1)
	go func() {
		refreshed <- request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/credentials/refresh", jwt, map[string]any{"fingerprint": m.Fingerprint, "install_dir": m.InstallDir, "operation_id": uuid.New().String(), "expected_credential_version": 1}).Code
	}()
	waitForStateLock(t, s, "UPDATE lpcc.machine_states SET revision=revision+1%", 1)
	if err = blocking.Rollback(); err != nil {
		t.Fatal(err)
	}
	writeErr := <-written
	if writeErr != nil && !errors.Is(writeErr, machineconfig.ErrFenced) {
		t.Fatal(writeErr)
	}
	if status := <-refreshed; status != 200 {
		t.Fatal("refresh failed", status)
	}
	current, err := store.Load(t.Context(), m.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	want := revision + 1
	if writeErr == nil {
		want++
	}
	if current.CredentialVersion != 2 || current.Revision != want {
		t.Fatal("refresh and approval did not serialize", current, writeErr)
	}
	if err = lease.Save(t.Context()); !errors.Is(err, machineconfig.ErrFenced) {
		t.Fatal("completed refresh did not fence old worker", err)
	}
}

func TestPrivateMachineRolloutAndRemoval(t *testing.T) {
	s := newTestServer(t)
	s.params.TunnelDrainTimeout = time.Minute
	// Leave StatusTTL unset to cover the private draining freshness default.
	s.configs = s.newConfigurationManager()
	c := enroll(t, s, ownerA, strings.Repeat("7", 64))
	m, previous := priorMachineConfiguration(t, s, c, nil)
	var err error
	if err = s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	state, _, err := s.loadTunnel(t.Context(), m.NodeID)
	if err != nil || !state.DrainRequested || state.HeldOrchestrator != previous {
		t.Fatal("private replacement was not drain gated", state, err)
	}
	if s.tunnels.Enabled() || state.TunnelID != "" {
		t.Fatal("private rollout acquired provider resources")
	}
	stale := currentReport(t, s, m.NodeID, machineconfig.Report{NodeID: m.NodeID, CredentialVersion: 1, Component: "runner", Generation: state.Generation - 1, BundleFormat: contract.BundleFormat, Apps: &contract.AppStatus{Instances: []contract.InstanceStatus{}}, HTTPS: true})
	for len(s.reconcileWake) > 0 {
		<-s.reconcileWake
	}
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/status", c["token"], stale), 200)
	if len(s.reconcileWake) != 0 {
		t.Fatal("stale report woke the fleet")
	}
	if err = s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, manifest := publishedMachineConfiguration(t, s, m.NodeID)
	if manifest != previous {
		t.Fatal("stale drain report released workload")
	}
	reportRuntime(t, s, c, "runner", true)
	if len(s.reconcileWake) != 1 {
		t.Fatal("matching drained runner did not wake reconciliation")
	}
	if err = s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, manifest = publishedMachineConfiguration(t, s, m.NodeID)
	if manifest == previous {
		t.Fatal("matching drain did not release replacement")
	}
	adminA(t, s)
	requireStatus(t, request(t, s, "DELETE", "/api/admin/machines/"+m.NodeID, "session-a", map[string]any{}), 202)
	if err = s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.machines`) != 1 {
		t.Fatal("removal accepted predecessor rollout report")
	}
	reportRuntime(t, s, c, "runner", true)
	if err = s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.machines`) != 0 || count(t, s, `SELECT count(*) FROM lpcc.enrollments WHERE terminal_bundle IS NOT NULL`) != 1 {
		t.Fatal("private removal did not publish terminal configuration")
	}
}

func TestMachineRolloutWithdrawsTunnelReadiness(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("9", 64))
	initial := readyTunnel(t, s, c)
	m, prior := priorMachineConfiguration(t, s, c, &initial)
	initial.HeldOrchestrator = prior
	priorDigest := machineconfig.Digest(desiredConfiguration(s, m, &initial))
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{approved_config_digest}',to_jsonb($2::text)),revision=revision+1 WHERE node_id=$1`, m.NodeID, priorDigest)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	reportRuntime(t, s, c, "runner", true)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	sources, err := s.tunnels.DiscoverySources(t.Context())
	if err != nil || len(sources) != 1 || sources[0].Ready || sources[0].Reason != "rollout_pending" {
		t.Fatal("prior generation advertised during workload replacement", sources, err)
	}
	state, _, err := s.loadTunnel(t.Context(), m.NodeID)
	if err != nil || state.Ready || state.Reason != "rollout_pending" {
		t.Fatal("prior generation reported ready", state, err)
	}
	reportRuntime(t, s, c, "runtime", true)
	reportRuntime(t, s, c, "connector", true)
	driveTunnels(t, s)
	sources, err = s.tunnels.DiscoverySources(t.Context())
	if err != nil || len(sources) != 1 || !sources[0].Ready {
		t.Fatal("matching observations did not restore readiness", sources, err)
	}
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=jsonb_set(state,'{reason}','"ownership_conflict"'),rollout=rollout || '{"drain_requested":true,"rollout_reason":"drain_pending"}' WHERE node_id=$1`, m.NodeID)
	sources, err = s.tunnels.DiscoverySources(t.Context())
	if err != nil || len(sources) != 1 || !sources[0].Blocked || sources[0].Reason != "drain_pending" {
		t.Fatal("drain diagnostic erased provider blocker", sources, err)
	}
}

func desiredConfiguration(s *Server, m Machine, routing *tunnel.Snapshot) machineconfig.Desired {
	state := machineconfig.InitialState(m.Terminal)
	var e *machineconfig.Exposure
	if routing != nil {
		state = routing.State
		e = exposure(routing.RoutingState)
	}
	return s.configs.Desired(configurationMachine(m), state, e)
}

func priorMachineConfiguration(t *testing.T, s *Server, c map[string]string, routing *tunnel.Snapshot) (Machine, string) {
	t.Helper()
	m, err := s.authenticateMachine(t.Context(), c["node_id"], c["token"], false)
	if err != nil {
		t.Fatal(err)
	}
	desired := desiredConfiguration(s, m, routing)
	data, _, err := machineconfig.Build(desired)
	if err != nil {
		t.Fatal(err)
	}
	prior := strings.Replace(archiveFiles(t, data)["system/node/orchestrator.yaml"], `Network = "offchain"`, `Network = "previous"`, 1)
	desired.State.HeldOrchestrator = prior
	data, digest, err := machineconfig.Build(desired)
	if err != nil {
		t.Fatal(err)
	}
	execSQL(t, s.db, `UPDATE lpcc.machine_configs SET bundle=$2,sha256=$3 WHERE node_id=$1`, m.NodeID, data, digest)
	return m, prior
}

func publishedMachineConfiguration(t *testing.T, s *Server, node string) (machineconfig.Runtime, string) {
	t.Helper()
	var data []byte
	if err := s.db.QueryRow(`SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, node).Scan(&data); err != nil {
		t.Fatal(err)
	}
	runtime, manifest, err := machineconfig.ReadApplied(data)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, manifest
}

func TestRemovalKeepsAppliedWorkload(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("a", 64))
	m, prior := priorMachineConfiguration(t, s, c, nil)
	adminA(t, s)
	requireStatus(t, request(t, s, "DELETE", "/api/admin/machines/"+m.NodeID, "session-a", map[string]any{}), 202)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	runtime, manifest := publishedMachineConfiguration(t, s, m.NodeID)
	if !runtime.DrainRequested {
		t.Fatal("removal did not request drain")
	}
	if manifest != prior {
		t.Fatal("published replacement workload during unfinished removal drain, without any runner report")
	}
}

func TestCredentialRefreshFencesRolloutApproval(t *testing.T) {
	s := newTestServer(t)
	s.params.TunnelDrainTimeout = time.Minute
	s.params.TunnelStatusTTL = time.Minute
	s.configs = s.newConfigurationManager()
	c := enroll(t, s, ownerA, strings.Repeat("b", 64))
	m, prior := priorMachineConfiguration(t, s, c, nil)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	reportRuntime(t, s, c, "runner", true)
	refreshed := false
	s.configs = machineconfig.New(machineconfig.Config{RuntimeImage: s.params.RuntimeImage, DrainTimeout: time.Minute, StatusTTL: time.Minute, APIURL: s.params.PublicAPIURL}, machineconfig.Dependencies{DB: s.db, Logger: s.logger, Exposure: func(json.RawMessage) (*machineconfig.Exposure, error) {
		if !refreshed {
			refreshed = true
			jwt, _, _ := signEnrollment(s.params.JWTSigningSecret, ownerA, time.Now())
			requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/credentials/refresh", jwt, map[string]any{"fingerprint": m.Fingerprint, "install_dir": m.InstallDir, "operation_id": uuid.New().String(), "expected_credential_version": 1}), 200)
		}
		return nil, nil
	}})
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	runtime, manifest := publishedMachineConfiguration(t, s, m.NodeID)
	if runtime.CredentialVersion != 2 {
		t.Fatalf("not refreshed: %#v", runtime)
	}
	if manifest != prior {
		t.Fatal("published replacement for credential v2 using only a revoked v1 drain report")
	}
}

func TestTerminalBundleUsesRetirementCredential(t *testing.T) {
	s := newTestServer(t)
	one := enroll(t, s, ownerA, strings.Repeat("e", 64))
	two := enroll(t, s, ownerA, strings.Repeat("f", 64))
	if one["node_id"] > two["node_id"] {
		one, two = two, one
	}
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	m, err := s.authenticateMachine(t.Context(), two["node_id"], two["token"], false)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	s.configs = machineconfig.New(machineconfig.Config{RuntimeImage: s.params.RuntimeImage, APIURL: s.params.PublicAPIURL}, machineconfig.Dependencies{DB: s.db, Logger: s.logger, Build: func(d machineconfig.Desired) ([]byte, string, error) {
		if d.NodeID == one["node_id"] && !changed {
			changed = true
			jwt, _, _ := signEnrollment(s.params.JWTSigningSecret, ownerA, time.Now())
			requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/credentials/refresh", jwt, map[string]any{"fingerprint": m.Fingerprint, "install_dir": m.InstallDir, "operation_id": uuid.New().String(), "expected_credential_version": 1}), 200)
			if err := s.RetireMachine(t.Context(), m.NodeID); err != nil {
				t.Fatal(err)
			}
		}
		return machineconfig.Build(d)
	}})
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	var data []byte
	var credential int64
	if err := s.db.QueryRow(`SELECT terminal_bundle,credential_version FROM lpcc.enrollments WHERE node_id=$1`, m.NodeID).Scan(&data, &credential); err != nil {
		t.Fatal(err)
	}
	var runtime machineconfig.Runtime
	if err := json.Unmarshal([]byte(archiveFiles(t, data)["runtime.json"]), &runtime); err != nil {
		t.Fatal(err)
	}
	if runtime.CredentialVersion != credential {
		t.Fatalf("permanent terminal bundle credential=%d differs from enrollment/header credential=%d", runtime.CredentialVersion, credential)
	}
}

func TestSharedLeaseRetainsProviderBackoff(t *testing.T) {
	s := newTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("1", 64))
	m, err := s.authenticateMachine(t.Context(), c["node_id"], c["token"], false)
	if err != nil {
		t.Fatal(err)
	}
	store := machineconfig.Store{DB: s.db}
	l, err := store.Claim(t.Context(), configurationMachine(m), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	l.Finish(t.Context(), true)
	var failures int
	var due time.Time
	if err := s.db.QueryRow(`SELECT failures,next_attempt_at FROM lpcc.machine_states WHERE node_id=$1`, m.NodeID).Scan(&failures, &due); err != nil {
		t.Fatal(err)
	}
	cLease, err := store.Claim(t.Context(), configurationMachine(m), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(t.Context(), configurationMachine(m), nil, false); err == nil {
		t.Fatal("concurrent claim succeeded")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	cLease.Release(cancelled)
	released, err := store.Claim(t.Context(), configurationMachine(m), nil, false)
	if err != nil {
		t.Fatal("cancelled configuration pass did not release lease", err)
	}
	released.Release(t.Context())
	var afterFailures int
	var afterDue time.Time
	if err := s.db.QueryRow(`SELECT failures,next_attempt_at FROM lpcc.machine_states WHERE node_id=$1`, m.NodeID).Scan(&afterFailures, &afterDue); err != nil {
		t.Fatal(err)
	}
	if failures != afterFailures || !due.Equal(afterDue) {
		t.Fatal("configuration release reset provider backoff")
	}
	if _, err := store.Claim(t.Context(), configurationMachine(m), nil, true); err == nil {
		t.Fatal("provider ignored next_attempt_at")
	}
}

func TestOrdinaryReportDoesNotWakeWholeFleet(t *testing.T) {
	s := newTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("1", 64))
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	for len(s.reconcileWake) > 0 {
		<-s.reconcileWake
	}
	for _, component := range []string{"runtime", "connector", "runner"} {
		reportRuntime(t, s, c, component, true)
		if len(s.reconcileWake) != 0 {
			t.Fatal("ordinary report queued a full-fleet reconcile", component)
		}
	}
}

func TestConcurrentRemovalDoesNotAbortFleetPass(t *testing.T) {
	s := newTestServer(t)
	s.params.TunnelDrainTimeout = time.Minute
	s.configs = s.newConfigurationManager()
	one := enroll(t, s, ownerA, strings.Repeat("2", 64))
	two := enroll(t, s, ownerA, strings.Repeat("3", 64))
	if one["node_id"] > two["node_id"] {
		one, two = two, one
	}
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	removed := false
	builtSecond := false
	s.configs = machineconfig.New(machineconfig.Config{RuntimeImage: s.params.RuntimeImage, DrainTimeout: time.Minute}, machineconfig.Dependencies{DB: s.db, Logger: s.logger, Exposure: func(json.RawMessage) (*machineconfig.Exposure, error) {
		if !removed {
			removed = true
			if err := s.RetireMachine(t.Context(), one["node_id"]); err != nil {
				t.Fatal(err)
			}
		}
		return nil, nil
	}, Build: func(d machineconfig.Desired) ([]byte, string, error) {
		if d.NodeID == two["node_id"] {
			builtSecond = true
		}
		return machineconfig.Build(d)
	}})
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatalf("one concurrent retirement aborted fleet pass: %v", err)
	}
	if !builtSecond {
		t.Fatal("remaining enrollment was not processed")
	}
}

func TestRotationRejectsConfigOnlyRow(t *testing.T) {
	s := newTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("5", 64))
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	adminA(t, s)
	for _, kind := range []string{"connector", "access"} {
		w := request(t, s, "POST", "/api/admin/machines/"+c["node_id"]+"/tunnel/rotate", "session-a", map[string]any{"kind": kind, "compromised": true})
		requireStatus(t, w, 404)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE action='tunnel.rotate' AND outcome='success'`) != 0 {
		t.Fatal("nonexistent rotation was audited as successful")
	}
}

func TestRetirementReasonSurvivesOldDrainReason(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("6", 64))
	readyTunnel(t, s, c)
	adminA(t, s)
	path := "/api/admin/machines/" + c["node_id"]
	requireStatus(t, request(t, s, "DELETE", path, "session-a", map[string]any{}), 202)
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{drain_started_at}',to_jsonb($1::text))`, time.Now().Add(-time.Hour).Format(time.RFC3339Nano))
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, request(t, s, "DELETE", path, "session-a", map[string]any{"force": true}), 202)
	driveTunnels(t, s)
	state, _, err := s.loadTunnel(t.Context(), c["node_id"])
	if err != nil {
		t.Fatal(err)
	}
	if !state.CleanupComplete || state.Lifecycle != "removed" {
		t.Fatal("cleanup did not complete", state)
	}
	if state.Reason != "removed" {
		t.Errorf("completed cleanup surfaced reason %q", state.Reason)
	}
	sources, err := s.tunnels.DiscoverySources(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0].Reason != "removed" {
		t.Errorf("discovery cleanup reason is stale: %#v", sources)
	}
}

func TestCompletedEndpointDrainDoesNotMaskProviderFailure(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("7", 64))
	readyTunnel(t, s, c)
	s.params.CloudflareBaseDomain = "replacement.example.invalid"
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	reportRuntime(t, s, c, "runner", true)
	testTunnelDeps(s).Provider = &appCreateFailure{f}
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	state, _, err := s.loadTunnel(t.Context(), c["node_id"])
	if err != nil {
		t.Fatal(err)
	}
	if state.Reason != "provisioning_pending" {
		t.Fatalf("completed endpoint drain masked provider failure as %q", state.Reason)
	}
}
