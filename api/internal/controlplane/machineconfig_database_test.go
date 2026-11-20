package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
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
	jwt, _, _ := s.params.signEnrollment(ownerA, testOrchestrator(ownerA), time.Now())
	refreshed := make(chan int, 1)
	go func() {
		refreshed <- request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/credentials/refresh", jwt, map[string]any{"management_proof": s.enrollmentToken(m), "fingerprint": m.Fingerprint, "install_dir": m.InstallDir, "operation_id": uuid.New().String(), "expected_credential_version": 1}).Code
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

func TestForceExpiredWorkloadRollout(t *testing.T) {
	for _, test := range []struct {
		name       string
		superseded bool
	}{
		{name: "pending target"},
		{name: "superseded target", superseded: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := newTestServer(t)
			s.params.TunnelDrainTimeout = time.Minute
			s.configs = s.newConfigurationManager()
			adminA(t, s)
			c := enroll(t, s, ownerA, strings.Repeat("7", 64))
			m, previous := priorMachineConfiguration(t, s, c, nil)
			store := machineconfig.Store{DB: s.db}
			loadRollout := func() machineconfig.State {
				t.Helper()
				record, err := store.Load(t.Context(), m.NodeID)
				if err != nil {
					t.Fatal(err)
				}
				return record.State
			}
			reconcile := func() {
				t.Helper()
				if err := s.reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			force := func(token string, generation int64, status int) {
				t.Helper()
				path := "/api/admin/machines/" + m.NodeID + "/drain/force"
				requireStatus(t, request(t, s, "POST", path, token, map[string]int64{"generation": generation}), status)
			}
			force("session-a", 1, 409)
			reconcile()
			pending := loadRollout()
			if pending.PendingConfigDigest == "" || pending.HeldOrchestrator != previous {
				t.Fatal("expected a pending, held rollout", pending.RolloutReason)
			}
			force("session-b", pending.Generation, 403)
			force("session-a", pending.Generation, 409)
			execSQL(t, s.db, `UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{drain_started_at}',to_jsonb($2::text)) WHERE node_id=$1`, m.NodeID, time.Now().Add(-time.Hour).Format(time.RFC3339Nano))
			reconcile()
			if reason := loadRollout().RolloutReason; reason != "drain_timeout" {
				t.Fatal("expected expired drain", reason)
			}
			force("session-a", pending.Generation-1, 409)
			force("session-a", pending.Generation, 202)
			force("session-a", pending.Generation, 409)
			if test.superseded {
				s.params.RuntimeNodeImage = "registry.invalid/node@sha256:" + strings.Repeat("c", 64)
				s.configs = s.newConfigurationManager()
			}
			reconcile()
			state := loadRollout()
			runtime, manifest := publishedMachineConfiguration(t, s, m.NodeID)
			if !state.DrainRequested || !runtime.DrainRequested || runtime.OnchainActive {
				t.Fatal("admission resumed early", state.RolloutReason)
			}
			if test.superseded {
				if manifest != previous || state.PendingConfigDigest == pending.PendingConfigDigest || state.ApplyingConfigDigest != "" || state.ForcedDrainTarget != "" {
					t.Fatal("force authorized a different workload", state.RolloutReason)
				}
				return
			}
			if state.ApplyingConfigDigest != pending.PendingConfigDigest || manifest == previous || runtime.ConfigDigest != state.ApplyingConfigDigest {
				t.Fatal("force did not publish the authorized workload", state.RolloutReason)
			}
			if count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE action='machine.drain.force' AND outcome='success'`) != 1 {
				t.Fatal("expected one audited force operation")
			}
			reportRuntime(t, s, c, "runtime", true)
			reconcile()
			if state = loadRollout(); state.DrainRequested || state.ApprovedConfigDigest != pending.PendingConfigDigest || state.ForcedDrainTarget != "" {
				t.Fatal("ready replacement did not finish the rollout", state.RolloutReason)
			}
		})
	}
}

func TestForceRolloutIsFencedByConnectorRotation(t *testing.T) {
	for _, timing := range []string{"before planning", "during rendering"} {
		t.Run(timing, func(t *testing.T) {
			s, _ := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("7", 64))
			initial := readyTunnel(t, s, c)
			adminA(t, s)
			node := c["node_id"]
			s.params.RuntimeNodeImage = "registry.invalid/node@sha256:" + strings.Repeat("c", 64)
			configureTestTunnels(t, s)
			expired := expireWorkloadDrain(t, s, node)
			path := "/api/admin/machines/" + node
			requireStatus(t, request(t, s, "POST", path+"/drain/force", "session-a", map[string]int64{"generation": expired.Generation}), 202)
			rotated := false
			rotate := func() {
				rotated = true
				requireStatus(t, request(t, s, "POST", path+"/tunnel/rotate", "session-a", map[string]string{"kind": "connector"}), 202)
				if err := s.tunnels.Reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if timing == "during rendering" {
				build := s.build
				s.build = func(desired machineconfig.Desired) ([]byte, string, error) {
					if !rotated && desired.NodeID == node && desired.State.ApplyingConfigDigest == expired.PendingConfigDigest {
						rotate()
					}
					return build(desired)
				}
			} else {
				rotate()
			}
			for i := 0; i < 2; i++ {
				if err := s.reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
				runtime, _ := publishedMachineConfiguration(t, s, node)
				if runtime.ConfigDigest == expired.PendingConfigDigest {
					t.Fatal("published the replacement after its force generation was superseded")
				}
			}
			state, _, err := s.loadTunnel(t.Context(), node)
			if err != nil {
				t.Fatal(err)
			}
			if !rotated || state.Generation <= expired.Generation+1 || state.CredentialGeneration == initial.CredentialGeneration {
				t.Fatal("expected connector rotation to advance the generation")
			}
			if state.ForcedDrainTarget != "" || state.ApplyingConfigDigest != "" || state.HeldOrchestrator == "" {
				t.Fatal("expected the old workload to stay held after rotation")
			}
		})
	}
}

func TestForceAcrossRetryOrObservationFailure(t *testing.T) {
	for _, action := range []string{"ordinary retry", "timeout before publication", "timeout after publication"} {
		t.Run(action, func(t *testing.T) {
			s, _ := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("9", 64))
			readyTunnel(t, s, c)
			adminA(t, s)
			node := c["node_id"]
			s.params.RuntimeNodeImage = "registry.invalid/node@sha256:" + strings.Repeat("d", 64)
			configureTestTunnels(t, s)
			expired := expireWorkloadDrain(t, s, node)
			path := "/api/admin/machines/" + node + "/drain/"
			requireStatus(t, request(t, s, "POST", path+"force", "session-a", map[string]int64{"generation": expired.Generation}), 202)
			if err := s.tunnels.Reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			if action == "timeout after publication" {
				if err := s.configs.Reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			state, _, err := s.loadTunnel(t.Context(), node)
			previous, _ := publishedMachineConfiguration(t, s, node)
			published := previous.ConfigDigest == expired.PendingConfigDigest
			if err != nil || state.ApplyingConfigDigest != expired.PendingConfigDigest || published != (action == "timeout after publication") {
				t.Fatal("unexpected publication state for planned force", err)
			}

			switch action {
			case "ordinary retry":
				requireStatus(t, request(t, s, "POST", path+"retry", "session-a", map[string]int64{"generation": state.Generation}), 202)
			case "timeout before publication", "timeout after publication":
				tx, err := s.db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				if _, err = tx.Exec(`LOCK TABLE lpcc.onchain_state IN ACCESS EXCLUSIVE MODE`); err != nil {
					t.Fatal(err)
				}
				if err = s.configs.Reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err = tx.Rollback(); err != nil {
					t.Fatal(err)
				}
				state, _, err = s.loadTunnel(t.Context(), node)
				if err != nil || state.RolloutReason != "lifecycle_observation_failed" || state.HeldOrchestrator == "" {
					t.Fatal("expected management reconcile to retain the previous workload", err)
				}
			}
			wantPaused := action != "timeout after publication"
			if !wantPaused {
				reportRuntime(t, s, c, "runtime", true)
			}
			for range 2 {
				if err := s.reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			runtime, _ := publishedMachineConfiguration(t, s, node)
			want := expired.PendingConfigDigest
			if action == "ordinary retry" {
				want = previous.ConfigDigest
			}
			if runtime.ConfigDigest != want || runtime.DrainRequested != wantPaused {
				t.Fatal("unexpected workload after reconciliation", runtime.ConfigDigest, runtime.DrainRequested)
			}
		})
	}
}

func TestForceRolloutRejectsInitialPublicExposure(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("c", 64))
	adminA(t, s)
	node := c["node_id"]
	_, previous := publishedMachineConfiguration(t, s, node)
	reportRuntime(t, s, c, "runtime", false)
	driveTunnels(t, s)
	expired := expireWorkloadDrain(t, s, node)
	if expired.Target != "" || expired.HeldOrchestrator != previous {
		t.Fatal("expected initial public exposure to use a workload drain")
	}
	path := "/api/admin/machines/" + node + "/drain/force"
	requireStatus(t, request(t, s, "POST", path, "session-a", map[string]int64{"generation": expired.Generation}), 409)
}

func TestForceRolloutFencesOnchainChangeBeforeRender(t *testing.T) {
	s, _, c := onchainMachine(t)
	node := c["node_id"]
	adminA(t, s)
	next, err := s.loadOnchainTemplate()
	if err != nil {
		t.Fatal(err)
	}
	next.RedeemerURL = "https://api.example/pending"
	writeOnchainTemplate(t, s, next)
	expired := expireWorkloadDrain(t, s, node)
	previous, _ := publishedMachineConfiguration(t, s, node)
	path := "/api/admin/machines/" + node + "/drain/force"
	requireStatus(t, request(t, s, "POST", path, "session-a", map[string]int64{"generation": expired.Generation}), 202)

	var database string
	if err := s.db.QueryRow(`SELECT current_database()`).Scan(&database); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database, cfg.DefaultQueryExecMode = database, pgx.QueryExecModeExec
	changed := false
	cfg.Tracer = onchainQueryTrace(func(query string) {
		if changed || !strings.HasPrefix(query, "UPDATE lpcc.machine_states SET apps_generation=1,revision=") {
			return
		}
		changed = true
		next.TicketFaceValue = "4321"
		writeOnchainTemplate(t, s, next)
		if enrolled := enroll(t, s, ownerA, strings.Repeat("a", 64)); enrolled["node_id"] != node {
			t.Fatal("onchain settings change created a new enrollment")
		}
	})
	db := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { db.Close() })
	s.db = db
	s.configs = s.newConfigurationManager()
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	runtime, _ := publishedMachineConfiguration(t, s, node)
	if !changed || runtime.ConfigDigest != previous.ConfigDigest {
		t.Fatal("published a different configuration after force authorization", changed, runtime.ConfigDigest)
	}
}

func expireWorkloadDrain(t *testing.T, s *Server, node string) machineconfig.State {
	t.Helper()
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{drain_started_at}',to_jsonb($2::text)) WHERE node_id=$1`, node, time.Now().Add(-24*time.Hour).Format(time.RFC3339Nano))
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	state, _, err := s.loadTunnel(t.Context(), node)
	if err != nil || state.RolloutReason != "drain_timeout" || state.PendingConfigDigest == "" {
		t.Fatal("expected an expired workload drain", state.RolloutReason, err)
	}
	return state.State
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
			jwt, _, _ := s.params.signEnrollment(ownerA, testOrchestrator(ownerA), time.Now())
			requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/credentials/refresh", jwt, map[string]any{"management_proof": s.enrollmentToken(m), "fingerprint": m.Fingerprint, "install_dir": m.InstallDir, "operation_id": uuid.New().String(), "expected_credential_version": 1}), 200)
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
			jwt, _, _ := s.params.signEnrollment(ownerA, testOrchestrator(ownerA), time.Now())
			requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/credentials/refresh", jwt, map[string]any{"management_proof": s.enrollmentToken(m), "fingerprint": m.Fingerprint, "install_dir": m.InstallDir, "operation_id": uuid.New().String(), "expected_credential_version": 1}), 200)
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
	for _, kind := range []string{"connector"} {
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
	testTunnelDeps(s).Provider = &endpointCreateFailure{f}
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

// Count client commands without logging SQL arguments or bundle contents.
type configurationQueryCounter struct{ queries int }

func (c *configurationQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.queries++
	return ctx
}
func (*configurationQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestConfigurationFetchUpdatesTimestamp(t *testing.T) {
	s := newTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("a", 64))
	other := enroll(t, s, ownerB, strings.Repeat("b", 64))
	node := c["node_id"]
	var bundle []byte
	var digest, database string
	if err := s.db.QueryRow(`SELECT bundle,sha256,current_database() FROM lpcc.machine_configs WHERE node_id=$1`, node).Scan(&bundle, &digest, &database); err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	config.Database = database
	config.DefaultQueryExecMode = pgx.QueryExecModeExec
	counter := &configurationQueryCounter{}
	config.Tracer = counter
	db := sql.OpenDB(stdlib.GetConnector(*config))
	t.Cleanup(func() { db.Close() })
	s.db = db
	path := "/v1/nodes/" + node + "/config"
	for _, token := range []string{c["token"], c["token"], other["token"]} {
		before := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
		if _, err := db.Exec(`UPDATE lpcc.machines SET last_config_fetch_at=$2 WHERE node_id=$1`, node, before); err != nil {
			t.Fatal(err)
		}
		counter.queries = 0
		w := request(t, s, "GET", path, token, nil)
		queries := counter.queries
		var fetched time.Time
		if err := db.QueryRow(`SELECT last_config_fetch_at FROM lpcc.machines WHERE node_id=$1`, node).Scan(&fetched); err != nil {
			t.Fatal(err)
		}
		if token != c["token"] {
			if w.Code != 401 || !fetched.Equal(before) {
				t.Fatal("unauthorized fetch changed timestamp", w.Code, fetched)
			}
			continue
		}
		if w.Code != 200 || queries != 2 || !fetched.After(before) {
			t.Fatal("live fetch must use two commands and refresh timestamp", w.Code, queries, fetched)
		}
		if !bytes.Equal(w.Body.Bytes(), bundle) || digest != fmt.Sprintf("%x", sha256.Sum256(bundle)) || w.Header().Get("ETag") != `"`+digest+`"` || w.Header().Get("Content-Type") != "application/gzip" || w.Header().Get("X-Livepeer-Node-ID") != node || w.Header().Get("X-Livepeer-Credential-Version") != "1" || w.Header().Get("X-Livepeer-Terminal") != "false" || w.Header().Get("X-Livepeer-App-Cleanup-Ready") != "" {
			t.Fatal("configuration content or headers changed")
		}
	}
	if _, err := db.Exec(`DELETE FROM lpcc.machine_configs WHERE node_id=$1`, node); err != nil {
		t.Fatal(err)
	}
	var before, after time.Time
	if err := db.QueryRow(`SELECT last_config_fetch_at FROM lpcc.machines WHERE node_id=$1`, node).Scan(&before); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, "GET", path, c["token"], nil)
	if err := db.QueryRow(`SELECT last_config_fetch_at FROM lpcc.machines WHERE node_id=$1`, node).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if w.Code != 404 || !before.Equal(after) {
		t.Fatal("missing bundle marked a fetch", w.Code, before, after)
	}
}

func TestConfigurationFetchFencedAfterLockWait(t *testing.T) {
	for _, change := range []string{"refresh", "retire"} {
		t.Run(change, func(t *testing.T) {
			s := newTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("c", 64))
			node := c["node_id"]
			blocking, err := s.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer blocking.Rollback()
			if _, err := blocking.Exec(`SELECT FROM lpcc.machines WHERE node_id=$1 FOR UPDATE`, node); err != nil {
				t.Fatal(err)
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- request(t, s, "GET", "/v1/nodes/"+node+"/config", c["token"], nil) }()
			waitForStateLock(t, s, "UPDATE lpcc.machines m SET last_config_fetch_at=%", 1)
			if change == "refresh" {
				if _, err := blocking.Exec(`UPDATE lpcc.machines SET credential_version=credential_version+1 WHERE node_id=$1`, node); err != nil {
					t.Fatal(err)
				}
				if _, err := blocking.Exec(`UPDATE lpcc.enrollments SET credential_version=credential_version+1 WHERE node_id=$1`, node); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := blocking.Exec(`DELETE FROM lpcc.machines WHERE node_id=$1`, node); err != nil {
					t.Fatal(err)
				}
			}
			if err := blocking.Commit(); err != nil {
				t.Fatal(err)
			}
			w := <-done
			if w.Code != 404 || w.Header().Get("ETag") != "" {
				t.Fatal("racing fetch returned a bundle", w.Code)
			}
			if change == "refresh" {
				var fetched sql.NullTime
				if err := s.db.QueryRow(`SELECT last_config_fetch_at FROM lpcc.machines WHERE node_id=$1`, node).Scan(&fetched); err != nil {
					t.Fatal(err)
				}
				if fetched.Valid {
					t.Fatal("stale credential marked a fetch")
				}
			}
		})
	}
}
