package controlplane

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/schema"
)

func TestAppReconcilerReportOrderingAndDuplicateFreshness(t *testing.T) {
	s := newTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("a", 64))
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	payload := machineconfig.Report{ReportVersion: 1, ObservedAt: time.Now().UTC(), Epoch: c["epoch"], CredentialVersion: 1, Component: "runner", Generation: 1, BundleFormat: contract.BundleFormat, Sequence: 1, Ready: true, Reason: "ready", Apps: &contract.AppStatus{Instances: []contract.InstanceStatus{}}}
	path := "/v1/nodes/" + c["node_id"] + "/status"
	requireStatus(t, request(t, s, "POST", path, c["token"], payload), 200)
	var received time.Time
	if err := s.db.QueryRow(`SELECT received_at FROM lpcc.machine_reports WHERE node_id=$1 AND component='runner'`, c["node_id"]).Scan(&received); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, request(t, s, "POST", path, c["token"], payload), 200)
	var repeated time.Time
	s.db.QueryRow(`SELECT received_at FROM lpcc.machine_reports WHERE node_id=$1 AND component='runner'`, c["node_id"]).Scan(&repeated)
	if !received.Equal(repeated) {
		t.Fatal("duplicate report renewed old proof age")
	}
	payload.Ready = false
	requireStatus(t, request(t, s, "POST", path, c["token"], payload), 409)
	payload.Sequence = 2
	requireStatus(t, request(t, s, "POST", path, c["token"], payload), 200)
	payload.Sequence = 1
	requireStatus(t, request(t, s, "POST", path, c["token"], payload), 409)
	payload.Sequence = 3
	payload.Drained = true
	requireStatus(t, request(t, s, "POST", path, c["token"], payload), 409)
}

func TestTerminalConnectorSurvivesOnlyPendingAppCleanup(t *testing.T) {
	for _, compromise := range []string{"none", "access", "connector"} {
		t.Run(compromise, func(t *testing.T) {
			s, f := tunnelTestServer(t)
			adminA(t, s)
			c := enroll(t, s, ownerA, strings.Repeat("f", 64))
			initial := readyTunnel(t, s, c)
			s.params.AppStopSignals = true
			s.configs = s.newConfigurationManager()
			requireStatus(t, request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/status", c["token"], currentReport(t, s, c["node_id"], machineconfig.Report{Epoch: c["epoch"], CredentialVersion: 1, Component: "runtime", Generation: initial.Generation, BundleFormat: contract.BundleFormat, Reason: "ready"})), 200)
			if err := s.reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			revision := publishAssignmentRevision(t, s, registryFixture(t), "")
			requireStatus(t, putApp(t, s, c, revision, 0, 1), 202)
			if err := s.reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			if compromise != "none" {
				requireStatus(t, request(t, s, "POST", "/api/admin/machines/"+c["node_id"]+"/tunnel/rotate", "session-a", map[string]any{"epoch": c["epoch"], "kind": compromise, "compromised": true}), 202)
			}
			requireStatus(t, request(t, s, "DELETE", "/api/admin/machines/"+c["node_id"], "session-a", map[string]any{"epoch": c["epoch"], "force": true}), 202)
			path := "/v1/nodes/" + c["node_id"] + "/tunnel/connector-token"
			if compromise != "none" {
				requireStatus(t, request(t, s, "POST", path, c["token"], map[string]any{}), 409)
			}
			driveTunnels(t, s)
			retained, _, err := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
			if compromise != "none" {
				if err != nil || !retained.CleanupComplete || len(f.resources) != 0 || count(t, s, `SELECT count(*) FROM lpcc.access_credentials WHERE revoked_at IS NULL`) != 0 {
					t.Fatal("known compromise did not override app cleanup hold", retained, err)
				}
				return
			}
			if err != nil || retained.ConnectorRevoked || retained.CleanupComplete || f.disconnected != 0 || len(f.resources) == 0 {
				t.Fatal("provider routes/credentials removed before app cleanup", retained, err)
			}
			requireStatus(t, request(t, s, "POST", path, c["token"], map[string]any{}), 200)
			terminal := request(t, s, "GET", "/v1/nodes/"+c["node_id"]+"/config", c["token"], nil)
			requireStatus(t, terminal, 200)
			files := archiveFiles(t, terminal.Body.Bytes())
			if terminal.Header().Get("X-Livepeer-App-Cleanup-Ready") == "true" || strings.Contains(files["system/node/orchestrator.yaml"], "kind: Deployment") {
				t.Fatal("forced retirement retained Node or skipped pending app receipts")
			}
			raw := []byte(files[appbundle.IntentFile])
			set, err := schema.DecodeAssignmentSet(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range set.Entries {
				requireStatus(t, appReport(t, s, c, a, schema.Digest(raw), "removed"), 200)
			}
			requireStatus(t, request(t, s, "POST", path, c["token"], map[string]any{}), 401)
			driveTunnels(t, s)
			final, _, err := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
			if err != nil || !final.CleanupComplete || len(f.resources) != 0 {
				t.Fatal("provider cleanup failed after receipts", final, err)
			}
		})
	}
}

func TestManagementSurvivesUnsupportedAppRendering(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("b", 64))
	s.configs = s.newConfigurationManager()
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	supported := machineconfig.Report{Epoch: c["epoch"], CredentialVersion: 1, Component: "runtime", Generation: 1, BundleFormat: contract.BundleFormat, Reason: "ready"}
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/status", c["token"], currentReport(t, s, c["node_id"], supported)), 200)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := request(t, s, "GET", "/v1/nodes/"+c["node_id"]+"/config", c["token"], nil)
	requireStatus(t, first, 200)
	files := archiveFiles(t, first.Body.Bytes())
	var before machineconfig.Runtime
	json.Unmarshal([]byte(files["runtime.json"]), &before)
	if before.BundleFormat != contract.BundleFormat {
		t.Fatal("unexpected bundle version")
	}
	source := strings.Replace(registryFixture(t), `mode = "reusable"`, `mode = "single-session"`, 1)
	// The shared schema accepts single-session intent; this Runtime explicitly refuses its execution.
	revision := publishAssignmentRevision(t, s, source, "")
	requireStatus(t, putApp(t, s, c, revision, 0, 1), 202)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	next := request(t, s, "GET", "/v1/nodes/"+c["node_id"]+"/config", c["token"], nil)
	requireStatus(t, next, 200)
	files = archiveFiles(t, next.Body.Bytes())
	var after machineconfig.Runtime
	json.Unmarshal([]byte(files["runtime.json"]), &after)
	if after.AppsError == "" || after.AppsDigest != before.AppsDigest || after.AppsGeneration != before.AppsGeneration || files["management/app-reconciler.yaml"] == "" {
		t.Fatal("app failure suppressed management or changed delivered membership", after)
	}
}

func TestMaintenanceAdmissionFreezeEndsOnlyAtActualTarget(t *testing.T) {
	s := newTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("e", 64))
	s.configs = machineconfig.New(machineconfig.Config{RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64), NodeImage: "registry.invalid/node@sha256:" + strings.Repeat("c", 64), DrainTimeout: time.Hour}, machineconfig.Dependencies{DB: s.db, Logger: s.logger})
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	runtime := machineconfig.Report{Epoch: c["epoch"], CredentialVersion: 1, Component: "runtime", Generation: 1, BundleFormat: contract.BundleFormat, Reason: "ready"}
	path := "/v1/nodes/" + c["node_id"] + "/status"
	requireStatus(t, request(t, s, "POST", path, c["token"], currentReport(t, s, c["node_id"], runtime)), 200)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	state, err := (machineconfig.Store{DB: s.db}).Load(t.Context(), c["node_id"], c["epoch"])
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	drain := machineconfig.Report{Epoch: c["epoch"], CredentialVersion: 1, Component: "runner", Generation: state.Generation, BundleFormat: contract.BundleFormat, Sequence: 1, Drained: true, Reason: "drain_pending", Apps: &contract.AppStatus{Instances: []contract.InstanceStatus{}}, Evidence: &contract.Evidence{Kind: "no_owner", Target: machineconfig.DrainTarget(c["node_id"], c["epoch"], state.State), WithdrawalID: "withdrawal", ObservedAt: now, ExpiresAt: now.Add(30 * time.Second)}}
	requireStatus(t, request(t, s, "POST", path, c["token"], currentReport(t, s, c["node_id"], drain)), 200)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	state, err = (machineconfig.Store{DB: s.db}).Load(t.Context(), c["node_id"], c["epoch"])
	if err != nil {
		t.Fatal(err)
	}
	if state.HeldOrchestrator != "" || state.ApplyingConfigDigest == "" || !state.DrainRequested {
		t.Fatal("delivery release reopened admission", state.State)
	}
	runtime.Generation = state.Generation
	runtime.Ready = true
	runtime.ConfigDigest = state.ApplyingConfigDigest
	runtime.K3sVersion = "wrong-version"
	requireStatus(t, request(t, s, "POST", path, c["token"], currentReport(t, s, c["node_id"], runtime)), 200)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	pending, _ := (machineconfig.Store{DB: s.db}).Load(t.Context(), c["node_id"], c["epoch"])
	if !pending.DrainRequested {
		t.Fatal("unobserved K3s target reopened admission")
	}
	runtime.K3sVersion = state.ApplyingUpgradeVersion
	requireStatus(t, request(t, s, "POST", path, c["token"], currentReport(t, s, c["node_id"], runtime)), 200)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	complete, _ := (machineconfig.Store{DB: s.db}).Load(t.Context(), c["node_id"], c["epoch"])
	if complete.DrainRequested || complete.ApplyingConfigDigest != "" {
		t.Fatal("verified actual target did not release admission", complete.State)
	}
}
