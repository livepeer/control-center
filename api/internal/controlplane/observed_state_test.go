package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	fleet "github.com/livepeer/control-center/api/internal/controlplane/discovery"
	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
	"github.com/livepeer/control-center/runtime/management"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/httpsource"
	"github.com/livepeer/control-center/runtime/transport"
	"github.com/livepeer/control-center/schema"
)

type observationQueryCounter struct{ atomic.Int64 }

func (c *observationQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.Add(1)
	return ctx
}
func (*observationQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestObservedStateScalarProjection(t *testing.T) {
	s, desired, machine := onchainMachine(t)
	node := machine["node_id"]
	var database string
	if err := s.db.QueryRow(`SELECT current_database()`).Scan(&database); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	queries := &observationQueryCounter{}
	cfg.Database, cfg.Tracer, cfg.DefaultQueryExecMode = database, queries, pgx.QueryExecModeExec
	s.db = stdlib.OpenDB(*cfg)
	t.Cleanup(func() { s.db.Close() })
	read := func(lifecycle string) machineObservation {
		t.Helper()
		queries.Store(0)
		w := request(t, s, "GET", "/api/machines/"+node+"/status", "session-a", nil)
		requireStatus(t, w, 200)
		if got := queries.Load(); got != 3 {
			t.Fatalf("status executed %d SQL statements, want 3", got)
		}
		var v machineObservation
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		if v.Lifecycle != lifecycle || v.Onchain.Desired.Generation != 2 || v.Onchain.DeliveredGeneration != 1 || v.Onchain.Desired.RPCSecret != "" || len(v.Onchain.Desired.RPCGrants)+len(v.Onchain.Desired.RedeemerGrants) != 0 {
			t.Fatalf("incorrect lifecycle or onchain projection: %+v", v)
		}
		return v
	}
	// Desired onchain state can advance while the published bundle stays older.
	desired.Generation = 2
	desired.RPCGrants, desired.RedeemerGrants = []string{"10.0.0.1:443"}, []string{"10.0.0.2:443"}
	raw, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}
	execSQL(t, s.db, `INSERT INTO lpcc.onchain_configs(fingerprint,generation,config) SELECT fingerprint,2,$2 FROM lpcc.enrollments WHERE node_id=$1`, node, string(raw))
	execSQL(t, s.db, `UPDATE lpcc.onchain_state SET generation=2 WHERE fingerprint=(SELECT fingerprint FROM lpcc.enrollments WHERE node_id=$1)`, node)
	execSQL(t, s.db, `INSERT INTO lpcc.machine_states(node_id,state,apps_generation,apps_error) VALUES($1,'{}',23,'private diagnostic')
 ON CONFLICT(node_id) DO UPDATE SET apps_generation=EXCLUDED.apps_generation,apps_error=EXCLUDED.apps_error`, node)
	at := time.Now().UTC().Truncate(time.Microsecond)
	for _, generation := range []int64{10, 11, 99} {
		published := at
		if generation == 99 {
			published = at.Add(-time.Hour)
		}
		digest := fmt.Sprintf("%064x", generation)
		execSQL(t, s.db, `INSERT INTO lpcc.machine_app_deliveries(node_id,apps_digest,bundle_sha256,apps_generation,entries,terminal,published_at) VALUES($1,$2,$3,$4,'[]',false,$5)`, node, "sha256:"+digest, digest, generation, published)
	}
	v := read("active")
	if v.Requested.Generation != 23 || v.DeliveryReason != "unknown_failure" || v.Delivered == nil || v.Delivered.Generation != 11 || v.Delivered.AppsDigest != "sha256:"+fmt.Sprintf("%064x", 11) || v.Delivered.ArtifactDigest != v.Delivered.AppsDigest || v.DeliveredAt == nil || !v.DeliveredAt.Equal(at) {
		t.Fatalf("incorrect requested/latest delivery projection: %+v", v)
	}
	// Retirement removes machine_configs; delivered onchain evidence uses the
	// retained live bundle, even if a terminal bundle is present.
	execSQL(t, s.db, `DELETE FROM lpcc.machines WHERE node_id=$1`, node)
	execSQL(t, s.db, `UPDATE lpcc.enrollments SET terminal_bundle='invalid',terminal_sha256=$2 WHERE node_id=$1`, node, strings.Repeat("a", 64))
	read("cleanup_pending")
	execSQL(t, s.db, `UPDATE lpcc.enrollments SET removal_ack_at=now() WHERE node_id=$1`, node)
	read("removed")
	// Invalid retained archives are ignored, as for invalid live archives.
	execSQL(t, s.db, `UPDATE lpcc.enrollments SET retained_bundle='invalid' WHERE node_id=$1`, node)
	v, err = s.machineObservation(t.Context(), Machine{NodeID: node, CredentialVersion: 1, Terminal: true})
	if err != nil || v.Onchain.DeliveredGeneration != 0 {
		t.Fatal("invalid retained bundle produced delivery evidence", err)
	}
}

func TestObservedStateMissingScalars(t *testing.T) {
	s := newTestServer(t)
	machine := enroll(t, s, ownerA, strings.Repeat("a", 64))
	node := machine["node_id"]
	execSQL(t, s.db, `DELETE FROM lpcc.machine_states WHERE node_id=$1`, node)
	execSQL(t, s.db, `DELETE FROM lpcc.machine_configs WHERE node_id=$1`, node)
	for _, id := range []string{node, "missing"} {
		v, err := s.machineObservation(t.Context(), Machine{NodeID: id, CredentialVersion: 1})
		if err != nil || v.Lifecycle != "active" || v.RolloutGeneration != 1 || v.Requested.Generation != 0 || v.DeliveryReason != "" || v.Delivered != nil || v.DeliveredAt != nil || v.Onchain.Desired.Mode != "offchain" || v.Onchain.DeliveredGeneration != 0 {
			t.Fatalf("missing scalar defaults: %+v, %v", v, err)
		}
	}
	if _, err := s.machineObservation(t.Context(), Machine{NodeID: "missing", Terminal: true}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing terminal enrollment: %v", err)
	}
}

func TestSharedAppMembershipQueries(t *testing.T) {
	a := observedAssignment{Name: "backend", Version: "v1", DiscoveryApps: []string{"first", "second"}}
	i := contract.InstanceStatus{InstanceID: "instance", AppID: "r-instance-0"}
	for _, mode := range []string{"persistent", "single-shot"} {
		a.Mode = mode
		queries := a.membershipQueries(i, "https://orch.example", "https://{proxy}.apps.example")
		if len(queries) != 2 {
			t.Fatal("missing public app query", queries)
		}
		for n, q := range queries {
			endpoint := fmt.Sprintf("https://orch.example/apps/r-instance-%d/session", n)
			if mode == "single-shot" {
				endpoint = fmt.Sprintf("https://r-instance-%d.apps.example", n)
			}
			if q.InstanceID != i.InstanceID || q.App != a.DiscoveryApps[n] || q.Version != a.Version || q.Endpoint != endpoint {
				t.Fatalf("wrong app membership query: %+v", q)
			}
		}
	}
}

func observationFixture(t *testing.T) (*Server, map[string]string, contract.Metadata, schema.AppAssignment) {
	t.Helper()
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("a", 64))
	s.params.RuntimeImage = "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64)
	s.params.AppStopSignals = true
	s.configs = s.newConfigurationManager()
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/status", c["token"], currentReport(t, s, c["node_id"], machineconfig.Report{NodeID: c["node_id"], CredentialVersion: 1, Component: "runtime", Generation: 1, BundleFormat: contract.BundleFormat, Reason: "applying"})), 200)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(registryFixture(t), "LOG_LEVEL = \"info\"", "LOG_LEVEL = \"environment-sentinel\"", 1)
	r := publishAssignmentRevision(t, s, source, "")
	requireStatus(t, putApp(t, s, c, r, 0, 1), 202)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, "GET", "/v1/nodes/"+c["node_id"]+"/config", c["token"], nil)
	requireStatus(t, w, 200)
	files := archiveFiles(t, w.Body.Bytes())
	var m contract.Metadata

	if err := json.Unmarshal([]byte(files["runtime.json"]), &m); err != nil {
		t.Fatal(err)
	}

	var intent []byte
	if err := s.db.QueryRow(`SELECT entries FROM lpcc.machine_app_deliveries WHERE node_id=$1 AND apps_digest=$2 LIMIT 1`, m.NodeID, m.AppsDigest).Scan(&intent); err != nil {
		t.Fatal(err)
	}
	var entries []schema.AppAssignment
	if err := json.Unmarshal(intent, &entries); err != nil || len(entries) != 1 {
		t.Fatal("missing delivery", err)
	}
	return s, c, m, entries[0]
}

func observationReport(m contract.Metadata, a schema.AppAssignment) machineconfig.Report {
	now := time.Now().UTC()
	return machineconfig.Report{ReportVersion: 1, ObservedAt: now, NodeID: m.NodeID, CredentialVersion: m.CredentialVersion, Component: "runner", Generation: m.Generation, BundleFormat: contract.BundleFormat, Sequence: 1, Ready: true, Reason: "ready", Apps: &contract.AppStatus{DesiredGeneration: m.AppsGeneration, DesiredDigest: m.AppsDigest, Assignments: []contract.AssignmentStatus{{RevisionID: a.RevisionID, Generation: a.Generation, ActivationGeneration: a.ActivationGeneration, Instances: 1, Ready: 1, Registered: 1}}, InstancesTotal: 1, Instances: []contract.InstanceStatus{{RevisionID: a.RevisionID, Generation: a.Generation, ActivationGeneration: a.ActivationGeneration, InstanceID: "instance-1", PodUID: "pod-1", RunnerID: "runner-1", AppID: "app-1", Phase: "running", Ready: true, Registered: true, Capacity: 1, Sessions: 0, NodeObservedAt: now, NodeExpiresAt: now.Add(30 * time.Second), AcceptedSequence: new(uint64(1))}}}}
}

func TestFleetReadinessEvidenceRequiresNodeAdmission(t *testing.T) {
	s, c, m, a := observationFixture(t)
	runtime := currentReport(t, s, m.NodeID, machineconfig.Report{
		NodeID: m.NodeID, CredentialVersion: m.CredentialVersion, Component: "runtime",
		Generation: m.Generation, BundleFormat: contract.BundleFormat, Ready: true, Reason: "ready",
	})
	path := "/v1/nodes/" + m.NodeID + "/status"
	requireStatus(t, request(t, s, "POST", path, c["token"], runtime), 200)
	runner := observationReport(m, a)
	runner.Apps.Applied = &contract.StageIdentity{
		Generation: m.AppsGeneration, AppsDigest: m.AppsDigest, ArtifactDigest: "sha256:" + strings.Repeat("4", 64),
	}
	expiry := runner.ObservedAt.Add(15 * time.Second)
	runner.Apps.Assignments[0].NodeExpiresAt = runner.Apps.Instances[0].NodeExpiresAt
	runner.Apps.Assignments[0].ProbeExpiresAt = expiry
	requireStatus(t, request(t, s, "POST", path, c["token"], runner), 200)
	check := func(wantNode string, admitted int, pending bool) {
		t.Helper()
		checkEvidence := func(e *machineReadinessEvidence) {
			t.Helper()
			if e == nil || e.Node.State != wantNode || !e.Apps.Complete || !e.Apps.Applied || e.Apps.Requested != 1 ||
				e.Apps.Admitted != admitted || (e.Apps.Pending != nil) != pending ||
				(admitted > 0 && (e.Apps.AdmittedValidForMS <= 0 || e.Apps.AdmittedValidForMS > 15000)) {
				t.Fatalf("readiness evidence = %+v", e)
			}
		}
		for _, path := range []string{"/api/machines?orchestrator_address=" + orchA, "/api/admin/overview"} {
			w := request(t, s, "GET", path, "session-a", nil)
			requireStatus(t, w, 200)
			var got struct{ Machines []observedMachineSummary }
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got.Machines) != 1 {
				t.Fatalf("unexpected fleet response for %s: %v (%v)", path, got.Machines, err)
			}
			checkEvidence(got.Machines[0].ReadinessEvidence)
		}
		w := request(t, s, "GET", "/api/machines/"+m.NodeID+"/status", "session-a", nil)
		requireStatus(t, w, 200)
		var detail machineObservation
		if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
			t.Fatal(err)
		}
		checkEvidence(detail.ReadinessEvidence)
	}

	check("ready", 0, false) // An older report attests health and registration alone.
	runner = currentReport(t, s, m.NodeID, runner)
	runner.Apps.Assignments[0].Admission = &contract.ReplicaAdmission{}
	requireStatus(t, request(t, s, "POST", path, c["token"], runner), 200)
	check("ready", 0, true)
	runner = currentReport(t, s, m.NodeID, runner)
	runner.Apps.Assignments[0].Admission = &contract.ReplicaAdmission{Ready: 1, ExpiresAt: expiry}
	runner.Apps.Instances[0].AdmissionExpiresAt = expiry
	runner.Apps.Instances[0].Probe = &contract.ProbeStatus{ObservedAt: expiry.Add(-15 * time.Second), ExpiresAt: expiry, Success: true, Started: true}
	runner.Apps.Assignments[0].Admission.ExpiresAt = expiry.Add(time.Second)
	requireStatus(t, request(t, s, "POST", path, c["token"], runner), 409)
	runner.Apps.Assignments[0].Admission.ExpiresAt = expiry
	requireStatus(t, request(t, s, "POST", path, c["token"], runner), 200)
	check("ready", 1, false)
	execSQL(t, s.db, `UPDATE lpcc.machine_reports SET report=jsonb_set(report,'{apps,assignments,0,admission,expires_at}',to_jsonb(now()-interval '1 second'))
 WHERE node_id=$1 AND component='runner'`, m.NodeID)
	check("ready", 0, false)
	runtime = currentReport(t, s, m.NodeID, runtime)
	runtime.Ready, runtime.Reason = false, "applying"
	requireStatus(t, request(t, s, "POST", path, c["token"], runtime), 200)
	check("pending", 0, false)
}

func TestReadinessEvidenceFencesIngressAndDiscovery(t *testing.T) {
	now := time.Now()
	expires := now.Add(time.Minute)
	instance := contract.InstanceStatus{RevisionID: "app", InstanceID: "instance", Generation: 1, ActivationGeneration: 1,
		Ready: true, Registered: true, AdmissionExpiresAt: expires}
	apps := &contract.AppStatus{DesiredGeneration: 1, Applied: &contract.StageIdentity{Generation: 1},
		Instances: []contract.InstanceStatus{instance},
		Assignments: []contract.AssignmentStatus{{RevisionID: "app", Generation: 2, ActivationGeneration: 1, Instances: 2,
			Ready: 2, Registered: 2, Admission: &contract.ReplicaAdmission{Ready: 2, ExpiresAt: expires}}}}
	report := componentObservation{Fresh: true, Current: true, Ready: true, ReceivedAt: &now, ExpiresAt: &expires}
	runtime, runner, connector := report, report, report
	runtime.Component, runner.Component, connector.Component = "runtime", "runner", "connector"
	runner.Apps, connector.ConnectorExpiresAt = apps, &expires
	view := machineObservation{
		ServerTime: now, Lifecycle: "active", Requested: contract.StageIdentity{Generation: 1},
		Components:       []componentObservation{runtime, runner, connector},
		Assignments:      []observedAssignment{{RevisionID: "app", Generation: 2, ActivationGeneration: 1, Desired: "present", Replicas: 1, StartAllowed: true}},
		Tunnel:           tunnelObservation{Enabled: true, Ready: true, IngressVerified: true, SourceGeneration: 2, ExpiresAt: &expires},
		DiscoveryEnabled: true, DiscoveryInitialized: true, DiscoverySelectionExpiresAt: &expires,
		DiscoverySource: &fleet.SourceStatus{State: "fresh", SelectedGeneration: 2, ExpiresAt: &expires, PublicationBlocked: true},
		Membership:      map[string]fleet.Membership{"instance": {State: "present", ExpiresAt: &expires, SourceGeneration: 2}},
	}
	check := func(ingress, discovery string, admitted int) {
		t.Helper()
		e := view.readinessEvidence()
		if e.Ingress.State != ingress || e.Discovery.State != discovery || e.Apps.Admitted != admitted {
			t.Fatalf("ingress=%+v discovery=%+v apps=%+v", e.Ingress, e.Discovery, e.Apps)
		}
	}
	check("ready", "ready", 1) // Retained instance and exact publication survive scale-down and unrelated filtering.
	a := &view.Assignments[0]
	a.Replicas, a.Failure = 2, "reconcile_failed"
	reported := &apps.Assignments[0]
	reported.Admission.Ready, reported.Reason = 1, "secrets_unavailable"
	if e := view.readinessEvidence().Apps; e.Admitted != 1 || e.Blocker == nil || e.Blocker.Reason != "secrets_unavailable" {
		t.Fatalf("current admission and cause were hidden by Flux failure: %+v", e)
	}
	a.Replicas, a.Failure, reported.Admission.Ready, reported.Reason = 1, "", 2, ""
	view.Tunnel.IngressVerified = false
	check("pending", "ready", 1)
	view.Tunnel.IngressVerified = true
	view.Components[2].ConnectorExpiresAt = &now
	check("unverified", "ready", 1)
	view.Components[2].ConnectorExpiresAt = &expires
	view.DiscoverySource.SelectedGeneration--
	check("ready", "unverified", 1)
	view.DiscoverySource.SelectedGeneration++
	apps.Instances[0].AdmissionExpiresAt = now
	check("ready", "unverified", 1)
	view.DiscoverySource.State, view.DiscoverySource.SelectionReason = "excluded", "blocked"
	check("ready", "blocked", 1)
	view.Requested.Generation = 2
	apps.Reason = "resource_refused"
	if e := view.readinessEvidence(); e.Apps.Blocker != nil || e.Apps.Admitted != 0 {
		t.Fatalf("an old app report established current evidence: %+v", e.Apps)
	}
}

func TestReplicaIssuesKeepTheirOwnFreshness(t *testing.T) {
	now := time.Now()
	probeExpiry := now.Add(3 * time.Second)
	a := observedAssignment{RevisionID: "app", Generation: 1, ActivationGeneration: 1, Replicas: 1}
	i := contract.InstanceStatus{RevisionID: "app", Generation: 1, ActivationGeneration: 1, Probe: &contract.ProbeStatus{ExpiresAt: probeExpiry}}
	for _, tc := range []struct {
		reason string
		clock  time.Time
		ttl    int64
	}{
		{"readiness_failed", now, 3000}, {"readiness_failed", probeExpiry, 0},
		{"stop_signal_unverified", now, 30000}, {"secret_invalid", now, 30000},
	} {
		i.Reason = tc.reason
		_, _, issue := replicaEvidence(a, &contract.AppStatus{Instances: []contract.InstanceStatus{i}}, tc.clock, now.Add(30*time.Second))
		if issue.ValidForMS != tc.ttl || (tc.ttl > 0 && issue.Reason != tc.reason) {
			t.Fatalf("%s at %s: %+v", tc.reason, tc.clock, issue)
		}
	}
}

func TestObservedStateOwnerAdminBoundariesAndRedaction(t *testing.T) {
	s, c, m, a := observationFixture(t)
	report := observationReport(m, a)
	recordedAt := time.Now().Add(-24 * time.Hour).UTC()
	software := []contract.SoftwareIdentity{{Component: "runtime", Scope: "running", Version: "v1", Commit: strings.Repeat("a", 40)}, {Component: "gvisor", Scope: "installed", Version: "release-observed", RecordedAt: &recordedAt}}
	runtimeReport := currentReport(t, s, m.NodeID, machineconfig.Report{NodeID: m.NodeID, CredentialVersion: m.CredentialVersion, Component: "runtime", Generation: m.Generation, Reason: "applying", Software: software})
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/status", c["token"], runtimeReport), 200)
	runtimeReport = currentReport(t, s, m.NodeID, runtimeReport)
	for _, digest := range []string{"invalid", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		runtimeReport.IngressConfigDigest = digest
		requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/status", c["token"], runtimeReport), 400)
	}
	runtimeReport.IngressReady, runtimeReport.IngressConfigDigest = true, strings.Repeat("e", 64)
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/status", c["token"], runtimeReport), 200)
	path := "/v1/nodes/" + m.NodeID + "/status"
	requireStatus(t, request(t, s, "POST", path, c["token"], report), 200)
	read := "/api/machines/" + m.NodeID + "/status"
	w := request(t, s, "GET", read, "session-a", nil)
	requireStatus(t, w, 200)
	var v machineObservation
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	for _, component := range v.Components {
		if component.Component == "runtime" && (!component.Fresh || !reflect.DeepEqual(component.Software, software) || !component.IngressReady || component.IngressConfigDigest != runtimeReport.IngressConfigDigest) {
			t.Fatal("lost software, timestamp or ingress evidence", w.Body.String())
		}
	}
	if len(v.Assignments) != 1 || v.Assignments[0].Generation != a.Generation || v.Delivered == nil || v.Delivered.AppsDigest != m.AppsDigest || v.ExternalReachability != "unverified" {
		t.Fatal("lost desired/delivery evidence", w.Body.String())
	}
	for _, secret := range []string{"environment-sentinel", c["token"], `"container":`, `"environment":`, `"actor_id":`, `"runner_service_url":`, "10.43."} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("unsafe projection", secret)
		}
	}
	requireStatus(t, request(t, s, "GET", read, "session-b", nil), 404)
	requireStatus(t, request(t, s, "GET", read, c["token"], nil), 401)
	other := enroll(t, s, ownerB, strings.Repeat("b", 64))
	requireStatus(t, request(t, s, "GET", "/api/machines/"+other["node_id"]+"/status", "session-a", nil), 200)
	// Owner B can inspect its status, but has no assignment/admin mutation authority.
	requireStatus(t, request(t, s, "GET", "/api/machines/"+other["node_id"]+"/status", "session-b", nil), 200)
	requireStatus(t, request(t, s, "PUT", "/api/admin/machines/"+other["node_id"]+"/apps/"+a.RevisionID, "session-b", map[string]any{}), 403)
	// A different machine credential cannot submit this report.
	requireStatus(t, request(t, s, "POST", path, other["token"], report), 401)
	oversized := report
	oversized.Reason = strings.Repeat("x", contract.MaxStatusBytes)
	requireStatus(t, request(t, s, "POST", path, c["token"], oversized), 400)
	requireStatus(t, appReport(t, s, c, a, m.AppsDigest, "failed"), 200)
	w = request(t, s, "GET", read, "session-a", nil)
	requireStatus(t, w, 200)
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || v.Assignments[0].Failure != "reconcile_failed" {
		t.Fatal("failure diagnostic missing", w.Body.String(), err)
	}
	requireStatus(t, appReport(t, s, c, a, m.AppsDigest, "applied"), 200)
	w = request(t, s, "GET", read, "session-a", nil)
	requireStatus(t, w, 200)
	v = machineObservation{}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || v.Assignments[0].Failure != "" || v.Assignments[0].CompletedAt == nil {
		t.Fatal("completion retained an obsolete failure", w.Body.String(), err)
	}

	// Known catalog identities that were never delivered are not observations.
	report.Sequence++
	report.Apps.Instances[0].Generation++
	requireStatus(t, request(t, s, "POST", path, c["token"], report), 409)
	revision, err := loadPinnedRevision(t.Context(), s.db, a.RevisionRef)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, putApp(t, s, c, revision, a.Generation, 2), 202)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	var generation int64
	var digest string
	if err := s.db.QueryRow(`SELECT apps_generation,apps_digest FROM lpcc.machine_app_deliveries WHERE node_id=$1 ORDER BY apps_generation DESC LIMIT 1`, m.NodeID).Scan(&generation, &digest); err != nil {
		t.Fatal(err)
	}
	newer := observationReport(m, a)
	newer.Sequence = 3
	newer.Apps.DesiredGeneration = generation
	newer.Apps.DesiredDigest = digest
	newer.Apps.Assignments[0].Generation++
	requireStatus(t, request(t, s, "POST", path, c["token"], newer), 200)
	older := observationReport(m, a)
	older.Sequence = 4
	requireStatus(t, request(t, s, "POST", path, c["token"], older), 409)

}

func TestNonRunnerOrderDuplicateAgeClockAndCredentialScope(t *testing.T) {
	s, c, m, a := observationFixture(t)
	p := "/v1/nodes/" + m.NodeID + "/status"
	runner := observationReport(m, a)
	requireStatus(t, request(t, s, "POST", p, c["token"], runner), 200)
	r := machineconfig.Report{ReportVersion: 1, ObservedAt: time.Now().UTC(), NodeID: m.NodeID, CredentialVersion: 1, Component: "app-reconciler", Generation: m.Generation, Sequence: 2, Reason: "failed", Apps: &contract.AppStatus{Reason: "state_recovery_failed", Instances: []contract.InstanceStatus{}}}
	requireStatus(t, request(t, s, "POST", p, c["token"], r), 200)
	var at, before time.Time
	s.db.QueryRow(`SELECT received_at FROM lpcc.machine_reports WHERE node_id=$1 AND component='app-reconciler'`, m.NodeID).Scan(&before)
	requireStatus(t, request(t, s, "POST", p, c["token"], r), 200)
	s.db.QueryRow(`SELECT received_at FROM lpcc.machine_reports WHERE node_id=$1 AND component='app-reconciler'`, m.NodeID).Scan(&at)
	if at != before {
		t.Fatal("duplicate renewed observation age")
	}
	r.Sequence = 1
	requireStatus(t, request(t, s, "POST", p, c["token"], r), 412)
	r.Sequence = 3
	r.ObservedAt = r.ObservedAt.Add(-time.Hour)
	r.Ready = true
	requireStatus(t, request(t, s, "POST", p, c["token"], r), 200)
	stored, effective, err := (machineconfig.Store{DB: s.db}).Report(t.Context(), configurationMachine(Machine{NodeID: m.NodeID, CredentialVersion: 1}), "app-reconciler")
	if err != nil || !stored.ClockUncertain || !effective.IsZero() {
		t.Fatal("clock regression attested readiness", stored, effective, err)
	}
	requireStatus(t, request(t, s, "POST", p, c["token"], r), 200)
	runtime := r
	runtime.Component, runtime.Apps, runtime.BundleFormat = "runtime", nil, contract.BundleFormat
	for _, sequence := range []uint64{3, 4} {
		runtime.Sequence = sequence
		runtime.ObservedAt = runtime.ObservedAt.Add(time.Second)
		requireStatus(t, request(t, s, "POST", p, c["token"], runtime), 200)
		_, at, err := (machineconfig.Store{DB: s.db}).Report(t.Context(), configurationMachine(Machine{NodeID: m.NodeID, CredentialVersion: 1}), "runtime")
		if err != nil || (!at.IsZero() && time.Since(at) < 2*time.Minute) {
			t.Fatal("continuing old clock established fresh runtime readiness", at, err)
		}
	}
	runtime.Sequence = 5
	runtime.ObservedAt = time.Now().UTC().Add(time.Hour)
	requireStatus(t, request(t, s, "POST", p, c["token"], runtime), 200)
	for _, path := range []string{"/api/machines?orchestrator_address=" + orchA, "/api/admin/machines"} {
		w := request(t, s, "GET", path, "session-a", nil)
		requireStatus(t, w, 200)
		var list struct {
			Machines []observedMachineSummary `json:"machines"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		if len(list.Machines) != 1 || list.Machines[0].ReportState != "clock_uncertain" || list.Machines[0].LastObservedAt != nil {
			t.Fatal("clock fault collapsed to silence", w.Body.String())
		}
	}
	w := request(t, s, "GET", "/api/machines/"+m.NodeID+"/status", "session-a", nil)
	requireStatus(t, w, 200)
	var view machineObservation
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	for _, c := range view.Components {
		if c.ClockUncertain && (c.ExpiresAt != nil || c.Fresh) {
			t.Fatal("unknown evidence acquired expiry", c)
		}
	}
	runtime.Sequence, runtime.ObservedAt = 6, time.Now().UTC()
	requireStatus(t, request(t, s, "POST", p, c["token"], runtime), 200)
	recovered, at, err := (machineconfig.Store{DB: s.db}).Report(t.Context(), configurationMachine(Machine{NodeID: m.NodeID, CredentialVersion: 1}), "runtime")
	if err != nil || recovered.ClockUncertain || at.IsZero() || time.Since(at) > 2*time.Minute {
		t.Fatal("valid clock did not recover trusted observation", recovered, at, err)
	}
	r.Sequence = 4
	r.ObservedAt = time.Now().UTC()
	r.Ready = false
	requireStatus(t, request(t, s, "POST", p, c["token"], r), 200)
	for _, sequence := range []uint64{5, 6} {
		r.Sequence, r.ClockUncertain, r.ObservedAt = sequence, true, time.Now().UTC()
		requireStatus(t, request(t, s, "POST", p, c["token"], r), 200)
		stored, at, err := (machineconfig.Store{DB: s.db}).Report(t.Context(), configurationMachine(Machine{NodeID: m.NodeID, CredentialVersion: 1}), "app-reconciler")
		if err != nil || !stored.ClockUncertain || !at.IsZero() {
			t.Fatal("producer clock uncertainty discarded", stored, at, err)
		}
	}
	r.Sequence, r.ClockUncertain, r.ObservedAt = 7, false, time.Now().UTC()
	requireStatus(t, request(t, s, "POST", p, c["token"], r), 200)
	r.ReportVersion = 0
	r.Sequence = 0
	requireStatus(t, request(t, s, "POST", p, c["token"], r), 409)
	jwt, _, _ := s.params.signEnrollment(ownerA, testOrchestrator(ownerA), time.Now())
	w = request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/credentials/refresh", jwt, map[string]any{"management_proof": c["token"], "fingerprint": strings.Repeat("a", 64), "install_dir": "/opt/livepeer", "operation_id": uuid.New().String(), "expected_credential_version": 1})
	requireStatus(t, w, 200)
	credential := credentials(t, w.Body.Bytes())
	r.CredentialVersion = 2
	// Credential rotation resets order, never the accepted report contract.
	requireStatus(t, request(t, s, "POST", p, credential["token"], r), 409)
	runner.CredentialVersion, runner.ReportVersion, runner.Sequence = 2, 0, 2
	requireStatus(t, request(t, s, "POST", p, credential["token"], runner), 409)
	runner.ReportVersion, runner.Sequence = 1, 1
	requireStatus(t, request(t, s, "POST", p, credential["token"], runner), 200)
	r.ReportVersion = 1
	r.Sequence = 1
	r.ObservedAt = time.Now().UTC()
	requireStatus(t, request(t, s, "POST", p, credential["token"], r), 200)
	requireStatus(t, request(t, s, "POST", p, c["token"], r), 401)

}

func TestInvalidAppDownloadKeepsManagementReportsIngestible(t *testing.T) {
	s, c, m, _ := observationFixture(t)
	p := "/v1/nodes/" + m.NodeID
	w := request(t, s, "GET", p+"/config", c["token"], nil)
	requireStatus(t, w, 200)
	data := w.Body.Bytes()
	handler := s.Handler()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == p+"/config" {
			w.Header().Set("X-Livepeer-Node-ID", m.NodeID)
			w.Header().Set("X-Livepeer-Credential-Version", "1")
			_, _ = w.Write(data)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(backend.Close)
	kube := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	t.Cleanup(kube.Close)
	directory := t.TempDir()
	token := filepath.Join(directory, "token")
	if err := os.WriteFile(token, []byte(c["token"]), 0600); err != nil {
		t.Fatal(err)
	}
	control, err := transport.NewControl(backend.URL+p+"/config", token, true)
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(directory, "identity.json")
	if err := os.WriteFile(identity, []byte(fmt.Sprintf(`{"node_id":%q,"credential_version":1}`, m.NodeID)), 0600); err != nil {
		t.Fatal(err)
	}
	reportDir := filepath.Join(directory, "reports")
	if err := os.MkdirAll(reportDir, 0700); err != nil {
		t.Fatal(err)
	}
	counter := filepath.Join(reportDir, "runtime-"+strings.TrimPrefix(artifact.Digest([]byte(m.NodeID)), "sha256:")+".json")
	if err := os.WriteFile(counter, []byte(fmt.Sprintf(`{"node_id":%q,"credential_version":1,"sequence":1}`, m.NodeID)), 0600); err != nil {
		t.Fatal(err)
	}
	source := &httpsource.Source{IdentityFile: identity, Control: control, Reporter: &transport.Reports{Client: control, Directory: reportDir}, Kube: &transport.Kube{Base: kube.URL, Client: kube.Client()}, Store: artifact.Store{Directory: filepath.Join(directory, "artifacts")}, ArtifactURL: "http://adapter.invalid"}
	if err := source.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := source.Report(t.Context()); err != nil {
		t.Fatal(err)
	}
	store := machineconfig.Store{DB: s.db}
	machine := configurationMachine(Machine{NodeID: m.NodeID, CredentialVersion: 1})
	first, _, err := store.Report(t.Context(), machine, "runtime")
	if err != nil || first.Downloaded == nil || first.Downloaded.AppsDigest != m.AppsDigest {
		t.Fatal("valid predecessor missing", first, err)
	}
	files, err := artifact.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	files[appbundle.IntentFile] = []byte(`invalid app input`)
	data, err = artifact.Pack(files)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Sync(t.Context()); err != nil {
		t.Fatal("app failure blocked management delivery", err)
	}
	if err := source.Report(t.Context()); err != nil {
		t.Fatal("app failure blocked management status ingestion", err)
	}
	last, _, err := store.Report(t.Context(), machine, "runtime")
	if err != nil || last.AppsError == "" || last.Downloaded == nil || *last.Downloaded != *first.Downloaded || !last.DownloadedAt.Equal(first.DownloadedAt) || last.Sequence <= first.Sequence {
		t.Fatal("last-good identity/age or repair report lost", last, err)
	}
	w = request(t, s, "GET", "/api/machines/"+m.NodeID+"/status", "session-a", nil)
	requireStatus(t, w, 200)
	var view machineObservation
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Components[0].AppsError != last.AppsError || strings.Contains(w.Body.String(), "invalid app input") {
		t.Fatal("adapter validation classification lost or payload exposed", w.Body.String())
	}
}

func TestTerminalDiagnosticsRetainEarlierInstanceLineage(t *testing.T) {
	s, c, m, a := observationFixture(t)
	prior := observationReport(m, a)
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/status", c["token"], prior), 200)
	requireStatus(t, request(t, s, "DELETE", "/api/admin/machines/"+m.NodeID, "session-a", map[string]any{"force": true}), 202)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, "GET", "/v1/nodes/"+m.NodeID+"/config", c["token"], nil)
	requireStatus(t, w, 200)
	terminalDigest := strings.Trim(w.Header().Get("ETag"), "\"")
	files := archiveFiles(t, w.Body.Bytes())
	var terminal contract.Metadata
	if err := json.Unmarshal([]byte(files["runtime.json"]), &terminal); err != nil {
		t.Fatal(err)
	}
	prior.Generation = terminal.Generation
	prior.Sequence++
	prior.ObservedAt = time.Now().UTC()
	prior.Ready = false
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/status", c["token"], prior), 409)
	prior.Apps.DesiredGeneration, prior.Apps.DesiredDigest = 0, ""
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/status", c["token"], prior), 409)
	prior.Apps.DesiredGeneration = terminal.AppsGeneration
	prior.Apps.DesiredDigest = terminal.AppsDigest
	prior.Apps.Assignments = nil
	prior.Apps.Instances[0].Reason = "cleanup_unconfirmed"
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/status", c["token"], prior), 200)
	diagnosis := machineconfig.Report{ReportVersion: 1, ObservedAt: time.Now().UTC(), NodeID: m.NodeID, CredentialVersion: 1, Component: "app-reconciler", Generation: terminal.Generation, Sequence: 1, Reason: "failed", Apps: &contract.AppStatus{Reason: "state_recovery_failed", Instances: []contract.InstanceStatus{}}}
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/status", c["token"], diagnosis), 200)
	read := "/api/machines/" + m.NodeID + "/status"
	w = request(t, s, "GET", read, "session-a", nil)
	requireStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "cleanup_unconfirmed") {
		t.Fatal("intermediate terminal cleanup hidden")
	}
	list := request(t, s, "GET", "/api/machines?orchestrator_address="+orchA, "session-a", nil)
	requireStatus(t, list, 200)
	if !strings.Contains(list.Body.String(), m.NodeID) || !strings.Contains(list.Body.String(), "cleanup_pending") {
		t.Fatal("pending retirement disappeared")
	}
	prior.Sequence++
	prior.Drained = true
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/status", c["token"], prior), 409)
	prior.Drained = false
	replacement := enroll(t, s, ownerB, strings.Repeat("a", 64))
	if replacement["node_id"] == m.NodeID {
		t.Fatal("expected replacement enrollment")
	}
	if _, err := s.db.Exec(`UPDATE lpcc.administrator_grants SET revoked_at=now() WHERE bound_user_id=$1`, ownerA); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, request(t, s, "GET", read, "session-b", nil), 404)
	requireStatus(t, request(t, s, "GET", read, "session-a", nil), 200)
	requireStatus(t, request(t, s, "GET", "/api/machines/"+replacement["node_id"]+"/status", "session-a", nil), 404)
	requireStatus(t, request(t, s, "GET", "/api/machines/"+replacement["node_id"]+"/status", "session-b", nil), 200)
	prior.Sequence++
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/status", c["token"], prior), 200)
	var removal schema.AppAssignmentSetV1
	if err := json.Unmarshal([]byte(files[appbundle.IntentFile]), &removal); err != nil {
		t.Fatal(err)
	}
	for _, a := range removal.Entries {
		requireStatus(t, appReport(t, s, c, a, terminal.AppsDigest, "removed"), 200)
	}
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/removal-ack", c["token"], map[string]any{"node_id": m.NodeID, "digest": terminalDigest, "connector_absent": true}), 200)
	list = request(t, s, "GET", "/api/machines?orchestrator_address="+orchA, "session-a", nil)
	requireStatus(t, list, 200)
	if strings.Contains(list.Body.String(), m.NodeID) {
		t.Fatal("acknowledged retired enrollment still listed")
	}

}

type statusDiscoverySource struct{ source fleet.Source }

func (s statusDiscoverySource) Sources(context.Context) ([]fleet.Source, error) {
	return []fleet.Source{s.source}, nil
}

func TestObservedStateComposesExactDiscoveryMembership(t *testing.T) {
	s, c, m, shot := observationFixture(t)
	source := strings.Replace(registryFixture(t), `name = "whoami"`, `name = "whoami-persistent"`, 1)
	source = strings.Replace(source, `mode = "single-shot"`, `mode = "persistent"`, 1)
	revision := publishAssignmentRevision(t, s, source, "")
	requireStatus(t, putApp(t, s, c, revision, 0, 1), 202)
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, "GET", "/v1/nodes/"+m.NodeID+"/config", c["token"], nil)
	requireStatus(t, w, 200)
	files := archiveFiles(t, w.Body.Bytes())
	if err := json.Unmarshal([]byte(files["runtime.json"]), &m); err != nil {
		t.Fatal(err)
	}
	intent, err := schema.DecodeAssignmentSet([]byte(files[appbundle.IntentFile]))
	if err != nil {
		t.Fatal(err)
	}
	var persistent schema.AppAssignment
	for _, a := range intent.Entries {
		if a.RevisionID == revision.RevisionID {
			persistent = a
		}
	}
	if persistent.RevisionID == "" {
		t.Fatal("persistent assignment not delivered")
	}
	route := tunnel.RoutingState{ServiceURL: "https://orch.example", ProxyURLTemplate: "https://{proxy}.apps.example"}
	raw, _ := json.Marshal(route)
	if _, err := s.db.Exec(`UPDATE lpcc.machine_states SET state=$2 WHERE node_id=$1`, m.NodeID, string(raw)); err != nil {
		t.Fatal(err)
	}
	report := observationReport(m, shot)
	report.Apps.Instances[0].AppID = "shot-app"
	report.Apps.Instances[0].InstanceID = "shot-instance"
	i := report.Apps.Instances[0]
	i.RevisionID, i.Generation, i.ActivationGeneration = persistent.RevisionID, persistent.Generation, persistent.ActivationGeneration
	i.AppID, i.InstanceID = "persistent-app", "persistent-instance"
	report.Apps.Instances = append(report.Apps.Instances, i)
	report.Apps.InstancesTotal = 2
	requireStatus(t, request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/status", c["token"], report), 200)
	var version atomic.Value
	version.Store("wrong-version")
	f, err := fleet.New(fleet.Config{RefreshInterval: time.Second, ReconcileInterval: time.Minute}, fleet.Dependencies{
		Store: statusDiscoverySource{fleet.Source{NodeID: m.NodeID, URL: "https://source.example/discovery", ServiceURL: route.ServiceURL, ProxyURLTemplate: route.ProxyURLTemplate, AuthMode: fleet.AuthNone, Lifecycle: "active", Ready: true, Generation: 1, VerifiedGeneration: 1}}, Logger: s.logger,
		Transport: fleetRoundTripFunc(func(*http.Request) (*http.Response, error) {
			body := `[{"address":"https://orch.example","runners":[{"url":"https://shot-app.apps.example","app":"whoami","version":"1","observed_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"},{"url":"https://orch.example/apps/persistent-app/session","app":"whoami-persistent","version":"` + version.Load().(string) + `","observed_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}]}]`
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.discovery = f
	if err := f.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); f.Run(ctx) }()
	t.Cleanup(func() { cancel(); f.Close(); <-done })
	for _, want := range []string{"absent", "present"} {
		if want == "present" {
			version.Store("1")
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			w := request(t, s, "GET", "/api/machines/"+m.NodeID+"/status", "session-a", nil)
			requireStatus(t, w, 200)
			var view machineObservation
			if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
				t.Fatal(err)
			}
			if view.Membership["shot-instance"].State == "present" && view.Membership["persistent-instance"].State == want {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("API did not preserve exact endpoints, versions and instance keys", want, w.Body.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func TestLargeObservedReportCrossesRelayAndIngestion(t *testing.T) {
	s, c, m, a := observationFixture(t)
	store := machineconfig.Store{DB: s.db}
	state, err := store.Load(t.Context(), m.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	state.DrainRequested, state.DrainStartedAt = true, now.Add(-time.Second)
	raw, _ := json.Marshal(state.State)
	if _, err := s.db.Exec(`UPDATE lpcc.machine_states SET rollout=$2 WHERE node_id=$1`, m.NodeID, string(raw)); err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(s.Handler())
	t.Cleanup(backend.Close)
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte(c["token"]), 0600); err != nil {
		t.Fatal(err)
	}
	control, err := transport.NewControl(backend.URL+"/v1/nodes/"+m.NodeID+"/config", token, true)
	if err != nil {
		t.Fatal(err)
	}
	relay := management.AppReports{Control: control, Desired: func() (contract.Metadata, bool) { return m, true }}
	r := observationReport(m, a)
	r.Drained, r.Ready, r.Reason = true, false, "drain_pending"
	r.Evidence = &contract.Evidence{Kind: "no_owner", Target: machineconfig.DrainTarget(m.NodeID, state.State), OwnerID: "retained-owner", CredentialFingerprint: "sha256:" + strings.Repeat("f", 64), WithdrawalID: "withdrawal", MutationSequence: new(uint64(0)), ObservedAt: now, ExpiresAt: now.Add(time.Minute)}
	proof := *r.Evidence
	r.Apps.Instances = nil
	r.Apps.Assignments[0].Instances, r.Apps.Assignments[0].Ready, r.Apps.Assignments[0].Registered = 128, 0, 0
	for n := 0; n < 128; n++ {
		r.Apps.Instances = append(r.Apps.Instances, contract.InstanceStatus{RevisionID: a.RevisionID, Generation: a.Generation, ActivationGeneration: a.ActivationGeneration, InstanceID: fmt.Sprintf("instance-%03d", n), Phase: "removed", Sessions: -1, RegistrationGone: true, TerminatedAt: now})
	}
	r.Apps.InstancesTotal = 128
	r.ClockUncertain = true
	body, _ := json.Marshal(r)
	w := httptest.NewRecorder()
	relay.ServeHTTP(w, httptest.NewRequest("POST", "http://management/status", bytes.NewReader(body)))
	requireStatus(t, w, 409)
	r.ClockUncertain = false
	for _, detailed := range []bool{false, true} {
		if detailed {
			r.Sequence++
			// A near-limit bounded diagnostic fixture; producer selection is covered in appreconciler.
			r.Apps.Instances = r.Apps.Instances[:101]
			r.Apps.InstancesOmitted = 27
			for n := range r.Apps.Instances {
				i := &r.Apps.Instances[n]
				i.AppID, i.RunnerID, i.PodUID = strings.Repeat("a", 128), strings.Repeat("r", 128), strings.Repeat("p", 128)
				i.Reason, i.WorkloadReason = strings.Repeat("e", 128), strings.Repeat("w", 128)
			}
		}
		body, err := json.Marshal(r)
		if err != nil || len(body) > contract.MaxStatusBytes {
			t.Fatal("invalid bounded fixture", len(body), err)
		}
		if detailed && len(body) < contract.MaxStatusBytes-8192 {
			t.Fatal("fixture no longer exercises the byte boundary", len(body))
		}
		t.Logf("ingesting %d instances, %d omitted, %d serialized bytes", len(r.Apps.Instances), r.Apps.InstancesOmitted, len(body))
		w := httptest.NewRecorder()
		relay.ServeHTTP(w, httptest.NewRequest("POST", "http://management/status", bytes.NewReader(body)))
		requireStatus(t, w, 200)
		stored, _, err := store.Report(t.Context(), configurationMachine(Machine{NodeID: m.NodeID, CredentialVersion: 1}), "runner")
		if err != nil || stored.Evidence == nil || !reflect.DeepEqual(*stored.Evidence, proof) || len(stored.Apps.Instances) != len(r.Apps.Instances) || stored.Apps.InstancesOmitted != r.Apps.InstancesOmitted || stored.Apps.InstancesTotal != 128 {
			t.Fatal("relay/ingestion changed bounded state or proof", len(body), stored, err)
		}
	}
}
