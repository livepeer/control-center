package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
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

	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/httpsource"
	"github.com/livepeer/control-center/runtime/transport"
	"github.com/livepeer/control-center/schema"
)

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

func TestObservedStateOwnerAdminBoundariesAndRedaction(t *testing.T) {
	s, c, m, a := observationFixture(t)
	report := observationReport(m, a)
	path := "/v1/nodes/" + m.NodeID + "/status"
	requireStatus(t, request(t, s, "POST", path, c["token"], report), 200)
	read := "/api/machines/" + m.NodeID + "/status"
	w := request(t, s, "GET", read, "session-a", nil)
	requireStatus(t, w, 200)
	var v machineObservation
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Assignments) != 1 || v.Assignments[0].Generation != a.Generation || v.Delivered == nil || v.Delivered.AppsDigest != m.AppsDigest || v.ExternalReachability != "unverified" {
		t.Fatal("lost desired/delivery evidence", w.Body.String())
	}
	for _, secret := range []string{"environment-sentinel", c["token"], `"container":`, `"environment":`, `"actor_id":`, `"runner_service_url":`, "10.43.", "CF-Access"} {
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
	for _, path := range []string{"/api/machines", "/api/admin/machines"} {
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
	jwt, _, _ := signEnrollment(s.params.JWTSigningSecret, ownerA, time.Now())
	w = request(t, s, "POST", "/v1/nodes/"+m.NodeID+"/credentials/refresh", jwt, map[string]any{"fingerprint": strings.Repeat("a", 64), "install_dir": "/opt/livepeer", "operation_id": uuid.New().String(), "expected_credential_version": 1})
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
	list := request(t, s, "GET", "/api/machines", "session-a", nil)
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
	list = request(t, s, "GET", "/api/machines", "session-a", nil)
	requireStatus(t, list, 200)
	if strings.Contains(list.Body.String(), m.NodeID) {
		t.Fatal("acknowledged retired enrollment still listed")
	}

}

type statusDiscoverySource struct{ source fleet.Source }

func (s statusDiscoverySource) Sources(context.Context) ([]fleet.Source, error) {
	return []fleet.Source{s.source}, nil
}
func (statusDiscoverySource) Resolve(context.Context, string) (fleet.Credential, error) {
	return fleet.Credential{}, nil
}
func (statusDiscoverySource) Acknowledge(context.Context, fleet.Source) error { return nil }

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
