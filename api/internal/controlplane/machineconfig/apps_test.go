package machineconfig

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/livepeer/control-center/api/internal/testdb"
	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/schema"
)

func TestIndependentManagementAndFullWorkloadDigest(t *testing.T) {
	m := Desired{Machine: Machine{NodeID: strings.Repeat("a", 26), CredentialVersion: 1, InstallDir: "/opt/livepeer", K3sVersion: "v1.37.2+k3s1"}, RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64), NodeImage: "registry.invalid/node@sha256:" + strings.Repeat("b", 64)}
	missing := m
	missing.RuntimeImage = ""
	if _, _, err := Build(missing); err == nil {
		t.Fatal("missing required Runtime image")
	}
	data, _, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	files, err := artifact.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(files["kustomization.yaml"]), "app-desired") || !strings.Contains(string(files["management/kustomization.yaml"]), "app-reconciler.yaml") {
		t.Fatal("two app apply paths")
	}
	var metadata contract.Metadata
	if json.Unmarshal(files["runtime.json"], &metadata) != nil {
		t.Fatal("invalid metadata")
	}
	p, err := appbundle.Read(files, metadata)
	if err != nil || p.Index.Available {
		t.Fatal("missing payload became empty intent", err)
	}
	if !strings.Contains(string(files["system/node/orchestrator.yaml"]), "image: "+m.NodeImage) {
		t.Fatal("ignored the configured Node image")
	}
	first := Digest(m)
	m.NodeImage = "registry.invalid/node@sha256:" + strings.Repeat("c", 64)
	if Digest(m) == first {
		t.Fatal("Node image bypassed drain")
	}
	m.State.HeldOrchestrator = string(files["system/node/orchestrator.yaml"])
	m.State.HeldUpgradePlan = string(files["upgrade-plan/plan.yaml"])
	m.K3sVersion = "v1.37.3+k3s1"
	if Digest(m) != first {
		t.Fatal("held workload identity changed")
	}
	held, _, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := artifact.Read(held)
	if string(actual["system/node/orchestrator.yaml"]) != string(files["system/node/orchestrator.yaml"]) || string(actual["upgrade-plan/plan.yaml"]) != m.State.HeldUpgradePlan {
		t.Fatal("disruptive target released during repair")
	}
	m.State.HeldOrchestrator = ""
	m.State.HeldUpgradePlan = ""
	withUpgrade := Digest(m)
	m.K3sVersion = "v1.37.2+k3s1"
	if Digest(m) == withUpgrade {
		t.Fatal("K3s upgrade bypassed drain")
	}
	if !strings.Contains(string(files["system/node/orchestrator.yaml"]), `RunnerGrants = ["10.43.0.0/16"]`) {
		t.Fatal("missing private app grant")
	}

}
func TestDrainProofDoesNotGainFreshnessFromDeliveryRetry(t *testing.T) {
	now := time.Now().UTC()
	m := Machine{NodeID: "node"}
	state := State{Generation: 7, DrainRequested: true, DrainStartedAt: now.Add(-time.Hour), PendingConfigDigest: "target"}
	r := Report{Generation: 7, Drained: true, Evidence: &contract.Evidence{Kind: "no_owner", Target: DrainTarget(m.NodeID, state), WithdrawalID: "withdrawal", ObservedAt: now, ExpiresAt: now.Add(30 * time.Second)}}
	if !validDrainEvidence(m, state, r, now) {
		t.Fatal("late confirmed completion rejected")
	}
	if validDrainEvidence(m, state, r, now.Add(time.Minute)) {
		t.Fatal("old proof refreshed by retry")
	}
	r.Evidence.Target = "different"
	if validDrainEvidence(m, state, r, now) {
		t.Fatal("wrong target accepted")
	}
}

func TestTerminalAppFallbackRetainsAvailableIntent(t *testing.T) {
	db := testdb.Open(t)
	if _, err := db.Exec(`CREATE SCHEMA lpcc; CREATE TABLE lpcc.enrollments(node_id TEXT PRIMARY KEY, retained_bundle BYTEA)`); err != nil {
		t.Fatal(err)
	}
	intent := schema.AppAssignmentSetV1{SchemaVersion: 1, NodeID: strings.Repeat("a", 26), Generation: 3, Entries: []schema.AppAssignment{}}
	m := Desired{Machine: Machine{NodeID: intent.NodeID, CredentialVersion: 1, InstallDir: "/opt/livepeer", K3sVersion: "v1.37.2+k3s1"}, Apps: &intent, RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64)}
	bundle, _, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO lpcc.enrollments VALUES($1,$2)`, m.NodeID, bundle); err != nil {
		t.Fatal(err)
	}
	m.Terminal = true
	New(Config{}, Dependencies{DB: db}).prepareApps(t.Context(), &m, errors.New("lookup unavailable"))
	if m.AppsError != "generation_failed" || !m.AppPayload.Index.Available || m.Apps == nil || m.Apps.Generation != intent.Generation {
		t.Fatal("lost retained cleanup intent", m.AppsError, m.AppPayload)
	}
}

type observationQueries struct{ count atomic.Int64 }

func (q *observationQueries) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	q.count.Add(1)
	return ctx
}
func (*observationQueries) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestValidateObservationsDeliveryChecks(t *testing.T) {
	db := testdb.Open(t)
	if _, err := db.Exec(`CREATE SCHEMA lpcc; CREATE TABLE lpcc.machine_app_deliveries(
 node_id text, apps_generation bigint, apps_digest text, bundle_sha256 text, terminal boolean, entries jsonb)`); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	otherDigest := "sha256:" + strings.Repeat("b", 64)
	firstRevision := "11111111-1111-1111-1111-111111111111"
	secondRevision := "22222222-2222-2222-2222-222222222222"
	for _, delivery := range []struct {
		node, digest, bundle, revision string
		generation, activation         int64
		terminal                       bool
	}{
		{"node", digest, strings.Repeat("a", 64), firstRevision, 1, 1, false},
		{"node", digest, strings.Repeat("b", 64), secondRevision, 2, 2, true},
		{"other", otherDigest, strings.Repeat("c", 64), firstRevision, 9, 9, true},
	} {
		if _, err := db.Exec(`INSERT INTO lpcc.machine_app_deliveries VALUES($1,$2,$3,$4,$5,
 jsonb_build_array(jsonb_build_object('revision_id',$6::text,'generation',$2::bigint,'activation_generation',$7::bigint)))`,
			delivery.node, delivery.generation, delivery.digest, delivery.bundle, delivery.terminal, delivery.revision, delivery.activation); err != nil {
			t.Fatal(err)
		}
	}
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var config *pgx.ConnConfig
	if err := conn.Raw(func(c any) error {
		config = c.(*stdlib.Conn).Conn().Config()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	queries := &observationQueries{}
	config.Tracer = queries
	counted := stdlib.OpenDB(*config)
	t.Cleanup(func() { counted.Close() })
	manager := New(Config{}, Dependencies{DB: counted})
	for _, tc := range []struct {
		name   string
		change func(*Report, *Machine)
		stale  bool
	}{
		{"independent witnesses", func(*Report, *Machine) {}, false},
		{"download only", func(r *Report, m *Machine) { r.Apps = nil }, false},
		{"unknown artifact", func(r *Report, m *Machine) { r.Downloaded.ArtifactDigest = "sha256:" + strings.Repeat("c", 64) }, true},
		{"missing artifact", func(r *Report, m *Machine) { r.Downloaded.ArtifactDigest = "" }, true},
		{"unknown download generation", func(r *Report, m *Machine) { r.Downloaded.Generation = 9 }, true},
		{"unknown staged generation", func(r *Report, m *Machine) { r.Apps.Staged.Generation = 9 }, true},
		{"stage delivered to another node", func(r *Report, m *Machine) {
			r.Apps.Published.AppsDigest = otherDigest
			r.Apps.Published.Generation = 9
		}, true},
		{"unknown applied generation", func(r *Report, m *Machine) { r.Apps.Applied.Generation = 9 }, true},
		{"assignment delivered to another node", func(r *Report, m *Machine) {
			r.Apps.Assignments[0].Generation = 9
			r.Apps.Assignments[0].ActivationGeneration = 9
		}, true},
		{"wrong activation", func(r *Report, m *Machine) { r.Apps.Instances[0].ActivationGeneration = 1 }, true},
		{"wrong revision", func(r *Report, m *Machine) { r.Apps.Instances[0].RevisionID = firstRevision }, true},
		{"terminal binding", func(r *Report, m *Machine) { r.Apps.DesiredGeneration = 1 }, true},
		{"terminal wildcard refused", func(r *Report, m *Machine) { r.Apps.DesiredGeneration = 0 }, true},
		{"nonterminal wildcard", func(r *Report, m *Machine) { m.Terminal = false; r.Apps.DesiredGeneration = 0 }, false},
		{"reconciler unbound", func(r *Report, m *Machine) { r.Component = "app-reconciler"; r.Apps.DesiredGeneration = 1 }, false},
		{"empty membership", func(r *Report, m *Machine) {
			r.Apps = &contract.AppStatus{Instances: []contract.InstanceStatus{}}
			m.Terminal = false
		}, false},
		{"no deliveries", func(r *Report, m *Machine) { m.NodeID = "missing" }, true},
		{"missing terminal delivery", func(r *Report, m *Machine) {
			m.NodeID = "missing"
			r.Downloaded = nil
			r.Apps = &contract.AppStatus{Instances: []contract.InstanceStatus{}}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Machine{NodeID: "node", Terminal: true}
			r := Report{Component: "runner", Downloaded: &contract.StageIdentity{AppsDigest: digest, ArtifactDigest: digest, Generation: 2},
				Apps: &contract.AppStatus{DesiredGeneration: 2, DesiredDigest: digest,
					Staged: &contract.StageIdentity{AppsDigest: digest}, Published: &contract.StageIdentity{AppsDigest: digest, Generation: 1}, Applied: &contract.StageIdentity{AppsDigest: digest, Generation: 2},
					Assignments: []contract.AssignmentStatus{{RevisionID: firstRevision, Generation: 1, ActivationGeneration: 1}},
					Instances:   []contract.InstanceStatus{{RevisionID: secondRevision, Generation: 2, ActivationGeneration: 2, InstanceID: "instance"}}, InstancesTotal: 1}}
			tc.change(&r, &m)
			queries.count.Store(0)
			err := manager.validateObservations(t.Context(), m, r)
			if (tc.stale && !errors.Is(err, ErrStaleStatus)) || (!tc.stale && err != nil) {
				t.Fatalf("stale=%v: %v", tc.stale, err)
			}
			if got := queries.count.Load(); got != 1 {
				t.Fatalf("validation queries = %d, want 1", got)
			}
		})
	}
}

func TestValidateObservationsWithoutDeliveryReads(t *testing.T) {
	// A nil database also verifies that these paths never issue a query.
	manager := New(Config{}, Dependencies{})
	for _, r := range []Report{
		{Component: "connector"}, {Component: "runtime"},
		{Downloaded: &contract.StageIdentity{ArtifactDigest: "sha256:" + strings.Repeat("a", 64)}},
	} {
		if err := manager.validateObservations(t.Context(), Machine{}, r); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []Report{
		{Software: []contract.SoftwareIdentity{}}, {ObserverID: "bad observer"}, {AppsError: "Bad"}, {DeliveryReason: "Bad"},
		{Downloaded: &contract.StageIdentity{Generation: -1}},
		{Downloaded: &contract.StageIdentity{Generation: 1}},
		{Downloaded: &contract.StageIdentity{AppsDigest: "bad"}},
		{Downloaded: &contract.StageIdentity{ArtifactDigest: "bad"}},
		{Apps: &contract.AppStatus{}},
		{Apps: &contract.AppStatus{Instances: []contract.InstanceStatus{}, InstancesTotal: 1}},
		{Apps: &contract.AppStatus{Instances: []contract.InstanceStatus{}, StagedDigest: "bad"}},
	} {
		if err := manager.validateObservations(t.Context(), Machine{}, r); !errors.Is(err, ErrStaleStatus) {
			t.Fatalf("malformed report returned %v", err)
		}
	}
}
