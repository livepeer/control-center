package appreconciler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/internal/testutil"
	"github.com/livepeer/control-center/runtime/transport"
	"github.com/livepeer/control-center/schema"
	protocol "github.com/livepeer/control-center/secrets"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeSecretResolver struct {
	set         protocol.VersionSet
	err         error
	enabled     bool
	activateErr error
	renewErr    error
}

func (f *fakeSecretResolver) Enabled() bool      { return f.enabled }
func (f *fakeSecretResolver) MarkManaged() error { f.enabled = true; return nil }
func (f *fakeSecretResolver) Versions(context.Context, protocol.ResolveRequest) (protocol.VersionSet, error) {
	return f.set, f.err
}
func (f *fakeSecretResolver) Renew(context.Context) error    { return f.renewErr }
func (f *fakeSecretResolver) Activate(context.Context) error { return f.activateErr }
func (f *fakeSecretResolver) IdentityReady() bool            { return f.enabled }
func (f *fakeSecretResolver) VersionsAll(_ context.Context, in []protocol.ResolveRequest) (map[string]protocol.VersionSet, map[string]string, error) {
	sets := map[string]protocol.VersionSet{}
	faults := map[string]string{}
	if f.err != nil && f.err.Error() != "secret_missing" && f.err.Error() != "secret_unprovisioned" {
		return nil, nil, f.err
	}
	for _, a := range in {
		if f.err != nil {
			faults[a.RevisionID] = f.err.Error()
		} else {
			sets[a.RevisionID] = f.set
		}
	}
	return sets, faults, nil
}
func (f *fakeSecretResolver) Resolve(context.Context, protocol.ResolveRequest) (protocol.VersionSet, error) {
	b, _ := json.Marshal(f.set)
	var copy protocol.VersionSet
	_ = json.Unmarshal(b, &copy)
	return copy, f.err
}

type renewingSecretResolver struct {
	fakeSecretResolver
	renewals int
}

func (f *renewingSecretResolver) Renew(context.Context) error { f.renewals++; return nil }

func TestIdleMachinesContinueCertificateRenewal(t *testing.T) {
	client := &renewingSecretResolver{fakeSecretResolver: fakeSecretResolver{enabled: true}}
	delivery := &SecretDelivery{Client: client, Kube: secretKube(nil)}
	now := time.Now()
	delivery.Poll(t.Context(), State{}, now)
	delivery.Poll(t.Context(), State{}, now.Add(time.Second))
	if client.renewals != 1 {
		t.Fatal("idle renewal missing or poll interval ignored", client.renewals)
	}
	delivery.Poll(t.Context(), State{}, now.Add(time.Minute))
	if client.renewals != 2 {
		t.Fatal("idle renewal did not continue", client.renewals)
	}
}

func TestSecretPreparationIsDirectCollisionFreeAndRetryable(t *testing.T) {
	set := testutil.Assignment(t)
	a := &set.Entries[0]
	a.Replicas = 1
	a.Revision.Definition.Container.Secrets = []schema.SecretEnvironment{{Name: "TOKEN_A", Secret: "lp-app-a", Key: "token"}, {Name: "TOKEN_B", Secret: "lp-app-b", Key: "token"}}
	testutil.Refresh(a)
	payload, e := appbundle.Render(set, appbundle.Options{})
	if e != nil {
		t.Fatal(e)
	}
	files, name, e := payload.Instantiate(payload.Index.Groups[0], strings.Repeat("a", 32))
	if e != nil {
		t.Fatal(e)
	}
	version := protocol.VersionSet{NodeID: set.NodeID, IdentityGeneration: 1, PolicyGeneration: 1, Assignment: request(*a)}
	for _, ref := range a.Revision.Definition.Container.Secrets {
		encrypted, key, e := protocol.Encrypt(protocol.Binding{Owner: "operator", ID: ref.Secret, Name: ref.Secret, Key: ref.Key, Version: "1"}, []byte("sentinel-"+ref.Secret))
		if e != nil {
			t.Fatal(e)
		}
		version.Values = append(version.Values, protocol.Resolved{Ciphertext: encrypted, DataKey: key})
	}
	version.Digest = protocol.VersionDigest(version.Values)
	resolver := &fakeSecretResolver{set: version, enabled: true}
	var created map[string]any
	posts := 0
	kube := secretKube(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if r.Header.Get("Content-Type") != "application/json" {
				t.Error("Secret create requires JSON", r.Header.Get("Content-Type"))
				w.WriteHeader(http.StatusUnsupportedMediaType)
				return
			}
			posts++
			if posts > 1 {
				w.WriteHeader(409)
				return
			}
			if json.NewDecoder(r.Body).Decode(&created) != nil {
				t.Error("invalid Secret")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
			return
		}
		_ = json.NewEncoder(w).Encode(created)
	}))
	delivery := &SecretDelivery{Client: resolver, Kube: kube, Targets: map[string]protocol.VersionSet{a.RevisionID: version}}
	i := &Instance{Name: name, Files: files}
	if e = delivery.Prepare(t.Context(), *a, i); e != nil {
		t.Fatal(e)
	}
	if !i.SecretPrepared || i.SecretVersion != version.Digest {
		t.Fatal("preparation state")
	}
	data := created["data"].(map[string]any)
	if len(data) != 2 {
		t.Fatal("key collision")
	}
	for _, ref := range a.Revision.Definition.Container.Secrets {
		raw, e := base64.StdEncoding.DecodeString(data[protocol.LocalKey(ref.Secret, ref.Key)].(string))
		if e != nil || string(raw) != "sentinel-"+ref.Secret {
			t.Fatal("incorrect mapping", e)
		}
	}
	for _, raw := range i.Files {
		if strings.Contains(string(raw), "sentinel-") || strings.Contains(string(raw), "data_key") {
			t.Fatal("plaintext persisted in artifact")
		}
	}
	files, _, _ = payload.Instantiate(payload.Index.Groups[0], strings.Repeat("a", 32))
	retry := &Instance{Name: name, Files: files}
	if e = delivery.Prepare(t.Context(), *a, retry); e != nil {
		t.Fatal("crash retry", e)
	}
	files, _, _ = payload.Instantiate(payload.Index.Groups[0], strings.Repeat("b", 32))
	for file, raw := range files {
		var pod map[string]any
		_ = json.Unmarshal(raw, &pod)
		if pod["kind"] == "Pod" {
			spec := pod["spec"].(map[string]any)
			container := spec["containers"].([]any)[0].(map[string]any)
			container["env"].([]any)[0].(map[string]any)["name"] = strings.Repeat("N", 128<<10)
			files[file], _ = json.Marshal(pod)
		}
	}
	oversized := &Instance{Name: name, Files: files}
	if e = delivery.Prepare(t.Context(), *a, oversized); e != protocol.ErrInvalid || posts != 2 || oversized.SecretPrepared {
		t.Fatal("oversized environment reached Kubernetes", e, posts)
	}
	resolver.err = protocol.ErrUnavailable
	delivery.Poll(t.Context(), State{Payload: payload}, time.Now())
	if len(delivery.Targets) != 0 {
		t.Fatal("outage retained positive start authorization")
	}
}

func TestManagedStartsWaitForAuthorizationAndPreparationFailureKeepsSource(t *testing.T) {
	c, _, cluster, _, _, _, resolver, set := secretController(t, 1, nil)
	resolver.enabled = false
	resolver.err = protocol.ErrUnavailable
	d := c.Secrets
	tick(t, c)
	if !resolver.enabled || len(c.Journal.View().Instances) != 0 {
		t.Fatal("first managed input bypassed the authorization gate")
	}
	v := regressionVersion(t, set, "v1")
	resolver.err = nil
	resolver.set = v
	d.Next = time.Time{}
	tick(t, c)
	cluster.apply(c)
	tick(t, c)
	var source *Instance
	for _, i := range c.Journal.View().Instances {
		source = i
	}
	if source == nil || !source.SecretPrepared {
		t.Fatal("initial Secret not prepared")
	}
	// A new version cannot withdraw a healthy source until its own preparation succeeds.
	resolver.set.Values[0].Version = "v2"
	resolver.set.Digest = protocol.VersionDigest(resolver.set.Values)
	d.Next = time.Time{}
	tick(t, c)
	state := c.Journal.View()
	if state.Instances[source.ID].WithdrawalID != "" {
		t.Fatal("failed successor preparation withdrew source")
	}
	for _, next := range state.SecretSuccessors {
		if next.SecretPrepared {
			t.Fatal("tampered successor ciphertext accepted")
		}
	}
}

func TestSameRevisionSecretRotationWaitsForSuccessorReadiness(t *testing.T) {
	c, _, cluster, owner, _, now, resolver, set := secretController(t, 2, nil)
	version := func(id string, revision int64) protocol.VersionSet { return regressionVersion(t, set, id, revision) }
	secretTicks(t, c, cluster, 5)
	state := c.Journal.View()
	if len(state.Instances) != 2 {
		t.Fatal("initial replica count", len(state.Instances))
	}
	for _, i := range state.Instances {
		secretReady(c, state, *now, i)
		owner.sessions[i.AppID] = []string{"busy"}
	}
	resolver.set = version("v2", 2)
	c.Secrets.Next = time.Time{}
	tick(t, c) // Optional preparation follows lifecycle publication.
	tick(t, c)
	withdrawn := 0
	for _, i := range c.Journal.View().Instances {
		if i.WithdrawalID != "" {
			withdrawn++
			owner.sessions[i.AppID] = nil
		}
	}
	if withdrawn != 1 {
		t.Fatal("rotation did not withdraw exactly one source", withdrawn)
	}
	for range 12 {
		tick(t, c)
		cluster.apply(c)
		occupiedCount := 0
		for _, i := range c.Journal.View().Instances {
			if occupied(i) {
				occupiedCount++
			}
		}
		if occupiedCount > 2 {
			t.Fatal("secret rotation exceeded replica limit", occupiedCount)
		}
	}
	state = c.Journal.View()
	var successor, source *Instance
	for _, i := range state.Instances {
		if i.WithdrawalID == "" && i.SecretVersion == resolver.set.Digest && i.AppID != "" {
			successor = i
		} else if i.WithdrawalID == "" {
			source = i
		}
	}
	if successor == nil || source == nil {
		for _, i := range state.Instances {
			t.Logf("slot=%d phase=%s withdrawal=%t prepared=%t current=%t pod=%t registered=%t gone=%t", i.Group.Slot, i.Phase, i.WithdrawalID != "", i.SecretPrepared, i.SecretVersion == resolver.set.Digest, i.PodUID != "", i.AppID != "", i.RegistrationGone)
		}
		t.Fatal("second source did not wait for the successor")
	}
	secretReady(c, state, *now, successor)
	tick(t, c)
	if c.Journal.View().Instances[source.ID].WithdrawalID == "" {
		t.Fatal("ready registered successor did not release the next rotation slot")
	}
}

type regressionTransport func(*http.Request) (*http.Response, error)

func (f regressionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func secretKube(h http.Handler) *transport.Kube {
	if h == nil {
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(map[string]any{}) })
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var value any
		switch r.URL.Path {
		case "/api/v1/namespaces/livepeer-apps":
			value = map[string]any{"metadata": map[string]any{"labels": map[string]string{"livepeer.io/managed-secrets": "true"}}}
		case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/livepeer-app-pods":
			value = map[string]any{"spec": map[string]any{"failurePolicy": "Fail", "validations": []map[string]string{{"expression": ownSecretRule}}}}
		case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/livepeer-app-pods":
			value = map[string]any{"spec": map[string]any{"policyName": "livepeer-app-pods", "validationActions": []string{"Deny"}}}
		default:
			h.ServeHTTP(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(value)
	})
	return &transport.Kube{Base: "https://test.invalid", Client: &http.Client{Transport: regressionTransport(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Result(), nil
	})}}
}

func regressionSecretFixture(t *testing.T) (schema.AppAssignmentSetV1, appbundle.Payload) {
	t.Helper()
	set := testutil.Assignment(t)
	a := &set.Entries[0]
	a.Replicas = 1
	a.Revision.Definition.Container.Secrets = []schema.SecretEnvironment{{Name: "TOKEN", Secret: "lp-app-provider", Key: "token"}}
	testutil.Refresh(a)
	p, e := appbundle.Render(set, appbundle.Options{})
	if e != nil {
		t.Fatal(e)
	}
	return set, p
}
func secretController(t *testing.T, replicas int, h http.Handler) (*Controller, *testInputs, *testCluster, *testOwner, *testReporter, *time.Time, *fakeSecretResolver, schema.AppAssignmentSetV1) {
	t.Helper()
	c, input, cluster, owner, reports, now := fixtureController(t)
	set, _ := regressionSecretFixture(t)
	set.Entries[0].Replicas = replicas
	input.set(t, set)
	input.value.Metadata.ManagedSecrets = true
	resolver := &fakeSecretResolver{enabled: true, set: regressionVersion(t, set, "v1")}
	k := secretKube(h)
	c.Secrets = &SecretDelivery{Client: resolver, Kube: k}
	return c, input, cluster, owner, reports, now, resolver, set
}
func secretTicks(t *testing.T, c *Controller, cluster *testCluster, n int) {
	t.Helper()
	for range n {
		tick(t, c)
		cluster.apply(c)
	}
}
func secretReady(c *Controller, s State, now time.Time, i *Instance) {
	c.Probes.values[i.ID] = &health{uid: i.PodUID, ready: true, started: true, next: now.Add(time.Minute)}
	c.proofs[i.ID] = proof{PodUID: i.PodUID, Observation: Observation{RunnerID: s.Identity.RunnerID, Credential: s.Identity.Credential, At: now, TTL: time.Minute}, App: AppObservation{ID: i.AppID, Status: "ready"}}
}
func regressionVersion(t *testing.T, set schema.AppAssignmentSetV1, id string, revisions ...int64) protocol.VersionSet {
	a := set.Entries[0]
	ciphertext, key, e := protocol.Encrypt(protocol.Binding{Owner: "owner", ID: "id", Name: "lp-app-provider", Key: "token", Version: id}, []byte("dummy-test-value"))
	if e != nil {
		t.Fatal(e)
	}
	v := protocol.VersionSet{NodeID: set.NodeID, IdentityGeneration: 1, PolicyGeneration: 1, Assignment: request(a), Values: []protocol.Resolved{{Ciphertext: ciphertext, DataKey: key, Revision: 1}}}
	if len(revisions) > 0 {
		v.Values[0].Revision = revisions[0]
	}
	v.Digest = protocol.VersionDigest(v.Values)
	return v
}
func TestRegressionPreparationCrashThenRotationMustRecover(t *testing.T) {
	set, p := regressionSecretFixture(t)
	v1 := regressionVersion(t, set, "v1")
	resolver := &fakeSecretResolver{enabled: true, set: v1}
	var existing map[string]any
	kube := secretKube(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			existing = nil
			w.WriteHeader(200)
			return
		}
		if r.Method == "POST" {
			if existing != nil {
				w.WriteHeader(409)
				return
			}
			if e := json.NewDecoder(r.Body).Decode(&existing); e != nil {
				t.Error(e)
			}
		}
		_ = json.NewEncoder(w).Encode(existing)
	}))
	d := &SecretDelivery{Client: resolver, Kube: kube, Targets: map[string]protocol.VersionSet{set.Entries[0].RevisionID: v1}}
	files, name, _ := p.Instantiate(p.Index.Groups[0], strings.Repeat("a", 32))
	prepared := &Instance{Name: name, Files: files}
	if e := d.Prepare(t.Context(), set.Entries[0], prepared); e != nil {
		t.Fatal(e)
	}
	// The Secret was created, but the process crashes before journaling the copy.
	resolver.set = regressionVersion(t, set, "v2")
	d.Targets[set.Entries[0].RevisionID] = resolver.set
	files, _, _ = p.Instantiate(p.Index.Groups[0], strings.Repeat("a", 32))
	pending := &Instance{Name: name, Files: files}
	if e := d.Prepare(t.Context(), set.Entries[0], pending); e != nil {
		t.Fatalf("retry after crash plus newer version is permanently stuck on the old immutable name: %v", e)
	}
}
func TestRegressionCollectRemovedUncommittedPreparation(t *testing.T) {
	c, _, _, _, _, _ := fixtureController(t)
	deletions := 0
	kube := secretKube(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			deletions++
		}
		w.WriteHeader(200)
	}))
	c.Secrets = &SecretDelivery{Client: &fakeSecretResolver{enabled: true}, Kube: kube}
	if e := c.Journal.Update(func(s *State) error {
		s.Instances["pending"] = &Instance{ID: "pending", Name: "lp-app-pending", Phase: "removed", SecretPrepared: false}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := c.collectSecrets(t.Context()); e != nil {
		t.Fatal(e)
	}
	if deletions == 0 {
		t.Fatal("Secret created before preparation commit was never deleted")
	}
}
func TestRegressionSettledStartAfterMustAllowRotation(t *testing.T) {
	c, _, _, _, _, _ := fixtureController(t)
	set, p := regressionSecretFixture(t)
	a := &set.Entries[0]
	a.StartAfter = &schema.AppStartAfter{RevisionID: "22222222-2222-4222-8222-222222222222", Generation: 2}
	a.StartAllowed = true // backend confirmed prerequisite cleanup; no old revision remains
	var e error
	p, e = appbundle.Render(set, appbundle.Options{})
	if e != nil {
		t.Fatal(e)
	}
	files, name, _ := p.Instantiate(p.Index.Groups[0], strings.Repeat("a", 32))
	v := regressionVersion(t, set, "v2")
	resolver := &fakeSecretResolver{enabled: true, set: v}
	kube := secretKube(nil)
	d := &SecretDelivery{Client: resolver, Kube: kube, Targets: map[string]protocol.VersionSet{a.RevisionID: v}}
	c.Secrets = d
	if e = c.Journal.Update(func(s *State) error {
		s.Payload = p
		s.Instances["old"] = &Instance{ID: "old", Name: name, Group: p.Index.Groups[0], Generation: a.Generation, Definition: a.Revision.Definition, Files: files, PodUID: "pod", SecretPrepared: true, SecretVersion: "v1", Phase: "running"}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = d.StageRotation(t.Context(), c, c.Journal.View()); e != nil {
		t.Fatal(e)
	}
	if len(c.Journal.View().SecretSuccessors) == 0 {
		t.Fatal("completed StartAfter suppresses all later secret rotations")
	}
}
func TestRegressionDeletionMustOverrideRevisionReplacement(t *testing.T) {
	c, _, _, _, _, now := fixtureController(t)
	fixture, _ := regressionSecretFixture(t)
	definition := fixture.Entries[0].Revision.Definition
	source := "11111111-1111-4111-8111-111111111111"
	target := "22222222-2222-4222-8222-222222222222"
	a := schema.AppAssignment{RevisionRef: schema.RevisionRef{RevisionID: target}, Revision: &schema.ResolvedRevision{Definition: definition}, Desired: "present", StartAllowed: true, Replacement: &schema.AppReplacement{RevisionID: source, ActivationGeneration: 1, Generation: 2, Replicas: 2}}
	old := &Instance{ID: "old", Definition: definition, Group: appbundle.Group{RevisionID: source, ActivationGeneration: 1, Slot: 1}, Phase: "running"}
	draining := &Instance{ID: "draining", Definition: definition, Group: appbundle.Group{RevisionID: source, ActivationGeneration: 1, Slot: 2}, Phase: "withdrawing", WithdrawalID: "committed"}
	s := State{Payload: appbundle.Payload{Intent: &schema.AppAssignmentSetV1{Entries: []schema.AppAssignment{a}}}, Instances: map[string]*Instance{old.ID: old, draining.ID: draining}}
	c.Secrets = &SecretDelivery{Faults: map[string]string{target: "secret_missing", source: "secret_missing"}}
	if retainRolling(&s, old, c, *now) {
		t.Fatal("deleted secret blocks successor, but retained source still receives a keep-running decision")
	}
}

type regressionSlowResolver struct{ fakeSecretResolver }

func (f *regressionSlowResolver) Resolve(ctx context.Context, _ protocol.ResolveRequest) (protocol.VersionSet, error) {
	<-ctx.Done()
	return protocol.VersionSet{}, protocol.ErrUnavailable
}

type regressionCountingInput struct {
	base  *testInputs
	reads int
}

func (i *regressionCountingInput) Read(ctx context.Context) (Input, error) {
	i.reads++
	return i.base.Read(ctx)
}

type regressionContextCluster struct{ *testCluster }

func (k regressionContextCluster) Read(ctx context.Context) (View, error) {
	if e := ctx.Err(); e != nil {
		return View{}, e
	}
	return k.testCluster.Read(ctx)
}
func TestRegressionVaultWaitMustNotStarveLifecycleInput(t *testing.T) {
	c, input, k, _, _, now := fixtureController(t)
	set, p := regressionSecretFixture(t)
	v := regressionVersion(t, set, "v2")
	slow := &regressionSlowResolver{fakeSecretResolver{enabled: true, set: v}}
	c.Secrets = &SecretDelivery{Client: slow, Kube: secretKube(nil), Targets: map[string]protocol.VersionSet{set.Entries[0].RevisionID: v}, Next: now.Add(time.Hour)}
	counter := &regressionCountingInput{base: input}
	c.Input = counter
	c.Cluster = regressionContextCluster{k}
	if e := c.Journal.Update(func(s *State) error {
		s.Payload = p
		s.Instances["old"] = &Instance{ID: "old", Name: "old", Group: p.Index.Groups[0], Generation: 1, Definition: set.Entries[0].Revision.Definition, PodUID: "pod", SecretPrepared: true, SecretVersion: "v1", Phase: "running"}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	_ = c.Tick(ctx)
	if counter.reads == 0 {
		t.Fatal("slow secret preparation consumed the tick before central denial/removal input was read")
	}
}
func TestRegressionAppliedMustRequireFreshNodeRegistration(t *testing.T) {
	c, _, k, _, reports, now := fixtureController(t)
	registerApps(t, c, k)
	ready := map[string]bool{}
	var revision string
	if e := c.Journal.Update(func(s *State) error {
		s.SecretRollouts = map[string]contract.SecretRollout{}
		for id, i := range s.Instances {
			i.SecretVersion = "v2"
			revision = i.Group.RevisionID
			ready[id] = true
			s.SecretRollouts[revision] = contract.SecretRollout{Generation: 2, Desired: "v2"}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	c.proofs = map[string]proof{} // saved AppID remains; no fresh Node observation
	if e := c.report(t.Context(), ready, k.view, *now); e != nil {
		t.Fatal(e)
	}
	r := reports.reports[len(reports.reports)-1].Apps.SecretRollouts[revision]
	if r.Applied == r.Desired {
		t.Fatal("reported applied although no current Node registration proof exists")
	}
}

func TestRapidRotationCollectsSupersededPreparation(t *testing.T) {
	c, input, cluster, owner, _, now := fixtureController(t)
	set, _ := regressionSecretFixture(t)
	input.set(t, set)
	input.value.Metadata.ManagedSecrets = true
	version := func(id string, revision int64) protocol.VersionSet { return regressionVersion(t, set, id, revision) }
	resolver := &fakeSecretResolver{enabled: true, set: version("v1", 1)}
	secrets := map[string]map[string]any{}
	kube := secretKube(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var v map[string]any
			if e := json.NewDecoder(r.Body).Decode(&v); e != nil {
				t.Fatal(e)
			}
			name := v["metadata"].(map[string]any)["name"].(string)
			if secrets[name] != nil {
				w.WriteHeader(409)
				return
			}
			secrets[name] = v
		}
		if r.Method == "DELETE" {
			for name := range secrets {
				if r.URL.Path == "/api/v1/namespaces/livepeer-apps/secrets/"+name {
					delete(secrets, name)
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	c.Secrets = &SecretDelivery{Client: resolver, Kube: kube}
	secretTicks(t, c, cluster, 6)
	s := c.Journal.View()
	if len(s.Instances) != 1 {
		t.Fatal("initial instance count", len(s.Instances))
	}
	var source *Instance
	for _, i := range s.Instances {
		source = i
	}
	c.Probes.values[source.ID] = &health{uid: source.PodUID, ready: true, started: true, next: now.Add(time.Minute)}
	c.proofs[source.ID] = proof{PodUID: source.PodUID, Observation: Observation{RunnerID: s.Identity.RunnerID, Credential: s.Identity.Credential, At: *now, TTL: time.Minute}, App: AppObservation{ID: source.AppID, Status: "ready"}}
	owner.sessions[source.AppID] = []string{"busy"}
	resolver.set = version("v2", 2)
	c.Secrets.Next = time.Time{}
	tick(t, c)
	tick(t, c)
	s = c.Journal.View()
	if s.Instances[source.ID].WithdrawalID == "" || len(s.SecretSuccessors) != 1 {
		t.Fatal("rotation was not committed")
	}
	var staleName string
	for _, i := range s.SecretSuccessors {
		staleName = i.Name
	}
	resolver.set = version("v3", 3)
	c.Secrets.Next = time.Time{}
	owner.sessions[source.AppID] = nil
	secretTicks(t, c, cluster, 30)
	s = c.Journal.View()
	current := 0
	for _, i := range s.Instances {
		if i.WithdrawalID == "" && i.SecretVersion == resolver.set.Digest && i.PodUID != "" {
			current++
		}
	}
	if current != 1 {
		t.Fatal("latest version did not start", current)
	}
	if len(s.SecretSuccessors) != 0 || secrets[staleName] != nil {
		t.Fatalf("v3 is running, but superseded v2 preparation remains: journal=%d secret=%t", len(s.SecretSuccessors), secrets[staleName] != nil)
	}
}

func TestCancelledPreparationCleanupContinuesThroughOutage(t *testing.T) {
	c, _, _, _, _, _ := fixtureController(t)
	set, payload := regressionSecretFixture(t)
	latest := regressionVersion(t, set, "v3")
	attempts := 0
	kube := secretKube(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	c.Secrets = &SecretDelivery{Client: &fakeSecretResolver{enabled: true}, Kube: kube, Targets: map[string]protocol.VersionSet{set.Entries[0].RevisionID: latest}}
	if e := c.Journal.Update(func(s *State) error {
		s.Payload = payload
		s.Instances["source"] = &Instance{ID: "source", Phase: "withdrawing"}
		s.SecretSuccessors = map[string]*Instance{"source": {Name: "lp-app-prepared", Generation: 1, Phase: "starting", Group: payload.Index.Groups[0], SecretPrepared: true, SecretVersion: "superseded"}}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := c.collectSecrets(t.Context()); e == nil {
		t.Fatal("failed deletion was ignored")
	}
	if c.Journal.View().SecretSuccessors["source"].Phase != "retired" {
		t.Fatal("cancellation was not durable")
	}
	c.Secrets.Targets = nil
	c.Secrets.Faults = map[string]string{set.Entries[0].RevisionID: "secrets_unavailable"}
	if e := c.collectSecrets(t.Context()); e != nil {
		t.Fatal(e)
	}
	if len(c.Journal.View().SecretSuccessors) != 0 || attempts != 2 {
		t.Fatal("outage lost pending cleanup", attempts)
	}
}

func TestTwoUnpublishedSecretReplicasMustConverge(t *testing.T) {
	c, _, cluster, _, _, _, resolver, set := secretController(t, 2, nil)
	prepared := false
	for range 5 {
		tick(t, c)
		state := c.Journal.View()
		prepared = len(state.Instances) == 2
		for _, i := range state.Instances {
			prepared = prepared && i.SecretPrepared && i.PodUID == ""
		}
		if prepared {
			break
		}
	}
	if !prepared {
		t.Fatal("fixture did not prepare two unpublished replicas")
	}
	resolver.set = regressionVersion(t, set, "v2")
	resolver.set.Values[0].Revision = 2
	c.Secrets.Next = time.Time{}
	secretTicks(t, c, cluster, 30)
	state := c.Journal.View()
	current := 0
	for _, i := range state.Instances {
		if i.SecretVersion == resolver.set.Digest && i.PodUID != "" && i.WithdrawalID == "" {
			current++
		}
	}
	if current != 2 {
		t.Fatalf("secret update stalled initial start: current=%d successors=%d", current, len(state.SecretSuccessors))
	}
}

func TestRapidRotationWaitsForReplacementAfterSupersession(t *testing.T) {
	c, _, cluster, owner, _, now, resolver, set := secretController(t, 2, nil)
	secretTicks(t, c, cluster, 6)
	initial := c.Journal.View()
	for _, i := range initial.Instances {
		secretReady(c, initial, *now, i)
		owner.sessions[i.AppID] = []string{"busy"}
	}
	resolver.set = regressionVersion(t, set, "v2")
	resolver.set.Values[0].Revision = 2
	c.Secrets.Next = time.Time{}
	tick(t, c)
	tick(t, c)
	var survivor string
	withdrawn := 0
	for _, i := range c.Journal.View().Instances {
		if i.WithdrawalID == "" {
			survivor = i.ID
		} else {
			withdrawn++
			owner.sessions[i.AppID] = nil
		}
	}
	if withdrawn != 1 || survivor == "" {
		t.Fatal("fixture did not withdraw one source", withdrawn)
	}
	resolver.set = regressionVersion(t, set, "v3")
	resolver.set.Values[0].Revision = 3
	c.Secrets.Next = time.Time{}
	for step := 0; step < 30; step++ {
		tick(t, c)
		cluster.apply(c)
		state := c.Journal.View()
		if state.Instances[survivor].WithdrawalID != "" {
			t.Fatalf("remaining healthy source withdrew at tick %d before any replacement readiness proof", step)
		}
	}
}

func TestCommittedPublicationSurvivesAuthorizationOutage(t *testing.T) {
	c, _, _, _, _, _, resolver, _ := secretController(t, 1, nil)
	included := ""
	for range 6 {
		tick(t, c)
		s := c.Journal.View()
		for id := range s.Snapshots[s.Published].Included {
			included = id
		}
		if included != "" {
			break
		}
	}
	if included == "" {
		t.Fatal("fixture never published the authorized incarnation")
	}
	resolver.err = fmt.Errorf("temporary synthetic authorization outage")
	tick(t, c)
	s := c.Journal.View()
	if !s.Snapshots[s.Published].Included[included] {
		t.Fatal("already-published incarnation removed before Pod observation on temporary authorization failure")
	}
}

func TestSecretReportingPrunesHistoryAndRetainsPreparationFailure(t *testing.T) {
	fail := true
	c, _, cluster, _, reports, _, resolver, set := secretController(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && fail {
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	for range 5 {
		tick(t, c)
	}
	revision := set.Entries[0].RevisionID
	if r := reports.reports[len(reports.reports)-1].Apps.SecretRollouts[revision]; r.Reason != "secrets_unavailable" {
		t.Fatal("preparation failure lost before reporting", r)
	}
	if e := c.Journal.Update(func(s *State) error {
		for n := range 1500 {
			s.SecretRollouts[fmt.Sprintf("historic-%d", n)] = contract.SecretRollout{Desired: strings.Repeat("a", 71)}
		}
		s.SecretWatermarks["retired-secret"] = 7
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	fail = false
	secretTicks(t, c, cluster, 5)
	s := c.Journal.View()
	if len(s.SecretRollouts) != 1 || s.SecretWatermarks["retired-secret"] != 7 {
		t.Fatal("history not collected or safety watermark lost", len(s.SecretRollouts))
	}
	r := reports.reports[len(reports.reports)-1].Apps.SecretRollouts[revision]
	if r.Reason != "" {
		t.Fatal("successful retry did not clear preparation failure", r)
	}
	resolver.err = protocol.ErrUnavailable
	c.Secrets.Next = time.Time{}
	tick(t, c)
	resolver.err = nil
	c.Secrets.Next = time.Time{}
	tick(t, c)
	if r := reports.reports[len(reports.reports)-1].Apps.SecretRollouts[revision]; r.Reason != "" {
		t.Fatal("recovered discovery retained an old availability fault", r)
	}
}

func TestCorrectiveRotationStartsWhenOldReplicasAreUnready(t *testing.T) {
	c, _, cluster, _, _, _, resolver, set := secretController(t, 2, nil)
	secretTicks(t, c, cluster, 6)
	resolver.set = regressionVersion(t, set, "v2")
	resolver.set.Values[0].Revision = 2
	c.Secrets.Next = time.Time{}
	secretTicks(t, c, cluster, 20)
	started := 0
	old := 0
	for _, i := range c.Journal.View().Instances {
		if i.WithdrawalID == "" {
			if i.SecretVersion == resolver.set.Digest && i.PodUID != "" {
				started++
			} else {
				old++
			}
		}
	}
	if started != 1 || old != 1 {
		t.Fatal("corrective rotation did not start exactly one slot", started, old)
	}
	resolver.set = regressionVersion(t, set, "v3")
	resolver.set.Values[0].Revision = 3
	c.Secrets.Next = time.Time{}
	secretTicks(t, c, cluster, 20)
	latest := 0
	for _, i := range c.Journal.View().Instances {
		if i.WithdrawalID == "" && i.SecretVersion == resolver.set.Digest && i.PodUID != "" {
			latest++
		}
	}
	if latest != 1 {
		t.Fatal("active rotation slot could not coalesce another update", latest)
	}
}

func TestIdentityFaultsCoverRetainedSecretConsumers(t *testing.T) {
	for _, phase := range []string{"renew", "activate", "bulk"} {
		for _, failure := range []error{protocol.ErrDenied, protocol.ErrUnavailable} {
			t.Run(phase+"/"+failure.Error(), func(t *testing.T) {
				c, input, _, _, _, now, resolver, set := secretController(t, 1, nil)
				switch phase {
				case "renew":
					resolver.renewErr = failure
				case "activate":
					resolver.activateErr = failure
				case "bulk":
					resolver.err = failure
				}
				s := State{Payload: input.value.Payload, Instances: map[string]*Instance{
					"retained": {Phase: "running", Group: appbundle.Group{RevisionID: "retained"}, Definition: set.Entries[0].Revision.Definition},
					"plain":    {Phase: "running", Group: appbundle.Group{RevisionID: "plain"}},
				}}
				c.Secrets.Poll(t.Context(), s, *now)
				want := "secrets_unavailable"
				if failure == protocol.ErrDenied {
					want = "secrets_denied"
				}
				if c.Secrets.Faults["retained"] != want || c.Secrets.Faults["plain"] != "" {
					t.Fatal("identity fault missed retained source or affected plain app", c.Secrets.Faults)
				}
			})
		}
	}
}

func TestPreparationPreservesConcurrentOwnerWithdrawal(t *testing.T) {
	for _, status := range []int{200, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c, input, _, _, _, now, resolver, set := secretController(t, 1, nil)
			payload := input.value.Payload
			a := set.Entries[0]
			id := strings.Repeat("d", 32)
			files, name, err := payload.Instantiate(payload.Index.Groups[0], id)
			if err != nil {
				t.Fatal(err)
			}
			if err = c.Journal.Update(func(s *State) error {
				s.Payload = payload
				s.Identity.RunnerID = "runner"
				s.Identity.Credential = "old-credential"
				s.Instances[id] = &Instance{ID: id, Name: name, Files: files, Group: payload.Index.Groups[0], Generation: a.Generation, Definition: a.Revision.Definition, Phase: "starting", CreatedAt: *now}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			c.Secrets.Targets = map[string]protocol.VersionSet{a.RevisionID: resolver.set}
			observed := false
			c.Secrets.Kube = secretKube(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					err = c.observe(Observation{RunnerID: "runner", PreviousCredential: "old-credential", Credential: "new-credential", Bootstrap: true, At: *now})
					if err != nil {
						t.Fatal(err)
					}
					observed = c.Journal.View().Instances[id].WithdrawalID != ""
				}
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]any{})
			}))
			if err = c.prepareSecrets(t.Context()); err != nil {
				t.Fatal(err)
			}
			if !observed {
				t.Fatal("fixture did not commit concurrent owner-recreation withdrawal")
			}
			i := c.Journal.View().Instances[id]
			if status == 200 && !i.SecretPrepared {
				t.Fatal("created Secret not tracked for cleanup")
			}
			if i.WithdrawalID == "" || !i.Forced || i.Reason != "node_registration_recreated" {
				t.Fatalf("preparation overwrote durable withdrawal: phase=%s withdrawn=%t forced=%t reason=%q", i.Phase, i.WithdrawalID != "", i.Forced, i.Reason)
			}
		})
	}
}
