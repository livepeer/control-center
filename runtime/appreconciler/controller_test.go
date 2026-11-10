package appreconciler

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/internal/testutil"
	"github.com/livepeer/control-center/runtime/transport"
	"github.com/livepeer/control-center/schema"
)

type testInputs struct {
	value Input
	fail  bool
}

func (i *testInputs) Read(context.Context) (Input, error) {
	if i.fail {
		return Input{}, errors.New("input_down")
	}
	return i.value, nil
}
func (i *testInputs) set(t *testing.T, set schema.AppAssignmentSetV1) {
	t.Helper()
	p, err := appbundle.Render(set, appbundle.Options{})
	if err != nil {
		t.Fatal(err)
	}
	i.value = Input{Metadata: contract.Metadata{NodeID: set.NodeID, Epoch: set.Epoch, CredentialVersion: 1, Generation: 1, BundleFormat: contract.BundleFormat, AppsGeneration: set.Generation, AppsDigest: p.Index.IntentDigest, AppsPayloadDigest: p.Digest()}, Payload: p, Digest: artifact.Digest([]byte(p.Digest()))}
}

type testCluster struct {
	view      View
	published string
	fail      bool
	releases  int
}

func newCluster() *testCluster {
	return &testCluster{view: View{Pods: map[string]Pod{}, Services: map[string]bool{}, Endpoints: map[string]map[string]bool{}, Inventory: map[string]bool{}, Budget: Resources{128000, 128 << 30, 512 << 30}}}
}
func (k *testCluster) Read(context.Context) (View, error) { return k.view, nil }
func (k *testCluster) Publish(_ context.Context, a *transport.Artifact) error {
	if k.fail {
		return errors.New("publication_down")
	}
	k.published = a.Digest
	k.view.Artifact = a.Digest
	return nil
}

func (k *testCluster) Release(_ context.Context, name string, pod Pod) error {
	if !pod.Deleting || k.view.Pods[name].UID != pod.UID {
		return errors.New("wrong_release")
	}
	k.releases++
	delete(k.view.Pods, name)
	return nil
}
func (k *testCluster) apply(c *Controller) {
	s := c.Journal.View()
	snap := s.Snapshots[k.published]
	k.view.Applied = k.published
	k.view.Inventory = map[string]bool{}
	for id, i := range s.Instances {
		if snap.Included[id] {
			if _, exists := k.view.Pods[i.Name]; !exists {
				k.view.Pods[i.Name] = Pod{UID: "uid-" + id, ResourceVersion: "1", Phase: "Running", Finalizers: []string{appbundle.Finalizer}}
			}
			k.view.Services[i.Name] = true
			k.view.Endpoints[i.Name] = map[string]bool{k.view.Pods[i.Name].UID: true}
			k.view.Inventory[inventoryID(i.Name, "Pod")] = true
			k.view.Inventory[inventoryID(i.Name, "Service")] = true
		} else {
			if pod, exists := k.view.Pods[i.Name]; exists {
				pod.Deleting = true
				k.view.Pods[i.Name] = pod
			}
			delete(k.view.Services, i.Name)
		}
	}
}

type testOwner struct {
	accepted             OwnerRequest
	sessions             map[string][]string
	down                 bool
	unregisterFail       bool
	unregisters          int
	rejectAbove, rejects int
	credential           string
	syncFailure          func(OwnerRequest, OwnerHooks) error
}

func (o *testOwner) Accepted() OwnerRequest      { return o.accepted }
func (o *testOwner) Close(context.Context) error { return nil }
func (o *testOwner) Sync(_ context.Context, r OwnerRequest, h OwnerHooks) error {
	if o.syncFailure != nil {
		return o.syncFailure(r, h)
	}
	if o.rejectAbove > 0 && len(r.Entries) > o.rejectAbove {
		o.rejects++
		return ErrResourceRefused
	}
	if o.down {
		return errors.New("node_down")
	}
	n, err := h.Reserve(r.Hash)
	if err != nil {
		return err
	}
	credential := o.credential
	if credential == "" {
		credential = "issued-secret"
	}
	obs := Observation{Epoch: r.Epoch, Hash: r.Hash, RunnerID: r.Identity.RunnerID, Credential: credential, PreviousCredential: r.Identity.Credential, ReservedSequence: n, Sequence: n, Bootstrap: r.Identity.Credential == "" || r.Recover, At: h.Now(), TTL: 30 * time.Second, Entries: r.Entries}
	submitted := map[string]bool{}
	for _, e := range r.Entries {
		id := e.Options.ID
		if id == "" {
			id = "app-" + e.InstanceID
		}
		submitted[id] = true
		obs.Apps = append(obs.Apps, AppObservation{ID: id, Status: e.Options.Status, SessionIDs: o.sessions[id]})
	}
	for id, sessions := range o.sessions {
		if !submitted[id] && len(sessions) > 0 {
			obs.Apps = append(obs.Apps, AppObservation{ID: id, Status: "draining", SessionIDs: sessions})
		}
	}
	if err = h.Observe(obs); err != nil {
		return err
	}
	o.accepted = r
	o.accepted.Identity = Identity{RunnerID: r.Identity.RunnerID, Credential: credential, Confirmed: !obs.Bootstrap}
	for n := range o.accepted.Entries {
		o.accepted.Entries[n].Options.ID = obs.Apps[n].ID
	}
	return nil
}
func TestMaintenanceWithoutAcceptedPayloadDoesNotPublishEmpty(t *testing.T) {
	c, input, k, _, r, _ := fixtureController(t)
	input.value.Payload = appbundle.Unavailable()
	input.value.Metadata.DrainRequested = true
	input.value.Metadata.DrainTarget = artifact.Digest([]byte("target"))
	input.value.Metadata.AppsError = "unsupported_instance_mode"
	tick(t, c)
	report := r.reports[len(r.reports)-1]
	if !report.Drained || report.Evidence == nil || report.Evidence.Target != input.value.Metadata.DrainTarget || k.published != "" {
		t.Fatal("unavailable payload blocked empty-owner proof or authorized empty publication", report)
	}
}
func (o *testOwner) Unregister(context.Context, Identity) error {
	o.unregisters++
	if o.down || o.unregisterFail {
		return errors.New("unregister_down")
	}
	o.sessions = map[string][]string{}
	return nil
}

type testReporter struct {
	reports    []Report
	receipts   []Receipt
	statusFail bool
}

func (r *testReporter) Status(_ context.Context, value Report) error {
	r.reports = append(r.reports, value)
	if r.statusFail {
		return errors.New("report_down")
	}
	return nil
}

func TestRejectedAdditionIsDeferredWithoutMaskingFailureOrDelayingWithdrawal(t *testing.T) {
	c, input, k, o, r, _ := fixtureController(t)
	set := testutil.Assignment(t)
	set.Entries[0].Replicas = 1
	input.set(t, set)
	registerApps(t, c, k)
	o.rejectAbove = 1
	set.Generation++
	set.Entries[0].Generation++
	set.Entries[0].Replicas = 2
	input.set(t, set)
	tick(t, c)
	k.apply(c)
	if c.Tick(t.Context()) == nil {
		t.Fatal("addition was not rejected")
	}
	epoch := c.Journal.View().OwnerEpoch
	tick(t, c)
	if o.rejects != 1 || c.Journal.View().OwnerEpoch != epoch || r.reports[len(r.reports)-1].Apps.Reason != "resource_refused" {
		t.Fatal("retry churned healthy subset or hid requested-membership failure")
	}
	set.Generation++
	set.Entries[0].Generation++
	set.Entries[0].Desired = "absent"
	set.Entries[0].Replicas = 0
	set.Entries[0].StartAllowed = false
	set.Entries[0].Revision = nil
	input.set(t, set)
	tick(t, c)
	if len(o.accepted.Entries) != 1 || o.accepted.Entries[0].Options.Status != "not-ready" {
		t.Fatal("addition retry delay also delayed safety withdrawal")
	}
}

func TestOwnerFailureKeepsClassificationAndUsesCurrentRecoveryDecision(t *testing.T) {
	for _, reset := range []bool{false, true} {
		t.Run(map[bool]string{false: "node_unavailable", true: "registration_auth_failed"}[reset], func(t *testing.T) {
			c, input, k, o, reports, _ := fixtureController(t)
			set := *input.value.Payload.Intent
			set.Entries[0].Replicas = 1
			input.set(t, set)
			registerApps(t, c, k)
			set.Generation++
			set.Entries[0].Generation++
			set.Entries[0].Replicas = 2
			input.set(t, set)
			tick(t, c)
			k.apply(c)
			calls := 0
			reason := "node_unavailable"
			if reset {
				reason = "registration_auth_failed"
			}
			o.syncFailure = func(r OwnerRequest, h OwnerHooks) error {
				calls++
				h.Failure(OwnerFailure{Epoch: r.Epoch, Hash: r.Hash, Reason: reason, Reset: reset})
				if reset {
					return &transport.HTTPError{Status: 401}
				}
				return errors.New("node_request_failed")
			}
			if c.Tick(t.Context()) == nil {
				t.Fatal("fixture failure ignored")
			}
			s := c.Journal.View()
			if s.OwnerReason != reason || reports.reports[len(reports.reports)-1].Apps.Reason != reason || (reset && s.RejectedOwnerHash != "") {
				t.Fatal("classified failure became generic or resource backoff", s.OwnerReason, s.RejectedOwnerHash)
			}
			if reset && calls != 1 {
				t.Fatal("resumed invalid accepted credential after auth failure", calls)
			}
		})
	}
}
func (r *testReporter) Receipt(_ context.Context, _ contract.Metadata, value Receipt) error {
	r.receipts = append(r.receipts, value)
	return nil
}
func fixtureController(t *testing.T) (*Controller, *testInputs, *testCluster, *testOwner, *testReporter, *time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	j, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	input := &testInputs{}
	input.set(t, testutil.Assignment(t))
	cluster := newCluster()
	owner := &testOwner{sessions: map[string][]string{}}
	reporter := &testReporter{}
	c := &Controller{Journal: j, Input: input, Cluster: cluster, Owner: owner, Store: artifact.Store{Directory: t.TempDir()}, ArtifactURL: "http://apps:8080", Reporter: reporter, Now: func() time.Time { return now }}
	return c, input, cluster, owner, reporter, &now
}
func tick(t *testing.T, c *Controller) {
	t.Helper()
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func registerApps(t *testing.T, c *Controller, k *testCluster) {
	t.Helper()
	tick(t, c)
	k.apply(c)
	tick(t, c)
	tick(t, c)
}

func TestRecreatedOwnerDoesNotConfirmOldWork(t *testing.T) {
	c, _, cluster, _, _, _ := fixtureController(t)
	registerApps(t, c, cluster)
	owner := &testOwner{credential: "recreated-secret", sessions: map[string][]string{}}
	c.Owner, c.proofs, c.recoverOwner = owner, nil, true
	ready := map[string]bool{}
	for id := range c.Journal.View().Instances {
		ready[id] = true
	}
	if err := c.syncOwner(t.Context(), c.Journal.View(), ready, cluster.view); err != nil {
		t.Fatal(err)
	}
	s := c.Journal.View()
	if s.Identity.Credential != owner.credential || s.Identity.Confirmed || s.AcceptedSequence != 0 || len(c.proofs) != 0 {
		t.Fatal("recreated owner supplied confirmed work evidence", s.Identity)
	}
	for _, entry := range owner.Accepted().Entries {
		if entry.Options.Status != "not-ready" {
			t.Fatal("recovery admitted new work", entry)
		}
	}
	for _, i := range s.Instances {
		if !i.Forced || i.WithdrawalID == "" || i.Reason != "node_registration_recreated" {
			t.Fatal("recreated owner did not withdraw the old incarnation", i)
		}
	}
}

func TestWithdrawalRetainsSessionsAndRequiresExactExclusionBeforeFinalizer(t *testing.T) {
	c, input, k, o, r, _ := fixtureController(t)
	registerApps(t, c, k)
	s := c.Journal.View()
	var retired, sibling *Instance
	for _, i := range s.Instances {
		if i.Group.Slot == 1 {
			retired = i
		} else {
			sibling = i
		}
	}
	o.sessions[retired.AppID] = []string{"busy"}
	set := *input.value.Payload.Intent
	set.Generation++
	set.Entries[0].Generation++
	set.Entries[0].Replicas = 1
	input.set(t, set)
	tick(t, c)
	tick(t, c)
	if c.Journal.View().Instances[retired.ID].Phase != "withdrawing" {
		t.Fatal("removed active work")
	}
	if len(o.accepted.Entries) != 2 {
		t.Fatal("lost retained sibling membership")
	}
	o.sessions[retired.AppID] = nil
	tick(t, c)
	tick(t, c)
	s = c.Journal.View()
	if s.Instances[retired.ID].Phase != "retired" || s.Snapshots[s.Published].Included[retired.ID] {
		t.Fatal("did not commit exclusion")
	}
	if k.releases != 0 {
		t.Fatal("released before exclusion applied")
	}
	k.apply(c)
	tick(t, c)
	tick(t, c)
	if remaining := c.Journal.View().Instances[retired.ID]; k.releases != 1 || (remaining != nil && remaining.Phase != "removed") {
		t.Fatal("did not wait for actual absence")
	}
	if c.Journal.View().Instances[sibling.ID].Phase == "removed" || o.unregisters != 0 {
		t.Fatal("removed sibling owner")
	}
	if c.Journal.View().Instances[retired.ID].RegistrationGone {
		t.Fatal("claimed registration removal before the next owner observation")
	}
	tick(t, c)
	found := false
	for _, receipt := range r.receipts {
		if receipt.Phase == "applied" && receipt.Generation == 2 {
			found = true
		}
	}
	if !found {
		t.Fatal("scale-down receipt missing")
	}
}
func TestDeadlinePublishesWithoutNodeAndKeepsCleanupUnconfirmed(t *testing.T) {
	c, input, k, o, r, now := fixtureController(t)
	registerApps(t, c, k)
	s := c.Journal.View()
	for _, i := range s.Instances {
		o.sessions[i.AppID] = []string{"busy"}
	}
	input.value.Metadata.DrainRequested = true
	input.value.Metadata.DrainTarget = artifact.Digest([]byte("maintenance"))
	input.value.Metadata.DrainDeadline = now.Add(5 * time.Second)
	tick(t, c)
	deadline := c.Journal.View().Instances[instanceIDs(&s)[0]].Deadline
	o.down = true
	*now = now.Add(6 * time.Second)
	k.fail = true
	if c.Tick(context.Background()) == nil {
		t.Fatal("ignored publisher failure")
	}
	s = c.Journal.View()
	for _, i := range s.Instances {
		if i.Phase != "retired" || !i.Forced || !i.Deadline.Equal(deadline) || i.Reason != "cleanup_unconfirmed" {
			t.Fatal("deadline lost", i)
		}
	}
	k.fail = false
	_ = c.Tick(context.Background())
	s = c.Journal.View()
	if len(s.Snapshots[s.Published].Included) != 0 || k.releases != 0 {
		t.Fatal("forced exclusion was not independently published")
	}
	k.apply(c)
	_ = c.Tick(context.Background())
	_ = c.Tick(context.Background())
	if r.reports[len(r.reports)-1].Drained {
		t.Fatal("claimed Node cleanup from pod absence")
	}
	o.down = false
	o.unregisterFail = true
	_ = c.Tick(context.Background())
	if !c.Journal.View().Identity.Retiring {
		t.Fatal("lost retirement tombstone")
	}
	o.unregisterFail = false
	tick(t, c)
	if !r.reports[len(r.reports)-1].Drained || o.unregisters < 2 {
		t.Fatal("did not retry final retirement")
	}
}

func TestPendingInstancesDoNotRetireOwnerAndRetirementAlwaysRetries(t *testing.T) {
	c, _, k, o, _, _ := fixtureController(t)
	tick(t, c)
	if err := c.Journal.Update(func(s *State) error {
		s.Identity = Identity{RunnerID: "old", Credential: "issued"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.syncOwner(t.Context(), c.Journal.View(), nil, k.view); err != nil || o.unregisters != 0 {
		t.Fatal("pending Pods prematurely retired owner", err)
	}
	// Resume an already committed retirement even if new Pods become runnable.
	c.Journal.Update(func(s *State) error { s.Identity.Retiring = true; return nil })
	k.apply(c)
	o.unregisterFail = true
	if err := c.syncOwner(t.Context(), c.Journal.View(), nil, k.view); err == nil {
		t.Fatal("ignored unregister failure")
	}
	o.unregisterFail = false
	if err := c.syncOwner(t.Context(), c.Journal.View(), nil, k.view); err != nil || o.unregisters != 2 {
		t.Fatal("new eligibility blocked retirement retry", err)
	}
	tick(t, c)
	for _, i := range c.Journal.View().Instances {
		if i.AppID == "" || i.RegistrationGone {
			t.Fatal("new registration poisoned by previous retirement", i)
		}
	}
}

func TestRegressedIntentDoesNotBlockCommittedDrain(t *testing.T) {
	c, input, k, o, r, now := fixtureController(t)
	registerApps(t, c, k)
	s := c.Journal.View()
	timeout := time.Duration(0)
	for _, i := range s.Instances {
		o.sessions[i.AppID] = []string{"busy"}
		timeout, _ = time.ParseDuration(i.Definition.Instances.DrainTimeout)
	}
	set := testutil.Assignment(t)
	set.Generation++
	set.Entries[0].Generation++
	set.Entries[0].Desired = "absent"
	set.Entries[0].Replicas = 0
	set.Entries[0].StartAllowed = false
	set.Entries[0].Revision = nil
	input.set(t, set)
	tick(t, c)
	digest := c.Journal.View().Payload.Index.IntentDigest
	input.set(t, testutil.Assignment(t))
	*now = now.Add(timeout + time.Second)
	if c.Tick(t.Context()) == nil {
		t.Fatal("accepted regressed input")
	}
	s = c.Journal.View()
	if s.Payload.Index.IntentDigest != digest || len(s.Snapshots[s.Published].Included) != 0 {
		t.Fatal("regression replaced accepted intent or blocked deadline exclusion")
	}
	k.apply(c)
	for n := 0; n < 3; n++ {
		_ = c.Tick(t.Context())
	}
	for _, i := range c.Journal.View().Instances {
		if i.Phase != "removed" || !i.RegistrationGone {
			t.Fatal("regressed input blocked accepted cleanup", i)
		}
	}
	if r.reports[len(r.reports)-1].Apps.Reason != "input_regression" {
		t.Fatal("missing input fault diagnostic")
	}
}
func TestUnavailableInputAndStateLossNeverPublishEmpty(t *testing.T) {
	c, input, k, _, _, _ := fixtureController(t)
	tick(t, c)
	original := k.published
	data, err := c.Store.Get(original)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.Store.Directory, original[7:]+".tar.gz")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	tick(t, c)
	stable, err := os.Stat(path)
	if err != nil || !info.ModTime().Equal(stable.ModTime()) {
		t.Fatal("unchanged tick rewrote its immutable archive", err)
	}
	input.fail = true
	_ = c.Tick(context.Background())
	if k.published != original {
		t.Fatal("failed input pruned apps")
	}
	for _, corrupt := range []bool{true, false} {
		if corrupt {
			err = os.WriteFile(path, []byte("corrupt"), 0644)
		} else {
			err = os.Remove(path)
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Tick(t.Context())
		repaired, err := c.Store.Get(original)
		if err != nil || k.published != original || !bytes.Equal(repaired, data) {
			t.Fatal("failed to repair accepted artifact without new input", err)
		}
	}
	j, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	c.Journal = j
	if err = c.Tick(context.Background()); !errors.Is(err, ErrStateLost) {
		t.Fatal("accepted complete state loss", err)
	}
}
func TestLateProofIsBoundToWithdrawalAndPodUID(t *testing.T) {
	c, _, _, _, _, now := fixtureController(t)
	i := &Instance{ID: "i", WithdrawalID: "new", PodUID: "new-pod"}
	c.proofs = map[string]proof{"i": {Observation: Observation{At: *now, TTL: time.Minute}, App: AppObservation{Status: "draining"}, WithdrawalID: "old", PodUID: "new-pod"}}
	if c.empty(i, *now) {
		t.Fatal("old withdrawal accepted")
	}
	p := c.proofs["i"]
	p.WithdrawalID = "new"
	p.PodUID = "old-pod"
	c.proofs["i"] = p
	if c.empty(i, *now) {
		t.Fatal("old UID accepted")
	}
	p.PodUID = i.PodUID
	c.proofs["i"] = p
	if !c.empty(i, *now) || c.empty(i, now.Add(time.Minute)) {
		t.Fatal("freshness ignored")
	}
}

func TestSupersededResponsePreservesOnlyCurrentCredentialLineage(t *testing.T) {
	c, _, _, _, _, _ := fixtureController(t)
	c.Journal.Update(func(s *State) error {
		s.Identity = Identity{RunnerID: "owner", Credential: "old", Confirmed: true}
		s.OwnerHash, s.OwnerEpoch = "current", "new-epoch"
		s.IdentitySequence, s.AcceptedSequence = 7, 7
		return nil
	})
	o := Observation{RunnerID: "owner", Hash: "superseded", Epoch: "old-epoch", PreviousCredential: "old", Credential: "rotated", ReservedSequence: 8, Sequence: 8}
	if err := c.observe(o); !errors.Is(err, ErrSuperseded) {
		t.Fatal("accepted superseded work", err)
	}
	s := c.Journal.View()
	if s.Identity.Credential != "rotated" || s.Identity.Confirmed || s.AcceptedSequence != 0 || s.IdentitySequence != 8 {
		t.Fatal("lost rotated credential or confirmed old scope", s.Identity)
	}
	o.Credential, o.ReservedSequence = "stale", 7
	if err := c.observe(o); !errors.Is(err, ErrSuperseded) || c.Journal.View().Identity.Credential != "rotated" {
		t.Fatal("older lineage overwrote latest credential", err)
	}
	c.Journal.Update(func(s *State) error { s.Identity.Retiring = true; return nil })
	o.PreviousCredential, o.Credential, o.ReservedSequence = "rotated", "final", 9
	if err := c.observe(o); !errors.Is(err, ErrSuperseded) {
		t.Fatal("retirement accepted work", err)
	}
	s = c.Journal.View()
	if s.Identity.Credential != "final" || !s.Identity.Retiring {
		t.Fatal("in-flight credential was lost or revived retiring owner")
	}
}

func TestRegressionMustObserveExclusionAfterPublishingAddition(t *testing.T) {
	c, input, k, _, r, _ := fixtureController(t)
	set := testutil.Assignment(t)
	empty := set
	empty.Entries = []schema.AppAssignment{}
	input.set(t, empty)
	tick(t, c)
	k.apply(c)
	oldEmpty := k.view.Applied
	set.Generation = 2
	input.set(t, set)
	tick(t, c)
	addition := k.published
	if addition == oldEmpty {
		t.Fatal("addition missing")
	}
	// Flux may be applying addition; its last successful revision is still oldEmpty.
	set.Generation = 3
	set.Entries[0].Generation++
	set.Entries[0].Desired = "absent"
	set.Entries[0].Replicas = 0
	set.Entries[0].StartAllowed = false
	set.Entries[0].Revision = nil
	input.set(t, set)
	tick(t, c)
	for _, receipt := range r.receipts {
		if receipt.Phase == "removed" {
			t.Fatalf("acknowledged removal while Flux last applied the pre-addition empty revision; exclusion reconciliation never occurred")
		}
	}
}
func TestRegressionNewAppIDMustBePersistedBeforeReady(t *testing.T) {
	c, input, k, o, _, _ := fixtureController(t)
	registerApps(t, c, k)
	set := *input.value.Payload.Intent
	set.Generation++
	set.Entries[0].Generation++
	set.Entries[0].Replicas = 3
	input.set(t, set)
	tick(t, c)
	k.apply(c)
	o.down = true
	_ = c.Tick(context.Background())
	o.down = false
	s := c.Journal.View()
	ready := map[string]bool{}
	newID := ""
	for id, i := range s.Instances {
		ready[id] = true
		if i.AppID == "" {
			newID = id
		}
	}
	if newID == "" {
		t.Fatal("new app fixture missing")
	}
	if err := c.syncOwner(context.Background(), s, ready, k.view); err != nil {
		t.Fatal(err)
	}
	for _, entry := range o.accepted.Entries {
		if entry.InstanceID == newID && entry.Options.Status == "ready" {
			t.Fatalf("first successful registration of newly added instance submitted ready before its assigned ID was persisted")
		}
	}
}

func TestRegressionPublicationFailureStillWithdrawsAdmission(t *testing.T) {
	c, input, k, o, _, _ := fixtureController(t)
	registerApps(t, c, k)
	s := c.Journal.View()
	ready := map[string]bool{}
	for id, i := range s.Instances {
		ready[id] = true
		o.sessions[i.AppID] = []string{"busy"}
	}
	if err := c.syncOwner(context.Background(), s, ready, k.view); err != nil {
		t.Fatal(err)
	}
	set := *input.value.Payload.Intent
	set.Generation++
	set.Entries[0].Generation++
	set.Entries[0].Replicas = 1
	input.set(t, set)
	k.fail = true
	_ = c.Tick(context.Background())
	for _, e := range o.accepted.Entries {
		if s.Instances[e.InstanceID].Group.Slot == 1 && e.Options.Status == "ready" {
			t.Fatalf("publication error left removed instance advertised ready in the live owner snapshot")
		}
	}
}
