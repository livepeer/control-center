package appreconciler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/internal/testutil"
	"github.com/livepeer/control-center/runtime/onchain"
	"github.com/livepeer/control-center/runtime/transport"
	"github.com/livepeer/control-center/schema"
	runner "github.com/livepeer/golang-runner"
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
	i.value = Input{Metadata: contract.Metadata{Onchain: onchain.Offchain(), NodeID: set.NodeID, CredentialVersion: 1, Generation: 1, BundleFormat: contract.BundleFormat, AppsGeneration: set.Generation, AppsDigest: p.Index.IntentDigest, AppsPayloadDigest: p.Digest()}, Payload: p, Digest: artifact.Digest([]byte(p.Digest()))}
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
	accepted       OwnerRequest
	sessions       map[string][]string
	down           bool
	unregisterFail bool
	unregisters    int
	credential     string
	syncFailure    func(OwnerRequest, OwnerHooks) error
}

func (o *testOwner) Accepted() Identity          { return o.accepted.Identity }
func (o *testOwner) Close(context.Context) error { return nil }
func (o *testOwner) Sync(_ context.Context, r OwnerRequest, h OwnerHooks) error {
	if o.syncFailure != nil {
		return o.syncFailure(r, h)
	}
	if o.down {
		return errors.New("node_down")
	}
	n := uint64(0)
	if r.Identity.Sequence != nil {
		n = *r.Identity.Sequence + 1
	}
	credential := o.credential
	if credential == "" {
		credential = "issued-secret"
	}
	obs := Observation{RunnerID: r.Identity.RunnerID, Credential: credential, PreviousCredential: r.Identity.Credential, Accepted: true, Sequence: n, Bootstrap: r.Identity.Credential == "" || (o.credential != "" && o.credential != r.Identity.Credential), At: h.Now(), TTL: 30 * time.Second, Entries: r.Entries, Withdrawals: r.Tracked}
	submitted := map[string]bool{}
	for _, e := range r.Entries {
		id := e.Options.ID
		if id == "" {
			id = "app-" + e.InstanceID
		}
		submitted[id] = true
		obs.Apps = append(obs.Apps, AppObservation{ID: id, Status: e.Options.Status, SessionIDs: append([]string{}, o.sessions[id]...)})
		obs.Entries[len(obs.Apps)-1].Options.ID = id
	}
	for id, sessions := range o.sessions {
		if !submitted[id] && len(sessions) > 0 {
			obs.Apps = append(obs.Apps, AppObservation{ID: id, Status: "draining", SessionIDs: sessions})
		}
	}
	if err := h.Observe(obs); err != nil {
		return err
	}
	o.accepted = r
	o.accepted.Identity = Identity{RunnerID: r.Identity.RunnerID, Credential: credential, Confirmed: !obs.Bootstrap, Sequence: new(n)}
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
				h.Failure(OwnerFailure{RunnerID: r.Identity.RunnerID, Reason: reason, Reset: reset})
				if reset {
					return &transport.HTTPError{Status: 401}
				}
				return errors.New("node_request_failed")
			}
			if c.Tick(t.Context()) == nil {
				t.Fatal("fixture failure ignored")
			}
			s := c.Journal.View()
			if s.OwnerReason != reason || reports.reports[len(reports.reports)-1].Apps.Reason != reason {
				t.Fatal("classified failure became generic", s.OwnerReason)
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
	if s.Identity.Credential != owner.credential || s.Identity.Confirmed || s.Identity.Sequence != nil || len(c.proofs) != 0 {
		t.Fatal("recreated owner supplied confirmed work evidence", s.Identity)
	}
	for _, entry := range owner.accepted.Entries {
		if !entry.Options.Proxy {
			t.Fatal("managed app omitted generated proxy Host", entry)
		}
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
	if len(o.accepted.Entries) != 1 || o.accepted.Entries[0].InstanceID != sibling.ID {
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
	if i := c.Journal.View().Instances[retired.ID]; i != nil && !i.RegistrationGone {
		t.Fatal("lost committed registration removal")
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
	o.sessions = map[string][]string{}
	o.unregisterFail = true
	_ = c.Tick(context.Background())
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
		timeout = time.Second
	}
	set := testutil.Assignment(t)
	set.Generation++
	set.Entries[0].Generation++
	set.Entries[0].Desired = "absent"
	set.Entries[0].Replicas = 0
	set.Entries[0].StartAllowed = false
	set.Entries[0].Revision = nil
	input.set(t, set)
	input.value.Metadata.DrainDeadline = now.Add(timeout)
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
	o.sessions = map[string][]string{}
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
func TestRemovalObservationIsBoundAndDurable(t *testing.T) {
	c, _, _, _, _, now := fixtureController(t)
	c.Journal.Update(func(s *State) error {
		s.Identity = Identity{RunnerID: "owner", Credential: "issued"}
		s.Instances["i"] = &Instance{ID: "i", AppID: "app", WithdrawalID: "withdrawal", PodUID: "pod"}
		return nil
	})
	e := Registration{InstanceID: "i", WithdrawalID: "wrong", PodUID: "pod"}
	o := Observation{RunnerID: "owner", Credential: "issued", PreviousCredential: "issued", Accepted: true, At: *now, TTL: time.Minute, Apps: []AppObservation{}, Withdrawals: []Registration{e}}
	c.observe(o)
	if c.Journal.View().Instances["i"].RegistrationGone {
		t.Fatal("wrong withdrawal accepted")
	}
	o.Sequence++
	o.Withdrawals[0].WithdrawalID = "withdrawal"
	o.Withdrawals[0].PodUID = "old-pod"
	c.observe(o)
	if c.Journal.View().Instances["i"].RegistrationGone {
		t.Fatal("wrong incarnation accepted")
	}
	o.Sequence++
	o.Withdrawals[0].PodUID = "pod"
	o.At = now.Add(-2 * time.Minute)
	c.observe(o)
	if c.Journal.View().Instances["i"].RegistrationGone {
		t.Fatal("expired response accepted")
	}
	o.Sequence++
	o.At = *now
	if err := c.observe(o); err != nil {
		t.Fatal(err)
	}
	if !c.Journal.View().Instances["i"].RegistrationGone {
		t.Fatal("fresh accepted absence did not commit removal")
	}
}

func TestCredentialLineageAndOwnerIdentityFence(t *testing.T) {
	c, _, _, _, _, _ := fixtureController(t)
	c.Journal.Update(func(s *State) error {
		s.Identity = Identity{RunnerID: "owner", Credential: "old", Confirmed: true}
		return nil
	})
	o := Observation{RunnerID: "owner", PreviousCredential: "old", Credential: "rotated", Bootstrap: true}
	if err := c.observe(o); err != nil {
		t.Fatal(err)
	}
	if c.Journal.View().Identity.Credential != "rotated" || c.Journal.View().Identity.Confirmed {
		t.Fatal("credential scope not reset")
	}
	o.PreviousCredential = "old"
	o.Credential = "stale"
	if err := c.observe(o); !errors.Is(err, ErrSuperseded) {
		t.Fatal("stale lineage accepted", err)
	}
	o.PreviousCredential = "rotated"
	o.Credential = "other"
	o.RunnerID = "other"
	if err := c.observe(o); !errors.Is(err, ErrSuperseded) {
		t.Fatal("stale node accepted", err)
	}
}

func TestRetirementPersistsCredentialIssuedBeforeHeartbeatJoin(t *testing.T) {
	c, _, _, _, _, _ := fixtureController(t)
	c.Journal.Update(func(s *State) error {
		s.Identity = Identity{RunnerID: "owner", Credential: "issued", Confirmed: true, Retiring: true}
		return nil
	})
	o := Observation{RunnerID: "owner", PreviousCredential: "issued", Credential: "rotated", Bootstrap: true, Accepted: true, Sequence: 0}
	if err := c.observe(o); err != nil {
		t.Fatal("lost credential while joining SDK loop", err)
	}
	s := c.Journal.View()
	if s.Identity.Credential != "rotated" || !s.Identity.Retiring || s.Identity.Confirmed || len(c.proofs) != 0 {
		t.Fatal("retirement lost credential or accepted work", s.Identity)
	}
	o.PreviousCredential = "issued"
	o.Credential = "stale"
	if err := c.observe(o); !errors.Is(err, ErrSuperseded) {
		t.Fatal("stale credential crossed retirement lineage", err)
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

func TestBootstrapOutageRemovalWaitsForNode(t *testing.T) {
	c, input, k, _, _, _ := fixtureController(t)
	var available atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !available.Load() {
			http.Error(w, "outage", 503)
			return
		}
		if req.URL.Path != "/runners/heartbeat" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var hb runner.HeartbeatRequest
		json.NewDecoder(req.Body).Decode(&hb)
		if len(hb.Apps) != 0 {
			t.Error("resubmitted withdrawn apps after Node recovery")
		}
		json.NewEncoder(w).Encode(runner.HeartbeatResponse{RunnerID: hb.RunnerID, HeartbeatSecret: "issued", Apps: []runner.HeartbeatAppStatus{}, HeartbeatTTL: "30s", HeartbeatInterval: "1h"})
	}))
	defer srv.Close()
	o, err := NewSDKOwner(srv.URL, "bootstrap", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close(context.Background())
	c.Owner = o
	tick(t, c)
	k.apply(c)
	if c.Tick(t.Context()) == nil {
		t.Fatal("expected initial registration outage")
	}
	set := *input.value.Payload.Intent
	set.Generation++
	set.Entries[0] = set.Entries[0].Absent()
	set.Entries[0].Generation++
	input.set(t, set)
	for n := 0; n < 8; n++ {
		_ = c.Tick(t.Context())
		k.apply(c)
	}
	if c.Journal.View().Identity.RunnerID == "" {
		t.Fatal("forgot owner during Node outage")
	}
	available.Store(true)
	for n := 0; n < 8; n++ {
		tick(t, c)
		k.apply(c)
	}
	if c.Journal.View().Identity.RunnerID != "" {
		t.Fatal("owner never retired")
	}
}

func TestLostBootstrapRetainsOldOwnerUntilNodeAbsence(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "natural", true: "maintenance-expired"}[expired], func(t *testing.T) {
			c, input, k, _, reports, now := fixtureController(t)
			type nodeOwner struct {
				credential string
				apps       map[string]bool
			}
			var mu sync.Mutex
			owners := map[string]*nodeOwner{}
			rejectHeartbeats, unexpectedHeartbeats := false, 0
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.URL.Path != "/runners/heartbeat" {
					id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/runners/"), "/unregister")
					existing := owners[id]
					if existing == nil {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					if r.Header.Get("Authorization") != existing.credential {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					delete(owners, id)
					return
				}
				if rejectHeartbeats {
					unexpectedHeartbeats++
					http.Error(w, "heartbeat unavailable", 503)
					return
				}
				var req runner.HeartbeatRequest
				json.NewDecoder(r.Body).Decode(&req)
				existing := owners[req.RunnerID]
				bootstrap := existing == nil
				if bootstrap {
					existing = &nodeOwner{credential: "issued-" + req.RunnerID, apps: map[string]bool{}}
					owners[req.RunnerID] = existing
				} else if r.Header.Get("Authorization") != existing.credential {
					w.WriteHeader(401)
					return
				}
				response := runner.HeartbeatResponse{RunnerID: req.RunnerID, Apps: []runner.HeartbeatAppStatus{}, HeartbeatTTL: "1h", HeartbeatInterval: "1h"}
				if bootstrap {
					response.HeartbeatSecret = existing.credential
				} else {
					response.Seq = new(req.Seq)
				}
				for n, app := range req.Apps {
					id := app.ID
					if id == "" {
						id = fmt.Sprintf("app-%s-%d", req.RunnerID, n)
					}
					existing.apps[id] = true
					response.Apps = append(response.Apps, runner.HeartbeatAppStatus{ID: id, Status: app.Status, SessionIDs: []string{}})
				}
				json.NewEncoder(w).Encode(response)
			})
			var lose atomic.Bool
			lose.Store(true)
			client := &http.Client{Transport: reviewRoundTripper(func(req *http.Request) (*http.Response, error) {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				resp, err := w.Result(), error(nil)
				if err == nil && req.URL.Path == "/runners/heartbeat" && lose.Swap(false) {
					resp.Body.Close()
					return nil, errors.New("lost bootstrap response")
				}
				return resp, err
			})}
			o, _ := NewSDKOwner("http://node.invalid", "bootstrap", client)
			defer o.Close(context.Background())
			c.Owner = o
			tick(t, c)
			k.apply(c)
			if c.Tick(t.Context()) == nil {
				t.Fatal("fixture did not lose bootstrap response")
			}
			oldID := c.Journal.View().Identity.RunnerID
			mu.Lock()
			oldApps := len(owners[oldID].apps)
			mu.Unlock()
			if oldApps == 0 {
				t.Fatal("fixture did not retain Node registrations")
			}
			set := *input.value.Payload.Intent
			set.Generation++
			set.Entries[0] = set.Entries[0].Absent()
			set.Entries[0].Generation++
			input.set(t, set)
			for n := 0; n < 7; n++ {
				_ = c.Tick(t.Context())
				k.apply(c)
			}
			if c.Journal.View().Identity.RunnerID != oldID {
				t.Fatal("abandoned unresolved owner identity")
			}
			for _, i := range c.Journal.View().Instances {
				if !i.RegistrationPending || i.RegistrationGone {
					t.Fatal("discarded potentially submitted registration", i)
				}
			}
			for _, r := range reports.receipts {
				if r.Phase == "removed" {
					mu.Lock()
					remaining := len(owners[oldID].apps)
					mu.Unlock()
					if remaining > 0 {
						t.Fatalf("reported removed while abandoned owner still has %d registrations", remaining)
					}
				}
			}

			// Recreate the SDK adapter with the same journal while the unknown owner lives.
			_ = o.Close(context.Background())
			restored, err := NewSDKOwner("http://node.invalid", "bootstrap", client)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close(context.Background())
			c.Owner = restored
			if c.Tick(t.Context()) == nil {
				t.Fatal("restart ignored old owner's 401")
			}
			if c.Journal.View().Identity.RunnerID != oldID {
				t.Fatal("restart forgot unresolved identity")
			}
			deadline := now.Add(time.Minute)
			if expired {
				input.value.Metadata.DrainRequested = true
				input.value.Metadata.DrainTarget = artifact.Digest([]byte("maintenance"))
				input.value.Metadata.DrainDeadline = deadline
				input.value.Metadata.Generation++
				*now = deadline.Add(time.Second)
				for n := 0; n < 7; n++ {
					_ = c.Tick(t.Context())
					k.apply(c)
				}
				for _, i := range c.Journal.View().Instances {
					if i.Phase != "removed" || !i.Forced || i.RegistrationGone || !i.RegistrationPending || !i.DrainExpiredAt.Equal(deadline) {
						t.Fatal("expired cleanup lost its unresolved registration", i)
					}
				}
			}
			// Simulate Node expiry; only its subsequent unregister 404 authorizes recovery.
			mu.Lock()
			delete(owners, oldID)
			rejectHeartbeats = true
			mu.Unlock()
			for n := 0; n < 8; n++ {
				tick(t, c)
				k.apply(c)
			}
			if c.Journal.View().Identity.RunnerID != "" {
				t.Fatal("did not finish retirement after old-owner absence")
			}
			found := false
			for _, r := range reports.receipts {
				found = found || r.Phase == "removed"
			}
			if !found {
				t.Fatal("cleanup never completed after confirmed absence")
			}
			mu.Lock()
			attempts := unexpectedHeartbeats
			mu.Unlock()
			if attempts != 0 {
				t.Fatal("created another owner to prove an absent owner's cleanup", attempts)
			}
			if expired {
				preserved := false
				for _, report := range reports.reports {
					for _, i := range report.Apps.Instances {
						preserved = preserved || (i.RegistrationGone && i.Forced && i.DrainExpiredAt.Equal(deadline))
					}
				}
				if !preserved {
					t.Fatal("late Node absence erased maintenance expiry")
				}
			}
		})
	}
}

func TestAppRemovalRequiresCompleteNodeAbsence(t *testing.T) {
	c, input, _, _, reporter, now := fixtureController(t)
	definition := input.value.Payload.Intent.Entries[0].Revision.Definition
	definition.Apps = []schema.App{{Name: "first", Path: "/first", Capacity: 2, Price: definition.Price}, {Name: "second", Path: "/second", Capacity: 2, Price: definition.Price}}
	i := &Instance{ID: "shared", PodUID: "pod", Definition: definition, WithdrawalID: "withdrawal", WithdrawnAt: *now, Phase: "withdrawing"}
	i.AppID = appID(i, 0)
	if err := c.Journal.Update(func(s *State) error {
		s.Identity = Identity{RunnerID: "owner", Credential: "issued"}
		s.Instances[i.ID] = i
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	tracked, err := AppRegistrations(i, false)
	if err != nil {
		t.Fatal(err)
	}
	o := Observation{RunnerID: "owner", Credential: "issued", PreviousCredential: "issued", Accepted: true, At: *now, TTL: time.Minute, Withdrawals: tracked, Apps: []AppObservation{{ID: appID(i, 1), Status: "draining", SessionIDs: []string{"work"}}}}
	if err = c.observe(o); err != nil {
		t.Fatal(err)
	}
	if err := c.report(t.Context(), nil, View{}, *now); err != nil {
		t.Fatal(err)
	}
	got := reporter.reports[len(reporter.reports)-1].Apps.Instances[0]
	if got.Sessions != 1 || !got.Registered || got.NodeObservedAt.IsZero() || c.Journal.View().Instances[i.ID].RegistrationGone {
		t.Fatalf("lost retained registration: %+v", got)
	}
	o.Sequence++
	o.Apps[0].SessionIDs = []string{}
	if err = c.observe(o); err != nil {
		t.Fatal(err)
	}
	if c.Journal.View().Instances[i.ID].RegistrationGone {
		t.Fatal("empty session list is not registration removal")
	}
	o.Sequence++
	o.Apps = []AppObservation{}
	o.Withdrawals = tracked[:1]
	if err = c.observe(o); err != nil {
		t.Fatal(err)
	}
	if c.Journal.View().Instances[i.ID].RegistrationGone {
		t.Fatal("partial alias withdrawal established backend removal")
	}
	o.Sequence++
	o.Withdrawals = tracked
	if err = c.observe(o); err != nil {
		t.Fatal(err)
	}
	if !c.Journal.View().Instances[i.ID].RegistrationGone {
		t.Fatal("complete Node-confirmed alias absence did not establish removal")
	}
}
