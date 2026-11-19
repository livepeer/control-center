package appreconciler

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/internal/testutil"
	"github.com/livepeer/control-center/schema"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestReceiptsDiscardSupersededAndBindFailuresToExactAttempt(t *testing.T) {
	c, input, k, _, _, _ := fixtureController(t)
	tick(t, c)
	old := c.Journal.View()
	a := old.Payload.Intent.Entries[0]
	obsolete := Receipt{RevisionID: a.RevisionID, Generation: a.Generation, ActivationGeneration: a.ActivationGeneration, AppsDigest: old.Payload.Index.IntentDigest, Phase: "applied"}
	if err := c.Journal.Update(func(s *State) error { s.Receipts[receiptKey(obsolete)] = obsolete; return nil }); err != nil {
		t.Fatal(err)
	}
	set := *input.value.Payload.Intent
	set.Generation++
	set.Entries[0].Generation++
	input.set(t, set)
	tick(t, c)
	if _, exists := c.Journal.View().Receipts[receiptKey(obsolete)]; exists {
		t.Fatal("undeliverable superseded receipt remained in outbox")
	}
	view := k.view
	view.Failed = old.Published
	if err := c.queueReceipts(view); err != nil {
		t.Fatal(err)
	}
	if len(c.Journal.View().Receipts) != 0 {
		t.Fatal("old Flux failure attributed to new intent")
	}
	view.Failed = c.Journal.View().Published
	if err := c.queueReceipts(view); err != nil {
		t.Fatal(err)
	}
	receipts := c.Journal.View().Receipts
	if len(receipts) != 1 {
		t.Fatal("missing exact-attempt failure", receipts)
	}
	for _, r := range receipts {
		if r.Phase != "failed" || r.Reason != "reconcile_failed" || r.Generation != a.Generation+1 || r.AppsDigest != c.Journal.View().Payload.Index.IntentDigest {
			t.Fatal("wrong failure identity", r)
		}
	}
}

func TestReportRetriesUnchangedAndRefreshesAtCadence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, input, _, _, r, _ := fixtureController(t)
		c.Now = time.Now
		tick(t, c)
		tick(t, c)
		if len(r.reports) != 1 {
			t.Fatal("sent duplicate status every tick")
		}
		r.statusFail = true
		input.value.Metadata.AppsError = "unsupported_instance_mode"
		if c.Tick(t.Context()) == nil {
			t.Fatal("fixture report did not fail")
		}
		failed := r.reports[len(r.reports)-1]
		time.Sleep(time.Second)
		_ = c.Tick(t.Context())
		if r.reports[len(r.reports)-1].Sequence != failed.Sequence {
			t.Fatal("delivery retry became a fresh observation")
		}
		r.statusFail = false
		tick(t, c)
		count := len(r.reports)
		tick(t, c)
		if len(r.reports) != count {
			t.Fatal("acknowledged report retried immediately")
		}
		time.Sleep(31 * time.Second)
		tick(t, c)
		if len(r.reports) != count+1 || r.reports[len(r.reports)-1].Sequence <= failed.Sequence {
			t.Fatal("status observation was not refreshed")
		}
	})
}

func TestIdleOwnerAndClockFaultDoNotInventWorkProof(t *testing.T) {
	c, input, _, _, r, now := fixtureController(t)
	empty := testutil.Assignment(t)
	empty.Entries = empty.Entries[:0]
	input.set(t, empty)
	tick(t, c)
	if !r.reports[len(r.reports)-1].Ready {
		t.Fatal("idle owner reported a fault")
	}
	input.value.Metadata.DrainRequested = true
	input.value.Metadata.DrainTarget = artifact.Digest([]byte("target"))
	tick(t, c)
	if !r.reports[len(r.reports)-1].Drained {
		t.Fatal("empty actual state did not yield no-owner proof")
	}
	*now = now.Add(-30 * time.Second)
	if err := c.Tick(t.Context()); !errors.Is(err, ErrClock) {
		t.Fatal(err)
	}
	fault := r.reports[len(r.reports)-1]
	if fault.Ready || fault.Drained || fault.Evidence != nil || !fault.ClockUncertain || fault.Apps.Reason != "clock_uncertain" {
		t.Fatal("clock fault left stale readiness or manufactured completion", fault)
	}
}

func TestRetainedHeartbeatCountsDoNotBecomeWithdrawalProof(t *testing.T) {
	c, _, _, _, r, now := fixtureController(t)
	c.Journal.Update(func(s *State) error {
		s.Identity = Identity{RunnerID: "owner", Credential: "issued", Confirmed: true}
		s.Instances["retained"] = &Instance{ID: "retained", AppID: "app", PodUID: "uid", WithdrawalID: "withdrawal", Phase: "removed"}
		return nil
	})
	obs := Observation{RunnerID: "owner", Credential: "issued", PreviousCredential: "issued", Accepted: true, Sequence: 1, At: *now, TTL: time.Minute, Apps: []AppObservation{{ID: "app", Status: "draining", SessionIDs: []string{"work"}}}}
	if err := c.observe(obs); err != nil {
		t.Fatal(err)
	}
	if err := c.report(t.Context(), nil, View{}, *now); err != nil {
		t.Fatal(err)
	}
	if r.reports[len(r.reports)-1].Apps.Instances[0].Sessions != 1 {
		t.Fatal("discarded authoritative retained-app diagnostic")
	}
	obs.Sequence = 2
	obs.Apps = []AppObservation{}
	if err := c.observe(obs); err != nil {
		t.Fatal(err)
	}
	if c.Journal.View().Instances["retained"].RegistrationGone {
		t.Fatal("attached current withdrawal context to an uncaptured retained observation")
	}
}

func TestReportBudgetPreservesProofAndOmissionCounts(t *testing.T) {
	r := Report{Sequence: ^uint64(0), ObservedAt: time.Now(), Apps: contract.AppStatus{Instances: []contract.InstanceStatus{}, InstancesTotal: 128}, Evidence: &contract.Evidence{Target: "sha256:" + strings.Repeat("a", 64), OwnerID: strings.Repeat("x", 128), WithdrawalID: "withdrawal", ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Second)}}
	proof := *r.Evidence
	for n := 0; n < 128; n++ {
		r.Apps.Instances = append(r.Apps.Instances, contract.InstanceStatus{InstanceID: fmt.Sprint(n), AppID: strings.Repeat("a", 128), RunnerID: strings.Repeat("r", 128), PodUID: strings.Repeat("p", 128), Reason: strings.Repeat("e", 128), WorkloadReason: strings.Repeat("w", 128), RevisionID: strings.Repeat("b", 36), NodeObservedAt: time.Now(), NodeExpiresAt: time.Now().Add(time.Minute), StartupDeadline: time.Now(), Deadline: time.Now(), TerminatedAt: time.Now(), RemovalPublishedAt: time.Now(), DrainExpiredAt: time.Now()})
	}
	if err := boundReport(&r); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	if len(b) > contract.MaxStatusBytes || r.Evidence == nil || *r.Evidence != proof || r.Apps.InstancesOmitted == 0 || len(r.Apps.Instances)+r.Apps.InstancesOmitted != 128 {
		t.Fatal("diagnostics crowded out proof or lost omission counts", len(b), r.Apps.InstancesOmitted)
	}
}

func TestAssignmentRefusalIsSpecificBeforeInstanceCreation(t *testing.T) {
	c, input, k, _, r, _ := fixtureController(t)
	set := *input.value.Payload.Intent
	var second schema.AppAssignment
	raw, _ := json.Marshal(set.Entries[0])
	if err := json.Unmarshal(raw, &second); err != nil {
		t.Fatal(err)
	}
	second.RevisionID = "22222222-2222-4222-8222-222222222222"
	second.Revision.RevisionID = second.RevisionID
	set.Entries = append(set.Entries, second)
	input.set(t, set)
	// Enough for only the first assignment's requested replicas.
	limit := resources(set.Entries[0].Revision.Definition.Resources.Limits)
	k.view.Budget = Resources{limit.CPU * int64(set.Entries[0].Replicas), limit.Memory * int64(set.Entries[0].Replicas), limit.Storage * int64(set.Entries[0].Replicas)}
	tick(t, c)
	last := r.reports[len(r.reports)-1]
	if len(last.Apps.Assignments) != 2 {
		t.Fatal("missing assignment summaries")
	}
	found := false
	for _, a := range last.Apps.Assignments {
		if a.RevisionID == second.RevisionID {
			found = a.Reason == "resource_refused" && a.Instances == 0
		}
	}
	if !found {
		t.Fatal("refusal was not bound to the assignment", last.Apps.Assignments)
	}
}

func TestReportAdmissionRequiresCurrentNodeReadyAndProbe(t *testing.T) {
	c, _, k, _, reports, now := fixtureController(t)
	registerApps(t, c, k)
	c.Probes = NewProbes()
	revision := c.Journal.View().Payload.Intent.Entries[0].RevisionID
	if err := c.Journal.Update(func(s *State) error {
		s.SecretRollouts = map[string]contract.SecretRollout{revision: {Desired: "updated"}}
		for _, i := range s.Instances {
			i.SecretVersion = "updated"
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ready := map[string]bool{}
	for id, i := range c.Journal.View().Instances {
		ready[id] = true
		c.Probes.values[id] = &health{uid: i.PodUID, ready: true, observedAt: *now, success: true, started: true}
		p, ok := c.proofs[id]
		if !ok {
			t.Fatalf("fixture did not register instance %s", id)
		}
		p.App.Status = "not-ready"
		c.proofs[id] = p
	}
	check := func(want, healthy int, secretsApplied bool) {
		t.Helper()
		if err := c.report(t.Context(), ready, k.view, *now); err != nil {
			t.Fatal(err)
		}
		apps := reports.reports[len(reports.reports)-1].Apps
		a := apps.Assignments[0]
		if a.Ready != healthy || a.Registered != len(ready) || a.Admission == nil || a.Admission.Ready != want {
			t.Fatalf("report admission evidence: %+v", a)
		}
		if applied := apps.SecretRollouts[revision].Applied; (applied == "updated") != secretsApplied {
			t.Fatalf("secret rollout applied version = %q, want applied = %t", applied, secretsApplied)
		}
		for _, i := range apps.Instances {
			if i.AdmissionExpiresAt.IsZero() != (want == 0) {
				t.Fatalf("instance %s admission expiry = %v, count = %d", i.InstanceID, i.AdmissionExpiresAt, want)
			}
		}
	}
	check(0, len(ready), false)
	for id, p := range c.proofs {
		p.App.Status = "ready"
		c.proofs[id] = p
	}
	check(len(ready), len(ready), true)
	for _, h := range c.Probes.values {
		h.observedAt = now.Add(-time.Minute)
	}
	check(0, len(ready), true)
	for _, h := range c.Probes.values {
		h.observedAt, h.success, h.failures = *now, false, 1 // The configured threshold has not been crossed.
	}
	check(len(ready), len(ready), true)
	for _, h := range c.Probes.values {
		h.ready, h.failures = false, 3 // The copied ready map still says true.
	}
	check(0, 0, false)
	for id, h := range c.Probes.values {
		ready[id], h.ready, h.success, h.failures = false, true, true, 0
	}
	check(0, len(ready), false)
}

func TestFailingProbeSummaryPreservesItsOwnExpiry(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	synctest.Test(t, func(t *testing.T) {
		c, _, k, _, reports, _ := fixtureController(t)
		c.Now = time.Now
		c.Probes = NewProbes()
		c.Probes.Address = func(*Instance) string { return server.URL }
		c.Probes.Client.Transport = &http.Transport{DisableKeepAlives: true}
		registerApps(t, c, k)
		synctest.Wait()
		now := time.Now()
		for id, i := range c.Journal.View().Instances {
			c.Probes.values[id] = &health{uid: i.PodUID, observedAt: now, observedDue: now.Add(5 * time.Second), timeout: 2 * time.Second, success: false, failures: 3, started: true}
		}
		if err := c.report(t.Context(), map[string]bool{}, k.view, time.Now()); err != nil {
			t.Fatal(err)
		}
		a := reports.reports[len(reports.reports)-1].Apps.Assignments[0]
		if a.Ready != 0 || !a.ProbeExpiresAt.Equal(now.Add(30*time.Second)) {
			t.Fatal("fresh failing probes became unknown", a)
		}
		time.Sleep(31 * time.Second)
		if err := c.report(t.Context(), map[string]bool{}, k.view, time.Now()); err != nil {
			t.Fatal(err)
		}
		if got := reports.reports[len(reports.reports)-1].Apps.Assignments[0]; !got.ProbeExpiresAt.Equal(a.ProbeExpiresAt) || time.Now().Before(got.ProbeExpiresAt) {
			t.Fatal("delivery renewed failing evidence", got)
		}
	})
}
