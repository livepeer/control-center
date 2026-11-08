package appreconciler

import (
	"errors"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/internal/testutil"
	"testing"
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
	c, input, _, _, r, now := fixtureController(t)
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
	*now = now.Add(time.Second)
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
	*now = now.Add(31 * time.Second)
	tick(t, c)
	if len(r.reports) != count+1 || r.reports[len(r.reports)-1].Sequence <= failed.Sequence {
		t.Fatal("status observation was not refreshed")
	}
}

func TestIdleUnknownCapabilitiesAndClockFaultDoNotInventWorkProof(t *testing.T) {
	c, input, _, o, r, now := fixtureController(t)
	empty := testutil.Assignment(t)
	empty.Entries = empty.Entries[:0]
	input.set(t, empty)
	o.caps = &Capabilities{}
	tick(t, c)
	if !r.reports[len(r.reports)-1].Ready {
		t.Fatal("idle owner required capability negotiation")
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
	if fault.Ready || fault.Drained || fault.Evidence != nil || fault.Apps.Reason != "clock_uncertain" {
		t.Fatal("clock fault left stale readiness or manufactured completion", fault)
	}
}

func TestRetainedHeartbeatCountsDoNotBecomeWithdrawalProof(t *testing.T) {
	c, _, _, _, r, now := fixtureController(t)
	c.Journal.Update(func(s *State) error {
		s.Identity = Identity{RunnerID: "owner", Credential: "issued", Confirmed: true}
		s.OwnerHash, s.OwnerEpoch = "hash", "epoch"
		s.Instances["retained"] = &Instance{ID: "retained", AppID: "app", PodUID: "uid", WithdrawalID: "withdrawal", Phase: "removed"}
		return nil
	})
	obs := Observation{RunnerID: "owner", PreviousCredential: "issued", ReservedSequence: 1, Sequence: 1, Hash: "hash", Epoch: "epoch", At: *now, TTL: time.Minute, Capabilities: Capabilities{true, true, true}, Apps: []AppObservation{{ID: "app", Status: "draining", SessionIDs: []string{"work"}}}}
	if err := c.observe(obs); err != nil {
		t.Fatal(err)
	}
	if err := c.report(t.Context(), nil, View{}, *now); err != nil {
		t.Fatal(err)
	}
	if r.reports[len(r.reports)-1].Apps.Instances[0].Sessions != 1 {
		t.Fatal("discarded authoritative retained-app diagnostic")
	}
	obs.ReservedSequence, obs.Sequence = 2, 2
	obs.Apps[0].SessionIDs = nil
	if err := c.observe(obs); err != nil {
		t.Fatal(err)
	}
	if c.empty(c.Journal.View().Instances["retained"], *now) {
		t.Fatal("attached current withdrawal context to an uncaptured retained observation")
	}
}
