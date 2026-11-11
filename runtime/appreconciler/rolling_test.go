package appreconciler

import (
	"github.com/livepeer/control-center/runtime/internal/testutil"
	"github.com/livepeer/control-center/schema"
	"testing"
	"time"
)

func stageReplacement(t *testing.T, input *testInputs, replicas int, rolling bool) (schema.AppAssignment, schema.AppAssignment) {
	t.Helper()
	source := input.value.Payload.Intent.Entries[0]
	target := source
	revision := *source.Revision
	target.Revision = &revision
	target.RevisionID = "33333333-3333-4333-8333-333333333333"
	target.Revision.Definition.AppVersion = "2"
	target.Revision.AppVersion = "2"
	target.Replicas = replicas
	testutil.Refresh(&target)
	removal := source.Absent()
	removal.Generation++
	if rolling {
		target.Replacement = &schema.AppReplacement{RevisionID: source.RevisionID, ActivationGeneration: source.ActivationGeneration, Generation: removal.Generation, Replicas: source.Replicas}
	} else {
		target.StartAfter = &schema.AppStartAfter{RevisionID: source.RevisionID, Generation: removal.Generation}
		target.StartAllowed = false
	}
	set := *input.value.Payload.Intent
	set.Generation++
	set.Entries = []schema.AppAssignment{removal, target}
	input.set(t, set)
	return source, target
}

func TestRollingReplacementRetainsSiblingUntilSuccessorReady(t *testing.T) {
	c, input, k, o, _, _ := fixtureController(t)
	registerApps(t, c, k)
	state := c.Journal.View()
	source, target := stageReplacement(t, input, 2, true)
	for _, i := range state.Instances {
		o.sessions[i.AppID] = []string{"busy"}
	}
	tick(t, c)
	s := c.Journal.View()
	withdrawn := 0
	for _, i := range s.Instances {
		if i.WithdrawalID != "" {
			withdrawn++
		}
	}
	if withdrawn != 1 || len(o.accepted.Entries) != 1 || len(s.Instances) != 2 {
		t.Fatal("rolling withdrew healthy sibling or surged", s.Instances, o.accepted)
	}
	for _, i := range s.Instances {
		if i.WithdrawalID != "" {
			o.sessions[i.AppID] = nil
		}
	}
	for n := 0; n < 8; n++ {
		tick(t, c)
		k.apply(c)
	}
	s = c.Journal.View()
	oldServing, newStarting := 0, 0
	for _, i := range s.Instances {
		if i.Group.RevisionID == source.RevisionID && i.WithdrawalID == "" {
			oldServing++
		}
		if i.Group.RevisionID == target.RevisionID && occupied(i) {
			newStarting++
		}
	}
	if oldServing != 1 || newStarting != 1 || rollingCount(&s, target) != 2 {
		t.Fatal("replacement did not reuse exactly one cleaned slot", s.Instances)
	}
}
func TestSequentialReplacementWaitsForCleanupPrerequisite(t *testing.T) {
	c, input, k, o, _, _ := fixtureController(t)
	registerApps(t, c, k)
	_, target := stageReplacement(t, input, 3, false)
	for _, i := range c.Journal.View().Instances {
		o.sessions[i.AppID] = []string{"busy"}
	}
	tick(t, c)
	for _, i := range c.Journal.View().Instances {
		if i.Group.RevisionID == target.RevisionID {
			t.Fatal("sequential prerequisite bypassed")
		}
		if i.WithdrawalID == "" {
			t.Fatal("source not withdrawn")
		}
	}
}
func TestRollingFreeSlotsAndMachineBudget(t *testing.T) {
	set := testutil.Assignment(t)
	a := set.Entries[0]
	a.Replacement = &schema.AppReplacement{RevisionID: "33333333-3333-4333-8333-333333333333", ActivationGeneration: 1, Generation: 2, Replicas: 2}
	c := &Controller{Probes: NewProbes(), proofs: map[string]proof{}}
	s := initialState()
	s.Payload.Intent = &schema.AppAssignmentSetV1{Entries: []schema.AppAssignment{a}}
	old := &Instance{ID: "old", Definition: a.Revision.Definition}
	old.Group.RevisionID = a.Replacement.RevisionID
	old.Group.ActivationGeneration = 1
	s.Instances[old.ID] = old
	if !retainRolling(&s, old, c, time.Now()) {
		t.Fatal("withdrew old despite free slot")
	}
	cost := resources(a.Revision.Definition.Resources.Limits)
	unrelated := &Instance{ID: "other", Definition: a.Revision.Definition}
	s.Instances[unrelated.ID] = unrelated
	if fits(s.Instances, a.Revision.Definition, Resources{cost.CPU * 2, cost.Memory * 2, cost.Storage * 2}) {
		t.Fatal("unrelated app excluded from budget")
	}
}

func TestRollingUsesCurrentSuccessorStateBeforeWithdrawal(t *testing.T) {
	for _, failure := range []string{"healthy", "withdrawn", "process", "endpoint"} {
		t.Run(failure, func(t *testing.T) {
			c, input, k, o, _, now := fixtureController(t)
			set := *input.value.Payload.Intent
			set.Entries[0].Replicas = 3
			input.set(t, set)
			registerApps(t, c, k)
			source, target := stageReplacement(t, input, 3, true)
			for _, i := range c.Journal.View().Instances {
				o.sessions[i.AppID] = []string{"busy"}
			}
			tick(t, c)
			for _, i := range c.Journal.View().Instances {
				if i.WithdrawalID != "" {
					o.sessions[i.AppID] = nil
				}
			}
			var successor, candidate *Instance
			for n := 0; n < 15; n++ {
				tick(t, c)
				k.apply(c)
				for _, i := range c.Journal.View().Instances {
					if i.Group.RevisionID == target.RevisionID && i.PodUID != "" && i.AppID != "" {
						successor = i
					}
					if i.Group.RevisionID == source.RevisionID && i.Group.Slot == 1 {
						candidate = i
					}
				}
				if successor != nil {
					break
				}
			}
			if successor == nil || candidate == nil {
				t.Fatal("fixture did not reach successor")
			}
			s := c.Journal.View()
			c.Probes.values[successor.ID] = &health{uid: successor.PodUID, ready: true, started: true, next: now.Add(time.Minute)}
			c.proofs[successor.ID] = proof{PodUID: successor.PodUID, Observation: Observation{Epoch: s.OwnerEpoch, Credential: s.Identity.Credential, Accepted: true, At: *now, TTL: time.Minute}, App: AppObservation{ID: successor.AppID, Status: "ready", SessionIDs: []string{}}}
			if failure == "process" {
				pod := k.view.Pods[successor.Name]
				pod.Phase = "Failed"
				k.view.Pods[successor.Name] = pod
			} else if failure == "endpoint" {
				k.view.Endpoints[successor.Name] = map[string]bool{}
			} else if failure == "withdrawn" {
				if err := c.Journal.Update(func(s *State) error { withdraw(s.Instances[successor.ID], *now, s.Metadata); return nil }); err != nil {
					t.Fatal(err)
				}
			}
			tick(t, c)
			withdrew := c.Journal.View().Instances[candidate.ID].WithdrawalID != ""
			if withdrew != (failure == "healthy") {
				t.Fatalf("rolling withdrawal=%v for successor state %s", withdrew, failure)
			}
		})
	}
}
