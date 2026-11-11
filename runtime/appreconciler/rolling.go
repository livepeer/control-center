package appreconciler

import (
	"github.com/livepeer/control-center/schema"
	"time"
)

func occupied(i *Instance) bool { return i.Phase != "removed" || !i.RegistrationGone }
func inSource(i *Instance, r *schema.AppReplacement) bool {
	return i.Group.RevisionID == r.RevisionID && i.Group.ActivationGeneration == r.ActivationGeneration
}
func rollingCount(s *State, a schema.AppAssignment) int {
	n := 0
	for _, i := range s.Instances {
		if occupied(i) && (inSource(i, a.Replacement) || (i.Group.RevisionID == a.RevisionID && i.Group.ActivationGeneration == a.ActivationGeneration)) {
			n++
		}
	}
	return n
}

// Retain healthy old siblings until one slot is needed and all prior successors
// have fresh health and Node ready evidence. Existing withdrawals never reverse.
func retainRolling(s *State, i *Instance, c *Controller, now time.Time) bool {
	if i.WithdrawalID != "" {
		return false
	}
	for _, a := range s.Payload.Intent.Entries {
		r := a.Replacement
		if a.Desired != "present" || r == nil || a.StartAfter != nil || !a.StartAllowed || !inSource(i, r) {
			continue
		}
		candidate := ""
		blocked := false
		for _, other := range s.Instances {
			if !occupied(other) {
				continue
			}
			if inSource(other, r) {
				if other.WithdrawalID != "" {
					blocked = true
				}
				if candidate == "" || other.Group.Slot > s.Instances[candidate].Group.Slot {
					candidate = other.ID
				}
			} else if other.Group.RevisionID == a.RevisionID && other.Group.ActivationGeneration == a.ActivationGeneration {
				c.mu.Lock()
				p, ok := c.proofs[other.ID]
				c.mu.Unlock()
				if other.WithdrawalID != "" || other.Reason == "process_lost" || other.Reason == "unexpected_pod_replacement" || !ok || p.PodUID != other.PodUID || p.Observation.Epoch != s.OwnerEpoch || p.Observation.Credential != s.Identity.Credential || p.Observation.At.After(now.Add(time.Second)) || p.App.Status != "ready" || !now.Before(p.Observation.At.Add(p.Observation.TTL)) || c.Probes == nil || !c.Probes.Ready(other.ID, other.PodUID) {
					blocked = true
				}
			}
		}
		return blocked || rollingCount(s, a) < r.Replicas || i.ID != candidate
	}
	return false
}
