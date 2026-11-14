package appreconciler

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
	"github.com/livepeer/control-center/schema"
)

type proof struct {
	Observation Observation
	App         AppObservation
	PodUID      string
}
type Controller struct {
	Secrets      *SecretDelivery
	Journal      *Journal
	Input        Inputs
	Cluster      Cluster
	Owner        Owner
	Store        artifact.Store
	ArtifactURL  string
	Probes       *Probes
	Reporter     Reporter
	Now          func() time.Time
	mu           sync.Mutex
	proofs       map[string]proof
	fault        string
	recoverOwner bool
}

func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}
func (c *Controller) hooks() OwnerHooks {
	return OwnerHooks{Observe: c.observe, Failure: c.failed, Now: c.now,
		Eligibility: func(r Registration) (bool, bool) {
			member, ready := c.Journal.Eligibility(r)
			state := c.Journal.View()
			if state.Metadata.Onchain.Onchain() && !state.Metadata.OnchainActive {
				ready = false
			}
			return member, ready && c.Probes != nil && c.Probes.Ready(r.InstanceID, r.PodUID)
		}}
}
func (c *Controller) failed(f OwnerFailure) {
	if c.Journal.View().Identity.RunnerID != f.RunnerID {
		return
	}
	c.mu.Lock()
	if !f.Partial {
		c.proofs = nil
	}
	c.fault = f.Reason
	if f.Reset {
		c.recoverOwner = true
	}
	c.mu.Unlock()
}
func (c *Controller) observe(o Observation) error {
	var proofs map[string]proof
	err := c.Journal.Update(func(s *State) error {
		if o.Credential == "" {
			return errors.New("owner_credential")
		}
		if s.Identity.RunnerID != o.RunnerID {
			return ErrSuperseded
		}
		if s.Identity.Credential != o.PreviousCredential && s.Identity.Credential != o.Credential {
			return ErrSuperseded
		}
		changed := s.Identity.Credential != o.Credential
		previous := s.Identity.Credential
		s.Identity.Credential = o.Credential
		if changed {
			s.Identity.Sequence = nil
			s.Identity.Confirmed = false
		}
		if changed && previous != "" && o.Bootstrap {
			s.OwnerRecreatedAt = o.At
			for _, i := range s.Instances {
				if i.Phase != "removed" && i.WithdrawalID == "" {
					withdraw(i, o.At, s.Metadata)
					i.Forced = true
					i.Reason = "node_registration_recreated"
				}
			}
		}
		// Persist identities even when SetApps superseded the submitted snapshot.
		for _, e := range o.Entries {
			i := s.Instances[e.InstanceID]
			if i == nil || i.PodUID != e.PodUID || contract.ReservedProxyID(e.Options.ID) {
				return errors.New("app_identity")
			}
			if len(i.Definition.Apps) > 0 {
				if e.AppIndex < 0 || e.AppIndex >= len(i.Definition.Apps) || e.Options.ID != appID(i, e.AppIndex) {
					return errors.New("app_identity")
				}
				i.AppID = appID(i, 0)
			} else {
				if i.AppID != "" && i.AppID != e.Options.ID {
					return errors.New("app_identity")
				}
				i.AppID = e.Options.ID
			}
			i.RegistrationPending = false
		}
		if s.Identity.Retiring || !o.Accepted || o.Bootstrap || changed || s.ClockUncertain {
			return nil
		}
		if s.Identity.Sequence != nil && o.Sequence <= *s.Identity.Sequence {
			return nil
		}
		s.Identity.Sequence = new(o.Sequence)
		s.Identity.Confirmed = true
		proofs = map[string]proof{}
		seen := map[string]bool{}
		known := map[string]bool{}
		for _, a := range o.Apps {
			seen[a.ID] = true
		}
		for _, i := range s.Instances {
			if i.AppID != "" {
				for n := range appCount(i.Definition) {
					known[appID(i, n)] = true
				}
			}
		}
		byID := map[string]AppObservation{}
		for _, app := range o.Apps {
			byID[app.ID] = app
		}
		for id, i := range s.Instances {
			if app, observed := aggregateObservation(i, byID); observed {
				proofs[id] = proof{Observation: o, App: app}
			}
		}
		for _, e := range o.Entries {
			if p, ok := proofs[e.InstanceID]; ok {
				p.PodUID = e.PodUID
				proofs[e.InstanceID] = p
			}
		}
		unknown := false
		for id := range seen {
			if !known[id] {
				unknown = true
			}
		}
		if !o.At.After(c.now().Add(time.Second)) && c.now().Before(o.At.Add(o.TTL)) {
			omitted := map[string]map[string]bool{}
			for _, e := range o.Withdrawals {
				i := s.Instances[e.InstanceID]
				if i == nil || i.WithdrawalID != e.WithdrawalID || i.PodUID != e.PodUID || i.WithdrawalID == "" {
					continue
				}
				if len(i.Definition.Apps) > 0 && !ownsAppID(i, e.Options.ID) {
					continue
				}
				if omitted[i.ID] == nil {
					omitted[i.ID] = map[string]bool{}
				}
				omitted[i.ID][e.Options.ID] = true
			}
			for id, aliases := range omitted {
				i := s.Instances[id]
				if len(aliases) == appCount(i.Definition) && registrationsAbsent(i, seen) && (i.AppID != "" || !unknown) {
					i.RegistrationGone = true
					i.RegistrationPending = false
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.proofs = proofs
	if proofs != nil {
		c.fault = ""
		c.recoverOwner = false
	}
	return nil
}

// Tick never interprets an unavailable input, failed observation or missing object as an empty desired set.
// Only this loop makes lifecycle decisions; SDK callbacks commit identity and fresh observations.
func (c *Controller) Tick(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	now := c.now()
	before := c.Journal.View()
	if c.Secrets != nil && before.Metadata.ManagedSecrets && !c.Secrets.Client.Enabled() {
		if e := c.Secrets.Client.MarkManaged(); e != nil {
			return e
		}
	}
	if now.Before(before.LastClock.Add(-time.Second)) {
		// Stop/join the ready snapshot before sending a replacement that withdraws admission.
		// No deadline or lifecycle timestamp is moved backwards to accommodate the clock.
		err := c.Journal.Update(func(s *State) error { s.ClockUncertain = true; s.Identity.Confirmed = false; return nil })
		var closeErr error
		if !before.ClockUncertain {
			closeErr = c.Owner.Close(ctx)
		}
		if err != nil || closeErr != nil {
			return errors.Join(ErrClock, err, closeErr)
		}
		safetyErr := c.safety(ctx)
		// The clock flag forbids completion evidence; this reports only a fault,
		// never a fresh absence observation from safety's synthetic view.
		return errors.Join(ErrClock, safetyErr, c.report(ctx, map[string]bool{}, View{}, now))
	}
	view, err := c.Cluster.Read(ctx)
	if err != nil {
		return errors.Join(err, c.safety(ctx))
	}
	if before.InputDigest == "" && (view.Artifact != "" || len(view.Pods) != 0 || len(view.Services) != 0) {
		return ErrStateLost
	}
	input, inputErr := c.Input.Read(ctx)
	if inputErr == nil && input.Metadata.ManagedSecrets && c.Secrets != nil && !c.Secrets.Client.Enabled() {
		if e := c.Secrets.Client.MarkManaged(); e != nil {
			return e
		}
	}
	now = c.now() // Input/API latency must not keep an expired Node proof fresh.
	inputReason := ""
	if inputErr != nil {
		inputReason = "input_unavailable"
	}
	if inputErr == nil {
		m := input.Metadata
		if before.InputDigest != "" && (m.NodeID != before.Metadata.NodeID || m.CredentialVersion < before.Metadata.CredentialVersion || (before.Metadata.ManagedSecrets && !m.ManagedSecrets) || (before.Metadata.Terminal && !m.Terminal)) {
			return errors.New("input_enrollment_regression")
		}
		if m.Generation < before.Metadata.Generation || (input.Payload.Index.Available && before.Payload.Intent != nil && (input.Payload.Intent.Generation < before.Payload.Intent.Generation || (input.Payload.Intent.Generation == before.Payload.Intent.Generation && input.Payload.Index.IntentDigest != before.Payload.Index.IntentDigest))) {
			inputErr = errors.New("input_regression")
			inputReason = "input_regression"
		}
	}
	if c.Secrets != nil {
		pollState := before
		if inputErr == nil && input.Payload.Index.Available {
			pollState.Payload = input.Payload
		}
		pollCtx, stop := optionalSecretContext(ctx, 2*time.Second)
		c.Secrets.Poll(pollCtx, pollState, now)
		stop()
		if e := c.Journal.Update(func(st *State) error {
			if st.SecretWatermarks == nil {
				st.SecretWatermarks = map[string]int64{}
			}
			if st.SecretRollouts == nil {
				st.SecretRollouts = map[string]contract.SecretRollout{}
			}
			for revision, target := range c.Secrets.Targets {
				valid := target.PolicyGeneration >= st.SecretPolicyGeneration
				for _, v := range target.Values {
					if v.Revision < st.SecretWatermarks[v.ID] {
						valid = false
					}
				}
				if !valid {
					delete(c.Secrets.Targets, revision)
					c.Secrets.Faults[revision] = "secret_state_regression"
					continue
				}
				if target.PolicyGeneration > st.SecretPolicyGeneration {
					st.SecretPolicyGeneration = target.PolicyGeneration
				}
				for _, v := range target.Values {
					st.SecretWatermarks[v.ID] = v.Revision
				}
				rollout := st.SecretRollouts[revision]
				if rollout.Desired != target.Digest {
					rollout.Generation++
					rollout.Desired = target.Digest
				}
				rollout.Reason = ""
				st.SecretRollouts[revision] = rollout
			}
			for revision, reason := range c.Secrets.Faults {
				rollout := st.SecretRollouts[revision]
				rollout.Reason = reason
				st.SecretRollouts[revision] = rollout
			}
			return nil
		}); e != nil {
			return e
		}
		before = c.Journal.View()
	}
	usage, usageErr := c.Store.Usage()
	archiveRoom := usageErr == nil && usage <= archiveBudget-2*artifact.MaxArchive
	if c.Probes == nil {
		c.Probes = NewProbes()
	}
	// Consume fresh endpoint eligibility and pending probe results before rolling
	// decisions can rely on a successor's earlier ready observation.
	c.Probes.Configure(before.Instances, view)
	c.Probes.Poll(ctx, before.Instances, view, now)
	err = c.Journal.Update(func(s *State) error {
		s.LastClock = now
		s.ClockUncertain = false
		s.SchedulingReason = ""
		s.AssignmentReasons = map[string]string{}
		s.InputReason = inputReason
		if inputErr == nil {
			m := input.Metadata
			s.Metadata = m
			if input.Payload.Index.Available {
				if s.Payload.Index.IntentDigest != input.Payload.Index.IntentDigest {
					s.OwnerReason = ""
				}
				s.Payload = input.Payload
				s.InputDigest = input.Digest
			}
		}
		maintenance := s.Metadata.DrainRequested || s.Metadata.Terminal
		if maintenance && s.MaintenanceID != s.Metadata.DrainTarget {
			s.MaintenanceID = s.Metadata.DrainTarget
			s.MaintenanceWithdrawal = randomID()
		}
		if s.Payload.Intent == nil {
			return nil
		}
		wanted := map[string]appbundle.Group{}
		assignments := map[string]schema.AppAssignment{}
		for _, a := range s.Payload.Intent.Entries {
			assignments[a.RevisionID] = a
		}
		for _, g := range s.Payload.Index.Groups {
			wanted[g.Key] = g
		}
		ids := instanceIDs(s)
		// Observe every workload before any rolling decision can use cached health.
		for _, id := range ids {
			i := s.Instances[id]
			if i.Phase == "removed" {
				continue
			}
			if pod, ok := view.Pods[i.Name]; ok {
				i.StopVerified = i.Definition.Lifecycle.StopSignal == nil || pod.StopSignal == *i.Definition.Lifecycle.StopSignal
				if i.PodUID != "" && i.PodUID != pod.UID {
					i.Reason = "unexpected_pod_replacement"
					i.Forced = true
				}
				if i.PodUID == "" {
					i.PodUID = pod.UID
				}
				if pod.Deleting || pod.Phase == "Failed" || pod.Phase == "Succeeded" {
					i.Reason = "process_lost"
				}
			} else if i.PodUID != "" && i.Phase != "retired" {
				i.Reason = "process_lost"
			}
		}
		// Highest slots withdraw first; the complete withdrawal decision is one durable commit.
		sort.Slice(ids, func(a, b int) bool { return s.Instances[ids[a]].Group.Slot > s.Instances[ids[b]].Group.Slot })
		for _, id := range ids {
			i := s.Instances[id]
			if i.Phase == "removed" {
				continue
			}
			_, desired := wanted[i.Group.Key]
			if c.Secrets != nil && c.Secrets.Client.Enabled() && len(i.Definition.Container.Secrets) > 0 {
				fault := c.Secrets.Faults[i.Group.RevisionID]
				if fault == "secrets_denied" || fault == "secret_missing" {
					desired = false
				}
				if target, ok := c.Secrets.Targets[i.Group.RevisionID]; ok && (i.SecretPrepared || i.PodUID != "") && i.SecretVersion != target.Digest {
					a := assignments[i.Group.RevisionID]
					if !i.PublicationStarted && i.PodUID == "" {
						// Nothing could have consumed this superseded preparation.
						desired = false
					} else {
						if s.SecretRotationSlots == nil {
							s.SecretRotationSlots = map[string]string{}
						}
						if key := s.SecretRotationSlots[a.RevisionID]; key != "" {
							head := s.Instances[s.Heads[key]]
							_, wantedSlot := wanted[key]
							if !wantedSlot || (head != nil && head.WithdrawalID == "" && head.SecretVersion == target.Digest && c.secretSuccessorReady(head, s, now)) {
								delete(s.SecretRotationSlots, a.RevisionID)
							}
						}
						next := s.SecretSuccessors[i.ID]
						if !centralSecretTransition(*s, a) && (s.SecretRotationSlots[a.RevisionID] == "" || s.SecretRotationSlots[a.RevisionID] == i.Group.Key) && next != nil && next.Phase == "starting" && next.Generation == a.Generation && next.SecretPrepared && next.SecretVersion == target.Digest {
							desired = false
							s.SecretRotationSlots[a.RevisionID] = i.Group.Key
						}
					}
				}
			}

			if !maintenance && retainRolling(s, i, c, now) {
				desired = true
			}
			if (!desired || maintenance || i.Reason == "process_lost" || i.Reason == "unexpected_pod_replacement") && i.WithdrawalID == "" {
				withdraw(i, now, s.Metadata)
			}
			if i.WithdrawalID != "" {
				if !s.Metadata.DrainDeadline.IsZero() && (i.Deadline.IsZero() || s.Metadata.DrainDeadline.Before(i.Deadline)) {
					i.Deadline = s.Metadata.DrainDeadline
				}
				if i.Phase != "retired" && ((i.AppID == "" && !i.RegistrationPending) || i.RegistrationGone || (!i.Deadline.IsZero() && !now.Before(i.Deadline))) {
					unconfirmed := (i.AppID != "" || i.RegistrationPending) && !i.RegistrationGone
					i.Forced = i.Forced || unconfirmed
					i.Phase = "retired"
					i.RetiredAt = now
					if unconfirmed {
						i.Reason = "cleanup_unconfirmed"
						if !i.Deadline.IsZero() && !now.Before(i.Deadline) {
							i.DrainExpiredAt = i.Deadline
						}
					}
				}
			}
		}
		if !maintenance && !s.Identity.Retiring {
			groups := append([]appbundle.Group(nil), s.Payload.Index.Groups...)
			sort.SliceStable(groups, func(i, j int) bool {
				return assignments[groups[i].RevisionID].Replacement != nil && assignments[groups[j].RevisionID].Replacement == nil
			})
			for _, g := range groups {
				a := assignments[g.RevisionID]
				if s.Metadata.Onchain.Onchain() && !s.Metadata.OnchainActive {
					s.AssignmentReasons[a.RevisionID] = "onchain_pending"
					continue
				}
				if a.Revision != nil && s.Metadata.Onchain.Compatible(a.Revision.Definition) != nil {
					s.AssignmentReasons[a.RevisionID] = "onchain_incompatible"
					continue
				}
				if a.Revision != nil && len(a.Revision.Definition.Container.Secrets) > 0 {
					if c.Secrets == nil || !c.Secrets.Managed(a) {
						s.AssignmentReasons[a.RevisionID] = "secrets_unavailable"
						continue
					}
					if _, ok := c.Secrets.Targets[a.RevisionID]; !ok {
						s.AssignmentReasons[a.RevisionID] = c.Secrets.Faults[a.RevisionID]
						continue
					}
				}
				if !a.StartAllowed {
					s.AssignmentReasons[a.RevisionID] = "cleanup_prerequisite"
					continue
				}
				if id := s.Heads[g.Key]; id != "" && s.Instances[id] != nil && s.Instances[id].Phase != "removed" {
					continue
				}
				blocked := a.Replacement != nil && rollingCount(s, a) >= a.Replacement.Replicas
				for _, i := range s.Instances {
					if (i.Phase != "removed" || !i.RegistrationGone) && (i.Group.Key == g.Key || (a.StartAfter != nil && i.Group.RevisionID == a.StartAfter.RevisionID)) {
						blocked = true
					}
				}
				if blocked {
					s.AssignmentReasons[a.RevisionID] = "cleanup_pending"
					continue
				}
				count := 0
				for _, i := range s.Instances {
					if i.Phase != "removed" || !i.RegistrationGone {
						count++
					}
				}
				bytes := 2048
				for _, name := range g.Files {
					bytes += len(s.Payload.Files[name])
				}
				for _, i := range s.Instances {
					if i.Phase != "removed" {
						for _, file := range i.Files {
							bytes += len(file)
						}
					}
				}
				if !archiveRoom || bytes > appbundle.MaxRenderedBytes || count >= appbundle.MaxInstances || retainedRegistrations(s.Instances)+appCount(a.Revision.Definition) > schema.MaxRegistrations || !fits(s.Instances, a.Revision.Definition, view.Budget) {
					s.SchedulingReason = "resource_refused"
					s.AssignmentReasons[a.RevisionID] = "resource_refused"
					continue
				}
				id := randomID()
				files, name, err := s.Payload.Instantiate(g, id)
				if err != nil {
					return err
				}
				s.Instances[id] = &Instance{ID: id, Group: g, Generation: a.Generation, Definition: a.Revision.Definition, Files: files, Name: name, Phase: "starting", CreatedAt: now}
				for oldID, next := range s.SecretSuccessors {
					if next.Group.Key == g.Key && next.Phase == "starting" && next.Generation == a.Generation && next.SecretPrepared {
						if target, ok := c.Secrets.Targets[a.RevisionID]; ok && target.Digest == next.SecretVersion {
							delete(s.Instances, id)
							id = next.ID
							next.Generation = a.Generation
							next.CreatedAt = now
							s.Instances[id] = next
							delete(s.SecretSuccessors, oldID)
							break
						}
					}
				}
				s.Heads[g.Key] = id
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s := c.Journal.View()
	if s.Payload.Intent == nil {
		return errors.Join(inputErr, c.report(ctx, map[string]bool{}, view, now))
	}
	c.Probes.Configure(s.Instances, view)
	ready := c.Probes.Poll(ctx, s.Instances, view, now)
	if err := c.Journal.Update(func(s *State) error {
		for id := range ready {
			if c.Probes.Started(id, s.Instances[id].PodUID) && s.Instances[id].Phase == "starting" {
				s.Instances[id].Phase = "running"
			}
		}
		return nil
	}); err != nil {
		return err
	}
	s = c.Journal.View()
	var ownerErr error
	if inputErr == nil && input.Metadata.Terminal && input.NodeAbsent {
		ownerErr = c.Owner.Close(ctx)
		if ownerErr == nil {
			ownerErr = c.Journal.Update(func(s *State) error {
				s.Identity, s.OwnerReason = Identity{}, ""
				for _, i := range s.Instances {
					i.RegistrationGone, i.RegistrationPending = true, false
				}
				return nil
			})
		}
	} else {
		ownerErr = c.syncOwner(ctx, s, ready, view)
	}
	// Owner requests are bounded; a failed safety withdrawal cannot prevent
	// deadline removal publication, and artifact failure cannot keep old readiness.
	s = c.Journal.View()
	publishErr := c.publish(ctx, s, now)
	s = c.Journal.View()
	if publishErr == nil && view.Applied != "" && view.Applied == s.Published && view.Artifact == s.Published {
		snapshot, known := s.Snapshots[view.Applied]
		if known {
			err = c.Journal.Update(func(s *State) error { s.Applied = view.Applied; return nil })
			if err != nil {
				return err
			}
			for _, i := range s.Instances {
				if i.Phase != "retired" || !snapshot.Retired[i.ID] || snapshot.Included[i.ID] || view.Inventory[inventoryID(i.Name, "Pod")] {
					continue
				}
				pod, exists := view.Pods[i.Name]
				if exists {
					if pod.UID != i.PodUID || !pod.Deleting {
						continue
					}
					if err := c.Cluster.Release(ctx, i.Name, pod); err != nil {
						return err
					}
				} else if !view.Services[i.Name] {
					if err := c.Journal.Update(func(s *State) error {
						value := s.Instances[i.ID]
						value.Phase = "removed"
						value.TerminatedAt = now
						value.Files = nil
						if value.AppID == "" && !value.RegistrationPending {
							value.RegistrationGone = true
						}
						return nil
					}); err != nil {
						return err
					}
				}
			}
		}
	}
	if e := c.collectSecrets(ctx); e != nil {
		return e
	}
	reportErr := c.report(ctx, ready, view, now)
	result := errors.Join(inputErr, publishErr, ownerErr, reportErr, c.collect(view, now))
	if c.Secrets != nil {
		prepareCtx, stop := optionalSecretContext(ctx, 5*time.Second)
		defer stop()
		if e := c.prepareSecrets(prepareCtx); e != nil {
			result = errors.Join(result, e)
		}
		if prepareCtx.Err() == nil {
			if e := c.Secrets.StageRotation(prepareCtx, c, c.Journal.View()); e != nil {
				result = errors.Join(result, e)
			}
		}
	}
	return result
}

// Optional secret work reserves most of the caller's remaining lifecycle budget.
func optionalSecretContext(ctx context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline)/4 < limit {
		limit = time.Until(deadline) / 4
	}
	return context.WithTimeout(ctx, limit)
}
func (c *Controller) prepareSecrets(ctx context.Context) error {
	s := c.Journal.View()
	if s.Payload.Intent == nil {
		return nil
	}
	if c.Secrets != nil && c.Secrets.Client.Enabled() {
		for _, a := range s.Payload.Intent.Entries {
			if a.Desired != "present" || !c.Secrets.Managed(a) {
				continue
			}
			for _, i := range s.Instances {
				if i.Group.RevisionID != a.RevisionID || i.Phase == "removed" || i.Phase == "retired" {
					continue
				}
				if i.SecretPrepared || i.PodUID != "" {
					continue
				}
				if i.WithdrawalID != "" {
					continue
				}
				target, ok := c.Secrets.Targets[a.RevisionID]
				if !ok || ctx.Err() != nil {
					continue
				}
				if i.SecretVersion != "" && i.SecretVersion != target.Digest {
					if e := c.Secrets.Delete(ctx, i.Name); e != nil {
						continue
					}
				}
				if e := c.Journal.Update(func(st *State) error { st.Instances[i.ID].SecretVersion = target.Digest; return nil }); e != nil {
					return e
				}
				prepared, e := c.preparedSecret(ctx, a, i)
				if e != nil {
					return e
				}
				if prepared == nil {
					continue
				}
				if e = c.Journal.Update(func(st *State) error { mergePreparedSecret(st.Instances[i.ID], prepared); return nil }); e != nil {
					return e
				}
			}
		}
	}

	return nil
}

func withdraw(i *Instance, now time.Time, m contract.Metadata) {
	if i.WithdrawalID == "" {
		i.WithdrawalID = randomID()
		i.WithdrawnAt = now
		i.Phase = "withdrawing"
	}
	if !m.DrainDeadline.IsZero() && (i.Deadline.IsZero() || m.DrainDeadline.Before(i.Deadline)) {
		i.Deadline = m.DrainDeadline
	}
}
func instanceIDs(s *State) []string {
	ids := make([]string, 0, len(s.Instances))
	for id := range s.Instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
func (c *Controller) publish(ctx context.Context, s State, now time.Time) error {
	authCtx, stop := optionalSecretContext(ctx, 2*time.Second)
	defer stop()
	snapshot := Snapshot{Included: map[string]bool{}, Retired: map[string]bool{}, IntentDigest: s.Payload.Index.IntentDigest, AppsGeneration: s.Payload.Intent.Generation}
	for _, id := range instanceIDs(&s) {
		i := s.Instances[id]
		if i.Phase == "retired" || i.Phase == "removed" {
			snapshot.Retired[id] = true
			continue
		}
		if len(i.Definition.Container.Secrets) > 0 && i.PodUID == "" && !i.PublicationStarted && (c.Secrets == nil || !c.Secrets.Client.Enabled()) {
			continue
		}
		if c.Secrets != nil && c.Secrets.Client.Enabled() && len(i.Definition.Container.Secrets) > 0 {
			if !i.SecretPrepared && i.PodUID == "" {
				continue
			}
			if i.PodUID == "" && !i.PublicationStarted && i.WithdrawalID == "" {
				var a schema.AppAssignment
				for _, entry := range s.Payload.Intent.Entries {
					if entry.RevisionID == i.Group.RevisionID {
						a = entry
					}
				}
				if a.Revision == nil || c.Secrets.Authorize(authCtx, a, i) != nil {
					continue
				}
			}
		}
		snapshot.Included[id] = true
	}
	digest := s.Staged
	var data []byte
	if reflect.DeepEqual(s.Snapshots[digest], snapshot) {
		data, _ = c.Store.Get(digest)
	}
	if data == nil {
		files, resources := map[string][]byte{}, []string{}
		for id := range snapshot.Included {
			for name, b := range s.Instances[id].Files {
				files[name] = b
				resources = append(resources, name)
			}
		}
		sort.Strings(resources)
		// Lifecycle identity distinguishes a new exclusion from a pre-addition empty archive.
		files["snapshot.json"], _ = json.Marshal(snapshot)
		files["kustomization.yaml"], _ = json.Marshal(map[string]any{"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization", "resources": resources})
		var err error
		data, err = artifact.Pack(files)
		if err != nil {
			return err
		}
		digest, err = c.Store.Put(data)
		if err != nil {
			return err
		}
	}
	if err := c.Journal.Update(func(s *State) error {
		s.Staged = digest
		s.Snapshots[digest] = snapshot
		for id := range snapshot.Included {
			if i := s.Instances[id]; i != nil {
				i.PublicationStarted = true
			}
		}
		return nil
	}); err != nil {
		return err
	}
	info, err := os.Stat(filepath.Join(c.Store.Directory, digest[7:]+".tar.gz"))
	if err != nil {
		return err
	}
	value := &transport.Artifact{Digest: digest, Revision: "apps@" + digest, Path: "artifacts/" + digest[7:] + ".tar.gz", URL: strings.TrimRight(c.ArtifactURL, "/") + "/artifacts/" + digest[7:] + ".tar.gz", Size: len(data), LastUpdateTime: info.ModTime().UTC().Format(time.RFC3339)}
	if err := c.Cluster.Publish(ctx, value); err != nil {
		return err
	}
	return c.Journal.Update(func(s *State) error {
		s.Published = digest
		for id, i := range s.Instances {
			if i.Phase == "retired" && !snapshot.Included[id] && i.RemovalPublishedAt.IsZero() {
				i.RemovalPublishedAt = now
			}
		}
		return nil
	})
}
func (c *Controller) syncOwner(ctx context.Context, s State, ready map[string]bool, view View) error {
	if s.Identity.Retiring {
		return c.retireOwner(ctx, s)
	}
	// A lost bootstrap response may leave registrations under an unknown issued
	// credential. Retain that owner until native retirement confirms its absence.
	if s.Identity.RunnerID != "" && s.Identity.Credential == "" {
		pending := false
		for _, i := range s.Instances {
			pending = pending || i.RegistrationPending
		}
		if pending {
			if err := c.Owner.Close(ctx); err != nil {
				return err
			}
			s = c.Journal.View()
			if s.Identity.Credential == "" {
				if err := c.Owner.Unregister(ctx, s.Identity); err != nil {
					return err
				}
				if err := c.Journal.Update(func(s *State) error {
					s.Identity = Identity{}
					s.OwnerReason, s.Retirement = "", nil
					for _, i := range s.Instances {
						i.RegistrationPending = false
						if i.AppID == "" && i.WithdrawalID != "" {
							i.RegistrationGone = true
						}
					}
					return nil
				}); err != nil {
					return err
				}
				c.mu.Lock()
				c.fault, c.recoverOwner, c.proofs = "", false, nil
				c.mu.Unlock()
				s = c.Journal.View()
			}
		}
	}
	c.mu.Lock()
	recovery := c.recoverOwner
	c.mu.Unlock()
	// A restored identity first needs a non-ready scoped heartbeat in this process.
	confirmed := s.Identity.Confirmed && c.Owner.Accepted().sameOwner(s.Identity)
	entries, tracked := []Registration{}, []Registration{}
	live := false
	for _, id := range instanceIDs(&s) {
		i := s.Instances[id]
		live = live || i.Phase != "removed" || !i.RegistrationGone
		registrations, err := AppRegistrations(i, false)
		if err != nil {
			return err
		}
		tracked = append(tracked, registrations...)
		if i.Phase == "removed" || i.WithdrawalID != "" {
			continue
		}
		pod, exists := view.Pods[i.Name]
		if s.Metadata.Onchain.Onchain() && !s.Metadata.OnchainActive && i.AppID == "" {
			continue
		}
		if i.AppID == "" && (!exists || pod.UID != i.PodUID || pod.Deleting || pod.Phase != "Running") {
			continue
		}
		signalOK := i.Definition.Lifecycle.StopSignal == nil || (exists && pod.StopSignal == *i.Definition.Lifecycle.StopSignal)
		if (!s.Metadata.Onchain.Onchain() || s.Metadata.OnchainActive) && i.AppID != "" && ready[id] && signalOK && confirmed && !s.ClockUncertain && !recovery {
			for n := range registrations {
				registrations[n].Options.Status = "ready"
			}
		}
		entries = append(entries, registrations...)
	}
	if len(entries) == 0 && (s.Identity.RunnerID == "" || !live) {
		if s.Identity.RunnerID == "" {
			return nil
		}
		if err := c.Journal.Update(func(s *State) error { s.Identity.Retiring = true; return nil }); err != nil {
			return err
		}
		return c.retireOwner(ctx, s)
	}
	if s.Identity.RunnerID == "" {
		if err := c.Journal.Update(func(s *State) error { s.Identity.RunnerID = randomID(); return nil }); err != nil {
			return err
		}
		s = c.Journal.View()
	}
	if err := c.Journal.Update(func(s *State) error {
		for _, e := range entries {
			if i := s.Instances[e.InstanceID]; i != nil && i.AppID == "" {
				i.RegistrationPending = true
			}
		}
		return nil
	}); err != nil {
		return err
	}
	s = c.Journal.View()
	r := OwnerRequest{Identity: s.Identity, Entries: entries, Tracked: tracked}
	if err := c.Owner.Sync(ctx, r, c.hooks()); err != nil {
		c.mu.Lock()
		reason := c.fault
		c.mu.Unlock()
		if reason == "" {
			reason = "registration_pending"
		}
		c.failed(OwnerFailure{RunnerID: r.Identity.RunnerID, Reason: reason})
		return errors.Join(err, c.Journal.Update(func(s *State) error { s.OwnerReason = reason; return nil }))
	}
	return c.Journal.Update(func(s *State) error { s.OwnerReason = ""; return nil })
}

func (c *Controller) retireOwner(ctx context.Context, s State) error {
	if err := c.Owner.Close(ctx); err != nil {
		return err
	}
	s = c.Journal.View()
	if err := c.Owner.Unregister(ctx, s.Identity); err != nil {
		return err
	}
	return c.Journal.Update(func(s *State) error {
		fingerprint := ""
		if s.Identity.Credential != "" {
			fingerprint = artifact.Digest([]byte(s.Identity.Credential))
		}
		s.Retirement = &contract.Evidence{OwnerID: s.Identity.RunnerID, CredentialFingerprint: fingerprint, MutationSequence: s.Identity.Sequence, ObservedAt: c.now(), ExpiresAt: c.now().Add(30 * time.Second), Kind: "owner_retired"}
		for _, i := range s.Instances {
			if i.AppID != "" {
				i.RegistrationGone = true
			}
		}
		s.Identity = Identity{}
		s.OwnerReason = ""
		return nil
	})
}

// A Kubernetes outage cannot turn a failed probe into perpetual ready heartbeats.
// Only already registered immutable endpoints can resume here; no workloads,
// publication, cleanup proof or new registrations are inferred from cached state.
func (c *Controller) safety(ctx context.Context) error {
	s := c.Journal.View()
	view := View{Pods: map[string]Pod{}, Endpoints: map[string]map[string]bool{}}
	for _, i := range s.Instances {
		if i.AppID == "" || i.PodUID == "" || i.Phase == "removed" {
			continue
		}
		pod := Pod{UID: i.PodUID, Phase: "Running"}
		if i.StopVerified && i.Definition.Lifecycle.StopSignal != nil {
			pod.StopSignal = *i.Definition.Lifecycle.StopSignal
		}
		view.Pods[i.Name] = pod
		view.Endpoints[i.Name] = map[string]bool{i.PodUID: true}
	}
	if c.Probes == nil {
		c.Probes = NewProbes()
	}

	c.Probes.Configure(s.Instances, view)
	ready := c.Probes.Poll(ctx, s.Instances, view, c.now())
	return c.syncOwner(ctx, s, ready, view)
}
