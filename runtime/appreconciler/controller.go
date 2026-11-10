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
	Observation          Observation
	App                  AppObservation
	WithdrawalID, PodUID string
}
type Controller struct {
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
	return OwnerHooks{Identity: func() Identity { return c.Journal.View().Identity }, Reserve: c.Journal.Reserve, Observe: c.observe, Failure: c.failed, Now: c.now, PermitReady: func(r Registration) bool {
		uid, eligible := c.Journal.Eligible(r.InstanceID, r.Options.ID)
		return eligible && c.Probes != nil && c.Probes.Ready(r.InstanceID, uid)
	}}
}
func (c *Controller) failed(f OwnerFailure) {
	if c.Journal.View().OwnerEpoch != f.Epoch {
		return
	}
	c.mu.Lock()
	c.proofs = map[string]proof{}
	c.fault = f.Reason
	if f.Reset {
		c.recoverOwner = true
	}
	c.mu.Unlock()
}
func (c *Controller) observe(o Observation) error {
	// Durable identity is committed before the SDK accepts the response or confirms registration.
	var workErr error
	credentialChanged := false
	err := c.Journal.Update(func(s *State) error {
		if o.RunnerID == "" || (s.Identity.RunnerID != "" && s.Identity.RunnerID != o.RunnerID) {
			return errors.New("owner_identity")
		}
		if s.Identity.RunnerID == "" || (s.Identity.Credential != o.PreviousCredential && (o.Credential == "" || s.Identity.Credential != o.Credential)) || o.ReservedSequence < s.IdentitySequence {
			return ErrSuperseded
		}
		workCurrent := s.OwnerHash == o.Hash && s.OwnerEpoch == o.Epoch && !s.Identity.Retiring
		previous := s.Identity.Credential
		credentialChanged = o.Credential != "" && o.Credential != previous
		if o.Credential != "" {
			s.Identity.Credential = o.Credential
		}
		if s.Identity.Credential == "" {
			return errors.New("owner_credential")
		}
		s.IdentitySequence = o.ReservedSequence
		if credentialChanged {
			s.AcceptedSequence = 0
			s.Identity.Confirmed = false
		}
		if o.Bootstrap && credentialChanged && previous != "" {
			s.OwnerRecreatedAt = o.At
			for _, i := range s.Instances {
				if i.Phase == "removed" || i.WithdrawalID != "" {
					continue
				}
				// The old Node work state cannot be reconstructed. Drain the old
				// incarnation before admitting work to a fresh process/registration.
				withdraw(i, o.At, s.Metadata)
				s.OwnerHash = ""
				i.Forced = true
				i.Reason = "node_registration_recreated"
			}
		}
		// Keep a lineage-fenced credential even when its work snapshot was superseded.
		// Reconstruction and retirement must use the latest issued secret.
		if !workCurrent {
			workErr = ErrSuperseded
			return nil
		}
		if !o.Bootstrap && !credentialChanged && o.Sequence > 0 && o.Sequence <= s.AcceptedSequence {
			return ErrSuperseded
		}
		if o.Bootstrap || credentialChanged {
			s.AcceptedSequence = 0
		} else if o.Sequence > 0 {
			s.AcceptedSequence = o.Sequence
		}
		s.Identity.RunnerID = o.RunnerID
		s.Identity.Confirmed = !o.Bootstrap && !credentialChanged && o.Sequence > 0
		known := map[string]bool{}
		for _, i := range s.Instances {
			if i.AppID != "" {
				known[i.AppID] = true
			}
		}
		for n, entry := range o.Entries {
			i := s.Instances[entry.InstanceID]
			if i == nil || n >= len(o.Apps) || contract.ReservedProxyID(o.Apps[n].ID) || (i.AppID != "" && i.AppID != o.Apps[n].ID) {
				return errors.New("app_identity")
			}
			i.AppID = o.Apps[n].ID
			known[i.AppID] = true
		}
		for _, app := range o.Apps {
			if !known[app.ID] {
				return errors.New("unknown_owner_registration")
			}
		}
		seen := map[string]bool{}
		for _, app := range o.Apps {
			seen[app.ID] = true
		}
		for _, i := range s.Instances {
			if i.Phase == "removed" && i.AppID != "" && !seen[i.AppID] {
				i.RegistrationGone = true
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if workErr != nil {
		return workErr
	}
	s := c.Journal.View()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.proofs = map[string]proof{}
	c.fault = ""
	c.recoverOwner = false
	if o.Bootstrap || credentialChanged || o.Sequence == 0 {
		return nil
	}
	byID := map[string]AppObservation{}
	for _, app := range o.Apps {
		byID[app.ID] = app
	}
	for id, i := range s.Instances {
		if app, exists := byID[i.AppID]; exists {
			// Authoritative retained-app counts are useful diagnostics. Without
			// a captured withdrawal/UID they are deliberately not cleanup proof.
			c.proofs[id] = proof{Observation: o, App: app}
		}
	}
	for _, e := range o.Entries {
		i := s.Instances[e.InstanceID]
		app, exists := byID[i.AppID]
		if exists {
			c.proofs[i.ID] = proof{o, app, e.WithdrawalID, e.PodUID}
		}
	}
	return nil
}
func (c *Controller) empty(i *Instance, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.proofs[i.ID]
	return ok && i.WithdrawalID != "" && p.WithdrawalID == i.WithdrawalID && p.PodUID == i.PodUID &&
		p.Observation.At.Before(now.Add(time.Second)) && now.Before(p.Observation.At.Add(p.Observation.TTL)) &&
		(p.App.Status == "not-ready" || p.App.Status == "draining") && len(p.App.SessionIDs) == 0
}

// Tick never interprets an unavailable input, failed observation or missing object as an empty desired set.
// Only this loop makes lifecycle decisions; SDK callbacks commit identity and fresh observations.
func (c *Controller) Tick(ctx context.Context) error {
	now := c.now()
	before := c.Journal.View()
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
	now = c.now() // Input/API latency must not keep an expired Node proof fresh.
	inputReason := ""
	if inputErr != nil {
		inputReason = "input_unavailable"
	}
	if inputErr == nil {
		m := input.Metadata
		if before.InputDigest != "" && (m.NodeID != before.Metadata.NodeID || m.Epoch != before.Metadata.Epoch || m.CredentialVersion < before.Metadata.CredentialVersion || (before.Metadata.Terminal && !m.Terminal)) {
			return errors.New("input_enrollment_regression")
		}
		if m.Generation < before.Metadata.Generation || (input.Payload.Index.Available && before.Payload.Intent != nil && (input.Payload.Intent.Generation < before.Payload.Intent.Generation || (input.Payload.Intent.Generation == before.Payload.Intent.Generation && input.Payload.Index.IntentDigest != before.Payload.Index.IntentDigest))) {
			inputErr = errors.New("input_regression")
			inputReason = "input_regression"
		}
	}
	usage, usageErr := c.Store.Usage()
	archiveRoom := usageErr == nil && usage <= archiveBudget-2*artifact.MaxArchive
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
					s.OwnerReason, s.RejectedOwnerHash, s.OwnerRetryAt = "", "", time.Time{}
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
		// Highest slots withdraw first; the complete withdrawal decision is one durable commit.
		ids := instanceIDs(s)
		sort.Slice(ids, func(a, b int) bool { return s.Instances[ids[a]].Group.Slot > s.Instances[ids[b]].Group.Slot })
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
			_, desired := wanted[i.Group.Key]
			if (!desired || maintenance || i.Reason == "process_lost" || i.Reason == "unexpected_pod_replacement") && i.WithdrawalID == "" {
				withdraw(i, now, s.Metadata)
				s.OwnerHash = ""
			}
			if i.WithdrawalID != "" {
				if !s.Metadata.DrainDeadline.IsZero() && s.Metadata.DrainDeadline.Before(i.Deadline) {
					i.Deadline = s.Metadata.DrainDeadline
				}
				if i.Phase != "retired" && (i.AppID == "" || c.empty(i, now) || !now.Before(i.Deadline)) {
					unconfirmed := i.AppID != "" && !c.empty(i, now)
					i.Forced = i.Forced || unconfirmed
					i.Phase = "retired"
					i.RetiredAt = now
					if unconfirmed {
						i.Reason = "cleanup_unconfirmed"
						if !now.Before(i.Deadline) {
							i.DrainExpiredAt = i.Deadline
						}
					}
				}
			}
		}
		if !maintenance && !s.Identity.Retiring {
			for _, g := range s.Payload.Index.Groups {
				a := assignments[g.RevisionID]
				if !a.StartAllowed {
					s.AssignmentReasons[a.RevisionID] = "cleanup_prerequisite"
					continue
				}
				if id := s.Heads[g.Key]; id != "" && s.Instances[id] != nil && s.Instances[id].Phase != "removed" {
					continue
				}
				blocked := false
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
				if !archiveRoom || bytes > appbundle.MaxRenderedBytes || count >= appbundle.MaxInstances || !fits(s.Instances, a.Revision.Definition, view.Budget) {
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
	s = c.Journal.View()
	if c.Probes == nil {
		c.Probes = NewProbes()
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
	ownerErr := c.syncOwner(ctx, s, ready, view)
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
						if value.AppID == "" {
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
	reportErr := c.report(ctx, ready, view, now)
	return errors.Join(inputErr, publishErr, ownerErr, reportErr, c.collect(view, now))
}

func withdraw(i *Instance, now time.Time, m contract.Metadata) {
	if i.WithdrawalID == "" {
		i.WithdrawalID = randomID()
		timeout, _ := time.ParseDuration(i.Definition.Instances.DrainTimeout)
		i.Deadline = now.Add(timeout)
		i.Phase = "withdrawing"
	}
	if !m.DrainDeadline.IsZero() && m.DrainDeadline.Before(i.Deadline) {
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
	snapshot := Snapshot{Included: map[string]bool{}, Retired: map[string]bool{}, IntentDigest: s.Payload.Index.IntentDigest, AppsGeneration: s.Payload.Intent.Generation}
	for _, id := range instanceIDs(&s) {
		i := s.Instances[id]
		if i.Phase == "retired" || i.Phase == "removed" {
			snapshot.Retired[id] = true
			continue
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
	if err := c.Journal.Update(func(s *State) error { s.Staged = digest; s.Snapshots[digest] = snapshot; return nil }); err != nil {
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
	c.mu.Lock()
	recovery := c.recoverOwner
	c.mu.Unlock()
	// A restored identity first needs a non-ready scoped heartbeat in this process.
	confirmed := s.Identity.Confirmed && c.Owner.Accepted().Identity == s.Identity
	entries := []Registration{}
	for _, id := range instanceIDs(&s) {
		i := s.Instances[id]
		if i.Phase == "removed" {
			continue
		}
		if i.AppID == "" && i.WithdrawalID != "" {
			continue
		}
		pod, exists := view.Pods[i.Name]
		if i.AppID == "" && (!exists || pod.UID != i.PodUID || pod.Deleting || pod.Phase != "Running") {
			continue
		}
		signalOK := i.Definition.Lifecycle.StopSignal == nil || (exists && pod.StopSignal == *i.Definition.Lifecycle.StopSignal)
		options, err := AppOptions(i, i.AppID != "" && ready[id] && signalOK && i.WithdrawalID == "" && confirmed && !s.ClockUncertain && !recovery)
		if err != nil {
			return err
		}
		entries = append(entries, Registration{InstanceID: id, WithdrawalID: i.WithdrawalID, PodUID: i.PodUID, Options: options})
	}
	if len(entries) == 0 {
		if s.Identity.RunnerID == "" {
			return nil
		}
		for _, i := range s.Instances {
			if i.Phase != "removed" {
				return nil
			}
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
	r := OwnerRequest{Identity: s.Identity, Entries: entries, Recover: recovery}
	r.Hash = RequestHash(r)
	if r.Hash == s.RejectedOwnerHash && c.now().Before(s.OwnerRetryAt) {
		return c.resumeAccepted(ctx, s, ready, recovery)
	}
	if r.Hash != s.OwnerHash {
		if err := c.Journal.Update(func(s *State) error {
			s.OwnerHash = r.Hash
			s.OwnerEpoch = randomID()
			return nil
		}); err != nil {
			return err
		}
		c.mu.Lock()
		c.fault = ""
		c.mu.Unlock()
		s = c.Journal.View()
	}
	r.Epoch = s.OwnerEpoch
	err := c.Owner.Sync(ctx, r, c.hooks())
	if err != nil {
		c.mu.Lock()
		reason := c.fault
		recovery = c.recoverOwner
		c.mu.Unlock()
		if errors.Is(err, ErrResourceRefused) {
			reason = "resource_refused"
		} else if transport.IsStatus(err, 401) || transport.IsStatus(err, 403) {
			reason = "registration_auth_failed"
		} else if reason == "" {
			reason = "registration_pending"
		}
		c.failed(OwnerFailure{Epoch: r.Epoch, Hash: r.Hash, Reason: reason})
		accepted := c.Owner.Accepted()
		if e := c.Journal.Update(func(s *State) error {
			s.OwnerReason = reason
			if len(accepted.Entries) > 0 && len(r.Entries) > len(accepted.Entries) && !recovery {
				s.RejectedOwnerHash, s.OwnerRetryAt = r.Hash, c.now().Add(30*time.Second)
			}
			return nil
		}); e != nil {
			return errors.Join(err, e)
		}
		return errors.Join(err, c.resumeAccepted(ctx, c.Journal.View(), ready, recovery))
	}
	return c.Journal.Update(func(s *State) error {
		s.OwnerReason = ""
		s.RejectedOwnerHash = ""
		s.OwnerRetryAt = time.Time{}
		return nil
	})
}

func (c *Controller) resumeAccepted(ctx context.Context, s State, ready map[string]bool, recovery bool) error {
	accepted := c.Owner.Accepted()
	if len(accepted.Entries) == 0 || accepted.Identity.RunnerID != s.Identity.RunnerID || recovery {
		return nil
	}
	confirmed := s.Identity.Confirmed && accepted.Identity == s.Identity
	accepted.Identity = s.Identity
	for n, e := range accepted.Entries {
		if i := s.Instances[e.InstanceID]; i != nil {
			e.WithdrawalID, e.PodUID = i.WithdrawalID, i.PodUID
			e.Options, _ = AppOptions(i, i.AppID != "" && ready[i.ID] && i.WithdrawalID == "" && confirmed && !s.ClockUncertain)
			accepted.Entries[n] = e
		}
	}
	accepted.Hash = RequestHash(accepted)
	if err := c.Journal.Update(func(s *State) error {
		if s.OwnerHash != accepted.Hash {
			s.OwnerHash, s.OwnerEpoch = accepted.Hash, randomID()
		}
		return nil
	}); err != nil {
		return err
	}
	accepted.Epoch = c.Journal.View().OwnerEpoch
	return c.Owner.Sync(ctx, accepted, c.hooks())
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
		s.Retirement = &contract.Evidence{OwnerID: s.Identity.RunnerID, CredentialFingerprint: fingerprint, MutationSequence: s.AcceptedSequence, ObservedAt: c.now(), ExpiresAt: c.now().Add(30 * time.Second), Kind: "owner_retired"}
		for _, i := range s.Instances {
			if i.AppID != "" {
				i.RegistrationGone = true
			}
		}
		s.Identity = Identity{}
		s.AcceptedSequence = 0
		s.IdentitySequence = 0
		s.OwnerHash = ""
		s.OwnerEpoch = ""
		s.OwnerReason, s.RejectedOwnerHash, s.OwnerRetryAt = "", "", time.Time{}
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
