package appreconciler

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
)

type Report struct {
	ReportVersion     int                `json:"report_version,omitempty"`
	ObservedAt        time.Time          `json:"observed_at,omitempty"`
	ClockUncertain    bool               `json:"clock_uncertain,omitempty"`
	NodeID            string             `json:"node_id"`
	CredentialVersion int64              `json:"credential_version"`
	Component         string             `json:"component"`
	Generation        int64              `json:"generation"`
	BundleFormat      int                `json:"bundle_format"`
	Sequence          uint64             `json:"sequence"`
	Ready             bool               `json:"ready"`
	Drained           bool               `json:"drained"`
	Reason            string             `json:"reason"`
	Evidence          *contract.Evidence `json:"evidence,omitempty"`
	Apps              contract.AppStatus `json:"apps"`
}
type Reporter interface {
	Status(context.Context, Report) error
	Receipt(context.Context, contract.Metadata, Receipt) error
}
type ControlReporter struct{ Client transport.Requester }

func Diagnose(ctx context.Context, input Inputs, reporter Reporter, reason string) {
	value, err := input.Read(ctx)
	if err != nil {
		return
	}
	DiagnoseMetadata(ctx, value.Metadata, reporter, reason)
}
func DiagnoseMetadata(ctx context.Context, m contract.Metadata, reporter Reporter, reason string) {
	status := "failed"
	if reason == "" {
		status = "ready"
	}
	_ = reporter.Status(ctx, Report{ObservedAt: time.Now().UTC(), ClockUncertain: reason == "clock_uncertain", NodeID: m.NodeID, CredentialVersion: m.CredentialVersion, Component: "app-reconciler", Generation: m.Generation, BundleFormat: contract.BundleFormat, Ready: reason == "", Reason: status, Apps: contract.AppStatus{SecretsProtocol: 1, Reason: reason, Instances: []contract.InstanceStatus{}}})
}

func (r ControlReporter) Status(ctx context.Context, value Report) error {
	_, _, err := r.Client.Request(ctx, "status", value, 16384)
	return err
}
func (r ControlReporter) Receipt(ctx context.Context, m contract.Metadata, value Receipt) error {
	payload := map[string]any{"node_id": m.NodeID, "credential_version": m.CredentialVersion, "generation": value.Generation, "activation_generation": value.ActivationGeneration, "apps_digest": value.AppsDigest, "phase": value.Phase, "reason": value.Reason}
	_, _, err := r.Client.Request(ctx, "apps/"+value.RevisionID+"/status", payload, 16384)
	return err
}
func (c *Controller) report(ctx context.Context, ready map[string]bool, view View, now time.Time) error {
	if err := c.queueReceipts(view); err != nil {
		return err
	}
	if c.Reporter == nil {
		return nil
	}
	s := c.Journal.View()
	c.mu.Lock()
	fault := c.fault
	proofs := make(map[string]proof, len(c.proofs))
	for id, p := range c.proofs {
		proofs[id] = p
	}
	c.mu.Unlock()
	if s.Metadata.AppsError != "" {
		fault = s.Metadata.AppsError
	}
	if s.SchedulingReason != "" {
		fault = s.SchedulingReason
	}
	if s.InputReason != "" {
		fault = s.InputReason
	}
	if s.OwnerReason != "" {
		fault = s.OwnerReason
	}
	if s.ClockUncertain {
		fault = "clock_uncertain"
	}
	status := contract.AppStatus{SecretsProtocol: 1, StagedDigest: s.Staged, PublishedDigest: s.Published, AppliedDigest: s.Applied, Reason: fault, Instances: []contract.InstanceStatus{}, OwnerRecreatedAt: s.OwnerRecreatedAt}
	status.ManagedSecrets = s.Metadata.ManagedSecrets || (c.Secrets != nil && c.Secrets.Client.Enabled())
	status.SecretsEncryptionReady = s.Metadata.SecretsEncryptionReady
	if c.Secrets != nil {
		status.SecretsIdentityReady = c.Secrets.Client.IdentityReady()
	}
	if s.Payload.Intent != nil {
		status.DesiredGeneration = s.Payload.Intent.Generation
		status.DesiredDigest = s.Payload.Index.IntentDigest
	}
	status.Staged = stageIdentity(s, s.Staged)
	status.Published = stageIdentity(s, s.Published)
	status.Applied = stageIdentity(s, s.Applied)
	assignments := map[string]*contract.AssignmentStatus{}
	if s.Payload.Intent != nil {
		for _, a := range s.Payload.Intent.Entries {
			status.Assignments = append(status.Assignments, contract.AssignmentStatus{RevisionID: a.RevisionID, Generation: a.Generation, ActivationGeneration: a.ActivationGeneration, Reason: s.AssignmentReasons[a.RevisionID]})
		}
		for n := range status.Assignments {
			assignments[status.Assignments[n].RevisionID] = &status.Assignments[n]
		}
	}
	clean := true
	registeredInstances := map[string]bool{}
	ids := instanceIDs(&s)
	sort.SliceStable(ids, func(a, b int) bool {
		x, y := s.Instances[ids[a]], s.Instances[ids[b]]
		return (x.Phase != "removed" || !x.RegistrationGone) && (y.Phase == "removed" && y.RegistrationGone)
	})
	status.InstancesTotal = len(ids)
	for _, id := range ids {
		i := s.Instances[id]
		if i.Phase != "removed" || !i.RegistrationGone {
			clean = false
		}
		sessions := -1
		nodeAt, nodeExpiry := time.Time{}, time.Time{}
		accepted := uint64(0)
		if p, exists := proofs[id]; exists && !s.ClockUncertain && !p.Observation.At.After(now.Add(time.Second)) && now.Before(p.Observation.At.Add(p.Observation.TTL)) {
			sessions = len(p.App.SessionIDs)
			nodeAt, nodeExpiry, accepted = p.Observation.At, p.Observation.At.Add(p.Observation.TTL), p.Observation.Sequence
		}
		if i.RegistrationGone {
			sessions = 0
		}
		registered := s.Identity.Confirmed && i.AppID != "" && !i.RegistrationGone && !nodeAt.IsZero()
		p := proofs[id]
		registeredInstances[id] = registered && p.PodUID == i.PodUID && p.App.Status == "ready" && p.Observation.Accepted && p.Observation.RunnerID == s.Identity.RunnerID && p.Observation.Credential == s.Identity.Credential && s.Identity.Sequence != nil && p.Observation.Sequence == *s.Identity.Sequence
		var probe *contract.ProbeStatus
		if c.Probes != nil {
			probe = c.Probes.Status(id, i.PodUID)
		}
		if a := assignments[i.Group.RevisionID]; a != nil && a.ActivationGeneration == i.Group.ActivationGeneration {
			a.Instances++
			if ready[id] && i.WithdrawalID == "" {
				a.Ready++
			}
			if probe != nil && i.WithdrawalID == "" && (a.ProbeExpiresAt.IsZero() || probe.ExpiresAt.Before(a.ProbeExpiresAt)) {
				a.ProbeExpiresAt = probe.ExpiresAt
			}
			if registered {
				a.Registered++
				if a.NodeExpiresAt.IsZero() || nodeExpiry.Before(a.NodeExpiresAt) {
					a.NodeExpiresAt = nodeExpiry
				}
			}
			if i.WithdrawalID != "" && (i.Phase != "removed" || !i.RegistrationGone) {
				a.CleanupPending++
			}
		}
		if len(status.Instances) >= 128 {
			continue
		}
		timeout, _ := time.ParseDuration(i.Definition.Lifecycle.StartupTimeout)
		workload := view.Pods[i.Name].Reason
		if i.PodUID != "" && i.Definition.Lifecycle.StopSignal != nil && !i.StopVerified {
			workload = "stop_signal_unverified"
		}
		status.Instances = append(status.Instances, contract.InstanceStatus{RevisionID: i.Group.RevisionID, Generation: i.Generation, ActivationGeneration: i.Group.ActivationGeneration, InstanceID: id, PodUID: i.PodUID, AppID: i.AppID, Phase: i.Phase, Ready: ready[id] && i.WithdrawalID == "", Registered: registered, Capacity: i.Definition.Instances.CapacityPerInstance, Sessions: sessions, Reason: instanceReason(i, ready[id], now), Deadline: i.Deadline, Forced: i.Forced, RemovalPublishedAt: i.RemovalPublishedAt, TerminatedAt: i.TerminatedAt, RunnerID: s.Identity.RunnerID, WithdrawalID: i.WithdrawalID, DrainExpiredAt: i.DrainExpiredAt, RegistrationGone: i.RegistrationGone, NodeObservedAt: nodeAt, NodeExpiresAt: nodeExpiry, AcceptedSequence: sequencePointer(accepted, !nodeAt.IsZero()), StartupDeadline: i.CreatedAt.Add(timeout), Probe: probe, WorkloadReason: workload})
	}
	status.InstancesOmitted = status.InstancesTotal - len(status.Instances)
	status.SecretRollouts = map[string]contract.SecretRollout{}
	for revision, r := range s.SecretRollouts {
		if !secretRevisionRelevant(s, revision) {
			continue
		}
		if r.Reason == "" {
			check := func(i *Instance) {
				if i.Group.RevisionID == revision && i.Phase != "retired" && i.Phase != "removed" && !i.SecretPrepared && i.WithdrawalID == "" && preparationFailed(i.Reason) {
					r.Reason = i.Reason
				}
			}
			for _, i := range s.Instances {
				check(i)
			}
			for _, i := range s.SecretSuccessors {
				check(i)
			}
		}
		complete := fault == "" && r.Reason == "" && r.Desired != ""
		replicas := -1
		var activation int64
		if s.Payload.Intent != nil {
			for _, a := range s.Payload.Intent.Entries {
				if a.RevisionID == revision && a.Desired == "present" {
					replicas, activation = a.Replicas, a.ActivationGeneration
				}
			}
		}
		count := 0
		for id, i := range s.Instances {
			if i.Group.RevisionID == revision && occupied(i) {
				count++
				if i.Group.ActivationGeneration != activation || i.SecretVersion != r.Desired || !ready[id] || !registeredInstances[id] || i.WithdrawalID != "" {
					complete = false
				}
			}
		}
		r.Applied = ""
		if complete && count > 0 && count == replicas {
			r.Applied = r.Desired
		}
		status.SecretRollouts[revision] = r
	}
	status.Secrets = map[string]string{}
	for _, i := range s.Instances {
		if i.SecretPrepared && i.Phase != "removed" {
			status.Secrets[i.Name] = i.SecretVersion
		}
	}
	report := Report{ReportVersion: 1, ClockUncertain: s.ClockUncertain, NodeID: s.Metadata.NodeID, CredentialVersion: s.Metadata.CredentialVersion, Component: "runner", Generation: s.Metadata.Generation, BundleFormat: contract.BundleFormat, Ready: fault == "", Reason: "ready", Apps: status}
	if fault != "" {
		report.Ready = false
		report.Reason = "failed"
	}
	if s.Metadata.DrainRequested || s.Metadata.Terminal {
		if s.Metadata.Terminal {
			report.Ready = false
		}
		report.Reason = "drain_pending"
		if !s.Metadata.Terminal && clean && s.Identity.RunnerID == "" && s.MaintenanceWithdrawal != "" && !s.ClockUncertain {
			// No live owner can renew admission. This observation follows a successful Kube read
			// and durable owner retirement, rather than renewing an old heartbeat proof.
			report.Drained = true
			report.Evidence = &contract.Evidence{Target: s.Metadata.DrainTarget, WithdrawalID: s.MaintenanceWithdrawal, ObservedAt: now, ExpiresAt: now.Add(30 * time.Second), Kind: "no_owner"}
			if s.Retirement != nil && s.Retirement.MutationSequence != nil {
				report.Evidence.OwnerID = s.Retirement.OwnerID
				report.Evidence.CredentialFingerprint = s.Retirement.CredentialFingerprint
				report.Evidence.MutationSequence = s.Retirement.MutationSequence
			}
			if old := s.Report; old != nil && old.Drained && old.Evidence != nil && old.Evidence.Target == report.Evidence.Target && old.Evidence.WithdrawalID == report.Evidence.WithdrawalID && old.Evidence.OwnerID == report.Evidence.OwnerID && old.Evidence.CredentialFingerprint == report.Evidence.CredentialFingerprint && reflect.DeepEqual(old.Evidence.MutationSequence, report.Evidence.MutationSequence) && now.Before(old.Evidence.ExpiresAt) && (s.ReportDeliveredSequence < old.Sequence || now.Before(old.Evidence.ObservedAt.Add(10*time.Second))) {
				report.Evidence = old.Evidence
			}
		}
	}
	if err := boundReport(&report); err != nil {
		return err
	}
	if err := c.Journal.Update(func(s *State) error {
		report.Sequence = 0
		old := s.Report
		if old != nil {
			copy := *old
			copy.Sequence = 0
			copy.ObservedAt = time.Time{}
			a, _ := json.Marshal(copy)
			b, _ := json.Marshal(report)
			if string(a) == string(b) && now.Before(s.ReportObservedAt.Add(30*time.Second)) {
				return nil
			}
		}
		s.ReportSequence++
		s.ReportObservedAt = now
		report.Sequence = s.ReportSequence
		report.ObservedAt = now
		s.Report = &report
		return nil
	}); err != nil {
		return err
	}
	s = c.Journal.View()
	var statusErr error
	if s.Report.Sequence > s.ReportDeliveredSequence || !now.Before(s.ReportDeliveredAt.Add(30*time.Second)) {
		statusErr = c.Reporter.Status(ctx, *s.Report)
		if statusErr == nil {
			if err := c.Journal.Update(func(current *State) error {
				current.ReportDeliveredSequence, current.ReportDeliveredAt = s.Report.Sequence, now
				return nil
			}); err != nil {
				return err
			}
		}
	}
	s = c.Journal.View()
	var deliveryErr error
	for key, receipt := range s.Receipts {
		if receipt.Done {
			continue
		}
		if err := c.Reporter.Receipt(ctx, s.Metadata, receipt); err != nil {
			deliveryErr = errors.Join(deliveryErr, err)
			continue
		}
		if err := c.Journal.Update(func(s *State) error { r := s.Receipts[key]; r.Done = true; s.Receipts[key] = r; return nil }); err != nil {
			return err
		}
	}
	return errors.Join(statusErr, deliveryErr)
}
func (c *Controller) queueReceipts(view View) error {
	return c.Journal.Update(func(s *State) error {
		if s.Payload.Intent == nil {
			return nil
		}
		for key, r := range s.Receipts {
			current := false
			for _, a := range s.Payload.Intent.Entries {
				allowed := (r.Phase == "removed" && a.Desired == "absent") || ((r.Phase == "applied" || r.Phase == "failed") && !s.Metadata.Terminal && (r.Phase == "failed" || a.Desired == "present"))
				if a.RevisionID == r.RevisionID && a.Generation == r.Generation && a.ActivationGeneration == r.ActivationGeneration && allowed {
					current = true
				}
			}
			if !current {
				delete(s.Receipts, key)
			}
		}
		if failed, ok := s.Snapshots[view.Failed]; ok && view.Failed == s.Published && view.Artifact == s.Published && s.Published == s.Staged && failed.IntentDigest == s.Payload.Index.IntentDigest && !s.Metadata.Terminal {
			for _, a := range s.Payload.Intent.Entries {
				reason := "reconcile_failed"
				if a.Desired == "absent" {
					reason = "cleanup_failed"
				}
				r := Receipt{RevisionID: a.RevisionID, Generation: a.Generation, ActivationGeneration: a.ActivationGeneration, AppsDigest: s.Payload.Index.IntentDigest, Phase: "failed", Reason: reason, ArtifactDigest: view.Failed}
				if _, exists := s.Receipts[receiptKey(r)]; !exists {
					s.Receipts[receiptKey(r)] = r
				}
			}
		}
		snapshot, exists := s.Snapshots[s.Applied]
		if !exists || s.Applied != s.Published || s.Published != s.Staged || snapshot.IntentDigest != s.Payload.Index.IntentDigest {
			return nil
		}
		for _, a := range s.Payload.Intent.Entries {
			phase := "applied"
			complete := true
			if a.Desired == "absent" {
				phase = "removed"
				for _, i := range s.Instances {
					if i.Group.RevisionID == a.RevisionID && i.Group.ActivationGeneration == a.ActivationGeneration && (i.Phase != "removed" || !i.RegistrationGone) {
						complete = false
					}
				}
			} else {
				if !a.StartAllowed {
					continue
				}
				count := 0
				for _, i := range s.Instances {
					if i.Group.RevisionID != a.RevisionID || i.Group.ActivationGeneration != a.ActivationGeneration {
						continue
					}
					if i.Phase == "removed" {
						if !i.RegistrationGone {
							complete = false
						}
					} else if i.WithdrawalID != "" || !snapshot.Included[i.ID] || i.PodUID == "" || view.Pods[i.Name].UID != i.PodUID || !view.Services[i.Name] {
						complete = false
					} else {
						count++
					}
				}
				if count != a.Replicas {
					complete = false
				}
			}
			if complete {
				delete(s.Receipts, receiptKey(Receipt{RevisionID: a.RevisionID, Generation: a.Generation, Phase: "failed"}))
				r := Receipt{RevisionID: a.RevisionID, Generation: a.Generation, ActivationGeneration: a.ActivationGeneration, AppsDigest: s.Payload.Index.IntentDigest, Phase: phase, ArtifactDigest: s.Applied}
				if _, ok := s.Receipts[receiptKey(r)]; !ok {
					s.Receipts[receiptKey(r)] = r
				}
			}
		}
		return nil
	})
}

func instanceReason(i *Instance, ready bool, now time.Time) string {
	if i.Reason != "" {
		return i.Reason
	}
	timeout, _ := time.ParseDuration(i.Definition.Lifecycle.StartupTimeout)
	if !ready && i.Phase == "starting" && i.WithdrawalID == "" && !now.Before(i.CreatedAt.Add(timeout)) {
		return "startup_failed"
	}
	if !ready && i.Phase == "running" {
		return "readiness_failed"
	}
	return ""
}

func stageIdentity(s State, digest string) *contract.StageIdentity {
	if digest == "" {
		return nil
	}
	snapshot := s.Snapshots[digest]
	return &contract.StageIdentity{Generation: snapshot.AppsGeneration, AppsDigest: snapshot.IntentDigest, ArtifactDigest: digest}
}

// Leave ample envelope space for the final sequence/time and never trim drain proof.
func boundReport(r *Report) error {
	for {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if len(b) <= contract.MaxStatusBytes-512 {
			return nil
		}
		if len(r.Apps.Instances) == 0 {
			return errors.New("report_size")
		}
		r.Apps.Instances = r.Apps.Instances[:len(r.Apps.Instances)-1]
		r.Apps.InstancesOmitted++
	}
}

func sequencePointer(n uint64, present bool) *uint64 {
	if !present {
		return nil
	}
	return new(n)
}
