package controlplane

import (
	"time"

	"github.com/livepeer/control-center/runtime/contract"
)

// Timed observations expire relative to the start of the browser request.
// An untimed blocker or pending reason describes the current desired state.
type readinessObservation struct {
	State      string `json:"state"`
	Reason     string `json:"reason,omitempty"`
	ValidForMS int64  `json:"valid_for_ms,omitempty"`
}

type appReadinessEvidence struct {
	Requested          int                   `json:"requested"`
	Complete           bool                  `json:"complete"`
	Applied            bool                  `json:"applied"`
	Admitted           int                   `json:"admitted"`
	AdmittedValidForMS int64                 `json:"admitted_valid_for_ms,omitempty"`
	Blocker            *readinessObservation `json:"blocker,omitempty"`
	Pending            *readinessObservation `json:"pending,omitempty"`
}

type machineReadinessEvidence struct {
	Node      readinessObservation  `json:"node"`
	Apps      appReadinessEvidence  `json:"apps"`
	Onchain   *readinessObservation `json:"onchain,omitempty"`
	Ingress   *readinessObservation `json:"ingress,omitempty"`
	Discovery *readinessObservation `json:"discovery,omitempty"`
}

func (v machineObservation) component(name string) componentObservation {
	for _, c := range v.Components {
		if c.Component == name {
			return c
		}
	}
	return componentObservation{}
}

func (c componentObservation) currentAt(now time.Time) bool {
	return c.ReceivedAt != nil && c.Fresh && c.Current && !c.ClockUncertain && c.ExpiresAt != nil && now.Before(*c.ExpiresAt)
}

func timedObservation(state, reason string, now, expires time.Time) readinessObservation {
	if ms := expires.Sub(now).Milliseconds(); ms > 0 {
		return readinessObservation{State: state, Reason: reason, ValidForMS: ms}
	}
	return readinessObservation{State: "unverified"}
}

func issueState(reason string) string {
	switch reason {
	case "applying", "runtime_pending", "rollout_pending", "provisioning_pending", "tls_pending",
		"ingress_pending", "registration_pending", "onchain_pending", "sandbox_pending", "cleanup_pending", "cleanup_prerequisite",
		"certificate_pending", "tls_or_route_pending", "observation_pending":
		return "pending"
	case "runtime_offline", "observation_expired", "connector_observation_stale":
		return "unverified"
	default:
		return "blocked"
	}
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (v machineObservation) readinessEvidence() *machineReadinessEvidence {
	if v.Lifecycle != "active" {
		return nil
	}
	now := v.ServerTime
	runtime := v.component("runtime")
	runner := v.component("runner")
	apps := v.currentApps(runner)
	e := machineReadinessEvidence{
		Node: readinessObservation{State: "unverified"},
		Apps: v.appEvidence(runtime, runner, apps),
	}
	if runtime.currentAt(now) {
		if runtime.Ready {
			e.Node = timedObservation("ready", "", now, *runtime.ExpiresAt)
		} else {
			e.Node = timedObservation(issueState(runtime.Reason), runtime.Reason, now, *runtime.ExpiresAt)
		}
	}
	if desired := v.Onchain.Desired; desired.Mode == "onchain" {
		e.Onchain = &readinessObservation{State: "unverified"}
		if o := runtime.Onchain; runtime.currentAt(now) && o != nil && o.Mode == "onchain" && o.Generation == desired.Generation {
			state, reason := "pending", "onchain_pending"
			if o.Applied && o.Ready {
				state, reason = "ready", ""
			}
			*e.Onchain = timedObservation(state, reason, now, *runtime.ExpiresAt)
		}
	}
	if v.Tunnel.Enabled {
		ingress := v.ingressEvidence(runtime)
		e.Ingress = &ingress
	}
	if v.DiscoveryEnabled {
		discovery := v.discoveryEvidence(apps)
		e.Discovery = &discovery
	}
	return &e
}

func (v machineObservation) ingressEvidence(runtime componentObservation) readinessObservation {
	now, tunnel := v.ServerTime, v.Tunnel
	if !tunnel.Ready || tunnel.ExpiresAt == nil || !now.Before(*tunnel.ExpiresAt) {
		if !tunnel.Ready && tunnel.Reason != "" && tunnel.Reason != "ready" {
			return readinessObservation{State: issueState(tunnel.Reason), Reason: tunnel.Reason}
		}
		return readinessObservation{State: "unverified"}
	}
	if !runtime.currentAt(now) {
		return readinessObservation{State: "unverified"}
	}
	if !tunnel.IngressVerified {
		return timedObservation("pending", "ingress_pending", now, *runtime.ExpiresAt)
	}
	connector := v.component("connector")
	if !connector.currentAt(now) || connector.ConnectorExpiresAt == nil || !now.Before(*connector.ConnectorExpiresAt) {
		return readinessObservation{State: "unverified"}
	}
	if !connector.Ready {
		return timedObservation(issueState(connector.Reason), connector.Reason, now, earlier(*connector.ExpiresAt, *connector.ConnectorExpiresAt))
	}
	expires := earlier(*tunnel.ExpiresAt, earlier(*runtime.ExpiresAt, earlier(*connector.ExpiresAt, *connector.ConnectorExpiresAt)))
	return timedObservation("ready", "", now, expires)
}

func (v machineObservation) matchesAppInput(generation int64, digest string) bool {
	return generation == v.Requested.Generation &&
		(v.Delivered == nil || v.Delivered.Generation != generation || v.Delivered.AppsDigest == "" || v.Delivered.AppsDigest == digest)
}

func (v machineObservation) currentApps(c componentObservation) *contract.AppStatus {
	if apps := c.Apps; c.currentAt(v.ServerTime) && apps != nil && v.matchesAppInput(apps.DesiredGeneration, apps.DesiredDigest) {
		return apps
	}
	return nil
}

func (v machineObservation) appEvidence(runtime, runner componentObservation, apps *contract.AppStatus) appReadinessEvidence {
	now := v.ServerTime
	e := appReadinessEvidence{Complete: !v.AssignmentsOmitted}
	addIssue := func(o readinessObservation) {
		var target **readinessObservation
		switch o.State {
		case "blocked":
			target = &e.Blocker
		case "pending":
			target = &e.Pending
		default:
			return
		}
		if *target == nil || ((*target).ValidForMS > 0 && (o.ValidForMS == 0 || o.ValidForMS > (*target).ValidForMS)) {
			*target = &o
		}
	}
	if v.DeliveryReason != "" {
		addIssue(readinessObservation{State: issueState(v.DeliveryReason), Reason: v.DeliveryReason})
	}
	if stage := runtime.Downloaded; runtime.currentAt(now) && runtime.AppsError != "" && stage != nil && v.matchesAppInput(stage.Generation, stage.AppsDigest) {
		addIssue(timedObservation(issueState(runtime.AppsError), runtime.AppsError, now, *runtime.ExpiresAt))
	}
	if apps != nil {
		e.Applied = apps.Applied != nil && apps.Applied.Generation == apps.DesiredGeneration && apps.Applied.AppsDigest == apps.DesiredDigest
		if apps.Reason != "" {
			addIssue(timedObservation(issueState(apps.Reason), apps.Reason, now, *runner.ExpiresAt))
		} else if !runner.Ready {
			addIssue(timedObservation(issueState(runner.Reason), runner.Reason, now, *runner.ExpiresAt))
		}
	}
	if c := v.component("app-reconciler"); c.currentAt(now) && !c.Ready {
		reason := c.Reason
		if c.Apps != nil && c.Apps.Reason != "" {
			reason = c.Apps.Reason
		}
		// State recovery blocks the whole reconciler. Other faults apply only to the reported input.
		if reason == "state_recovery_failed" || v.currentApps(c) != nil {
			addIssue(timedObservation(issueState(reason), reason, now, *c.ExpiresAt))
		}
	}
	for _, a := range v.Assignments {
		if a.Desired != "present" || a.Replicas == 0 {
			continue
		}
		e.Requested += a.Replicas
		switch {
		case a.Failure != "":
			addIssue(readinessObservation{State: "blocked", Reason: a.Failure})
		case !a.StartAllowed:
			addIssue(readinessObservation{State: "pending", Reason: "cleanup_prerequisite"})
		case apps != nil:
			admitted, ttl, reason := replicaEvidence(a, apps, now, *runner.ExpiresAt)
			if admitted > 0 {
				if e.Admitted == 0 || ttl < e.AdmittedValidForMS {
					e.AdmittedValidForMS = ttl
				}
				e.Admitted += admitted
			}
			if reason != "" {
				addIssue(timedObservation(issueState(reason), reason, now, *runner.ExpiresAt))
			}
		}
	}
	return e
}

func (a observedAssignment) matchesInstance(i contract.InstanceStatus) bool {
	return i.RevisionID == a.RevisionID && i.ActivationGeneration == a.ActivationGeneration && i.Generation <= a.Generation &&
		i.WithdrawalID == "" && i.Phase != "removed"
}

func (a observedAssignment) report(apps *contract.AppStatus) *contract.AssignmentStatus {
	for i := range apps.Assignments {
		r := &apps.Assignments[i]
		if r.RevisionID == a.RevisionID && r.Generation == a.Generation && r.ActivationGeneration == a.ActivationGeneration {
			return r
		}
	}
	return nil
}

func replicaEvidence(a observedAssignment, apps *contract.AppStatus, now, reportExpiry time.Time) (admitted int, ttl int64, reason string) {
	o := a.report(apps)
	if o != nil && o.Admission != nil {
		ttl = earlier(o.Admission.ExpiresAt, reportExpiry).Sub(now).Milliseconds()
		if ttl > 0 {
			admitted = min(o.Admission.Ready, a.Replicas)
		}
	}
	if admitted == a.Replicas {
		return admitted, ttl, ""
	}
	if o != nil && o.Reason != "" {
		return admitted, ttl, o.Reason
	}
	for _, i := range apps.Instances {
		if a.matchesInstance(i) && !now.Before(i.AdmissionExpiresAt) {
			for _, r := range []string{i.WorkloadReason, i.Reason} {
				switch r {
				case "image_pull_failed", "container_start_failed", "startup_failed", "readiness_failed", "memory_limit",
					"scheduling_refused", "isolation_failed", "process_failed_to_start", "process_failed", "process_lost":
					return admitted, ttl, r
				}
			}
		}
	}
	if o != nil && o.Admission != nil && (o.Instances < a.Replicas || o.CleanupPending > 0 ||
		(o.Admission.Ready == 0 && now.Before(o.ProbeExpiresAt) && now.Before(o.NodeExpiresAt))) {
		return admitted, ttl, "registration_pending"
	}
	return admitted, ttl, ""
}

func (v machineObservation) discoveryEvidence(apps *contract.AppStatus) readinessObservation {
	unknown := readinessObservation{State: "unverified"}
	now, source := v.ServerTime, v.DiscoverySource
	if !v.DiscoveryInitialized || v.DiscoverySelectionStale || v.DiscoverySelectionExpiresAt == nil || !now.Before(*v.DiscoverySelectionExpiresAt) {
		return unknown
	}
	if source == nil || source.State == "excluded" {
		if source != nil && source.SelectionReason == "blocked" {
			return timedObservation("blocked", "discovery_excluded", now, *v.DiscoverySelectionExpiresAt)
		}
		return unknown
	}
	if source.Stale || source.ExpiresAt == nil || apps == nil ||
		(v.Tunnel.SourceGeneration > 0 && source.SelectedGeneration != v.Tunnel.SourceGeneration) {
		return unknown
	}
	var latest time.Time
	for _, i := range apps.Instances {
		m := v.Membership[i.InstanceID]
		if !now.Before(i.AdmissionExpiresAt) || m.State != "present" || m.ExpiresAt == nil || !now.Before(*m.ExpiresAt) ||
			m.SourceGeneration != source.SelectedGeneration {
			continue
		}
		for _, a := range v.Assignments {
			if a.Desired != "present" || a.Replicas == 0 || !a.StartAllowed || !a.matchesInstance(i) {
				continue
			}
			if report := a.report(apps); report != nil && report.Admission != nil && report.Admission.Ready > 0 && now.Before(report.Admission.ExpiresAt) {
				if expires := earlier(i.AdmissionExpiresAt, *m.ExpiresAt); expires.After(latest) {
					latest = expires
				}
			}
			break
		}
	}
	if latest.IsZero() {
		return unknown
	}
	expires := earlier(latest, earlier(*source.ExpiresAt, earlier(*v.DiscoverySelectionExpiresAt, *v.component("runner").ExpiresAt)))
	return timedObservation("ready", "", now, expires)
}
