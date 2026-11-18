package controlplane

import "time"

type readinessState string

const (
	readinessUnverified readinessState = "unverified"
	readinessPending    readinessState = "pending"
	readinessPartial    readinessState = "partial"
	readinessBlocked    readinessState = "blocked"
	readinessInactive   readinessState = "inactive"
	readinessReady      readinessState = "ready"
)

type machineReadiness struct {
	State      readinessState `json:"state"`
	ValidForMS int64          `json:"valid_for_ms,omitempty"`
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
	return c.ReceivedAt != nil && c.Fresh && c.Current && !c.ClockUncertain && unexpired(c.ExpiresAt, now)
}

func unexpired(expires *time.Time, now time.Time) bool {
	return expires != nil && now.Before(*expires)
}

func blockingReason(reason string) readinessState {
	switch reason {
	case "applying", "runtime_pending", "rollout_pending", "provisioning_pending", "tls_pending",
		"ingress_pending", "registration_pending", "onchain_pending", "sandbox_pending", "cleanup_pending", "cleanup_prerequisite":
		return readinessPending
	default:
		return readinessBlocked
	}
}

func workReadiness(v machineObservation) machineReadiness {
	if v.Lifecycle != "active" {
		return machineReadiness{State: readinessInactive}
	}
	now := v.ServerTime
	var expires time.Time
	use := func(t time.Time) {
		if expires.IsZero() || t.Before(expires) {
			expires = t
		}
	}

	runtime, runner := v.component("runtime"), v.component("runner")
	node := readinessUnverified
	if runtime.currentAt(now) {
		node = blockingReason(runtime.Reason)
		if runtime.Ready {
			node = readinessReady
			use(*runtime.ExpiresAt)
			if desired := v.Onchain.Desired; desired.Mode == "onchain" {
				o := runtime.Onchain
				if o == nil || o.Mode != "onchain" || o.Generation != desired.Generation || !o.Applied || !o.Ready {
					node = readinessUnverified
				}
			}
		}
	}

	tunnel := readinessReady
	if v.Tunnel.Enabled {
		connector := v.component("connector")
		switch {
		case !v.Tunnel.Ready || !unexpired(v.Tunnel.ExpiresAt, now):
			tunnel = readinessUnverified
			if v.Tunnel.Reason != "" && v.Tunnel.Reason != "ready" {
				tunnel = blockingReason(v.Tunnel.Reason)
			}
		case !connector.currentAt(now) || !unexpired(connector.ConnectorExpiresAt, now):
			tunnel = readinessUnverified
		case !connector.Ready:
			tunnel = blockingReason(connector.Reason)
		default:
			use(*v.Tunnel.ExpiresAt)
			use(*connector.ExpiresAt)
			use(*connector.ConnectorExpiresAt)
		}
	}

	apps, hasReadyReplica := assignmentReadiness(v, runtime, runner, use)
	discovery := discoveryReadiness(v, runner, use)
	for _, state := range []readinessState{node, tunnel, discovery} {
		if state == readinessBlocked {
			return machineReadiness{State: readinessBlocked}
		}
	}
	if apps == readinessBlocked && !hasReadyReplica {
		return machineReadiness{State: readinessBlocked}
	}
	if apps != readinessReady && hasReadyReplica && node == readinessReady && tunnel == readinessReady && discovery == readinessReady {
		return machineReadiness{State: readinessPartial, ValidForMS: expires.Sub(now).Milliseconds()}
	}
	for _, state := range []readinessState{node, apps, tunnel, discovery} {
		if state == readinessPending {
			return machineReadiness{State: readinessPending}
		}
	}
	for _, state := range []readinessState{node, apps, tunnel, discovery} {
		if state != readinessReady {
			return machineReadiness{State: readinessUnverified}
		}
	}
	return machineReadiness{State: readinessReady, ValidForMS: expires.Sub(now).Milliseconds()}
}

func assignmentReadiness(v machineObservation, runtime, runner componentObservation, use func(time.Time)) (readinessState, bool) {
	now := v.ServerTime
	apps := runner.Apps
	current := runner.currentAt(now) && apps != nil && apps.DesiredGeneration == v.Requested.Generation
	if v.Delivered != nil && v.Delivered.Generation == v.Requested.Generation && v.Delivered.AppsDigest != "" {
		current = current && apps.DesiredDigest == v.Delivered.AppsDigest
	}
	state := readinessReady
	if v.AssignmentsOmitted || !current || apps.Applied == nil || apps.Applied.Generation != v.Requested.Generation ||
		(apps.DesiredDigest != "" && apps.Applied.AppsDigest != apps.DesiredDigest) {
		state = readinessUnverified
	}
	add := func(next readinessState) {
		if next == readinessBlocked || state == readinessReady || (next == readinessPending && state == readinessUnverified) {
			state = next
		}
	}
	if runtime.currentAt(now) && runtime.AppsError != "" {
		add(blockingReason(runtime.AppsError))
	}
	if runner.currentAt(now) {
		switch {
		case apps != nil && apps.Reason != "":
			add(blockingReason(apps.Reason))
		case !runner.Ready:
			add(blockingReason(runner.Reason))
		}
	}
	if diagnosis := v.component("app-reconciler"); diagnosis.currentAt(now) && !diagnosis.Ready {
		reason := diagnosis.Reason
		if diagnosis.Apps != nil && diagnosis.Apps.Reason != "" {
			reason = diagnosis.Apps.Reason
		}
		add(blockingReason(reason))
	}

	active, hasReadyReplica := false, false
	for _, a := range v.Assignments {
		if a.Desired != "present" || a.Replicas == 0 {
			continue
		}
		active = true
		if !a.StartAllowed || a.Failure != "" {
			add(readinessBlocked)
			continue
		}
		if !current {
			add(readinessUnverified)
			continue
		}
		state := readinessUnverified
		for _, o := range apps.Assignments {
			if o.RevisionID != a.RevisionID || o.Generation != a.Generation || o.ActivationGeneration != a.ActivationGeneration {
				continue
			}
			fresh := now.Before(o.NodeExpiresAt) && now.Before(o.ProbeExpiresAt)
			// Lower bound on the overlap between healthy and registered replicas.
			ready := o.Ready + o.Registered - o.Instances
			if fresh && ready > 0 {
				hasReadyReplica = true
				use(o.NodeExpiresAt)
				use(o.ProbeExpiresAt)
			}
			switch {
			case o.Reason != "" && (o.Ready < a.Replicas || o.Registered < a.Replicas):
				state = blockingReason(o.Reason)
			case o.Instances == 0:
				state = readinessBlocked
			case !fresh:
				state = readinessUnverified
			case o.Ready < a.Replicas || o.Registered < a.Replicas:
				state = readinessBlocked
			case ready >= a.Replicas:
				state = readinessReady
			}
			break
		}
		if state != readinessReady {
			add(state)
		}
	}
	if !active && !v.AssignmentsOmitted {
		return readinessBlocked, false
	}
	if current {
		use(*runner.ExpiresAt)
	}
	return state, hasReadyReplica
}

func discoveryReadiness(v machineObservation, runner componentObservation, use func(time.Time)) readinessState {
	if !v.DiscoveryEnabled {
		return readinessReady
	}
	now := v.ServerTime
	if !v.DiscoveryInitialized || v.DiscoverySelectionStale || !unexpired(v.DiscoverySelectionExpiresAt, now) {
		return readinessUnverified
	}
	source := v.DiscoverySource
	if source == nil || source.State == "excluded" {
		return readinessBlocked
	}
	if source.Stale || !unexpired(source.ExpiresAt, now) {
		return readinessUnverified
	}
	if source.PublicationBlocked {
		return readinessBlocked
	}
	if runner.Apps != nil {
		for _, i := range runner.Apps.Instances {
			m := v.Membership[i.InstanceID]
			if !i.Ready || !i.Registered || !now.Before(i.NodeExpiresAt) || m.State != "present" || !unexpired(m.ExpiresAt, now) {
				continue
			}
			for _, a := range v.Assignments {
				if a.Desired == "present" && a.Replicas > 0 && a.RevisionID == i.RevisionID && a.Generation == i.Generation && a.ActivationGeneration == i.ActivationGeneration {
					use(*v.DiscoverySelectionExpiresAt)
					use(*source.ExpiresAt)
					use(*m.ExpiresAt)
					use(i.NodeExpiresAt)
					return readinessReady
				}
			}
		}
	}
	return readinessUnverified
}
