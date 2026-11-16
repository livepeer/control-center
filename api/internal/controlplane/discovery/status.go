package discovery

import (
	"strconv"
	"time"
)

// Status describes fleet discovery. Source freshness does not attest
// applied assignments, registration identity, or external app reachability.
type Status struct {
	Enabled              bool           `json:"enabled"`
	InstanceID           string         `json:"instance_id,omitempty"`
	Initialized          bool           `json:"initialized"`
	ReconciledAt         *time.Time     `json:"reconciled_at,omitempty"`
	ReconciliationFailed bool           `json:"reconciliation_failed"`
	SelectionExpiresAt   *time.Time     `json:"selection_expires_at,omitempty"`
	SelectionStale       bool           `json:"selection_stale"`
	Refreshes            uint64         `json:"refreshes"`
	RefreshFailures      uint64         `json:"refresh_failures"`
	RefreshSeconds       float64        `json:"refresh_seconds"`
	Sources              []SourceStatus `json:"sources"`
}

type SourceStatus struct {
	NodeID              string     `json:"node_id"`
	Generation          int64      `json:"generation"`
	SelectedGeneration  int64      `json:"selected_generation,omitempty"`
	Lifecycle           string     `json:"lifecycle"`
	Selected            bool       `json:"selected"`
	SelectionReason     string     `json:"selection_reason"`
	State               string     `json:"state"`
	Failures            int        `json:"failures"`
	LastSuccess         *time.Time `json:"last_success,omitempty"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	Stale               bool       `json:"stale"`
	CachedRunners       int        `json:"cached_runners"`
	LastAttempt         *time.Time `json:"last_attempt,omitempty"`
	TransportOutcome    string     `json:"transport_outcome,omitempty"`
	HTTPStatus          int        `json:"http_status,omitempty"`
	CredentialAvailable bool       `json:"credential_available"`
	PublicationBlocked  bool       `json:"publication_blocked"`
	OldestObservation   *time.Time `json:"oldest_observation,omitempty"`
	NewestObservation   *time.Time `json:"newest_observation,omitempty"`
}

// Infer Node's callback/label types from its public method. This avoids importing
// node/internal/observability or duplicating the Collector's source state machine.
func collectDiscoveryMetrics[L ~map[string]string, E ~func(string, float64, L)](collect func(E), emit func(string, float64, map[string]string)) {
	collect(func(name string, value float64, labels L) { emit(name, value, map[string]string(labels)) })
}

func (f *Manager) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now().UTC()
	status := Status{Enabled: true, InstanceID: f.instanceID, Initialized: f.collector.Initialized(), ReconciliationFailed: f.reconcileFailed,
		SelectionStale: f.reconciledAt.IsZero() || now.Sub(f.reconciledAt) > 2*f.selectionInterval,
		Refreshes:      f.refreshes, RefreshFailures: f.failures, RefreshSeconds: f.refreshDuration.Seconds(), Sources: []SourceStatus{}}
	if !f.reconciledAt.IsZero() {
		stamp := f.reconciledAt
		status.ReconciledAt = &stamp
		expiry := stamp.Add(2 * f.selectionInterval)
		status.SelectionExpiresAt = &expiry
	}
	selected := make([]SourceStatus, len(f.selected))
	for i, source := range f.selected {
		selected[i] = SourceStatus{NodeID: source.NodeID, Selected: true, SelectedGeneration: source.Generation}
	}
	collectDiscoveryMetrics(f.collector.CollectMetrics, func(name string, value float64, labels map[string]string) {
		i, err := strconv.Atoi(labels["source_index"])
		if err != nil || i < 0 || i >= len(selected) {
			return
		}
		s := &selected[i]
		switch name {
		case "discovery_source_state":
			if value == 1 {
				s.State = labels["state"]
			}
		case "discovery_source_failures":
			s.Failures = int(value)
		case "discovery_cached_runners":
			s.CachedRunners = int(value)
		case "discovery_last_success_timestamp_seconds":
			if value > 0 {
				stamp := time.Unix(int64(value), 0).UTC()
				s.LastSuccess = &stamp
			}
		}
	})
	f.transport.mu.Lock()
	defer f.transport.mu.Unlock()
	byID := map[string]SourceStatus{}
	for i, source := range f.selected {
		s := selected[i]
		s.Stale = s.LastSuccess == nil || now.Sub(*s.LastSuccess) > 2*f.interval
		if s.LastSuccess != nil {
			expiry := s.LastSuccess.Add(2 * f.interval)
			s.ExpiresAt = &expiry
		}
		if auth := f.transport.selection.Load(); auth != nil {
			s.CredentialAvailable = auth.sources[source.URL].available
		}
		if auth := f.transport.selection.Load(); auth != nil && auth.sources[source.URL] != nil {
			a := auth.sources[source.URL]
			if !a.attempt.completed.IsZero() {
				stamp := a.attempt.completed
				s.LastAttempt = &stamp
				s.TransportOutcome = a.attempt.outcome
				s.HTTPStatus = a.attempt.status
			}
		}
		byID[source.NodeID] = s
	}
	for _, snapshot := range f.collector.Snapshots() {
		for _, source := range f.selected {
			if source.URL != snapshot.URL {
				continue
			}
			s := byID[source.NodeID]
			for _, entry := range snapshot.Entries {
				if !publicEntry(source, entry) {
					s.PublicationBlocked = true
				}
				for _, runner := range entry.Runners {
					stamp, err := time.Parse(time.RFC3339Nano, runner.ObservedAt)
					if err != nil {
						continue
					}
					if s.OldestObservation == nil || stamp.Before(*s.OldestObservation) {
						s.OldestObservation = &stamp
					}
					if s.NewestObservation == nil || stamp.After(*s.NewestObservation) {
						s.NewestObservation = &stamp
					}
				}
			}
			byID[source.NodeID] = s
		}
	}
	for _, source := range f.configured {
		s, ok := byID[source.NodeID]
		if !ok {
			s = SourceStatus{NodeID: source.NodeID, State: "excluded", Stale: true}
		}
		s.SelectionReason = "selected"
		if !ok {
			s.SelectionReason = "unverified"
			if source.Lifecycle != "active" && source.Lifecycle != "draining" {
				s.SelectionReason = "inactive"
			}
			if source.Blocked {
				s.SelectionReason = "blocked"
			}
		}
		s.Generation = source.Generation
		s.Lifecycle = source.Lifecycle
		status.Sources = append(status.Sources, s)
	}
	return status
}
