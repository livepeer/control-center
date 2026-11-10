package discovery

import (
	"time"

	shared "github.com/livepeer/node/discovery/shared"
)

type snapshotProvenance struct {
	Key string
	At  time.Time
}

// Membership describes publication as of a successful source snapshot. It does
// not attest application reachability, and contains no protected source URL.
type Membership struct {
	State             string     `json:"state"`
	ProvenanceCurrent bool       `json:"provenance_current"`
	QueriedAt         *time.Time `json:"queried_at,omitempty"`
	ObservedAt        *time.Time `json:"observed_at,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
}

type MembershipQuery struct{ InstanceID, Endpoint, App, Version string }

// Caller holds the Manager lock and has captured attempts before snapshots.
func (f *Manager) snapshotCurrent(source Source, snapshot shared.Snapshot[runner], attempt attempt) bool {
	if f.provenance == nil {
		f.provenance = map[string]snapshotProvenance{}
	}
	prior := f.provenance[source.ID]
	current := prior.Key == ackKey(source) && prior.At.Equal(snapshot.QueriedAt)
	if !current && attempt.status == 200 && sameVersion(attempt.source, source) && !snapshot.QueriedAt.IsZero() && !snapshot.QueriedAt.Equal(attempt.before) {
		f.provenance[source.ID] = snapshotProvenance{ackKey(source), snapshot.QueriedAt}
		current = true
	}
	return current
}

func (f *Manager) Membership(node, epoch, endpoint, app, version string) Membership {
	return f.Memberships(node, epoch, []MembershipQuery{{Endpoint: endpoint, App: app, Version: version}})[""]
}

// Members of one bounded instance report share a single Collector snapshot read.
func (f *Manager) Memberships(node, epoch string, queries []MembershipQuery) map[string]Membership {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.transport.mu.Lock()
	attempts := make(map[string]attempt, len(f.transport.attempts))
	for endpoint, value := range f.transport.attempts {
		attempts[endpoint] = value
	}
	snapshots := f.collector.Snapshots()
	f.transport.mu.Unlock()
	published := f.publicInventory(snapshots)
	result := make(map[string]Membership, len(queries))
	for _, q := range queries {
		current := f.membership(node, epoch, q.Endpoint, q.App, q.Version, snapshots, published, attempts)
		if prior, ok := result[q.InstanceID]; ok {
			if prior.State != "present" {
				current = prior
			} else if current.State == "present" {
				if prior.ObservedAt.Before(*current.ObservedAt) {
					current.ObservedAt = prior.ObservedAt
				}
				if prior.ExpiresAt.Before(*current.ExpiresAt) {
					current.ExpiresAt = prior.ExpiresAt
				}
			}
		}
		result[q.InstanceID] = current
	}
	return result
}

func (f *Manager) membership(node, epoch, endpoint, app, version string, snapshots []shared.Snapshot[runner], published []shared.Entry[publishedRunner], attempts map[string]attempt) Membership {
	result := Membership{State: "excluded"}
	for _, source := range f.selected {
		if source.NodeID != node || source.Epoch != epoch {
			continue
		}
		result.State = "uninitialized"
		attempt := attempts[source.URL]
		for _, snapshot := range snapshots {
			if snapshot.URL != source.URL {
				continue
			}
			current := f.snapshotCurrent(source, snapshot, attempt)
			for _, configured := range f.configured {
				if configured.ID == source.ID && !sameVersion(configured, source) {
					current = false
				}
			}
			result.ProvenanceCurrent = current
			at, expiry := snapshot.QueriedAt, snapshot.QueriedAt.Add(2*f.interval)
			result.QueriedAt, result.ExpiresAt = &at, &expiry
			result.State = "absent"
			for _, entry := range published {
				for _, candidate := range entry.Runners {
					if candidate.sourceID != source.ID || !candidate.queriedAt.Equal(snapshot.QueriedAt) || candidate.URL != endpoint || candidate.App != app || candidate.Version != version {
						continue
					}
					stamp, err := time.Parse(time.RFC3339Nano, candidate.ObservedAt)
					if err != nil {
						continue
					}
					result.State = "present"
					result.ObservedAt = &stamp
					if bound := stamp.Add(2 * f.interval); bound.Before(expiry) {
						expiry = bound
					}
				}
			}
			if !current {
				result.State = "unverified_provenance"
			} else if f.reconcileFailed || f.reconciledAt.IsZero() || time.Since(f.reconciledAt) > 2*f.selectionInterval || !time.Now().Before(expiry) {
				result.State = "stale"
			}
			return result
		}
		return result
	}
	return result
}
