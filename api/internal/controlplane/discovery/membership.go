package discovery

import (
	"time"

	shared "github.com/livepeer/node/discovery/shared"
)

// Membership describes app publication as of a successful source snapshot.
type Membership struct {
	State      string     `json:"state"`
	QueriedAt  *time.Time `json:"queried_at,omitempty"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

type MembershipQuery struct{ InstanceID, Endpoint, App, Version string }

func (f *Manager) Membership(node, endpoint, app, version string) Membership {
	return f.Memberships(node, []MembershipQuery{{Endpoint: endpoint, App: app, Version: version}})[""]
}

// Members of one bounded instance report share a single Collector snapshot read.
func (f *Manager) Memberships(node string, queries []MembershipQuery) map[string]Membership {
	f.mu.Lock()
	defer f.mu.Unlock()
	snapshots := f.collector.Snapshots()
	published := f.publicInventory(snapshots)
	result := make(map[string]Membership, len(queries))
	for _, q := range queries {
		current := f.membership(node, q.Endpoint, q.App, q.Version, snapshots, published)
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

func (f *Manager) membership(node, endpoint, app, version string, snapshots []shared.Snapshot[runner], published []shared.Entry[publishedRunner]) Membership {
	result := Membership{State: "excluded"}
	for _, source := range f.selected {
		if source.NodeID != node {
			continue
		}
		result.State = "uninitialized"
		for _, snapshot := range snapshots {
			if snapshot.URL != source.URL {
				continue
			}
			at, expiry := snapshot.QueriedAt, snapshot.QueriedAt.Add(2*f.interval)
			result.QueriedAt, result.ExpiresAt = &at, &expiry
			result.State = "absent"
			for _, entry := range published {
				for _, candidate := range entry.Runners {
					if candidate.nodeID != source.NodeID || !candidate.queriedAt.Equal(snapshot.QueriedAt) || candidate.URL != endpoint || candidate.App != app || candidate.Version != version {
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
			if f.reconcileFailed || f.reconciledAt.IsZero() || time.Since(f.reconciledAt) > 2*f.selectionInterval || !time.Now().Before(expiry) {
				result.State = "stale"
			}
			return result
		}
		return result
	}
	return result
}
