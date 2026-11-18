package discovery

import "time"

// Membership describes app publication as of a successful source snapshot.
type Membership struct {
	State            string     `json:"state"`
	QueriedAt        *time.Time `json:"queried_at,omitempty"`
	ObservedAt       *time.Time `json:"observed_at,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	SourceGeneration int64      `json:"-"`
}

type MembershipQuery struct{ InstanceID, Endpoint, App, Version string }

func (f *Manager) Membership(node, endpoint, app, version string) Membership {
	return f.Memberships(node, []MembershipQuery{{Endpoint: endpoint, App: app, Version: version}})[""]
}

func (f *Manager) Memberships(node string, queries []MembershipQuery) map[string]Membership {
	return f.MembershipSnapshot().Memberships(node, queries)
}

type membershipKey struct{ node, endpoint, app, version string }

// MembershipSnapshot indexes one published inventory for all machines in a status read.
type MembershipSnapshot struct {
	sources   map[string]Membership
	published map[membershipKey]Membership
}

func (f *Manager) MembershipSnapshot() *MembershipSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	stale := f.reconcileFailed || f.reconciledAt.IsZero() || now.Sub(f.reconciledAt) > 2*f.selectionInterval
	freshness := 2 * f.interval
	snapshots := f.collector.Snapshots()
	queries := make(map[string]time.Time, len(snapshots))
	for _, snapshot := range snapshots {
		queries[snapshot.URL] = snapshot.QueriedAt
	}
	s := &MembershipSnapshot{sources: make(map[string]Membership, len(f.selected)), published: map[membershipKey]Membership{}}
	for _, source := range f.selected {
		at, ok := queries[source.URL]
		if !ok {
			s.sources[source.NodeID] = Membership{State: "uninitialized"}
			continue
		}
		expiry := at.Add(freshness)
		m := Membership{State: "absent", QueriedAt: &at, ExpiresAt: &expiry, SourceGeneration: source.Generation}
		if stale || !now.Before(expiry) {
			m.State = "stale"
		}
		s.sources[source.NodeID] = m
	}
	for _, entry := range f.publicInventory(snapshots) {
		for _, candidate := range entry.Runners {
			m := s.sources[candidate.nodeID]
			if m.QueriedAt == nil || !m.QueriedAt.Equal(candidate.queriedAt) {
				continue
			}
			stamp, err := time.Parse(time.RFC3339Nano, candidate.ObservedAt)
			if err != nil {
				continue
			}
			expiry := stamp.Add(freshness)
			m.ObservedAt = &stamp
			if expiry.Before(*m.ExpiresAt) {
				m.ExpiresAt = &expiry
			}
			if m.State != "stale" && now.Before(*m.ExpiresAt) {
				m.State = "present"
			} else {
				m.State = "stale"
			}
			s.published[membershipKey{candidate.nodeID, candidate.URL, candidate.App, candidate.Version}] = m
		}
	}
	return s
}

func (s *MembershipSnapshot) lookup(node string, q MembershipQuery) Membership {
	if m, ok := s.published[membershipKey{node, q.Endpoint, q.App, q.Version}]; ok {
		return m
	}
	if m, ok := s.sources[node]; ok {
		return m
	}
	return Membership{State: "excluded"}
}

func (s *MembershipSnapshot) Memberships(node string, queries []MembershipQuery) map[string]Membership {
	result := make(map[string]Membership, len(queries))
	for _, q := range queries {
		current := s.lookup(node, q)
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
