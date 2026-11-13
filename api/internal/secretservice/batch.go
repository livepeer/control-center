package secretservice

import (
	"database/sql"
	"errors"
	protocol "github.com/livepeer/control-center/secrets"
	"net/http"
)

func (s *Service) batchVersions(w http.ResponseWriter, r *http.Request) {
	m, g, e := s.machine(r)
	if e != nil {
		failAuthorization(w, e, 403, "identity_refused")
		return
	}
	if !m.Managed {
		fail(w, 503, "activation_pending")
		return
	}
	var in struct {
		Assignments      []protocol.ResolveRequest  `json:"assignments"`
		ApprovalProtocol int                        `json:"approval_protocol"`
		Consumers        []protocol.RuntimeConsumer `json:"consumers"`
	}
	if decode(r, &in) != nil || len(in.Assignments) > 100 || len(in.Consumers) > 1000 {
		fail(w, 400, "invalid_assignments")
		return
	}

	tx, e := s.DB.BeginTx(r.Context(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer tx.Rollback()
	access, e := readAccess(r.Context(), tx, m.Owner, true)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	sets := map[string]protocol.VersionSet{}
	appNames := map[string]string{}
	faults := map[string]string{}
	for _, a := range in.Assignments {
		assigned := eligibleAssignment(m, a)
		if assigned == nil {
			faults[a.RevisionID] = "assignment_changed"
			if assignmentDenied(m, a.RevisionID) {
				faults[a.RevisionID] = "secrets_denied"
			}
			continue
		}
		approval := access.approval(assigned, a.ApprovalProtocol)
		if approval == 0 {
			faults[a.RevisionID] = "secrets_denied"
			continue
		}
		v := protocol.VersionSet{NodeID: m.NodeID, IdentityGeneration: g, PolicyGeneration: m.PolicyGeneration, Assignment: a, ApprovalGeneration: approval, Values: []protocol.Resolved{}}
		for _, ref := range assigned.Revision.Definition.Container.Secrets {
			item := protocol.Resolved{Ciphertext: protocol.Ciphertext{Binding: protocol.Binding{Owner: m.Owner, Name: ref.Secret, Key: ref.Key}}}
			e = tx.QueryRowContext(r.Context(), `SELECT id::text,head::text,revision FROM lpsecrets.secrets WHERE owner_id=$1 AND name=$2 AND key=$3 AND NOT deleted AND head IS NOT NULL`, m.Owner, ref.Secret, ref.Key).Scan(&item.ID, &item.Version, &item.Revision)
			if errors.Is(e, sql.ErrNoRows) {
				reason, err := missingSecret(r.Context(), tx, m.Owner, ref.Secret, ref.Key)
				if err != nil {
					fail(w, 503, "unavailable")
					return
				}
				faults[a.RevisionID] = reason
				break
			}
			if e != nil {
				fail(w, 503, "unavailable")
				return
			}
			v.Values = append(v.Values, item)
		}
		if faults[a.RevisionID] == "" {
			v.Digest = protocol.VersionDigest(v.Values)
			if a.Expected != "" && a.Expected != v.Digest {
				faults[a.RevisionID] = "secret_changed"
			} else {
				sets[a.RevisionID] = v
				appNames[a.RevisionID] = assigned.Revision.Name
			}
		}
	}
	blockedApps := map[string]bool{}
	for _, consumer := range in.Consumers {
		grant := access.grant(consumer.Name)
		if in.ApprovalProtocol != 1 || grant == nil || grant.Generation != consumer.ApprovalGeneration {
			faults[consumer.RevisionID] = "secrets_denied"
			delete(sets, consumer.RevisionID)
			blockedApps[consumer.Name] = true
		}
	}
	for id := range sets {
		if blockedApps[appNames[id]] {
			faults[id] = "secrets_denied"
			delete(sets, id)
		}
	}
	for _, id := range m.DeniedRevisions {
		faults[id] = "secrets_denied"
	}
	// Removed assignments can retain serving Pods during replacement. Observe
	// their pinned declarations without granting any unwrap/start authority.
	for _, consumer := range m.Consumers {
		grant := access.grant(consumer.AppName)
		if in.ApprovalProtocol != 1 || grant == nil || !grant.covers(consumer.References) {
			faults[consumer.RevisionID] = "secrets_denied"
			continue
		}
		for _, ref := range consumer.References {
			var present bool
			if e = tx.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT FROM lpsecrets.secrets WHERE owner_id=$1 AND name=$2 AND key=$3 AND NOT deleted AND head IS NOT NULL)`, m.Owner, ref.Secret, ref.Key).Scan(&present); e != nil {
				fail(w, 503, "unavailable")
				return
			}
			if !present {
				reason, err := missingSecret(r.Context(), tx, m.Owner, ref.Secret, ref.Key)
				if err != nil {
					fail(w, 503, "unavailable")
					return
				}
				if faults[consumer.RevisionID] != "secrets_denied" {
					faults[consumer.RevisionID] = reason
				}
				break
			}
		}
	}
	again, ng, e := s.machine(r)
	if e != nil || ng != g || !again.Managed || again.PolicyGeneration != m.PolicyGeneration {
		fail(w, 409, "authorization_changed")
		return
	}
	for _, a := range in.Assignments {
		if set, ok := sets[a.RevisionID]; ok && approvedRequest(access, again, a) != set.ApprovalGeneration {
			fail(w, 409, "authorization_changed")
			return
		}
	}
	if tx.Commit() != nil {
		fail(w, 503, "unavailable")
		return
	}
	response(w, 200, map[string]any{"sets": sets, "errors": faults})
}
