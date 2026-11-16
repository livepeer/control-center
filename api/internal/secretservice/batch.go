package secretservice

import (
	"context"
	"database/sql"
	"encoding/json"
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
		Assignments []protocol.ResolveRequest `json:"assignments"`
	}
	if decode(r, &in) != nil || len(in.Assignments) > 100 {
		fail(w, 400, "invalid_assignments")
		return
	}

	var refs []secretReference
	for _, a := range in.Assignments {
		if eligibleAssignment(m, a) {
			for _, assigned := range m.Assignments {
				if assigned.RevisionID == a.RevisionID {
					for _, ref := range assigned.Revision.Definition.Container.Secrets {
						refs = append(refs, secretReference{ref.Secret, ref.Key})
					}
				}
			}
		}
	}
	for _, consumer := range m.Consumers {
		for _, ref := range consumer.References {
			refs = append(refs, secretReference{ref.Secret, ref.Key})
		}
	}
	metadata, e := batchSecretMetadata(r.Context(), s.DB, m.Owner, refs)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	sets := map[string]protocol.VersionSet{}
	faults := map[string]string{}
	for _, a := range in.Assignments {
		if !eligibleAssignment(m, a) {
			faults[a.RevisionID] = "assignment_changed"
			if assignmentDenied(m, a.RevisionID) {
				faults[a.RevisionID] = "secrets_denied"
			}
			continue
		}
		v := protocol.VersionSet{NodeID: m.NodeID, IdentityGeneration: g, PolicyGeneration: m.PolicyGeneration, Assignment: a, Values: []protocol.Resolved{}}
		for _, assigned := range m.Assignments {
			if assigned.RevisionID != a.RevisionID {
				continue
			}
			for _, ref := range assigned.Revision.Definition.Container.Secrets {
				refMetadata := metadata[secretReference{ref.Secret, ref.Key}]
				if refMetadata.reason != "" {
					faults[a.RevisionID] = refMetadata.reason
					break
				}
				item := refMetadata.value
				item.Owner = m.Owner
				v.Values = append(v.Values, item)
			}
		}
		if faults[a.RevisionID] == "" {
			v.Digest = protocol.VersionDigest(v.Values)
			if a.Expected != "" && a.Expected != v.Digest {
				faults[a.RevisionID] = "secret_changed"
			} else {
				sets[a.RevisionID] = v
			}
		}
	}
	for _, id := range m.DeniedRevisions {
		faults[id] = "secrets_denied"
	}
	// Removed assignments can retain serving Pods during replacement. Observe
	// their pinned declarations without granting any unwrap/start authority.
	for _, consumer := range m.Consumers {
		for _, ref := range consumer.References {
			reason := metadata[secretReference{ref.Secret, ref.Key}].reason
			if reason != "" {
				if faults[consumer.RevisionID] != "secrets_denied" {
					faults[consumer.RevisionID] = reason
				}
				break
			}
		}
	}
	response(w, 200, map[string]any{"sets": sets, "errors": faults})
}

type secretReference struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type secretMetadata struct {
	value  protocol.Resolved
	reason string
}

func batchSecretMetadata(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, owner string, refs []secretReference) (map[secretReference]secretMetadata, error) {
	out := map[secretReference]secretMetadata{}
	if len(refs) == 0 {
		return out, nil
	}
	raw, err := json.Marshal(refs)
	if err != nil {
		return nil, err
	}
	// Metadata and missing/deleted classifications share one statement snapshot.
	// Resolution still uses its own locking transaction and audit path.
	rows, err := q.QueryContext(ctx, `SELECT refs.name,refs.key,COALESCE(s.id::text,''),COALESCE(s.head::text,''),COALESCE(s.revision,0),
 CASE WHEN s.head IS NOT NULL THEN '' WHEN s.id IS NULL AND EXISTS(SELECT FROM lpsecrets.secrets d
 WHERE d.orchestrator_address=$1 AND d.name=refs.name AND d.key=refs.key AND d.deleted)
 THEN 'secret_missing' ELSE 'secret_unprovisioned' END
 FROM (SELECT DISTINCT name,key FROM jsonb_to_recordset($2::jsonb) AS x(name text,key text)) refs
 LEFT JOIN lpsecrets.secrets s ON s.orchestrator_address=$1 AND s.name=refs.name AND s.key=refs.key AND NOT s.deleted`, owner, string(raw))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ref secretReference
		var m secretMetadata
		if err = rows.Scan(&ref.Name, &ref.Key, &m.value.ID, &m.value.Version, &m.value.Revision, &m.reason); err != nil {
			return nil, err
		}
		m.value.Name, m.value.Key = ref.Name, ref.Key
		out[ref] = m
	}
	return out, rows.Err()
}
