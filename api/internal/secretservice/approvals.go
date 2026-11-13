package secretservice

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/livepeer/control-center/schema"
	protocol "github.com/livepeer/control-center/secrets"
)

type appApproval struct {
	schema.RevisionRef
	References []schema.SecretEnvironment `json:"references"`
	Generation int64                      `json:"generation"`
}
type appAccess struct {
	Name      string        `json:"name"`
	Denied    bool          `json:"denied"`
	Approvals []appApproval `json:"approvals"`
}
type ownerAccess struct {
	Generation int64       `json:"generation"`
	Apps       []appAccess `json:"apps"`
}

// The owner row fences delivery against concurrent approval or revocation.
// Assignment metadata can describe work, but cannot populate these grants.
func readAccess(ctx context.Context, tx *sql.Tx, owner string, lock bool) (ownerAccess, error) {
	out := ownerAccess{Apps: []appAccess{}}
	query := `SELECT generation FROM lpsecrets.app_policy_generation WHERE owner_id=$1`
	if lock {
		query += ` FOR SHARE`
	}
	e := tx.QueryRowContext(ctx, query, owner).Scan(&out.Generation)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return out, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT app_name,denied,approvals FROM lpsecrets.app_approvals WHERE owner_id=$1 ORDER BY app_name`, owner)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var a appAccess
		var raw []byte
		if e = rows.Scan(&a.Name, &a.Denied, &raw); e != nil {
			return out, e
		}
		if e = json.Unmarshal(raw, &a.Approvals); e != nil {
			return out, e
		}
		out.Apps = append(out.Apps, a)
	}
	return out, rows.Err()
}
func (p ownerAccess) grant(name string, ref schema.RevisionRef) *appApproval {
	for _, app := range p.Apps {
		if app.Name == name && !app.Denied {
			for _, grant := range app.Approvals {
				if grant.RevisionRef == ref && grant.Generation > 0 {
					return &grant
				}
			}
		}
	}
	return nil
}

// a has already passed the assignment and canonical revision checks.
func (p ownerAccess) approval(a *schema.AppAssignment, version int) int64 {
	if a == nil || version != 1 {
		return 0
	}
	grant := p.grant(a.Revision.Name, a.RevisionRef)
	if grant == nil || !slices.Equal(grant.References, a.Revision.Definition.Container.Secrets) {
		return 0
	}
	return grant.Generation
}
func (s *Service) appApprovals(w http.ResponseWriter, r *http.Request) {
	owner, e := s.owner(r)
	if e != nil {
		failAuthorization(w, e, 401, "authentication_required")
		return
	}
	tx, e := s.DB.BeginTx(r.Context(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer tx.Rollback()
	out, e := readAccess(r.Context(), tx, owner, false)
	if e != nil || tx.Commit() != nil {
		fail(w, 503, "unavailable")
		return
	}
	response(w, 200, out)
}
func (s *Service) setAppApproval(w http.ResponseWriter, r *http.Request) {
	owner, e := s.owner(r)
	if e != nil {
		failAuthorization(w, e, 401, "authentication_required")
		return
	}
	var in struct {
		Expected int64                    `json:"expected_generation"`
		Denied   bool                     `json:"denied"`
		Revision *schema.ResolvedRevision `json:"revision"`
	}
	name := r.PathValue("name")
	if decode(r, &in) != nil || !schema.ValidName(name) || in.Expected < 0 || (in.Revision != nil && (in.Denied || in.Revision.Name != name || in.Revision.Verify() != nil)) {
		fail(w, 400, "invalid_approval")
		return
	}
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(r.Context(), `INSERT INTO lpsecrets.app_policy_generation(owner_id) VALUES($1) ON CONFLICT DO NOTHING`, owner); e != nil {
		fail(w, 503, "unavailable")
		return
	}
	var gen int64
	if e = tx.QueryRowContext(r.Context(), `SELECT generation FROM lpsecrets.app_policy_generation WHERE owner_id=$1 FOR UPDATE`, owner).Scan(&gen); e != nil {
		fail(w, 503, "unavailable")
		return
	}
	if gen != in.Expected {
		fail(w, 409, "approval_conflict")
		return
	}
	grants := []appApproval{}
	if !in.Denied {
		var raw []byte
		e = tx.QueryRowContext(r.Context(), `SELECT approvals FROM lpsecrets.app_approvals WHERE owner_id=$1 AND app_name=$2`, owner, name).Scan(&raw)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			fail(w, 503, "unavailable")
			return
		}
		if e == nil && json.Unmarshal(raw, &grants) != nil {
			fail(w, 503, "unavailable")
			return
		}
		if in.Revision != nil {
			grant := appApproval{RevisionRef: in.Revision.RevisionRef, References: in.Revision.Definition.Container.Secrets}
			for _, old := range grants {
				if old.RevisionRef == grant.RevisionRef && slices.Equal(old.References, grant.References) {
					grant.Generation = old.Generation
				}
			}
			if grant.Generation == 0 {
				grant.Generation = gen + 1
			}
			grants = slices.DeleteFunc(grants, func(a appApproval) bool { return a.RevisionID == grant.RevisionID })
			grants = append(grants, grant)
		}
	}
	raw, _ := json.Marshal(grants)
	_, e = tx.ExecContext(r.Context(), `INSERT INTO lpsecrets.app_approvals(owner_id,app_name,denied,approvals) VALUES($1,$2,$3,$4) ON CONFLICT(owner_id,app_name) DO UPDATE SET denied=EXCLUDED.denied,approvals=EXCLUDED.approvals`, owner, name, in.Denied, string(raw))
	if e == nil {
		_, e = tx.ExecContext(r.Context(), `UPDATE lpsecrets.app_policy_generation SET generation=generation+1 WHERE owner_id=$1`, owner)
	}
	if e == nil {
		e = audit(r.Context(), tx, owner, "app.approval", name)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 503, "unavailable")
		return
	}
	response(w, 200, map[string]any{"generation": gen + 1})
}

func approvedRequest(p ownerAccess, m protocol.Machine, in protocol.ResolveRequest) int64 {
	return p.approval(eligibleAssignment(m, in), in.ApprovalProtocol)
}
