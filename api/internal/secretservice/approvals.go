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
	Scope      string                     `json:"scope"`
	Secrets    []protocol.SecretReference `json:"secrets"`
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
		a.Approvals = slices.DeleteFunc(a.Approvals, func(grant appApproval) bool { return grant.Scope != appSecretScope })
		out.Apps = append(out.Apps, a)
	}
	return out, rows.Err()
}

const appSecretScope = "app-secrets"

var errApprovalConflict = errors.New("approval_conflict")

func (p ownerAccess) grant(name string) *appApproval {
	for _, app := range p.Apps {
		if app.Name == name && !app.Denied {
			for _, grant := range app.Approvals {
				if grant.Scope == appSecretScope && grant.Generation > 0 && len(grant.Secrets) > 0 {
					return &grant
				}
			}
		}
	}
	return nil
}
func (g appApproval) covers(refs []schema.SecretEnvironment) bool {
	for _, ref := range refs {
		if !slices.Contains(g.Secrets, protocol.SecretReference{Secret: ref.Secret, Key: ref.Key}) {
			return false
		}
	}
	return true
}

// a has already passed the assignment and canonical revision checks.
func (p ownerAccess) approval(a *schema.AppAssignment, version int) int64 {
	if a == nil || version != 1 {
		return 0
	}
	grant := p.grant(a.Revision.Name)
	if grant == nil || !grant.covers(a.Revision.Definition.Container.Secrets) {
		return 0
	}
	return grant.Generation
}

// Every policy writer takes this lock before locking secret values.
func lockAccess(ctx context.Context, tx *sql.Tx, owner string, expected int64) (int64, error) {
	if _, e := tx.ExecContext(ctx, `INSERT INTO lpsecrets.app_policy_generation(owner_id) VALUES($1) ON CONFLICT DO NOTHING`, owner); e != nil {
		return 0, e
	}
	var gen int64
	if e := tx.QueryRowContext(ctx, `SELECT generation FROM lpsecrets.app_policy_generation WHERE owner_id=$1 FOR UPDATE`, owner).Scan(&gen); e != nil {
		return 0, e
	}
	if gen != expected {
		return 0, errApprovalConflict
	}
	return gen, nil
}

// One epoch covers the app's binding set until revocation. Extending the set
// or rotating a value must not restart already authorized instances.
func writeAppApproval(ctx context.Context, tx *sql.Tx, owner, name string, gen int64, denied bool, refs []protocol.SecretReference) error {
	grants := []appApproval{}
	if !denied {
		current := appAccess{Name: name}
		var raw []byte
		e := tx.QueryRowContext(ctx, `SELECT denied,approvals FROM lpsecrets.app_approvals WHERE owner_id=$1 AND app_name=$2`, owner, name).Scan(&current.Denied, &raw)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if e == nil {
			if e = json.Unmarshal(raw, &current.Approvals); e != nil {
				return e
			}
		}
		grant := (ownerAccess{Apps: []appAccess{current}}).grant(name)
		if grant == nil && len(refs) > 0 {
			grant = &appApproval{Scope: appSecretScope, Generation: gen + 1, Secrets: []protocol.SecretReference{}}
		}
		if grant != nil {
			for _, ref := range refs {
				if !slices.Contains(grant.Secrets, ref) {
					grant.Secrets = append(grant.Secrets, ref)
				}
			}
			grants = append(grants, *grant)
		}
	}
	raw, _ := json.Marshal(grants)
	_, e := tx.ExecContext(ctx, `INSERT INTO lpsecrets.app_approvals(owner_id,app_name,denied,approvals) VALUES($1,$2,$3,$4) ON CONFLICT(owner_id,app_name) DO UPDATE SET denied=EXCLUDED.denied,approvals=EXCLUDED.approvals`, owner, name, denied, string(raw))
	if e == nil {
		_, e = tx.ExecContext(ctx, `UPDATE lpsecrets.app_policy_generation SET generation=generation+1 WHERE owner_id=$1`, owner)
	}
	if e == nil {
		e = audit(ctx, tx, owner, "app.approval", name)
	}
	return e
}
func failApproval(w http.ResponseWriter, e error) {
	if errors.Is(e, errApprovalConflict) {
		fail(w, 409, "approval_conflict")
	} else {
		fail(w, 503, "unavailable")
	}
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
		Expected *int64                     `json:"expected_generation"`
		Denied   bool                       `json:"denied"`
		Secrets  []protocol.SecretReference `json:"secrets"`
	}
	name := r.PathValue("name")
	if decode(r, &in) != nil || !schema.ValidName(name) || in.Expected == nil || *in.Expected < 0 || len(in.Secrets) > 16 || (in.Denied && len(in.Secrets) > 0) {
		fail(w, 400, "invalid_approval")
		return
	}
	for _, ref := range in.Secrets {
		if !protocol.ValidReference(ref.Secret, ref.Key) {
			fail(w, 400, "invalid_approval")
			return
		}
	}
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer tx.Rollback()
	gen, e := lockAccess(r.Context(), tx, owner, *in.Expected)
	if e == nil {
		e = writeAppApproval(r.Context(), tx, owner, name, gen, in.Denied, in.Secrets)
	}
	if e != nil {
		failApproval(w, e)
		return
	}
	if tx.Commit() != nil {
		fail(w, 503, "unavailable")
		return
	}
	response(w, 200, map[string]any{"generation": gen + 1})
}

func approvedRequest(p ownerAccess, m protocol.Machine, in protocol.ResolveRequest) int64 {
	return p.approval(eligibleAssignment(m, in), in.ApprovalProtocol)
}
