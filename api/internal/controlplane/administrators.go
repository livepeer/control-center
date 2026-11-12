package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"
	"uuid"
)

// BootstrapAdmin seeds permission, not an Auth account. A pending or orphaned
// grant intentionally blocks reseeding until an explicit, audited revocation.
func (s *Server) BootstrapAdmin(ctx context.Context) error {
	if s.params.DefaultAdminEmail == "" {
		var exists bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.administrator_grants WHERE revoked_at IS NULL)`).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			s.logger.Info("administrator provisioning is not configured")
		}
		return nil
	}
	email, err := normalizeEmail(s.params.DefaultAdminEmail)
	if err != nil {
		return err
	}
	tx, err := s.policyTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.administrator_grants WHERE revoked_at IS NULL)`).Scan(&exists); err != nil {
		return err
	}
	if exists {
		var mismatch bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.administrator_grants WHERE revoked_at IS NULL AND bound_user_id IS NULL AND email<>$1)`, email).Scan(&mismatch); err != nil {
			return err
		}
		if mismatch {
			s.logger.Warn("configured administrator email differs from an existing pending grant; audited recovery is required to replace it")
		}
		return nil
	}
	id := uuid.New().String()
	if _, err := tx.ExecContext(ctx, `INSERT INTO lpcc.administrator_grants(grant_id,email) VALUES($1,$2)`, id, email); err != nil {
		return err
	}
	if err := writeAudit(ctx, tx, "system", "configured-bootstrap", "administrator.bootstrap", AdminTarget{"administrator_grant", id, "1"}, "success", "changed"); err != nil {
		return err
	}
	return tx.Commit()
}

// Auth writers do not take our advisory lock. FOR SHARE retains the chosen
// account's eligibility through insertion/binding. Never resolve editable data.
func resolveAccount(ctx context.Context, tx *sql.Tx, email string) (string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id::text FROM auth.users WHERE lower(email)=$1 AND email_confirmed_at IS NOT NULL AND deleted_at IS NULL AND NOT is_anonymous ORDER BY id LIMIT 2 FOR SHARE`, email)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return "", err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", problem(404, "account_not_found", "No eligible confirmed account has that email address.")
	}
	if len(ids) != 1 {
		return "", problem(409, "ambiguous_email", "More than one eligible account has that email address.")
	}
	return ids[0], nil
}

type AdministratorGrant struct {
	GrantID      string     `json:"grant_id"`
	Email        string     `json:"email"`
	UserID       *string    `json:"user_id"`
	Revision     int64      `json:"revision"`
	CreatedAt    time.Time  `json:"created_at"`
	BoundAt      *time.Time `json:"bound_at"`
	CurrentEmail *string    `json:"current_email"`
	State        string     `json:"state"`
}

const grantColumns = `grant_id::text,email,bound_user_id::text,revision,created_at,bound_at`

type scanner interface{ Scan(...any) error }

func scanGrant(row scanner) (AdministratorGrant, error) {
	var g AdministratorGrant
	err := row.Scan(&g.GrantID, &g.Email, &g.UserID, &g.Revision, &g.CreatedAt, &g.BoundAt)
	g.State = "bound"
	if g.UserID == nil {
		g.State = "pending"
	}
	return g, err
}

func (s *Server) listAdministrators(w http.ResponseWriter, r *http.Request, _ UserIdentity) {
	rows, err := s.db.QueryContext(r.Context(), `SELECT g.grant_id::text,g.email,g.bound_user_id::text,g.revision,g.created_at,g.bound_at,u.email,(u.id IS NULL OR u.deleted_at IS NOT NULL) FROM lpcc.administrator_grants g LEFT JOIN auth.users u ON u.id=g.bound_user_id WHERE g.revoked_at IS NULL ORDER BY g.created_at,g.grant_id`)
	if err != nil {
		s.respondError(w, err)
		return
	}
	defer rows.Close()
	grants := []AdministratorGrant{}
	for rows.Next() {
		var g AdministratorGrant
		var missing bool
		if err := rows.Scan(&g.GrantID, &g.Email, &g.UserID, &g.Revision, &g.CreatedAt, &g.BoundAt, &g.CurrentEmail, &missing); err != nil {
			s.respondError(w, err)
			return
		}
		g.State = "bound"
		if g.UserID == nil {
			g.State = "pending"
		} else if missing {
			g.State = "account_missing"
			g.CurrentEmail = nil
		}
		grants = append(grants, g)
	}
	if err := rows.Err(); err != nil {
		s.respondError(w, err)
		return
	}
	respond(w, 200, map[string]any{"administrators": grants})
}

func (s *Server) prepareGrant(r *http.Request, _ UserIdentity) (AdminApply, error) {
	var input struct {
		Email string `json:"email"`
	}
	if boundedInput(r, &input, 4096) != nil {
		return nil, problem(400, "invalid_email", "Provide one email address.")
	}
	email, err := normalizeEmail(input.Email)
	if err != nil {
		return nil, problem(400, "invalid_email", "Provide one email address.")
	}
	if err := s.emailProvisioning(r.Context()); err != nil {
		return nil, err
	}
	return func(ctx context.Context, tx *sql.Tx, _ UserIdentity) (AdminChange, error) {
		id, err := resolveAccount(ctx, tx, email)
		if err != nil {
			return AdminChange{}, err
		}
		g, err := scanGrant(tx.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM lpcc.administrator_grants WHERE bound_user_id=$1 AND revoked_at IS NULL`, id))
		if err == nil {
			return AdminChange{AdminTarget{"administrator_grant", g.GrantID, revisionString(g.Revision)}, false, 200, g}, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return AdminChange{}, err
		}
		g, err = scanGrant(tx.QueryRowContext(ctx, `INSERT INTO lpcc.administrator_grants(grant_id,email,bound_user_id,bound_at) VALUES($1,$2,$3,now()) RETURNING `+grantColumns, uuid.New().String(), email, id))
		if err != nil {
			return AdminChange{}, err
		}
		return AdminChange{AdminTarget{"administrator_grant", g.GrantID, revisionString(g.Revision)}, true, 201, g}, nil
	}, nil
}

func (s *Server) prepareRevoke(r *http.Request, _ UserIdentity) (AdminApply, error) {
	id, err := uuid.Parse(r.PathValue("grant_id"))
	if err != nil {
		return nil, problem(404, "grant_not_found", "Administrator grant not found.")
	}
	return func(ctx context.Context, tx *sql.Tx, user UserIdentity) (AdminChange, error) {
		g, err := scanGrant(tx.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM lpcc.administrator_grants WHERE grant_id=$1 AND revoked_at IS NULL`, id.String()))
		change := AdminChange{Target: AdminTarget{Kind: "administrator_grant", ID: id.String()}}
		if errors.Is(err, sql.ErrNoRows) {
			return change, problem(404, "grant_not_found", "Administrator grant not found.")
		}
		if err != nil {
			return change, err
		}
		change.Target.Revision = revisionString(g.Revision)
		if g.UserID != nil && *g.UserID == user.ID {
			return change, problem(409, "self_revocation", "Another administrator must revoke your access.")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE lpcc.administrator_grants SET revoked_at=now(),revision=revision+1 WHERE grant_id=$1`, id.String()); err != nil {
			return change, err
		}
		change.Target.Revision = revisionString(g.Revision + 1)
		change.Changed, change.Status = true, 204
		return change, nil
	}, nil
}

func (s *Server) fleetMachines(w http.ResponseWriter, r *http.Request, _ UserIdentity) {
	machines, err := s.observedMachineList(r.Context(), "", true)
	if err != nil {
		s.respondError(w, err)
		return
	}
	respond(w, 200, map[string]any{"machines": machines})
}
