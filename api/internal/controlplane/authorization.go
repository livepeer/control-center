package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/livepeer/control-center/schema"
)

type apiProblem struct {
	status          int
	reason, message string
	fields          []schema.FieldError
}

func (e *apiProblem) Error() string { return e.reason }
func problem(status int, reason, message string) error {
	return &apiProblem{status: status, reason: reason, message: message}
}

func errorDetails(err error) *apiProblem {
	var p *apiProblem
	if errors.As(err, &p) {
		return p
	}
	return &apiProblem{status: 503, reason: "unavailable", message: "The service is temporarily unavailable."}
}

func (s *Server) respondError(w http.ResponseWriter, err error) {
	var expected *apiProblem
	if !errors.As(err, &expected) {
		s.logLimited("control plane operation failed", "request.failure", "", err)
	}
	p := errorDetails(err)
	respond(w, p.status, struct {
		Error  string              `json:"error"`
		Code   string              `json:"code"`
		Fields []schema.FieldError `json:"fields,omitempty"`
	}{p.message, p.reason, p.fields})
}

// Policy writers share this lock. READ COMMITTED and the separate lock/check
// statements ensure a queued mutation sees a revocation committed while waiting.
func (s *Server) policyTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout = '2s'`); err == nil {
		_, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1129073483, 2)`)
	}
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func hasAdmin(ctx context.Context, q rowQuerier, userID string) (bool, error) {
	var yes bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.administrator_grants WHERE bound_user_id=$1 AND revoked_at IS NULL)`, userID).Scan(&yes)
	return yes, err
}

// adminStatus also claims a matching pending bootstrap grant. The binding is
// committed independently, even if the caller's subsequent operation is invalid.
func (s *Server) adminStatus(ctx context.Context, user UserIdentity) (bool, error) {
	yes, err := hasAdmin(ctx, s.db, user.ID)
	if err != nil || yes || !user.EmailConfirmed || user.Email == "" {
		return yes, err
	}
	var pending bool
	err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.administrator_grants WHERE email=$1 AND bound_user_id IS NULL AND revoked_at IS NULL)`, user.Email).Scan(&pending)
	if err != nil {
		return false, err
	}
	if !pending {
		// Another request can bind between the initial membership check and this
		// pending-grant read. Observe that committed binding before denying access.
		return hasAdmin(ctx, s.db, user.ID)
	}
	if err := s.emailProvisioning(ctx); err != nil {
		return false, err
	}
	tx, err := s.policyTx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if yes, err = hasAdmin(ctx, tx, user.ID); err != nil || yes {
		return yes, err
	}
	var target AdminTarget
	target.Kind = "administrator_grant"
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT grant_id::text,revision FROM lpcc.administrator_grants WHERE email=$1 AND bound_user_id IS NULL AND revoked_at IS NULL`, user.Email).Scan(&target.ID, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	resolved, err := resolveAccount(ctx, tx, user.Email)
	if err != nil {
		return false, err
	}
	if resolved != user.ID {
		return false, problem(403, "email_identity_mismatch", "This account cannot claim the administrator grant.")
	}
	_, err = tx.ExecContext(ctx, `UPDATE lpcc.administrator_grants SET bound_user_id=$1,bound_at=now(),revision=revision+1 WHERE grant_id=$2`, user.ID, target.ID)
	if err != nil {
		return false, err
	}
	target.Revision = revisionString(revision + 1)
	if err := writeAudit(ctx, tx, "user", user.ID, "administrator.bind", target, "success", "changed"); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Server) administrator(r *http.Request) (UserIdentity, error) {
	user, err := s.user(r.Context(), bearer(r))
	if err != nil {
		return user, err
	}
	yes, err := s.adminStatus(r.Context(), user)
	if err != nil {
		return user, err
	}
	if !yes {
		return user, problem(403, "administrator_required", "Administrator access is required.")
	}
	return user, nil
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	user, err := s.user(r.Context(), bearer(r))
	if err != nil {
		s.respondError(w, err)
		return
	}
	yes, err := s.adminStatus(r.Context(), user)
	if err != nil {
		s.respondError(w, err)
		return
	}
	respond(w, 200, struct {
		UserIdentity
		IsAdmin bool `json:"is_admin"`
	}{user, yes})
}

func (s *Server) adminRead(next func(http.ResponseWriter, *http.Request, UserIdentity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := s.administrator(r)
		if err != nil {
			s.denied("admin.read", user.ID, err)
			s.respondError(w, err)
			return
		}
		next(w, r, user)
	}
}

// AdminAction names are server constants, never request values.
type AdminAction string

// AdminChange describes the persisted state and response. No-op operations return
// the existing revision with Changed=false, so they do not invent audit changes.
type AdminChange struct {
	Target  AdminTarget
	Changed bool
	Status  int
	Body    any
}

// AdminApply must use only tx for database writes. It must not commit/rollback,
// change isolation, perform network I/O or trigger reconciliation.
type AdminApply func(context.Context, *sql.Tx, UserIdentity) (AdminChange, error)

// Preparation runs after authentication/initial authorization, outside the lock;
// it must bound input, perform no writes and return the transactional operation.
func (s *Server) adminMutation(action AdminAction, prepare func(*http.Request, UserIdentity) (AdminApply, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := s.administrator(r)
		if err != nil {
			s.denied(action, user.ID, err)
			s.respondError(w, err)
			return
		}
		apply, err := prepare(r, user)
		if err != nil {
			s.failedAdmin(r.Context(), user, action, AdminTarget{}, err)
			s.respondError(w, err)
			return
		}
		tx, err := s.policyTx(r.Context())
		if err != nil {
			s.failedAdmin(r.Context(), user, action, AdminTarget{}, err)
			s.respondError(w, err)
			return
		}
		defer tx.Rollback()
		yes, err := hasAdmin(r.Context(), tx, user.ID)
		if err != nil {
			tx.Rollback()
			s.failedAdmin(r.Context(), user, action, AdminTarget{}, err)
			s.respondError(w, err)
			return
		}
		if !yes {
			tx.Rollback()
			err := problem(403, "administrator_required", "Administrator access is required.")
			s.denied(action, user.ID, err)
			s.respondError(w, err)
			return
		}
		change, err := apply(r.Context(), tx, user)
		if err == nil && (change.Status < 200 || change.Status > 299 || !validTarget(change.Target) || change.Target.Revision == "") {
			err = errors.New("invalid administrative result")
		}
		if err == nil && change.Changed {
			err = writeAudit(r.Context(), tx, "user", user.ID, action, change.Target, "success", "changed")
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			tx.Rollback()
			s.failedAdmin(r.Context(), user, action, change.Target, err)
			s.respondError(w, err)
			return
		}
		if change.Changed {
			s.requestReconcile()
		}
		if change.Status == http.StatusNoContent {
			w.WriteHeader(change.Status)
		} else {
			respond(w, change.Status, change.Body)
		}
	}
}
