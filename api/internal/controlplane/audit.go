package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strconv"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5/pgconn"
)

type AdminTarget struct{ Kind, ID, Revision string }

var actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,63}$`)
var reasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var sqlStatePattern = regexp.MustCompile(`^[0-9A-Z]{5}$`)

func revisionString(n int64) string { return strconv.FormatInt(n, 10) }
func safeField(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func validTarget(t AdminTarget) bool {
	return actionPattern.MatchString(t.Kind) && t.ID != "" && safeField(t.ID, 254) && safeField(t.Revision, 128)
}

func writeAudit(ctx context.Context, tx *sql.Tx, actorKind, actorID string, action AdminAction, target AdminTarget, outcome, reason string) error {
	if !validTarget(target) || !actionPattern.MatchString(string(action)) || !reasonPattern.MatchString(reason) {
		return errors.New("invalid audit fields")
	}
	var revision any
	if target.Revision != "" {
		revision = target.Revision
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO lpcc.admin_audit_events(actor_kind,actor_id,action,target_kind,target_id,revision,outcome,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, actorKind, actorID, string(action), target.Kind, target.ID, revision, outcome, reason)
	return err
}

// Non-admin traffic never creates durable rows. Buckets are keyed only by
// server-defined actions, not attacker-controlled identities or request paths.
type denialWindow struct {
	start      time.Time
	suppressed uint64
}

func (s *Server) denied(action AdminAction, actor string, err error) {
	s.logLimited("administrator request denied", action, actor, err)
}

// Diagnostics contain fixed classifications, never arbitrary error text or PG
// message/detail fields, which may include callback inputs or credentials.
func diagnosticReason(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && sqlStatePattern.MatchString(pg.Code) {
		return "postgres_" + pg.Code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	if errors.Is(err, context.Canceled) {
		return "request_canceled"
	}
	return errorDetails(err).reason
}

func (s *Server) logLimited(message string, action AdminAction, actor string, err error) {
	s.denialMu.Lock()
	defer s.denialMu.Unlock()
	if s.denials == nil {
		s.denials = make(map[AdminAction]denialWindow)
	}
	window := s.denials[action]
	if time.Since(window.start) < time.Minute {
		window.suppressed++
		s.denials[action] = window
		return
	}
	s.logger.Warn(message, "action", action, "actor_id", actor, "reason", diagnosticReason(err), "suppressed", window.suppressed)
	s.denials[action] = denialWindow{start: time.Now()}
}

// Only callers that passed administrator authorization reach this path. A fresh,
// short context permits a best-effort failure record after request cancellation.
func (s *Server) failedAdmin(ctx context.Context, user UserIdentity, action AdminAction, target AdminTarget, cause error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	if !validTarget(target) {
		target = AdminTarget{Kind: "request", ID: "unresolved"}
	}
	reason := errorDetails(cause).reason
	if !reasonPattern.MatchString(reason) {
		reason = "unavailable"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err == nil {
		defer tx.Rollback()
		err = writeAudit(ctx, tx, "user", user.ID, action, target, "failure", reason)
		if err == nil {
			err = tx.Commit()
		}
	}
	if err != nil {
		s.logLimited("administrator failure audit unavailable", "audit.failure", user.ID, err)
	}
}
