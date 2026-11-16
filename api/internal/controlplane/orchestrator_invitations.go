package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	protocol "github.com/livepeer/control-center/secrets"
)

const invitationAudience = "livepeer-orchestrator-invitation"

type invitationClaims struct {
	jwt.RegisteredClaims
	Scope               string `json:"scope"`
	ControlCenter       string `json:"control_center"`
	OrchestratorAddress string `json:"orchestrator_address"`
}

func (s *Server) signInvitation(user, address string) (string, time.Time, error) {
	now := s.currentTime().Truncate(time.Second)
	expires := now.Add(24 * time.Hour)
	c := invitationClaims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: enrollmentIssuer, Subject: user, Audience: jwt.ClaimStrings{invitationAudience}, ID: uuid.New().String(), IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(expires)},
		Scope:            "orchestrators:join", ControlCenter: strings.TrimRight(s.params.PublicAPIURL, "/"), OrchestratorAddress: address,
	}
	raw, err := s.params.signJWT(c)
	return raw, expires, err
}

func (s *Server) verifyInvitation(raw string) (*invitationClaims, error) {
	keys, err := s.params.enrollmentKeys()
	if err != nil {
		return nil, err
	}
	c := new(invitationClaims)
	_, err = jwt.ParseWithClaims(raw, c, keys.Key, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(enrollmentIssuer), jwt.WithAudience(invitationAudience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(s.currentTime))
	if err != nil || c.Scope != "orchestrators:join" || c.ControlCenter != strings.TrimRight(s.params.PublicAPIURL, "/") || len(c.Audience) != 1 || c.Audience[0] != invitationAudience || c.IssuedAt == nil || c.ExpiresAt == nil || !c.ExpiresAt.After(c.IssuedAt.Time) || c.ExpiresAt.Sub(c.IssuedAt.Time) > 24*time.Hour {
		return nil, problem(400, "invalid_invitation", "This invitation is invalid or has expired.")
	}
	id, idErr := uuid.Parse(c.ID)
	user, userErr := uuid.Parse(c.Subject)
	address, addressErr := protocol.OrchestratorAddress(c.OrchestratorAddress)
	if idErr != nil || id == uuid.Nil() || userErr != nil || user == uuid.Nil() || addressErr != nil || c.OrchestratorAddress != address {
		return nil, problem(400, "invalid_invitation", "This invitation is invalid or has expired.")
	}
	c.ID, c.Subject = id.String(), user.String()
	return c, nil
}

func (s *Server) pathMember(r *http.Request) (UserIdentity, string, error) {
	u, err := s.user(r.Context(), bearer(r))
	if err != nil {
		return u, "", err
	}
	address, err := protocol.OrchestratorAddress(r.PathValue("address"))
	if err != nil {
		return u, "", problem(400, "invalid_orchestrator", "Choose an orchestrator.")
	}
	yes, err := member(r.Context(), s.db, u.ID, address)
	if err == nil && !yes {
		err = problem(403, "orchestrator_access_required", "Orchestrator access is required.")
	}
	return u, address, err
}

// Lock accounts in a stable order before serializing membership writers. Readers
// retain the existing account -> membership -> machine order, without this lock.
func (s *Server) membershipTx(ctx context.Context, address string, users ...string) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	slices.Sort(users)
	for _, user := range slices.Compact(users) {
		var id string
		err = tx.QueryRowContext(ctx, `SELECT id::text FROM auth.users WHERE id=$1 FOR SHARE`, user).Scan(&id)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			tx.Rollback()
			return nil, err
		}
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,17241))`, address); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	_, address, err := s.pathMember(r)
	if err != nil {
		s.respondError(w, err)
		return
	}
	rows, err := s.db.QueryContext(r.Context(), `SELECT u.id::text,COALESCE(u.email,'') FROM lpcc.orchestrator_memberships m JOIN auth.users u ON u.id=m.user_id WHERE m.orchestrator_address=$1 AND u.deleted_at IS NULL ORDER BY u.id`, address)
	if err != nil {
		s.respondError(w, err)
		return
	}
	defer rows.Close()
	type membership struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
	}
	result := []membership{}
	for rows.Next() {
		var m membership
		if err = rows.Scan(&m.UserID, &m.Email); err != nil {
			s.respondError(w, err)
			return
		}
		result = append(result, m)
	}
	if err = rows.Err(); err != nil {
		s.respondError(w, err)
		return
	}
	respond(w, 200, map[string]any{"members": result})
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	u, address, err := s.pathMember(r)
	if err != nil {
		s.respondError(w, err)
		return
	}
	target, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil || target == uuid.Nil() {
		s.respondError(w, problem(404, "member_not_found", "Member not found."))
		return
	}
	tx, err := s.membershipTx(r.Context(), address, u.ID, target.String())
	if err != nil {
		s.respondError(w, err)
		return
	}
	defer tx.Rollback()
	if err = lockMembership(r.Context(), tx, u.ID, address); err != nil {
		s.respondError(w, err)
		return
	}
	var exists bool
	err = tx.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT FROM lpcc.orchestrator_memberships WHERE orchestrator_address=$1 AND user_id=$2)`, address, target.String()).Scan(&exists)
	if err != nil {
		s.respondError(w, err)
		return
	}
	if !exists {
		s.respondError(w, problem(404, "member_not_found", "Member not found."))
		return
	}
	var remaining int
	err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM lpcc.orchestrator_memberships m JOIN auth.users u ON u.id=m.user_id WHERE m.orchestrator_address=$1 AND m.user_id<>$2 AND u.deleted_at IS NULL`, address, target.String()).Scan(&remaining)
	if err != nil {
		s.respondError(w, err)
		return
	}
	if remaining == 0 {
		s.respondError(w, problem(409, "last_member", "The last member cannot leave. Invite someone and wait for them to join first."))
		return
	}
	_, err = tx.ExecContext(r.Context(), `DELETE FROM lpcc.orchestrator_memberships WHERE orchestrator_address=$1 AND user_id=$2`, address, target.String())
	action := AdminAction("orchestrator.member.remove")
	if target.String() == u.ID {
		action = "orchestrator.member.leave"
	}
	if err == nil {
		err = writeAudit(r.Context(), tx, "user", u.ID, action, AdminTarget{Kind: "orchestrator_member", ID: address + "/" + target.String()}, "success", "changed")
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.respondError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) issueInvitation(w http.ResponseWriter, r *http.Request) {
	u, address, err := s.pathMember(r)
	if err != nil {
		s.respondError(w, err)
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.respondError(w, err)
		return
	}
	defer tx.Rollback()
	if err = lockMembership(r.Context(), tx, u.ID, address); err != nil {
		s.respondError(w, err)
		return
	}
	token, expires, err := s.signInvitation(u.ID, address)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.respondError(w, err)
		return
	}
	respond(w, 200, map[string]any{"token": token, "expires_at": expires})
}

func (s *Server) invitationInput(r *http.Request) (UserIdentity, *invitationClaims, error) {
	u, err := s.user(r.Context(), bearer(r))
	if err != nil {
		return u, nil, err
	}
	var in struct {
		Token string `json:"token"`
	}
	if boundedInput(r, &in, 16384) != nil {
		return u, nil, problem(400, "invalid_invitation", "Provide an invitation link.")
	}
	c, err := s.verifyInvitation(in.Token)
	return u, c, err
}

func unusedInvitation(ctx context.Context, q rowQuerier, id string) error {
	var used bool
	if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.orchestrator_invitation_acceptances WHERE invitation_id=$1)`, id).Scan(&used); err != nil {
		return err
	}
	if used {
		return problem(409, "invitation_used", "This invitation has already been accepted.")
	}
	return nil
}

func (s *Server) previewInvitation(w http.ResponseWriter, r *http.Request) {
	_, c, err := s.invitationInput(r)
	if err != nil {
		s.respondError(w, err)
		return
	}
	if err = unusedInvitation(r.Context(), s.db, c.ID); err != nil {
		s.respondError(w, err)
		return
	}
	yes, err := member(r.Context(), s.db, c.Subject, c.OrchestratorAddress)
	if err != nil {
		s.respondError(w, err)
		return
	}
	if !yes {
		s.respondError(w, problem(403, "invitation_unavailable", "The inviter no longer has access to this orchestrator."))
		return
	}
	var name string
	if err = s.db.QueryRowContext(r.Context(), `SELECT COALESCE(display_name,'') FROM lpcc.orchestrators WHERE address=$1`, c.OrchestratorAddress).Scan(&name); err != nil {
		s.respondError(w, err)
		return
	}
	respond(w, 200, map[string]any{"address": c.OrchestratorAddress, "display_name": name, "expires_at": c.ExpiresAt.Time})
}

func (s *Server) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	u, c, err := s.invitationInput(r)
	if err != nil {
		s.respondError(w, err)
		return
	}
	tx, err := s.membershipTx(r.Context(), c.OrchestratorAddress, u.ID, c.Subject)
	if err != nil {
		s.respondError(w, err)
		return
	}
	defer tx.Rollback()
	if err = unusedInvitation(r.Context(), tx, c.ID); err != nil {
		s.respondError(w, err)
		return
	}
	if err = lockMembership(r.Context(), tx, c.Subject, c.OrchestratorAddress); err != nil {
		s.respondError(w, err)
		return
	}
	var live bool
	err = tx.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT FROM auth.users WHERE id=$1 AND deleted_at IS NULL)`, u.ID).Scan(&live)
	if err != nil {
		s.respondError(w, err)
		return
	}
	if !live {
		s.respondError(w, problem(403, "invitation_unavailable", "This account cannot accept the invitation."))
		return
	}
	if !s.currentTime().Before(c.ExpiresAt.Time) {
		s.respondError(w, problem(400, "invalid_invitation", "This invitation has expired."))
		return
	}
	res, err := tx.ExecContext(r.Context(), `INSERT INTO lpcc.orchestrator_invitation_acceptances(invitation_id,orchestrator_address,inviter_user_id,accepted_by_user_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, c.ID, c.OrchestratorAddress, c.Subject, u.ID)
	if err != nil {
		s.respondError(w, err)
		return
	}
	n, err := res.RowsAffected()
	if err != nil {
		s.respondError(w, err)
		return
	}
	if n == 0 {
		s.respondError(w, problem(409, "invitation_used", "This invitation has already been accepted."))
		return
	}
	_, err = tx.ExecContext(r.Context(), `INSERT INTO lpcc.orchestrator_memberships(user_id,orchestrator_address) VALUES($1,$2) ON CONFLICT DO NOTHING`, u.ID, c.OrchestratorAddress)
	if err == nil {
		err = writeAudit(r.Context(), tx, "user", u.ID, "orchestrator.invitation.accept", AdminTarget{Kind: "orchestrator_invitation", ID: c.ID}, "success", "changed")
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.respondError(w, err)
		return
	}
	respond(w, 200, map[string]string{"address": c.OrchestratorAddress})
}
