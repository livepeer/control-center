package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	protocol "github.com/livepeer/control-center/secrets"
)

// lockMembership serializes authorization with account deletion and externally
// provisioned membership changes. Always lock account, membership, then machine.
func lockMembership(ctx context.Context, tx *sql.Tx, user, address string) error {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id::text FROM auth.users WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, user).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return problem(403, "orchestrator_access_required", "Orchestrator access is required.")
	}
	if err != nil {
		return err
	}
	err = tx.QueryRowContext(ctx, `SELECT orchestrator_address FROM lpcc.orchestrator_memberships WHERE user_id=$1 AND orchestrator_address=$2 FOR SHARE`, user, address).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return problem(403, "orchestrator_access_required", "Orchestrator access is required.")
	}
	return err
}

func member(ctx context.Context, q rowQuerier, user, address string) (bool, error) {
	var yes bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.orchestrator_memberships m JOIN auth.users u ON u.id=m.user_id WHERE m.user_id=$1 AND m.orchestrator_address=$2 AND u.deleted_at IS NULL)`, user, address).Scan(&yes)
	return yes, err
}

func (s *Server) orchestrator(r *http.Request, user string) (string, error) {
	address, err := protocol.OrchestratorAddress(r.URL.Query().Get("orchestrator_address"))
	if err != nil {
		return "", problem(400, "invalid_orchestrator", "Choose an orchestrator.")
	}
	yes, err := member(r.Context(), s.db, user, address)
	if err != nil {
		return "", err
	}
	if !yes {
		return "", problem(403, "orchestrator_access_required", "Orchestrator access is required.")
	}
	return address, nil
}

func (s *Server) listOrchestrators(w http.ResponseWriter, r *http.Request) {
	u, err := s.user(r.Context(), bearer(r))
	if err != nil {
		s.respondError(w, err)
		return
	}
	rows, err := s.db.QueryContext(r.Context(), `SELECT o.address,COALESCE(o.display_name,'') FROM lpcc.orchestrators o JOIN lpcc.orchestrator_memberships m ON m.orchestrator_address=o.address JOIN auth.users u ON u.id=m.user_id WHERE m.user_id=$1 AND u.deleted_at IS NULL ORDER BY o.address`, u.ID)
	if err != nil {
		s.respondError(w, err)
		return
	}
	defer rows.Close()
	type orchestrator struct {
		Address     string `json:"address"`
		DisplayName string `json:"display_name"`
	}
	result := []orchestrator{}
	for rows.Next() {
		var o orchestrator
		if err = rows.Scan(&o.Address, &o.DisplayName); err != nil {
			s.respondError(w, err)
			return
		}
		result = append(result, o)
	}
	if err = rows.Err(); err != nil {
		s.respondError(w, err)
		return
	}
	respond(w, 200, map[string]any{"orchestrators": result})
}

func (s *Server) orchestratorMembership(w http.ResponseWriter, r *http.Request) {
	if !hmacEqual(bearer(r), s.params.SecretsMetadataToken) {
		fail(w, 403, "metadata principal required")
		return
	}
	address, err := protocol.OrchestratorAddress(r.PathValue("address"))
	if err != nil {
		fail(w, 403, "membership refused")
		return
	}
	yes, err := member(r.Context(), s.db, r.PathValue("user_id"), address)
	if err != nil {
		s.respondError(w, err)
		return
	}
	if !yes {
		s.respondError(w, problem(403, "orchestrator_access_required", "Orchestrator access is required."))
		return
	}
	respond(w, 200, map[string]string{"user_id": r.PathValue("user_id"), "orchestrator_address": strings.ToLower(address)})
}
