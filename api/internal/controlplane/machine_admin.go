package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
)

func (s *Server) prepareMachineRemoval(r *http.Request, _ UserIdentity) (AdminApply, error) {
	var in struct {
		Force bool `json:"force"`
	}
	if err := machineInput(r, &in); err != nil {
		return nil, err
	}
	node := r.PathValue("node_id")
	return func(ctx context.Context, tx *sql.Tx, _ UserIdentity) (AdminChange, error) {
		result, err := s.configs.Remove(ctx, tx, node, in.Force)
		if err != nil {
			return AdminChange{}, configurationProblem(err)
		}
		target := AdminTarget{Kind: "machine", ID: node, Revision: node}
		if result.AlreadyRemoved {
			return AdminChange{Target: target, Status: 204}, nil
		}
		body := map[string]any{"lifecycle": result.Lifecycle, "node_id": result.NodeID}
		if result.Generation != 0 {
			target.Revision += ":" + strconv.FormatInt(result.Generation, 10)
			body["generation"] = result.Generation
		}
		return AdminChange{Target: target, Changed: result.Changed, Status: 202, Body: body}, nil
	}, nil
}

func (s *Server) prepareDrainRetry(r *http.Request, _ UserIdentity) (AdminApply, error) {
	var in struct {
		Generation int64 `json:"generation"`
	}
	if err := machineInput(r, &in); err != nil {
		return nil, err
	}
	node := r.PathValue("node_id")
	return func(ctx context.Context, tx *sql.Tx, _ UserIdentity) (AdminChange, error) {
		result, err := s.configs.RetryDrain(ctx, tx, node, in.Generation)
		if err != nil {
			return AdminChange{}, configurationProblem(err)
		}
		return AdminChange{Target: AdminTarget{Kind: "machine", ID: node, Revision: node + ":" + strconv.FormatInt(result.Generation, 10)}, Changed: result.Changed, Status: 202, Body: map[string]any{"generation": result.Generation, "lifecycle": result.Lifecycle}}, nil
	}, nil
}

func configurationProblem(err error) error {
	switch {
	case errors.Is(err, machineconfig.ErrNotFound):
		return problem(404, "machine_not_found", "Machine not found.")
	case errors.Is(err, machineconfig.ErrDrainChanged):
		return problem(409, "drain_changed", "Drain intent changed.")
	case errors.Is(err, machineconfig.ErrDrainNotExpired):
		return problem(409, "drain_not_expired", "The current drain deadline has not expired.")
	default:
		return err
	}
}

func (s *Server) prepareTunnelRotation(r *http.Request, _ UserIdentity) (AdminApply, error) {
	var in struct {
		Kind        string `json:"kind"`
		Compromised bool   `json:"compromised"`
	}
	if e := machineInput(r, &in); e != nil {
		return nil, e
	}
	if in.Kind != "connector" && in.Kind != "access" {
		return nil, problem(400, "invalid_rotation", "Choose connector or access rotation.")
	}
	node := r.PathValue("node_id")
	return func(ctx context.Context, tx *sql.Tx, _ UserIdentity) (AdminChange, error) {
		var b []byte
		var revision int64
		var state tunnel.RoutingState
		var lifecycle string
		e := tx.QueryRowContext(ctx, `SELECT state,revision,rollout->>'lifecycle' FROM lpcc.machine_states WHERE node_id=$1 FOR UPDATE`, node).Scan(&b, &revision, &lifecycle)
		if errors.Is(e, sql.ErrNoRows) {
			return AdminChange{}, problem(404, "tunnel_not_found", "Tunnel not found.")
		}
		if e != nil {
			return AdminChange{}, e
		}
		if e = json.Unmarshal(b, &state); e != nil {
			return AdminChange{}, e
		}
		if state.ServiceURL == "" {
			return AdminChange{}, problem(404, "tunnel_not_found", "Tunnel not found.")
		}
		if lifecycle != "active" {
			return AdminChange{}, problem(409, "tunnel_inactive", "Tunnel is not active.")
		}
		previous := string(b)
		if in.Kind == "connector" {
			state.RotateTunnel = true
			state.Compromised = state.Compromised || in.Compromised
		} else {
			state.RotateAccess = true
			state.CompromisedAccess = state.CompromisedAccess || in.Compromised
		}
		state.Ready = false
		b, _ = json.Marshal(state)
		changed := previous != string(b)
		if changed {
			e = tx.QueryRowContext(ctx, `UPDATE lpcc.machine_states SET state=$2,revision=revision+1,next_attempt_at=now() WHERE node_id=$1 RETURNING revision`, node, string(b)).Scan(&revision)
		}
		return AdminChange{Target: AdminTarget{Kind: "tunnel", ID: node, Revision: node + ":" + strconv.FormatInt(revision, 10)}, Changed: changed, Status: 202, Body: map[string]string{"status": "rotation_queued"}}, e
	}, nil
}
