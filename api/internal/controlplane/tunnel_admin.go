package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
)

func (s *Server) prepareMachineRemoval(r *http.Request, _ UserIdentity) (AdminApply, error) {
	var in struct {
		Epoch string `json:"epoch"`
		Force bool   `json:"force"`
	}
	if e := machineInput(r, &in); e != nil {
		return nil, e
	}
	node := r.PathValue("node_id")
	return func(ctx context.Context, tx *sql.Tx, _ UserIdentity) (AdminChange, error) {
		var epoch string
		var credentialVersion int64
		e := tx.QueryRowContext(ctx, `SELECT enrollment_epoch::text,credential_version FROM lpcc.machines WHERE node_id=$1 FOR UPDATE`, node).Scan(&epoch, &credentialVersion)
		target := AdminTarget{Kind: "machine", ID: node, Revision: in.Epoch}
		if errors.Is(e, sql.ErrNoRows) {
			var retired bool
			e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.enrollments WHERE node_id=$1 AND epoch::text=$2 AND retired_at IS NOT NULL)`, node, in.Epoch).Scan(&retired)
			if e != nil {
				return AdminChange{}, e
			}
			if retired {
				return AdminChange{Target: target, Status: 204}, nil
			}
			return AdminChange{}, problem(404, "machine_not_found", "Machine not found.")
		}
		if e != nil {
			return AdminChange{}, e
		}
		if epoch != in.Epoch {
			return AdminChange{}, problem(409, "epoch_changed", "Machine enrollment changed.")
		}
		if in.Force {
			_, e = tx.ExecContext(ctx, `DELETE FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2`, node, epoch)
			return AdminChange{Target: target, Changed: true, Status: 202, Body: map[string]string{"lifecycle": "removed", "epoch": epoch}}, e
		}
		if credentialVersion == 0 {
			return AdminChange{}, problem(409, "legacy_drain_unsupported", "Refresh credentials before ordinary removal, or explicitly force removal.")
		}
		if s.params.TunnelDrainTimeout <= 0 {
			return AdminChange{}, problem(409, "drain_deadline_required", "Configure a drain deadline before ordinary removal.")
		}
		var b []byte
		var state tunnel.RoutingState
		e = tx.QueryRowContext(ctx, `SELECT state FROM lpcc.machine_tunnels WHERE node_id=$1 AND epoch=$2 FOR UPDATE`, node, epoch).Scan(&b)
		if errors.Is(e, sql.ErrNoRows) {
			state = tunnel.RoutingFor(node, s.params.CloudflareBaseDomain)
		} else if e != nil {
			return AdminChange{}, e
		} else if e = json.Unmarshal(b, &state); e != nil {
			return AdminChange{}, e
		}
		changed := state.Lifecycle != "draining"
		if changed {
			state.Generation++
			state.Lifecycle = "draining"
			state.DrainRequested = true
			state.DrainStartedAt = time.Now().UTC()
			state.Ready = false
			b, _ = json.Marshal(state)
			_, e = tx.ExecContext(ctx, `INSERT INTO lpcc.machine_tunnels(node_id,epoch,state) VALUES($1,$2,$3) ON CONFLICT(node_id,epoch) DO UPDATE SET state=EXCLUDED.state,revision=lpcc.machine_tunnels.revision+1,next_attempt_at=now()`, node, epoch, b)
		}
		target.Revision = epoch + ":" + strconv.FormatInt(state.Generation, 10)
		return AdminChange{Target: target, Changed: changed, Status: 202, Body: map[string]any{"lifecycle": "draining", "epoch": epoch, "generation": state.Generation}}, e
	}, nil
}

func (s *Server) prepareDrainRetry(r *http.Request, _ UserIdentity) (AdminApply, error) {
	var in struct {
		Epoch      string `json:"epoch"`
		Generation int64  `json:"generation"`
	}
	if e := machineInput(r, &in); e != nil {
		return nil, e
	}
	if s.params.TunnelDrainTimeout <= 0 {
		return nil, problem(409, "drain_deadline_required", "Configure a drain deadline before retrying.")
	}
	node := r.PathValue("node_id")
	return func(ctx context.Context, tx *sql.Tx, _ UserIdentity) (AdminChange, error) {
		var present int
		e := tx.QueryRowContext(ctx, `SELECT 1 FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch::text=$2 FOR UPDATE`, node, in.Epoch).Scan(&present)
		if errors.Is(e, sql.ErrNoRows) {
			return AdminChange{}, problem(409, "epoch_changed", "Machine enrollment changed.")
		}
		if e != nil {
			return AdminChange{}, e
		}
		var b []byte
		if e = tx.QueryRowContext(ctx, `SELECT state FROM lpcc.machine_tunnels WHERE node_id=$1 AND epoch=$2 FOR UPDATE`, node, in.Epoch).Scan(&b); e != nil {
			return AdminChange{}, e
		}
		var state tunnel.RoutingState
		if e = json.Unmarshal(b, &state); e != nil {
			return AdminChange{}, e
		}
		if !state.DrainRequested || state.Generation != in.Generation || state.Lifecycle == "removed" {
			return AdminChange{}, problem(409, "drain_changed", "Drain intent changed.")
		}
		if !state.DrainStartedAt.IsZero() && time.Since(state.DrainStartedAt) <= s.params.TunnelDrainTimeout {
			return AdminChange{}, problem(409, "drain_not_expired", "The current drain deadline has not expired.")
		}
		state.Generation++
		state.DrainStartedAt = time.Now().UTC()
		state.Ready = false
		state.Reason = "drain_pending"
		b, _ = json.Marshal(state)
		_, e = tx.ExecContext(ctx, `UPDATE lpcc.machine_tunnels SET state=$3,revision=revision+1,next_attempt_at=now() WHERE node_id=$1 AND epoch=$2`, node, in.Epoch, b)
		return AdminChange{Target: AdminTarget{Kind: "machine", ID: node, Revision: in.Epoch + ":" + strconv.FormatInt(state.Generation, 10)}, Changed: true, Status: 202, Body: map[string]any{"generation": state.Generation, "lifecycle": state.Lifecycle}}, e
	}, nil
}

func (s *Server) prepareTunnelRotation(r *http.Request, _ UserIdentity) (AdminApply, error) {
	var in struct {
		Epoch       string `json:"epoch"`
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
		e := tx.QueryRowContext(ctx, `SELECT state,revision FROM lpcc.machine_tunnels WHERE node_id=$1 AND epoch::text=$2 FOR UPDATE`, node, in.Epoch).Scan(&b, &revision)
		if errors.Is(e, sql.ErrNoRows) {
			return AdminChange{}, problem(404, "tunnel_not_found", "Tunnel not found.")
		}
		if e != nil {
			return AdminChange{}, e
		}
		if e = json.Unmarshal(b, &state); e != nil {
			return AdminChange{}, e
		}
		if state.Lifecycle != "active" {
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
			e = tx.QueryRowContext(ctx, `UPDATE lpcc.machine_tunnels SET state=$3,revision=revision+1,next_attempt_at=now() WHERE node_id=$1 AND epoch=$2 RETURNING revision`, node, in.Epoch, b).Scan(&revision)
		}
		return AdminChange{Target: AdminTarget{Kind: "tunnel", ID: node, Revision: in.Epoch + ":" + strconv.FormatInt(revision, 10)}, Changed: changed, Status: 202, Body: map[string]string{"status": "rotation_queued"}}, e
	}, nil
}
