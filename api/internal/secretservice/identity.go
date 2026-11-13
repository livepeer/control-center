package secretservice

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	protocol "github.com/livepeer/control-center/secrets"
	"net/http"
)

func (s *Service) enroll(w http.ResponseWriter, r *http.Request) {
	c, e := s.grant(bearer(r), false)
	if e != nil {
		fail(w, 401, "grant_refused")
		return
	}
	var in protocol.EnrollRequest
	if decode(r, &in) != nil || !in.EncryptionReady {
		fail(w, 400, "invalid_enrollment")
		return
	}
	pub, e := protocol.PublicKey(in.PublicKey)
	if e != nil || !ed25519.Verify(pub, protocol.Proof(in.NodeID, in.PublicKey), in.Signature) {
		fail(w, 403, "key_proof_refused")
		return
	}
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer tx.Rollback()
	if lockGrant(r.Context(), tx, c.ID) != nil {
		fail(w, 503, "unavailable")
		return
	}
	var revoked bool
	e = tx.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT FROM lpsecrets.revoked_grants WHERE jti=$1)`, c.ID).Scan(&revoked)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	if revoked || !s.Now().Before(c.ExpiresAt.Time) {
		fail(w, 401, "grant_refused")
		return
	}
	if lockIdentity(r.Context(), tx, in.NodeID) != nil {
		fail(w, 503, "unavailable")
		return
	}
	var owner, key string
	var gen int64
	var reset bool
	e = tx.QueryRowContext(r.Context(), `SELECT owner_id::text,public_key,generation,revoked,reset_pending FROM lpsecrets.identities WHERE node_id=$1 FOR UPDATE`, in.NodeID).Scan(&owner, &key, &gen, &revoked, &reset)
	exists := e == nil
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		fail(w, 503, "unavailable")
		return
	}
	if exists && (owner != c.Subject || (revoked && !reset) || (!reset && key != in.PublicKey)) {
		fail(w, 409, "identity_conflict")
		return
	}
	var retired bool
	if e = tx.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT FROM lpsecrets.retired_keys WHERE node_id=$1 AND public_key=$2)`, in.NodeID, in.PublicKey).Scan(&retired); e != nil {
		fail(w, 503, "unavailable")
		return
	}
	if retired {
		fail(w, 409, "identity_reset_required")
		return
	}
	if reset && key != "" {
		_, e = s.Metadata.Machine(r.Context(), in.NodeID, &protocol.MachineBinding{EnrollRequest: protocol.EnrollRequest{NodeID: in.NodeID}, Owner: c.Subject, ResetKey: key})
		if e != nil {
			fail(w, 503, "reset_pending")
			return
		}
	}
	m, e := s.Metadata.Machine(r.Context(), in.NodeID, &protocol.MachineBinding{EnrollRequest: in, Owner: c.Subject})
	if errors.Is(e, protocol.ErrUnavailable) {
		fail(w, 503, "unavailable")
		return
	}
	if e != nil || !m.Active || m.Owner != c.Subject || m.PublicKey != in.PublicKey || !m.EncryptionReady {
		fail(w, 403, "machine_refused")
		return
	}
	if !exists {
		gen = 1
		_, e = tx.ExecContext(r.Context(), `INSERT INTO lpsecrets.identities(node_id,owner_id,public_key) VALUES($1,$2,$3)`, in.NodeID, c.Subject, in.PublicKey)
	} else if reset {
		_, e = tx.ExecContext(r.Context(), `UPDATE lpsecrets.identities SET public_key=$2,revoked=false,reset_pending=false WHERE node_id=$1`, in.NodeID, in.PublicKey)
	}
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	if !exists || reset {
		e = audit(r.Context(), tx, c.Subject, "machine.enroll", in.NodeID)
	}
	if e != nil || !s.Now().Before(c.ExpiresAt.Time) || tx.Commit() != nil {
		fail(w, 503, "enrollment_pending")
		return
	}
	response(w, 200, protocol.Identity{NodeID: in.NodeID, Owner: c.Subject, Generation: gen, Service: s.trust()})
}
func (s *Service) machine(r *http.Request) (protocol.Machine, int64, error) {
	return s.machineWith(r, s.DB)
}

type identityReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Service) machineWith(r *http.Request, q identityReader) (protocol.Machine, int64, error) {
	var m protocol.Machine
	id, ok := r.Context().Value(requestIdentityKey{}).(requestIdentity)
	if !ok {
		return m, 0, protocol.ErrDenied
	}
	var owner, key string
	var expected int64
	var revoked bool
	e := q.QueryRowContext(r.Context(), `SELECT owner_id::text,public_key,generation,revoked FROM lpsecrets.identities WHERE node_id=$1`, id.Subject).Scan(&owner, &key, &expected, &revoked)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return m, 0, protocol.ErrUnavailable
	}
	if e != nil || revoked || id.Generation != expected || id.PublicKey != key {
		return m, 0, protocol.ErrDenied
	}
	m, e = s.Metadata.Machine(r.Context(), id.Subject, nil)
	if e != nil {
		return m, 0, e
	}
	if !m.Active || m.Owner != owner || m.PublicKey != key || !m.EncryptionReady {
		return m, 0, protocol.ErrDenied
	}
	return m, expected, nil
}

// Activation proves that the host has installed the committed identity. Until
// this signed round trip, the Control Center binding remains pending.
func (s *Service) activate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AdmissionReady bool `json:"admission_ready"`
	}
	if decode(r, &in) != nil || !in.AdmissionReady {
		fail(w, 400, "admission_not_ready")
		return
	}
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer tx.Rollback()
	id := r.Context().Value(requestIdentityKey{}).(requestIdentity)
	if lockIdentity(r.Context(), tx, id.Subject) != nil {
		fail(w, 503, "unavailable")
		return
	}
	m, _, e := s.machineWith(r, tx)
	if e != nil {
		failAuthorization(w, e, 403, "identity_refused")
		return
	}
	m, e = s.Metadata.Machine(r.Context(), m.NodeID, &protocol.MachineBinding{EnrollRequest: protocol.EnrollRequest{NodeID: m.NodeID, PublicKey: m.PublicKey}, Owner: m.Owner, Activate: true, AdmissionReady: true})
	if e != nil || !m.Managed {
		fail(w, 503, "activation_pending")
		return
	}
	response(w, 200, map[string]bool{"activated": true})
}

func (s *Service) revokeIdentity(w http.ResponseWriter, r *http.Request) {
	s.changeIdentity(w, r, false)
}
func (s *Service) resetIdentity(w http.ResponseWriter, r *http.Request) { s.changeIdentity(w, r, true) }
func (s *Service) changeIdentity(w http.ResponseWriter, r *http.Request, reset bool) {
	owner, e := s.owner(r)
	if e != nil {
		fail(w, 401, "authentication_required")
		return
	}
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer tx.Rollback()
	node := r.PathValue("node")
	if lockIdentity(r.Context(), tx, node) != nil {
		fail(w, 503, "unavailable")
		return
	}
	var current string
	e = tx.QueryRowContext(r.Context(), `UPDATE lpsecrets.identities SET revoked=true,generation=generation+CASE WHEN reset_pending AND $3 THEN 0 ELSE 1 END,reset_pending=$3 WHERE node_id=$1 AND owner_id=$2 RETURNING public_key`, node, owner, reset).Scan(&current)
	if errors.Is(e, sql.ErrNoRows) {
		// A Control Center binding can precede the first committed identity.
		m, err := s.Metadata.Machine(r.Context(), node, nil)
		if err != nil || m.Owner != owner {
			fail(w, 404, "identity_not_found")
			return
		}
		current = m.PublicKey
		_, e = tx.ExecContext(r.Context(), `INSERT INTO lpsecrets.identities(node_id,owner_id,public_key,revoked,reset_pending) VALUES($1,$2,$3,true,$4)`, node, owner, current, reset)
	}
	if e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			fail(w, 404, "identity_not_found")
		} else {
			fail(w, 503, "unavailable")
		}
		return
	}
	if reset {
		if current != "" {
			_, e = tx.ExecContext(r.Context(), `INSERT INTO lpsecrets.retired_keys(node_id,public_key) VALUES($1,$2) ON CONFLICT DO NOTHING`, node, current)
		}
		if e != nil {
			fail(w, 503, "reset_pending")
			return
		}
	}
	action := "machine.revoke"
	if reset {
		action = "machine.reset"
	}
	if audit(r.Context(), tx, owner, action, node) != nil || tx.Commit() != nil {
		fail(w, 503, "unavailable")
		return
	}
	if reset && current != "" {
		m, e := s.Metadata.Machine(r.Context(), node, &protocol.MachineBinding{EnrollRequest: protocol.EnrollRequest{NodeID: node}, Owner: owner, ResetKey: current})
		if e != nil || m.Owner != owner {
			fail(w, 503, "reset_pending")
			return
		}
	}
	response(w, 200, map[string]bool{"changed": true})
}

func (s *Service) listIdentities(w http.ResponseWriter, r *http.Request) {
	owner, e := s.owner(r)
	if e != nil {
		fail(w, 401, "authentication_required")
		return
	}
	rows, e := s.DB.QueryContext(r.Context(), `SELECT node_id,generation,revoked FROM lpsecrets.identities WHERE owner_id=$1 ORDER BY node_id`, owner)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var node string
		var gen int64
		var revoked bool
		if rows.Scan(&node, &gen, &revoked) != nil {
			fail(w, 503, "unavailable")
			return
		}
		out = append(out, map[string]any{"node_id": node, "generation": gen, "revoked": revoked})
	}
	response(w, 200, map[string]any{"machines": out})
}
