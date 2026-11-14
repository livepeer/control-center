package secretservice

import (
	"context"
	"database/sql"
	"errors"
	protocol "github.com/livepeer/control-center/secrets"
	"net/http"
)

type secretView struct {
	protocol.Binding
	Revision int64 `json:"revision"`
	Deleted  bool  `json:"deleted"`
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	owner := operatorActor(r).Address
	rows, e := s.DB.QueryContext(r.Context(), `SELECT id::text,name,key,COALESCE(head::text,''),revision,deleted FROM lpsecrets.secrets WHERE orchestrator_address=$1 ORDER BY name,key LIMIT 1000`, owner)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer rows.Close()
	out := []secretView{}
	for rows.Next() {
		v := secretView{Binding: protocol.Binding{Owner: owner}}
		if rows.Scan(&v.ID, &v.Name, &v.Key, &v.Version, &v.Revision, &v.Deleted) != nil {
			fail(w, 503, "unavailable")
			return
		}
		out = append(out, v)
	}
	if rows.Err() != nil {
		fail(w, 503, "unavailable")
		return
	}
	response(w, 200, map[string]any{"secrets": out})
}
func (s *Service) reserve(w http.ResponseWriter, r *http.Request) {
	owner := operatorActor(r).Address
	var in struct {
		Name     string `json:"name"`
		Key      string `json:"key"`
		Revision int64  `json:"expected_revision"`
	}
	if decode(r, &in) != nil || !protocol.ValidReference(in.Name, in.Key) {
		fail(w, 400, "invalid_reference")
		return
	}
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer tx.Rollback()
	v := secretView{Binding: protocol.Binding{Owner: owner, Name: in.Name, Key: in.Key, Version: ident()}}
	e = tx.QueryRowContext(r.Context(), `SELECT id::text,revision FROM lpsecrets.secrets WHERE orchestrator_address=$1 AND name=$2 AND key=$3 AND NOT deleted FOR UPDATE`, owner, in.Name, in.Key).Scan(&v.ID, &v.Revision)
	if errors.Is(e, sql.ErrNoRows) && in.Revision == 0 {
		v.ID = ident()
		v.Revision = 1
		_, e = tx.ExecContext(r.Context(), `INSERT INTO lpsecrets.secrets(id,orchestrator_address,name,key) VALUES($1,$2,$3,$4)`, v.ID, owner, in.Name, in.Key)
	} else if e == nil && v.Revision != in.Revision {
		fail(w, 409, "secret_conflict")
		return
	}
	if e != nil {
		fail(w, 409, "secret_conflict")
		return
	}
	_, e = tx.ExecContext(r.Context(), `INSERT INTO lpsecrets.versions(id,secret_id,base_revision) VALUES($1,$2,$3)`, v.Version, v.ID, v.Revision)
	if e != nil || tx.Commit() != nil {
		fail(w, 503, "unavailable")
		return
	}
	response(w, 200, v)
}
func (s *Service) wrap(w http.ResponseWriter, r *http.Request) {
	owner := operatorActor(r).Address
	var in struct {
		Version   string             `json:"version_id"`
		SealedKey protocol.Sensitive `json:"sealed_key"`
	}
	if decode(r, &in) != nil || len(in.SealedKey) != 80 {
		fail(w, 400, "invalid_key")
		return
	}
	binding := protocol.Binding{Owner: owner, ID: r.PathValue("id"), Version: in.Version}
	e := s.DB.QueryRowContext(r.Context(), `SELECT s.name,s.key FROM lpsecrets.versions v JOIN lpsecrets.secrets s ON s.id=v.secret_id WHERE v.id=$1 AND s.id=$2 AND s.orchestrator_address=$3 AND NOT s.deleted AND v.base_revision=s.revision AND v.ciphertext IS NULL AND v.wrapped_key IS NULL`, in.Version, binding.ID, owner).Scan(&binding.Name, &binding.Key)
	if e != nil {
		fail(w, 409, "secret_conflict")
		return
	}
	key, e := protocol.OpenDataKey(s.Config.EncryptionKey, protocol.KeyInfo("upload", s.Config.PublicURL, binding), in.SealedKey)
	if e != nil {
		fail(w, 400, "invalid_key")
		return
	}
	wrapped, e := s.Transit.Wrap(r.Context(), owner, key)
	clear(key)
	if e != nil {
		fail(w, 503, "key_unavailable")
		return
	}
	res, e := s.DB.ExecContext(r.Context(), `UPDATE lpsecrets.versions v SET wrapped_key=$1 FROM lpsecrets.secrets s WHERE v.id=$2 AND s.id=v.secret_id AND s.id=$3 AND s.orchestrator_address=$4 AND NOT s.deleted AND s.revision=v.base_revision AND v.wrapped_key IS NULL AND v.ciphertext IS NULL`, wrapped, in.Version, r.PathValue("id"), owner)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		fail(w, 409, "secret_conflict")
		return
	}
	response(w, 200, map[string]string{"wrapped_key": wrapped})
}
func (s *Service) upload(w http.ResponseWriter, r *http.Request) {
	owner := operatorActor(r).Address
	var in protocol.Ciphertext
	if decode(r, &in) != nil || in.Owner != owner || in.ID != r.PathValue("id") || len(in.Nonce) != 12 || len(in.Ciphertext) < 16 || len(in.Ciphertext) > protocol.MaxValue+16 {
		fail(w, 400, "invalid_ciphertext")
		return
	}
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer tx.Rollback()
	var rev, base int64
	var name, key, wrapped string
	e = tx.QueryRowContext(r.Context(), `SELECT s.revision,v.base_revision,s.name,s.key,COALESCE(v.wrapped_key,'') FROM lpsecrets.secrets s JOIN lpsecrets.versions v ON s.id=v.secret_id WHERE s.id=$1 AND v.id=$2 AND s.orchestrator_address=$3 AND NOT s.deleted AND v.ciphertext IS NULL FOR UPDATE OF s,v`, in.ID, in.Version, owner).Scan(&rev, &base, &name, &key, &wrapped)
	if e != nil || rev != base || name != in.Name || key != in.Key || !equal(wrapped, in.WrappedKey) {
		fail(w, 409, "secret_conflict")
		return
	}
	_, e = tx.ExecContext(r.Context(), `UPDATE lpsecrets.versions SET nonce=$1,ciphertext=$2 WHERE id=$3`, in.Nonce, in.Ciphertext, in.Version)
	if e == nil {
		_, e = tx.ExecContext(r.Context(), `UPDATE lpsecrets.versions SET superseded_at=$1 WHERE id=(SELECT head FROM lpsecrets.secrets WHERE id=$2)`, s.Now(), in.ID)
	}
	if e == nil {
		_, e = tx.ExecContext(r.Context(), `UPDATE lpsecrets.secrets SET head=$1,revision=revision+1,updated_at=now() WHERE id=$2`, in.Version, in.ID)
	}
	if e == nil {
		e = audit(r.Context(), tx, owner, "secret.write", in.ID)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 503, "unavailable")
		return
	}
	response(w, 200, map[string]any{"revision": rev + 1, "version_id": in.Version})
}
func (s *Service) deleteSecret(w http.ResponseWriter, r *http.Request) {
	owner := operatorActor(r).Address
	var in struct {
		Revision int64 `json:"expected_revision"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "invalid_request")
		return
	}
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer tx.Rollback()
	res, e := tx.ExecContext(r.Context(), `UPDATE lpsecrets.secrets SET deleted=true,head=NULL,revision=revision+1,updated_at=now() WHERE id=$1 AND orchestrator_address=$2 AND revision=$3 AND NOT deleted`, r.PathValue("id"), owner, in.Revision)
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		fail(w, 409, "secret_conflict")
		return
	}
	_, e = tx.ExecContext(r.Context(), `DELETE FROM lpsecrets.versions WHERE secret_id=$1`, r.PathValue("id"))
	if e == nil {
		e = audit(r.Context(), tx, owner, "secret.delete", r.PathValue("id"))
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 503, "unavailable")
		return
	}
	response(w, 200, map[string]bool{"deleted": true})
}
func (s *Service) versions(w http.ResponseWriter, r *http.Request) { s.resolveValues(w, r, false) }
func (s *Service) resolve(w http.ResponseWriter, r *http.Request)  { s.resolveValues(w, r, true) }
func (s *Service) resolveValues(w http.ResponseWriter, r *http.Request, keys bool) {
	m, gen, e := s.machine(r)
	if e != nil {
		failAuthorization(w, e, 403, "identity_refused")
		return
	}
	if !m.Managed {
		fail(w, 503, "activation_pending")
		return
	}
	var request protocol.DeliveryRequest
	if decode(r, &request) != nil {
		fail(w, 400, "invalid_assignment")
		return
	}
	in := request.ResolveRequest
	if keys {
		if _, e := protocol.EncryptionKEM().NewPublicKey(request.RecipientKey); e != nil {
			fail(w, 400, "invalid_recipient_key")
			return
		}
	}
	var refs []struct{ Name, Key string }
	eligible := false
	for _, a := range m.Assignments {
		if a.Desired == "present" && a.StartAllowed && a.Revision != nil && a.RevisionID == in.RevisionID && a.Generation == in.Generation && a.ActivationGeneration == in.Activation && a.Digest == in.Digest {
			eligible = true
			for _, v := range a.Revision.Definition.Container.Secrets {
				refs = append(refs, struct{ Name, Key string }{v.Secret, v.Key})
			}
		}
	}
	if !eligible || assignmentDenied(m, in.RevisionID) {
		if assignmentDenied(m, in.RevisionID) {
			fail(w, 403, "assignment_refused")
		} else {
			fail(w, 409, "authorization_changed")
		}
		return
	}
	tx, e := s.DB.BeginTx(r.Context(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		fail(w, 503, "unavailable")
		return
	}
	defer tx.Rollback()
	out := protocol.VersionSet{NodeID: m.NodeID, IdentityGeneration: gen, PolicyGeneration: m.PolicyGeneration, Assignment: in, Values: []protocol.Resolved{}}
	for _, ref := range refs {
		v := protocol.Resolved{Ciphertext: protocol.Ciphertext{Binding: protocol.Binding{Owner: m.Owner, Name: ref.Name, Key: ref.Key}}}
		e = tx.QueryRowContext(r.Context(), `SELECT s.id::text,v.id::text,v.nonce,v.ciphertext,v.wrapped_key,s.revision FROM lpsecrets.secrets s JOIN lpsecrets.versions v ON v.id=s.head WHERE s.orchestrator_address=$1 AND s.name=$2 AND s.key=$3 AND NOT s.deleted FOR SHARE OF s,v`, m.Owner, ref.Name, ref.Key).Scan(&v.ID, &v.Version, &v.Nonce, &v.Ciphertext.Ciphertext, &v.WrappedKey, &v.Revision)
		if errors.Is(e, sql.ErrNoRows) {
			reason, err := missingSecret(r.Context(), tx, m.Owner, ref.Name, ref.Key)
			if err != nil {
				fail(w, 503, "unavailable")
				return
			}
			fail(w, 409, reason)
			return
		}
		if e != nil {
			fail(w, 503, "unavailable")
			return
		}
		out.Values = append(out.Values, v)
	}
	out.Digest = protocol.VersionDigest(out.Values)
	if in.Expected != "" && in.Expected != out.Digest {
		fail(w, 409, "version_changed")
		return
	}
	if keys {
		for i := range out.Values {
			key, e := s.Transit.Unwrap(r.Context(), m.Owner, out.Values[i].WrappedKey)
			if e != nil {
				clear(key)
				fail(w, 503, "key_unavailable")
				return
			}
			out.Values[i].SealedKey, e = protocol.SealDataKey(request.RecipientKey, protocol.KeyInfo("delivery", s.Config.PublicURL, out.Values[i].Binding), key)
			clear(key)
			if e != nil {
				fail(w, 400, "invalid_recipient_key")
				return
			}
		}
		if audit(r.Context(), tx, m.Owner, "secret.resolve", m.NodeID+"/"+in.RevisionID) != nil {
			fail(w, 503, "unavailable")
			return
		}
	}
	if tx.Commit() != nil {
		fail(w, 503, "unavailable")
		return
	}
	response(w, 200, out)
}

func eligibleAssignment(m protocol.Machine, in protocol.ResolveRequest) bool {
	if assignmentDenied(m, in.RevisionID) {
		return false
	}
	for _, a := range m.Assignments {
		if a.Desired == "present" && a.StartAllowed && a.Revision != nil && a.RevisionID == in.RevisionID && a.Generation == in.Generation && a.ActivationGeneration == in.Activation && a.Digest == in.Digest {
			return true
		}
	}
	return false
}

func assignmentDenied(m protocol.Machine, revision string) bool {
	for _, id := range m.DeniedRevisions {
		if id == revision {
			return true
		}
	}
	return false
}

// Only a current tombstone is authoritative deletion; an unprovisioned value
// blocks starts without withdrawing healthy consumers during adoption.
func missingSecret(ctx context.Context, tx *sql.Tx, owner, name, key string) (string, error) {
	var deleted, live bool
	e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpsecrets.secrets WHERE orchestrator_address=$1 AND name=$2 AND key=$3 AND deleted), EXISTS(SELECT FROM lpsecrets.secrets WHERE orchestrator_address=$1 AND name=$2 AND key=$3 AND NOT deleted)`, owner, name, key).Scan(&deleted, &live)
	if deleted && !live {
		return "secret_missing", e
	}
	return "secret_unprovisioned", e
}
