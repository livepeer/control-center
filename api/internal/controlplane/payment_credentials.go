package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"uuid"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/orchestrator"
	"github.com/livepeer/control-center/runtime/payment"
	"github.com/livepeer/control-center/runtime/transport"
)

func (s *Server) submissionToken(id string) string {
	h := hmac.New(sha256.New, []byte(s.params.MachineTokenSecret))
	h.Write([]byte("livepeer-redemption-submit-v1\x00" + id))
	return id + "." + hex.EncodeToString(h.Sum(nil))
}
func (s *Server) paymentCredentials(w http.ResponseWriter, r *http.Request) {
	m, e := s.authenticateMachine(r.Context(), r.PathValue("node_id"), bearer(r), false)
	if e != nil {
		s.respondError(w, e)
		return
	}
	var in orchestrator.Request
	if boundedMachineInput(r, &in, 4096) != nil || !orchestrator.ValidLaunch(in.Launch) || in.PaymentGeneration < 1 || !fingerprintPattern.MatchString(in.ConfigDigest) || !strings.HasPrefix(s.params.PublicAPIURL, "https://") {
		fail(w, 403, "payment delivery refused")
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	defer tx.Rollback()
	var current int64
	e = tx.QueryRowContext(r.Context(), `SELECT credential_version FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2 FOR UPDATE`, m.NodeID, m.Epoch).Scan(&current)
	if e != nil || current != m.CredentialVersion {
		fail(w, 409, "enrollment changed")
		return
	}
	var bundle []byte
	e = tx.QueryRowContext(r.Context(), `SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, m.NodeID).Scan(&bundle)
	if e != nil {
		fail(w, 409, "configuration unavailable")
		return
	}
	files, e := artifact.Read(bundle)
	var metadata contract.Metadata
	if e == nil {
		metadata, e = transport.ReadMetadata(files["runtime.json"])
	}
	if e != nil || metadata.Epoch != m.Epoch || metadata.CredentialVersion != m.CredentialVersion || !metadata.Payment.Paid() || metadata.Payment.Generation != in.PaymentGeneration || metadata.ConfigDigest != in.ConfigDigest {
		fail(w, 409, "payment configuration changed")
		return
	}
	rpc, e := s.readPaymentRPC(metadata.Payment.RPCSecret)
	if e != nil {
		fail(w, 503, "payment secret unavailable")
		return
	}
	hash := sha256.Sum256(rpc)
	var fingerprint string
	e = tx.QueryRowContext(r.Context(), `SELECT fingerprint FROM lpcc.payment_secrets WHERE reference=$1`, metadata.Payment.RPCSecret).Scan(&fingerprint)
	if e != nil || fingerprint != hex.EncodeToString(hash[:]) {
		fail(w, 503, "payment secret version changed")
		return
	}
	var initialized bool
	if e = tx.QueryRowContext(r.Context(), `SELECT initialized FROM lpcc.payment_machines WHERE node_id=$1`, m.NodeID).Scan(&initialized); e != nil {
		s.databaseError(w, e)
		return
	}
	id := uuid.New().String()
	var revoked sql.NullTime
	e = tx.QueryRowContext(r.Context(), `INSERT INTO lpcc.payment_grants(grant_id,node_id,epoch,payment_generation,config_digest,pod_uid,launch_id,process_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(node_id,epoch,payment_generation,pod_uid,launch_id,process_id) DO UPDATE SET grant_id=lpcc.payment_grants.grant_id RETURNING grant_id::text,revoked_at`, id, m.NodeID, m.Epoch, in.PaymentGeneration, in.ConfigDigest, in.PodUID, in.LaunchID, in.ProcessID).Scan(&id, &revoked)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	if revoked.Valid {
		fail(w, 403, "submission grant revoked")
		return
	}
	if e = tx.Commit(); e != nil {
		s.databaseError(w, e)
		return
	}
	respond(w, 200, orchestrator.Grant{Association: orchestrator.Association{Launch: in.Launch, Epoch: m.Epoch, CredentialVersion: m.CredentialVersion, PaymentGeneration: in.PaymentGeneration, ConfigDigest: in.ConfigDigest, GrantID: id}, RequireState: initialized, RPCURL: string(rpc), Headers: "Authorization: Bearer " + s.submissionToken(id)})
}

func (s *Server) redemptionAuthorize(w http.ResponseWriter, r *http.Request) {
	secret := s.params.PaymentWebhookSecret
	if len(secret) < 32 || len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(secret)) != 1 {
		fail(w, 401, "webhook authentication required")
		return
	}
	var in struct {
		Headers http.Header     `json:"headers"`
		Ticket  json.RawMessage `json:"ticket"`
	}
	if appInput(r, &in) != nil {
		respond(w, 200, map[string]int{"status": 403})
		return
	}
	token := ""
	count := 0
	for k, v := range in.Headers {
		if strings.EqualFold(k, "Authorization") {
			count += len(v)
			if len(v) == 1 {
				kind, t, ok := strings.Cut(v[0], " ")
				if ok && kind == "Bearer" {
					token = t
				}
			}
		}
	}
	id, _, ok := strings.Cut(token, ".")
	var ticket struct {
		Recipient string `json:"recipient"`
	}
	allowed := count == 1 && ok && appID(id) && len(s.params.MachineTokenSecret) >= 32 && hmac.Equal([]byte(token), []byte(s.submissionToken(id))) && json.Unmarshal(in.Ticket, &ticket) == nil && payment.Address.MatchString(ticket.Recipient)
	if allowed {
		var recipient string
		e := s.db.QueryRowContext(r.Context(), `SELECT v.config->>'recipient' FROM lpcc.payment_grants g JOIN lpcc.payment_versions v ON v.node_id=g.node_id AND v.generation=g.payment_generation JOIN lpcc.machines m ON m.node_id=g.node_id AND m.enrollment_epoch=g.epoch WHERE g.grant_id=$1 AND g.revoked_at IS NULL`, id).Scan(&recipient)
		allowed = e == nil && strings.EqualFold(recipient, ticket.Recipient)
	}
	status := 403
	if allowed {
		status = 200
	}
	respond(w, 200, map[string]int{"status": status})
}

// Accept only a fresh, matching observation of the issued grant. This permits a
// held Node's grant across ordinary management refresh, without allowing it to
// authenticate to any management endpoint.
func (s *Server) observePaymentGrant(ctx context.Context, m Machine, reportPayment *payment.Observation, digest string) error {
	p := reportPayment
	if p == nil || !p.Applied || p.PodUID == "" {
		return nil
	}
	if p.Mode != "offchain" && (p.Mode != "paid" || !appID(p.GrantID)) {
		return nil
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var b []byte
	e = tx.QueryRowContext(ctx, `SELECT c.bundle FROM lpcc.machines m JOIN lpcc.machine_configs c USING(node_id) WHERE m.node_id=$1 AND m.enrollment_epoch=$2 AND m.credential_version=$3 FOR UPDATE OF m`, m.NodeID, m.Epoch, m.CredentialVersion).Scan(&b)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	files, e := artifact.Read(b)
	if e != nil {
		return e
	}
	meta, e := transport.ReadMetadata(files["runtime.json"])
	if e != nil {
		return e
	}
	if meta.ConfigDigest != digest || meta.Payment.Generation != p.Generation || meta.Payment.Mode != p.Mode {
		return nil
	}
	if p.Mode == "offchain" {
		// The replacement has no submission bearer to observe. Retire the held
		// paid workload's grants only after its offchain successor is applied.
		_, e = tx.ExecContext(ctx, `UPDATE lpcc.payment_grants SET revoked_at=now() WHERE node_id=$1 AND epoch=$2 AND revoked_at IS NULL`, m.NodeID, m.Epoch)
		if e != nil {
			return e
		}
		return tx.Commit()
	}
	var id string
	e = tx.QueryRowContext(ctx, `UPDATE lpcc.payment_grants SET observed_at=now() WHERE grant_id=$1 AND node_id=$2 AND epoch=$3 AND payment_generation=$4 AND config_digest=$5 AND pod_uid=$6 AND revoked_at IS NULL RETURNING grant_id::text`, p.GrantID, m.NodeID, m.Epoch, p.Generation, digest, p.PodUID).Scan(&id)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE lpcc.payment_grants SET revoked_at=now() WHERE node_id=$1 AND epoch=$2 AND grant_id<>$3 AND revoked_at IS NULL AND issued_sequence<(SELECT issued_sequence FROM lpcc.payment_grants WHERE grant_id=$3)`, m.NodeID, m.Epoch, id)
	if e != nil {
		return e
	}
	if p.Ready {
		if _, e = tx.ExecContext(ctx, `UPDATE lpcc.payment_machines SET initialized=true WHERE node_id=$1`, m.NodeID); e != nil {
			return e
		}
	}
	return tx.Commit()
}
