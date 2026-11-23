package controlplane

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"uuid"

	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/runtime/consumer"
	"github.com/livepeer/control-center/runtime/onchain"
	protocol "github.com/livepeer/control-center/secrets"
)

func (s *Server) submissionToken(id string) string {
	h := hmac.New(sha256.New, []byte(s.params.MachineTokenSecret))
	h.Write([]byte("livepeer-redemption-submit-v1\x00" + id))
	return id + "." + hex.EncodeToString(h.Sum(nil))
}
func (s *Server) onchainCredentials(w http.ResponseWriter, r *http.Request) {
	m, e := s.authenticateMachine(r.Context(), r.PathValue("node_id"), bearer(r), false)
	if e != nil {
		s.respondError(w, e)
		return
	}
	var in consumer.Request
	if s.params.DevelopmentHTTP || boundedInput(r, &in, 4096) != nil || !consumer.ValidLaunch(in.Launch) || in.OnchainGeneration < 1 || !fingerprintPattern.MatchString(in.ConfigDigest) {
		fail(w, 403, "onchain delivery refused")
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	defer tx.Rollback()
	var bundle []byte
	var public string
	e = tx.QueryRowContext(r.Context(), `SELECT c.bundle,k.public_key FROM lpcc.machines m JOIN lpcc.machine_configs c USING(node_id) JOIN lpcc.secret_machines k USING(node_id) WHERE m.node_id=$1 AND m.credential_version=$2 FOR UPDATE OF m,k`, m.NodeID, m.CredentialVersion).Scan(&bundle, &public)
	if e != nil {
		fail(w, 409, "configuration or enrollment changed")
		return
	}
	pub, e := protocol.PublicKey(public)
	endpoint := strings.TrimRight(s.params.PublicAPIURL, "/") + "/v1/nodes/" + m.NodeID + "/onchain/credentials"
	if e != nil || !in.Verify(pub, m.NodeID, m.CredentialVersion, endpoint, s.currentTime()) {
		fail(w, 403, "runtime launch proof required")
		return
	}
	metadata, _, e := machineconfig.ReadApplied(bundle)
	if e != nil || metadata.NodeID != m.NodeID || metadata.CredentialVersion != m.CredentialVersion || !metadata.Onchain.Onchain() || metadata.Onchain.Generation != in.OnchainGeneration || metadata.ConfigDigest != in.ConfigDigest {
		fail(w, 409, "onchain configuration changed")
		return
	}
	rpc, e := s.readOnchainRPC(metadata.Onchain.RPCSecret)
	if e != nil {
		fail(w, 503, "onchain secret unavailable")
		return
	}
	var initialized bool
	if e = tx.QueryRowContext(r.Context(), `SELECT initialized FROM lpcc.onchain_state WHERE fingerprint=(SELECT fingerprint FROM lpcc.enrollments WHERE node_id=$1)`, m.NodeID).Scan(&initialized); e != nil {
		s.databaseError(w, e)
		return
	}
	id := uuid.New().String()
	var revoked sql.NullTime
	e = tx.QueryRowContext(r.Context(), `INSERT INTO lpcc.onchain_grants(grant_id,node_id,onchain_generation,config_digest,pod_uid,launch_id,process_id) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(node_id,onchain_generation,pod_uid,launch_id,process_id) DO UPDATE SET grant_id=lpcc.onchain_grants.grant_id RETURNING grant_id::text,revoked_at`, id, m.NodeID, in.OnchainGeneration, in.ConfigDigest, in.PodUID, in.LaunchID, in.ProcessID).Scan(&id, &revoked)
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
	respond(w, 200, consumer.Grant{Association: consumer.Association{Launch: in.Launch, NodeID: m.NodeID, CredentialVersion: m.CredentialVersion, OnchainGeneration: in.OnchainGeneration, ConfigDigest: in.ConfigDigest, GrantID: id}, RequireState: initialized, RPCURL: string(rpc), Headers: "Authorization: Bearer " + s.submissionToken(id)})
}

func (s *Server) redemptionAuthorize(w http.ResponseWriter, r *http.Request) {
	secret := s.params.OnchainWebhookSecret
	if len(secret) < 32 || len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(secret)) != 1 {
		fail(w, 401, "webhook authentication required")
		return
	}
	var in struct {
		Headers http.Header     `json:"headers"`
		Ticket  json.RawMessage `json:"ticket"`
	}
	if s.params.DevelopmentHTTP || appInput(r, &in) != nil {
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
	allowed := count == 1 && ok && appID(id) && len(s.params.MachineTokenSecret) >= 32 && hmac.Equal([]byte(token), []byte(s.submissionToken(id))) && json.Unmarshal(in.Ticket, &ticket) == nil && onchain.Address.MatchString(ticket.Recipient)
	if allowed {
		var recipient string
		e := s.db.QueryRowContext(r.Context(), `SELECT v.config->>'recipient' FROM lpcc.onchain_grants g JOIN lpcc.enrollments e ON e.node_id=g.node_id JOIN lpcc.onchain_configs v ON v.fingerprint=e.fingerprint AND v.generation=g.onchain_generation JOIN lpcc.machines m ON m.node_id=g.node_id WHERE g.grant_id=$1 AND g.revoked_at IS NULL AND m.tunnel_eligible`, id).Scan(&recipient)
		allowed = e == nil && strings.EqualFold(recipient, ticket.Recipient)
	}
	status := 403
	if allowed {
		status = 200
	}
	respond(w, 200, map[string]int{"status": status})
}
