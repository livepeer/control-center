package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"uuid"

	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
)

func (s *Server) enrollmentToken(m Machine) string {
	if m.CredentialVersion == 0 {
		return machineToken(s.params.MachineTokenSecret, m.OwnerID, m.NodeID)
	}
	mac := hmac.New(sha256.New, []byte(s.params.MachineTokenSecret))
	mac.Write([]byte("machine:v2:" + m.OwnerID + ":" + m.NodeID + ":" + m.Epoch + ":" + strconv.FormatInt(m.CredentialVersion, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}
func (s *Server) authenticateMachine(ctx context.Context, node, token string, retired bool) (Machine, error) {
	if !fingerprintPattern.MatchString(token) {
		return Machine{}, problem(401, "invalid_machine_credential", "Invalid machine credential.")
	}
	rows, e := s.db.QueryContext(ctx, `SELECT node_id,epoch::text,owner_id::text,fingerprint,hostname,install_dir,k3s_version,credential_version,retired_at IS NOT NULL FROM lpcc.enrollments WHERE node_id=$1`, node)
	if e != nil {
		return Machine{}, e
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var m Machine
		if e := rows.Scan(&m.NodeID, &m.Epoch, &m.OwnerID, &m.Fingerprint, &m.Hostname, &m.InstallDir, &m.K3sVersion, &m.CredentialVersion, &m.Terminal); e != nil {
			return m, e
		}
		found = true
		if hmac.Equal([]byte(token), []byte(s.enrollmentToken(m))) && (!m.Terminal || retired) {
			return m, nil
		}
	}
	if e := rows.Err(); e != nil {
		return Machine{}, e
	}
	if !found {
		return Machine{}, problem(404, "machine_not_found", "Machine not found.")
	}
	return Machine{}, problem(401, "invalid_machine_credential", "Invalid machine credential.")
}
func machineInput(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 16385))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil || dec.Decode(new(any)) != io.EOF {
		return problem(400, "invalid_request", "Provide one bounded machine request.")
	}
	return nil
}
func (s *Server) refreshCredentials(w http.ResponseWriter, r *http.Request) {
	owner, e := verifyEnrollment(s.params.JWTSigningSecret, bearer(r))
	if e != nil {
		fail(w, 401, "fresh owner enrollment token required")
		return
	}
	if !strings.HasPrefix(s.params.PublicAPIURL, "https://") {
		fail(w, 409, "credential refresh requires an HTTPS API")
		return
	}
	var in struct {
		Fingerprint     string `json:"fingerprint"`
		InstallDir      string `json:"install_dir"`
		OperationID     string `json:"operation_id"`
		ExpectedVersion int64  `json:"expected_credential_version"`
	}
	if e = machineInput(r, &in); e != nil {
		s.respondError(w, e)
		return
	}
	op, e := uuid.Parse(in.OperationID)
	if e != nil || op == (uuid.UUID{}) || in.ExpectedVersion < 0 {
		fail(w, 400, "invalid refresh operation")
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	defer tx.Rollback()
	var m Machine
	e = tx.QueryRowContext(r.Context(), `SELECT node_id,enrollment_epoch::text,owner_id::text,fingerprint,hostname,install_dir,k3s_version,credential_version FROM lpcc.machines WHERE node_id=$1 FOR UPDATE`, r.PathValue("node_id")).Scan(&m.NodeID, &m.Epoch, &m.OwnerID, &m.Fingerprint, &m.Hostname, &m.InstallDir, &m.K3sVersion, &m.CredentialVersion)
	if errors.Is(e, sql.ErrNoRows) {
		fail(w, 404, "machine not found")
		return
	}
	if e != nil {
		s.databaseError(w, e)
		return
	}
	if owner != m.OwnerID || in.Fingerprint != m.Fingerprint || in.InstallDir != m.InstallDir {
		fail(w, 403, "installation identity mismatch")
		return
	}
	var expected, result int64
	e = tx.QueryRowContext(r.Context(), `SELECT expected_version,resulting_version FROM lpcc.credential_refreshes WHERE node_id=$1 AND epoch=$2 AND operation_id=$3`, m.NodeID, m.Epoch, op.String()).Scan(&expected, &result)
	if e == nil {
		if expected != in.ExpectedVersion || result != m.CredentialVersion {
			fail(w, 409, "refresh operation is conflicting or superseded")
			return
		}
	} else if errors.Is(e, sql.ErrNoRows) {
		if in.ExpectedVersion != m.CredentialVersion {
			fail(w, 409, "credential version changed")
			return
		}
		m.CredentialVersion++
		if _, e = tx.ExecContext(r.Context(), `INSERT INTO lpcc.credential_refreshes(node_id,epoch,operation_id,expected_version,resulting_version) VALUES($1,$2,$3,$4,$5)`, m.NodeID, m.Epoch, op.String(), in.ExpectedVersion, m.CredentialVersion); e != nil {
			s.databaseError(w, e)
			return
		}
		if _, e = tx.ExecContext(r.Context(), `UPDATE lpcc.machines SET credential_version=$3,tunnel_eligible=true WHERE node_id=$1 AND enrollment_epoch=$2`, m.NodeID, m.Epoch, m.CredentialVersion); e != nil {
			s.databaseError(w, e)
			return
		}
		if _, e = tx.ExecContext(r.Context(), `UPDATE lpcc.enrollments SET credential_version=$3 WHERE node_id=$1 AND epoch=$2`, m.NodeID, m.Epoch, m.CredentialVersion); e != nil {
			s.databaseError(w, e)
			return
		}
	} else {
		s.databaseError(w, e)
		return
	}
	if e = tx.Commit(); e != nil {
		s.databaseError(w, e)
		return
	}
	respond(w, 200, s.machineCredentials(m))
}
func (s *Server) connectorToken(w http.ResponseWriter, r *http.Request) {
	m, e := s.authenticateMachine(r.Context(), r.PathValue("node_id"), bearer(r), false)
	if e != nil {
		s.respondError(w, e)
		return
	}
	if !s.params.CloudflareEnabled || !s.tunnels.Enabled() || m.CredentialVersion == 0 {
		fail(w, 403, "connector delivery is not enabled for this enrollment")
		return
	}
	state, _, e := s.loadTunnel(r.Context(), m.NodeID, m.Epoch)
	if e != nil {
		s.respondError(w, e)
		return
	}
	safe, e := s.tunnels.SecureRuntime(r.Context(), tunnelMachine(m))
	if e != nil {
		s.databaseError(w, e)
		return
	}
	if !safe || state.Lifecycle != "active" || state.TunnelID == "" || state.IngressDigest == "" {
		fail(w, 409, "secure configuration is not applied")
		return
	}
	token, e := s.tunnels.ConnectorToken(r.Context(), state)
	if e != nil {
		fail(w, 503, "connector credential temporarily unavailable")
		return
	}
	// Revalidate after the provider call so retirement/refresh cannot race delivery.
	if _, e = s.authenticateMachine(r.Context(), m.NodeID, bearer(r), false); e != nil {
		s.respondError(w, e)
		return
	}
	latest, _, e := s.loadTunnel(r.Context(), m.NodeID, m.Epoch)
	if e != nil || latest.Lifecycle != "active" || latest.TunnelID != state.TunnelID || latest.CredentialGeneration != state.CredentialGeneration || latest.RotateTunnel {
		fail(w, 409, "tunnel changed during credential retrieval")
		return
	}
	respond(w, 200, map[string]any{"token": token, "epoch": m.Epoch, "tunnel_id": state.TunnelID, "generation": state.Generation, "credential_generation": state.CredentialGeneration, "provider_version": state.ProviderVersion})
}
func (s *Server) machineStatus(w http.ResponseWriter, r *http.Request) {
	m, e := s.authenticateMachine(r.Context(), r.PathValue("node_id"), bearer(r), false)
	if e != nil {
		s.respondError(w, e)
		return
	}
	if m.CredentialVersion == 0 {
		fail(w, 403, "legacy credentials authorize configuration only; refresh over HTTPS")
		return
	}
	var report tunnel.MachineReport
	if e = machineInput(r, &report); e != nil {
		s.respondError(w, e)
		return
	}
	if report.Epoch != m.Epoch || report.CredentialVersion != m.CredentialVersion || report.Generation < 1 || (report.Component != "runtime" && report.Component != "connector" && report.Component != "runner") {
		fail(w, 409, "status does not match enrollment")
		return
	}
	if (report.BundleSHA256 != "" && !fingerprintPattern.MatchString(report.BundleSHA256)) || (report.ConfigDigest != "" && !fingerprintPattern.MatchString(report.ConfigDigest)) {
		fail(w, 400, "invalid status digest")
		return
	}
	desiredGeneration := int64(1)
	if state, _, err := s.loadTunnel(r.Context(), m.NodeID, m.Epoch); err == nil {
		desiredGeneration = state.Generation
	} else {
		var pending *apiProblem
		if !errors.As(err, &pending) || pending.status != 409 {
			s.respondError(w, err)
			return
		}
	}
	if report.Generation > desiredGeneration {
		fail(w, 409, "status generation is ahead of desired state")
		return
	}
	reasons := map[string]bool{"ready": true, "applying": true, "offline": true, "failed": true, "drain_pending": true, "removed": true, "tls_pending": true}
	if !reasons[report.Reason] {
		report.Reason = "failed"
	}
	b, _ := json.Marshal(report)
	result, e := s.db.ExecContext(r.Context(), `INSERT INTO lpcc.machine_reports(node_id,epoch,component,generation,credential_version,report) SELECT $1,$2,$3,$4,$5,$6 WHERE EXISTS(SELECT FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2 AND credential_version=$5) ON CONFLICT(node_id,epoch,component) DO UPDATE SET generation=EXCLUDED.generation,credential_version=EXCLUDED.credential_version,report=EXCLUDED.report,received_at=now() WHERE lpcc.machine_reports.generation<=EXCLUDED.generation AND lpcc.machine_reports.credential_version<=EXCLUDED.credential_version`, m.NodeID, m.Epoch, report.Component, report.Generation, m.CredentialVersion, b)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		fail(w, 409, "stale status")
		return
	}
	if report.Component == "runner" && report.Drained && !s.params.CloudflareEnabled {
		if _, e = s.db.ExecContext(r.Context(), `DELETE FROM lpcc.machines m USING lpcc.machine_tunnels t WHERE m.node_id=$1 AND m.enrollment_epoch=$2 AND m.credential_version=$4 AND t.node_id=m.node_id AND t.epoch=m.enrollment_epoch AND t.state->>'lifecycle'='draining' AND (t.state->>'generation')::bigint=$3 AND now()<=(t.state->>'drain_started_at')::timestamptz+make_interval(secs=>$5)`, m.NodeID, m.Epoch, report.Generation, m.CredentialVersion, s.params.TunnelDrainTimeout.Seconds()); e != nil {
			s.databaseError(w, e)
			return
		}
	}
	respond(w, 200, map[string]string{"status": "accepted"})
}
func (s *Server) removalAck(w http.ResponseWriter, r *http.Request) {
	m, e := s.authenticateMachine(r.Context(), r.PathValue("node_id"), bearer(r), true)
	if e != nil {
		s.respondError(w, e)
		return
	}
	var in struct {
		Epoch           string `json:"epoch"`
		Digest          string `json:"digest"`
		ConnectorAbsent bool   `json:"connector_absent"`
	}
	if e = machineInput(r, &in); e != nil {
		s.respondError(w, e)
		return
	}
	if !m.Terminal || in.Epoch != m.Epoch || !in.ConnectorAbsent || !fingerprintPattern.MatchString(in.Digest) {
		fail(w, 409, "invalid removal acknowledgement")
		return
	}
	result, e := s.db.ExecContext(r.Context(), `UPDATE lpcc.enrollments SET removal_ack_at=COALESCE(removal_ack_at,now()) WHERE node_id=$1 AND epoch=$2 AND retired_at IS NOT NULL AND terminal_sha256=$3`, m.NodeID, m.Epoch, in.Digest)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		fail(w, 409, "terminal digest mismatch")
		return
	}
	respond(w, 200, map[string]string{"status": "removed"})
}

// RetireMachine is the shared #111 removal operation. Its caller must authorize
// administrator policy in the same transaction when exposed through an API.
func (s *Server) RetireMachine(ctx context.Context, node string) error {
	_, e := s.db.ExecContext(ctx, `DELETE FROM lpcc.machines WHERE node_id=$1`, node)
	return e
}
