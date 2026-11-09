package controlplane

import (
	"bytes"
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

	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
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
	return boundedMachineInput(r, v, 16384)
}
func boundedMachineInput(r *http.Request, v any, limit int64) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return problem(400, "invalid_request", "Provide one bounded machine request.")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
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
		if e = s.configs.FenceCredentialRefresh(r.Context(), tx, m.NodeID, m.Epoch); e != nil {
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
	s.requestReconcile()
	respond(w, 200, s.machineCredentials(m))
}
func (s *Server) connectorToken(w http.ResponseWriter, r *http.Request) {
	m, e := s.authenticateMachine(r.Context(), r.PathValue("node_id"), bearer(r), true)
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
	retained, e := s.retainedConnector(r.Context(), m, state.BundleFormat)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	if m.Terminal && !retained {
		fail(w, 401, "invalid machine credential")
		return
	}
	safe := retained
	if !m.Terminal {
		safe, e = s.tunnels.SecureRuntime(r.Context(), configurationMachine(m))
	}
	if e != nil {
		s.databaseError(w, e)
		return
	}
	if !safe || (!retained && state.Lifecycle != "active") || state.TunnelID == "" || state.IngressDigest == "" || state.RotateTunnel || state.Compromised || (m.Terminal && state.CompromisedAccess) || state.Quarantined || state.ConnectorRevoked {
		fail(w, 409, "secure configuration is not applied")
		return
	}
	token, e := s.tunnels.ConnectorToken(r.Context(), state.RoutingState)
	if e != nil {
		fail(w, 503, "connector credential temporarily unavailable")
		return
	}
	// Revalidate after the provider call so retirement/refresh cannot race delivery.
	if _, e = s.authenticateMachine(r.Context(), m.NodeID, bearer(r), true); e != nil {
		s.respondError(w, e)
		return
	}
	latest, _, e := s.loadTunnel(r.Context(), m.NodeID, m.Epoch)
	stillRetained, retainErr := s.retainedConnector(r.Context(), m, latest.BundleFormat)
	if e != nil || retainErr != nil || (m.Terminal && (!stillRetained || latest.CompromisedAccess)) || (!stillRetained && latest.Lifecycle != "active") || latest.TunnelID != state.TunnelID || latest.CredentialGeneration != state.CredentialGeneration || latest.RotateTunnel || latest.Compromised || latest.Quarantined || latest.ConnectorRevoked {
		fail(w, 409, "tunnel changed during credential retrieval")
		return
	}
	respond(w, 200, map[string]any{"token": token, "epoch": m.Epoch, "tunnel_id": state.TunnelID, "generation": state.Generation, "credential_generation": state.CredentialGeneration, "provider_version": state.ProviderVersion})
}
func (s *Server) retainedConnector(ctx context.Context, m Machine, format int) (bool, error) {
	if !m.Terminal || format < 2 {
		return false, nil
	}
	return machineapps.Pending(ctx, s.db, m.NodeID, m.Epoch)
}
func (s *Server) machineStatus(w http.ResponseWriter, r *http.Request) {
	m, e := s.authenticateMachine(r.Context(), r.PathValue("node_id"), bearer(r), true)
	if e != nil {
		s.respondError(w, e)
		return
	}
	if m.CredentialVersion == 0 {
		fail(w, 403, "legacy credentials authorize configuration only; refresh over HTTPS")
		return
	}
	var report machineconfig.Report
	if e = boundedMachineInput(r, &report, 128<<10); e != nil {
		s.respondError(w, e)
		return
	}
	if report.Epoch != m.Epoch || report.CredentialVersion != m.CredentialVersion || report.Generation < 1 || (report.Component != "runtime" && report.Component != "connector" && report.Component != "runner" && report.Component != "app-reconciler") {
		fail(w, 409, "status does not match enrollment")
		return
	}
	if (report.BundleSHA256 != "" && !fingerprintPattern.MatchString(report.BundleSHA256)) || (report.ConfigDigest != "" && !fingerprintPattern.MatchString(report.ConfigDigest)) {
		fail(w, 400, "invalid status digest")
		return
	}
	wake, err := s.configs.RecordReport(r.Context(), configurationMachine(m), report)
	if err != nil {
		if errors.Is(err, machineconfig.ErrReportOrder) {
			fail(w, http.StatusPreconditionFailed, err.Error())
		} else if errors.Is(err, machineconfig.ErrStatusAhead) || errors.Is(err, machineconfig.ErrStaleStatus) {
			fail(w, 409, err.Error())
		} else {
			s.databaseError(w, err)
		}
		return
	}
	if wake {
		s.requestReconcile()
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
	pending, e := machineapps.Pending(r.Context(), s.db, m.NodeID, m.Epoch)
	if e != nil {
		s.respondError(w, e)
		return
	}
	if pending {
		fail(w, 409, "app cleanup is incomplete")
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
