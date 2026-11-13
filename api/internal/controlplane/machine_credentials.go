package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
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
	mac := hmac.New(sha256.New, []byte(s.params.MachineTokenSecret))
	mac.Write([]byte("machine:v2:" + m.OwnerID + ":" + m.NodeID + ":" + strconv.FormatInt(m.CredentialVersion, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}
func (s *Server) authenticateMachine(ctx context.Context, node, token string, retired bool) (Machine, error) {
	if !fingerprintPattern.MatchString(token) {
		return Machine{}, problem(401, "invalid_machine_credential", "Invalid machine credential.")
	}
	var m Machine
	e := s.db.QueryRowContext(ctx, `SELECT node_id,owner_id::text,fingerprint,hostname,install_dir,k3s_version,credential_version,retired_at IS NOT NULL FROM lpcc.enrollments WHERE node_id=$1`, node).Scan(&m.NodeID, &m.OwnerID, &m.Fingerprint, &m.Hostname, &m.InstallDir, &m.K3sVersion, &m.CredentialVersion, &m.Terminal)
	if errors.Is(e, sql.ErrNoRows) {
		return m, problem(404, "machine_not_found", "Machine not found.")
	}
	if e != nil {
		return m, e
	}
	if !hmac.Equal([]byte(token), []byte(s.enrollmentToken(m))) || m.Terminal && !retired {
		return m, problem(401, "invalid_machine_credential", "Invalid machine credential.")
	}
	return m, nil
}
func boundedInput(r *http.Request, out any, limit int64) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(raw)) > limit || jsonv2.Unmarshal(raw, out, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)) != nil {
		return problem(400, "invalid_request", "Provide one bounded JSON request with the documented fields.")
	}
	return nil
}
func (s *Server) refreshCredentials(w http.ResponseWriter, r *http.Request) {
	grant, e := s.params.enrollmentGrant(bearer(r), s.currentTime(), false)
	if e != nil {
		fail(w, 401, "fresh owner enrollment token required")
		return
	}
	if !strings.HasPrefix(s.params.PublicAPIURL, "https://") {
		fail(w, 409, "credential refresh requires an HTTPS API")
		return
	}
	var in struct {
		ManagementProof string `json:"management_proof"`
		Fingerprint     string `json:"fingerprint"`
		InstallDir      string `json:"install_dir"`
		OperationID     string `json:"operation_id"`
		ExpectedVersion int64  `json:"expected_credential_version"`
	}
	if e = appInput(r, &in); e != nil {
		s.respondError(w, e)
		return
	}
	op, e := uuid.Parse(in.OperationID)
	if e != nil || op == (uuid.UUID{}) || in.ExpectedVersion < 1 {
		fail(w, 400, "invalid refresh operation")
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	defer tx.Rollback()
	if e = s.acceptEnrollmentGrant(r.Context(), tx, grant); e != nil {
		s.respondError(w, e)
		return
	}
	var m Machine
	e = tx.QueryRowContext(r.Context(), `SELECT node_id,owner_id::text,fingerprint,hostname,install_dir,k3s_version,credential_version FROM lpcc.machines WHERE node_id=$1 FOR UPDATE`, r.PathValue("node_id")).Scan(&m.NodeID, &m.OwnerID, &m.Fingerprint, &m.Hostname, &m.InstallDir, &m.K3sVersion, &m.CredentialVersion)
	if errors.Is(e, sql.ErrNoRows) {
		fail(w, 404, "machine not found")
		return
	}
	if e != nil {
		s.databaseError(w, e)
		return
	}
	if grant.Subject != m.OwnerID || in.Fingerprint != m.Fingerprint || in.InstallDir != m.InstallDir {
		fail(w, 403, "installation identity mismatch")
		return
	}
	var expected, result int64
	e = tx.QueryRowContext(r.Context(), `SELECT expected_version,resulting_version FROM lpcc.credential_refreshes WHERE node_id=$1 AND operation_id=$2`, m.NodeID, op.String()).Scan(&expected, &result)
	if e == nil {
		if expected != in.ExpectedVersion || result != m.CredentialVersion {
			fail(w, 409, "refresh operation is conflicting or superseded")
			return
		}
		previous := m
		previous.CredentialVersion = expected
		if !hmacEqual(in.ManagementProof, s.enrollmentToken(previous)) && !hmacEqual(in.ManagementProof, s.enrollmentToken(m)) {
			fail(w, 403, "saved management credential required")
			return
		}
	} else if errors.Is(e, sql.ErrNoRows) {
		if in.ExpectedVersion != m.CredentialVersion {
			fail(w, 409, "credential version changed")
			return
		}
		if !hmacEqual(in.ManagementProof, s.enrollmentToken(m)) {
			fail(w, 403, "saved management credential required")
			return
		}
		m.CredentialVersion++
		if _, e = tx.ExecContext(r.Context(), `INSERT INTO lpcc.credential_refreshes(node_id,operation_id,expected_version,resulting_version) VALUES($1,$2,$3,$4)`, m.NodeID, op.String(), in.ExpectedVersion, m.CredentialVersion); e != nil {
			s.databaseError(w, e)
			return
		}
		if _, e = tx.ExecContext(r.Context(), `UPDATE lpcc.machines SET credential_version=$2,tunnel_eligible=true WHERE node_id=$1`, m.NodeID, m.CredentialVersion); e != nil {
			s.databaseError(w, e)
			return
		}
		if _, e = tx.ExecContext(r.Context(), `UPDATE lpcc.enrollments SET credential_version=$2 WHERE node_id=$1`, m.NodeID, m.CredentialVersion); e != nil {
			s.databaseError(w, e)
			return
		}
		if e = s.configs.FenceCredentialRefresh(r.Context(), tx, m.NodeID); e != nil {
			s.databaseError(w, e)
			return
		}

	} else {
		s.databaseError(w, e)
		return
	}
	if !s.currentTime().Before(grant.ExpiresAt.Time) {
		fail(w, 401, "enrollment grant expired")
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
	if !s.params.CloudflareEnabled || !s.tunnels.Enabled() {
		fail(w, 403, "connector delivery is not enabled for this enrollment")
		return
	}
	state, _, e := s.loadTunnel(r.Context(), m.NodeID)
	if e != nil {
		s.respondError(w, e)
		return
	}
	retained, e := s.retainedConnector(r.Context(), m)
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
	latest, _, e := s.loadTunnel(r.Context(), m.NodeID)
	stillRetained, retainErr := s.retainedConnector(r.Context(), m)
	if e != nil || retainErr != nil || (m.Terminal && (!stillRetained || latest.CompromisedAccess)) || (!stillRetained && latest.Lifecycle != "active") || latest.TunnelID != state.TunnelID || latest.CredentialGeneration != state.CredentialGeneration || latest.RotateTunnel || latest.Compromised || latest.Quarantined || latest.ConnectorRevoked {
		fail(w, 409, "tunnel changed during credential retrieval")
		return
	}
	respond(w, 200, map[string]any{"token": token, "node_id": m.NodeID, "tunnel_id": state.TunnelID, "generation": state.Generation, "credential_generation": state.CredentialGeneration, "provider_version": state.ProviderVersion})
}
func (s *Server) retainedConnector(ctx context.Context, m Machine) (bool, error) {
	if !m.Terminal {
		return false, nil
	}
	return machineapps.Pending(ctx, s.db, m.NodeID)
}
func (s *Server) machineStatus(w http.ResponseWriter, r *http.Request) {
	m, e := s.authenticateMachine(r.Context(), r.PathValue("node_id"), bearer(r), true)
	if e != nil {
		s.respondError(w, e)
		return
	}
	var report machineconfig.Report
	if e = boundedInput(r, &report, 128<<10); e != nil {
		s.respondError(w, e)
		return
	}
	if report.NodeID != m.NodeID || report.CredentialVersion != m.CredentialVersion || report.Generation < 1 || (report.Component != "runtime" && report.Component != "connector" && report.Component != "runner" && report.Component != "app-reconciler") {
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
		NodeID          string `json:"node_id"`
		Digest          string `json:"digest"`
		ConnectorAbsent bool   `json:"connector_absent"`
	}
	if e = appInput(r, &in); e != nil {
		s.respondError(w, e)
		return
	}
	if !m.Terminal || in.NodeID != m.NodeID || !in.ConnectorAbsent || !fingerprintPattern.MatchString(in.Digest) {
		fail(w, 409, "invalid removal acknowledgement")
		return
	}
	pending, e := machineapps.Pending(r.Context(), s.db, m.NodeID)
	if e != nil {
		s.respondError(w, e)
		return
	}
	if pending {
		fail(w, 409, "app cleanup is incomplete")
		return
	}
	result, e := s.db.ExecContext(r.Context(), `UPDATE lpcc.enrollments SET removal_ack_at=COALESCE(removal_ack_at,now()) WHERE node_id=$1 AND retired_at IS NOT NULL AND terminal_sha256=$2`, m.NodeID, in.Digest)
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

// RetireMachine removes a machine. Its caller must authorize
// administrator policy in the same transaction when exposed through an API.
func (s *Server) RetireMachine(ctx context.Context, node string) error {
	_, e := s.db.ExecContext(ctx, `DELETE FROM lpcc.machines WHERE node_id=$1`, node)
	return e
}
