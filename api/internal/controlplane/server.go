package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base32"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fleet "github.com/livepeer/control-center/api/internal/controlplane/discovery"
	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
	"github.com/livepeer/control-center/api/internal/migrations"
	protocol "github.com/livepeer/control-center/secrets"
)

//go:embed migrations/*.sql
var MigrationFiles embed.FS

type Machine struct {
	PublicKey           string     `json:"public_key,omitempty"`
	Signature           []byte     `json:"signature,omitempty"`
	NodeID              string     `json:"node_id"`
	OrchestratorAddress string     `json:"-"`
	EnrolledByUserID    string     `json:"-"`
	Fingerprint         string     `json:"fingerprint"`
	Hostname            string     `json:"hostname"`
	InstallDir          string     `json:"install_dir"`
	K3sVersion          string     `json:"k3s_version"`
	CreatedAt           time.Time  `json:"created_at"`
	LastConfigFetchAt   *time.Time `json:"last_config_fetch_at"`
	CredentialVersion   int64      `json:"-"`
	Terminal            bool       `json:"-"`
	DevelopmentHTTP     bool       `json:"development_http,omitempty"`
}

type Server struct {
	now            func() time.Time
	grantsIssued   atomic.Uint64
	grantsRejected atomic.Uint64
	db             *sql.DB
	params         Params
	logger         *slog.Logger
	client         *http.Client
	build          func(machineconfig.Desired) ([]byte, string, error)
	denialMu       sync.Mutex
	denials        map[AdminAction]denialWindow
	tunnels        *tunnel.Manager
	configs        *machineconfig.Manager
	discovery      *fleet.Manager
	reconcileWake  chan struct{}
	activeCheck    func(context.Context, string) (bool, error)
}

func New(db *sql.DB, p Params, logger *slog.Logger) *Server {
	s := &Server{db: db, params: p, logger: logger, build: machineconfig.Build, reconcileWake: make(chan struct{}, 1), client: &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	s.configs = s.newConfigurationManager()
	s.tunnels = s.newTunnelManager(tunnel.Dependencies{})
	return s
}

func Migrate(ctx context.Context, db *sql.DB) error {
	files, err := fs.Sub(MigrationFiles, "migrations")
	if err != nil {
		return err
	}
	return migrations.Up(ctx, db, files)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if s.db.PingContext(ctx) != nil {
			fail(w, 503, "database unavailable")
			return
		}
		respond(w, 200, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]string{"supabase_url": s.params.SupabaseURL, "supabase_publishable_key": s.params.SupabasePublishableKey})
	})
	mux.HandleFunc("GET /api/operator/config", s.operatorConfig)
	mux.HandleFunc("GET /api/operator/apps", s.operatorApps)
	mux.HandleFunc("PUT /api/operator/apps/{name}/policy", s.operatorPolicy)
	mux.HandleFunc("GET /internal/secrets/nodes/{node_id}", s.secretMachine)
	mux.HandleFunc("POST /internal/secrets/nodes/{node_id}", s.secretMachine)
	mux.HandleFunc("POST /api/bootstrap-token", s.bootstrapToken)
	mux.HandleFunc("POST /api/bootstrap-token/revoke", s.revokeEnrollmentGrant)
	mux.HandleFunc("GET /metrics", s.enrollmentMetrics)
	mux.HandleFunc("GET /api/orchestrators", s.listOrchestrators)
	mux.HandleFunc("POST /api/orchestrators/challenge", s.orchestratorChallenge)
	mux.HandleFunc("POST /api/orchestrators", s.createOrchestrator)
	mux.HandleFunc("GET /api/orchestrators/{address}/members", s.listMembers)
	mux.HandleFunc("DELETE /api/orchestrators/{address}/members/{user_id}", s.removeMember)
	mux.HandleFunc("POST /api/orchestrators/{address}/invitations", s.issueInvitation)
	mux.HandleFunc("POST /api/orchestrator-invitations/preview", s.previewInvitation)
	mux.HandleFunc("POST /api/orchestrator-invitations/accept", s.acceptInvitation)
	mux.HandleFunc("GET /internal/users/{user_id}/orchestrators/{address}", s.orchestratorMembership)
	mux.HandleFunc("GET /api/machines", s.listMachines)
	mux.HandleFunc("GET /api/machines/{node_id}/status", s.observedState)
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("GET /api/admin/administrators", s.adminRead(s.listAdministrators))
	mux.HandleFunc("GET /api/admin/deployment", s.adminRead(s.deployment))
	mux.HandleFunc("POST /api/admin/administrators", s.adminMutation("administrator.grant", s.prepareGrant))
	mux.HandleFunc("DELETE /api/admin/administrators/{grant_id}", s.adminMutation("administrator.revoke", s.prepareRevoke))
	mux.HandleFunc("GET /api/admin/machines", s.adminRead(s.fleetMachines))
	mux.HandleFunc("GET /discovery", s.discoveryHTTP)
	mux.HandleFunc("GET /api/admin/discovery", s.adminRead(func(w http.ResponseWriter, r *http.Request, _ UserIdentity) {
		respond(w, http.StatusOK, s.DiscoveryStatus())
	}))
	mux.HandleFunc("DELETE /api/admin/machines/{node_id}", s.adminMutation("machine.remove", s.prepareMachineRemoval))
	mux.HandleFunc("POST /api/admin/machines/{node_id}/tunnel/rotate", s.adminMutation("tunnel.rotate", s.prepareTunnelRotation))
	mux.HandleFunc("POST /api/admin/machines/{node_id}/drain/retry", s.adminMutation("machine.drain.retry", s.prepareDrainRetry))
	mux.HandleFunc("GET /api/admin/apps", s.adminRead(s.listApps))
	mux.HandleFunc("POST /api/admin/apps/validate", s.adminRead(s.validateApp))
	mux.HandleFunc("POST /api/admin/apps", s.adminMutation("app.create", s.prepareCreateApp))
	mux.HandleFunc("GET /api/admin/apps/{name}", s.adminRead(s.inspectApp))
	mux.HandleFunc("POST /api/admin/apps/{name}/revisions", s.adminMutation("app.publish", s.preparePublishApp))
	mux.HandleFunc("GET /api/admin/apps/{name}/revisions/{revision_id}", s.adminRead(s.inspectAppRevision))
	mux.HandleFunc("POST /api/admin/apps/{name}/revisions/{revision_id}/retire", s.adminMutation("app.retire", s.prepareRetireApp))
	mux.HandleFunc("GET /api/admin/machines/{node_id}/apps", s.adminRead(s.listAssignments))
	mux.HandleFunc("GET /api/admin/machines/{node_id}/apps/{revision_id}", s.adminRead(s.inspectAssignment))
	mux.HandleFunc("PUT /api/admin/machines/{node_id}/apps/{revision_id}", s.adminMutation("assignment.put", s.prepareAssignment))
	mux.HandleFunc("DELETE /api/admin/machines/{node_id}/apps/{revision_id}", s.adminMutation("assignment.remove", s.prepareAssignment))
	mux.HandleFunc("POST /api/admin/machines/{node_id}/apps/{revision_id}/replace", s.adminMutation("assignment.replace", s.prepareAssignment))
	mux.HandleFunc("POST /v1/nodes/{node_id}/apps/{revision_id}/status", s.assignmentStatus)
	mux.HandleFunc("POST /v1/nodes/register", s.register)
	mux.HandleFunc("GET /v1/nodes/{node_id}/config", s.configuration)
	mux.HandleFunc("POST /v1/nodes/{node_id}/onchain/credentials", s.onchainCredentials)
	mux.HandleFunc("POST /internal/redemption/authorize", s.redemptionAuthorize)
	mux.HandleFunc("POST /v1/nodes/{node_id}/credentials/refresh", s.refreshCredentials)
	mux.HandleFunc("POST /v1/nodes/{node_id}/tunnel/connector-token", s.connectorToken)
	mux.HandleFunc("POST /v1/nodes/{node_id}/status", s.machineStatus)
	mux.HandleFunc("POST /v1/nodes/{node_id}/removal-ack", s.removalAck)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Livepeer-Tunnels-Enabled", strconv.FormatBool(s.params.CloudflareEnabled))
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) operatorConfig(w http.ResponseWriter, r *http.Request) {
	if _, err := s.user(r.Context(), bearer(r)); err != nil {
		s.respondError(w, err)
		return
	}
	respond(w, 200, map[string]string{"public_api_url": s.params.PublicAPIURL, "secrets_url": s.params.SecretsURL, "mode": s.params.networkMode()})
}

func (s *Server) bootstrapToken(w http.ResponseWriter, r *http.Request) {
	owner, err := s.user(r.Context(), bearer(r))
	if err != nil {
		s.grantsRejected.Add(1)
		s.respondError(w, err)
		return
	}
	var in struct {
		Address string `json:"orchestrator_address"`
	}
	if boundedInput(r, &in, 4096) != nil {
		s.respondError(w, problem(400, "invalid_orchestrator", "Choose an orchestrator."))
		return
	}
	address, err := protocol.OrchestratorAddress(in.Address)
	if err != nil {
		s.respondError(w, problem(400, "invalid_orchestrator", "Choose an orchestrator."))
		return
	}
	yes, err := member(r.Context(), s.db, owner.ID, address)
	if err != nil {
		s.respondError(w, err)
		return
	}
	if !yes {
		s.respondError(w, problem(403, "orchestrator_access_required", "Orchestrator access is required."))
		return
	}
	if s.params.networkMode() == "onchain" {
		active, e := s.checkActive(r.Context(), address)
		if e != nil {
			s.respondError(w, problem(503, "chain_unavailable", "Could not verify orchestrator activity. Try again."))
			return
		}
		if !active {
			s.respondError(w, problem(403, "orchestrator_inactive", "Orchestrator is not active on chain."))
			return
		}
	}
	// The chain lookup can outlive membership. Hold authorization through signing
	// so a committed removal prevents issuance and serializes with consumption.
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.respondError(w, err)
		return
	}
	defer tx.Rollback()
	if err = lockMembership(r.Context(), tx, owner.ID, address); err != nil {
		s.respondError(w, err)
		return
	}
	token, expires, err := s.params.signEnrollment(owner.ID, address, s.currentTime())
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		fail(w, 500, "could not issue enrollment token")
		return
	}
	s.grantsIssued.Add(1)
	respond(w, 200, map[string]any{"token": token, "expires_at": expires})
}

func (s *Server) listMachines(w http.ResponseWriter, r *http.Request) {
	owner, err := s.user(r.Context(), bearer(r))
	if err != nil {
		s.respondError(w, err)
		return
	}
	address, err := s.orchestrator(r, owner.ID)
	if err != nil {
		s.respondError(w, err)
		return
	}
	machines, err := s.observedMachineList(r.Context(), address, false)
	if err != nil {
		s.databaseError(w, err)
		return
	}
	respond(w, 200, map[string]any{"machines": machines})
}

var fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var installDirPattern = regexp.MustCompile(`^/[a-zA-Z0-9_./-]+$`)
var versionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$`)

func validMachine(m Machine) bool {
	if !fingerprintPattern.MatchString(m.Fingerprint) || len(m.Hostname) == 0 || len(m.Hostname) > 253 || strings.ContainsAny(m.Hostname, "\r\n\x00") {
		return false
	}
	if !installDirPattern.MatchString(m.InstallDir) || strings.HasSuffix(m.InstallDir, "/") {
		return false
	}
	for _, part := range strings.Split(m.InstallDir, "/")[1:] {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return versionPattern.MatchString(m.K3sVersion)
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	grant, err := s.params.enrollmentGrant(bearer(r), s.currentTime(), false)
	if err != nil {
		fail(w, 401, err.Error())
		return
	}
	var m Machine
	if appInput(r, &m) != nil {
		fail(w, 400, "invalid machine registration")
		return
	}
	if !validMachine(m) {
		fail(w, 400, "invalid machine metadata")
		return
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		fail(w, 500, "cannot generate node identity")
		return
	}
	m.NodeID = strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id[:]))
	owner := grant.OrchestratorAddress
	m.OrchestratorAddress = owner
	m.EnrolledByUserID = grant.Subject
	newNodeID := m.NodeID
	pub, e := protocol.PublicKey(m.PublicKey)
	if e != nil || !ed25519.Verify(pub, protocol.RegistrationProof(bearer(r), m.Fingerprint, m.Hostname, m.InstallDir, m.K3sVersion, m.PublicKey, m.DevelopmentHTTP), m.Signature) {
		fail(w, 403, "runtime key proof required")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.databaseError(w, err)
		return
	}
	defer tx.Rollback()
	if err = s.acceptEnrollmentGrant(r.Context(), tx, grant); err != nil {
		s.respondError(w, err)
		return
	}
	// An active installation retains its ID on retry. A retired installation gets
	// a fresh ID; its retained cleanup records remain scoped to the previous ID.
	row := tx.QueryRowContext(r.Context(), `INSERT INTO lpcc.machines(node_id,fingerprint,orchestrator_address,enrolled_by_user_id,hostname,install_dir,k3s_version,credential_version,tunnel_eligible) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8)
 ON CONFLICT(fingerprint) DO UPDATE SET hostname=EXCLUDED.hostname,updated_at=now()
 WHERE lpcc.machines.orchestrator_address=EXCLUDED.orchestrator_address AND lpcc.machines.fingerprint=EXCLUDED.fingerprint
	 AND lpcc.machines.install_dir=EXCLUDED.install_dir AND lpcc.machines.k3s_version=EXCLUDED.k3s_version
 RETURNING node_id,credential_version`, m.NodeID, m.Fingerprint, owner, m.EnrolledByUserID, m.Hostname, m.InstallDir, m.K3sVersion, strings.HasPrefix(s.params.PublicAPIURL, "https://") && !m.DevelopmentHTTP)
	err = row.Scan(&m.NodeID, &m.CredentialVersion)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 409, "machine already registered with a different owner or installation")
		return
	}
	if err != nil {
		s.databaseError(w, err)
		return
	}
	// A random collision with a retained node must fail, never reuse cleanup state.
	if err = tx.QueryRowContext(r.Context(), `INSERT INTO lpcc.enrollments(node_id,orchestrator_address,enrolled_by_user_id,fingerprint,hostname,install_dir,k3s_version,credential_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
 ON CONFLICT(node_id) DO UPDATE SET hostname=EXCLUDED.hostname
 WHERE lpcc.enrollments.retired_at IS NULL AND lpcc.enrollments.orchestrator_address=EXCLUDED.orchestrator_address AND lpcc.enrollments.fingerprint=EXCLUDED.fingerprint
 RETURNING node_id`, m.NodeID, m.OrchestratorAddress, m.EnrolledByUserID, m.Fingerprint, m.Hostname, m.InstallDir, m.K3sVersion, m.CredentialVersion).Scan(&m.NodeID); err != nil {
		s.databaseError(w, err)
		return
	}
	if m.NodeID != newNodeID {
		var public string
		e := tx.QueryRowContext(r.Context(), `SELECT public_key FROM lpcc.secret_machines WHERE node_id=$1 FOR UPDATE`, m.NodeID).Scan(&public)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			s.databaseError(w, e)
			return
		}
		if public != m.PublicKey {
			fail(w, 409, "existing installation requires its bound key")
			return
		}
	}
	if _, e := tx.ExecContext(r.Context(), `INSERT INTO lpcc.secret_machines(node_id,public_key) VALUES($1,$2) ON CONFLICT(node_id) DO NOTHING`, m.NodeID, m.PublicKey); e != nil {
		s.databaseError(w, e)
		return
	}
	config, _, err := s.syncOnchainConfig(r.Context(), tx, m.Fingerprint, owner)
	if err != nil {
		s.databaseError(w, err)
		return
	}
	desired := s.configs.Desired(configurationMachine(m), machineconfig.InitialState(false), nil)
	desired.Onchain, desired.OnchainError = config, nil
	data, digest, err := s.build(desired)
	if err != nil {
		fail(w, 503, "configuration generation failed")
		return
	}
	// Preserve an existing bundle; the backend reconciler owns later updates.
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO lpcc.machine_configs(node_id,bundle,sha256) VALUES($1,$2,$3) ON CONFLICT(node_id) DO NOTHING`, m.NodeID, data, digest); err != nil {
		s.databaseError(w, err)
		return
	}
	if m.NodeID == newNodeID {
		if _, err = tx.ExecContext(r.Context(), `INSERT INTO lpcc.enrollment_audit(actor_user_id,orchestrator_address,action,target) VALUES($1,$2,'machine.enroll',$3)`, grant.Subject, owner, m.NodeID); err != nil {
			s.databaseError(w, err)
			return
		}
	}
	if !s.currentTime().Before(grant.ExpiresAt.Time) {
		fail(w, 401, "enrollment grant expired")
		return
	}
	if err := tx.Commit(); err != nil {
		s.databaseError(w, err)
		return
	}
	respond(w, 200, s.machineCredentials(m))
}

func (s *Server) machineCredentials(m Machine) map[string]any {
	return map[string]any{"node_id": m.NodeID, "credential_version": m.CredentialVersion, "token": s.enrollmentToken(m), "config_url": strings.TrimRight(s.params.PublicAPIURL, "/") + "/v1/nodes/" + m.NodeID + "/config"}
}

func (s *Server) configuration(w http.ResponseWriter, r *http.Request) {
	m, err := s.authenticateMachine(r.Context(), r.PathValue("node_id"), bearer(r), true)
	if err != nil {
		s.respondError(w, err)
		return
	}
	var digest string
	var data []byte
	if m.Terminal {
		err = s.db.QueryRowContext(r.Context(), `SELECT terminal_bundle,terminal_sha256 FROM lpcc.enrollments WHERE node_id=$1 AND terminal_bundle IS NOT NULL`, m.NodeID).Scan(&data, &digest)
	} else {
		// The target row's credential fence is rechecked after any concurrent refresh
		// or retirement releases its lock. A missing bundle must not mark a fetch.
		err = s.db.QueryRowContext(r.Context(), `UPDATE lpcc.machines m SET last_config_fetch_at=now()
 FROM lpcc.machine_configs c WHERE m.node_id=$1 AND m.credential_version=$2
 AND m.orchestrator_address=$3 AND c.node_id=m.node_id
 RETURNING c.bundle,c.sha256`, m.NodeID, m.CredentialVersion, m.OrchestratorAddress).Scan(&data, &digest)
	}
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "machine configuration not found")
		return
	}
	if err != nil {
		s.databaseError(w, err)
		return
	}
	if m.Terminal {
		if _, err := s.db.ExecContext(r.Context(), `UPDATE lpcc.machines SET last_config_fetch_at=now() WHERE node_id=$1`, m.NodeID); err != nil {
			s.databaseError(w, err)
			return
		}
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("ETag", `"`+digest+`"`)
	w.Header().Set("X-Livepeer-Node-ID", m.NodeID)
	if m.Terminal {
		pending, err := machineapps.Pending(r.Context(), s.db, m.NodeID)
		if err != nil {
			s.databaseError(w, err)
			return
		}
		if !pending {
			w.Header().Set("X-Livepeer-App-Cleanup-Ready", "true")
		}
	}
	w.Header().Set("X-Livepeer-Credential-Version", strconv.FormatInt(m.CredentialVersion, 10))
	w.Header().Set("X-Livepeer-Terminal", strconv.FormatBool(m.Terminal))
	w.WriteHeader(200)
	w.Write(data)
}

func (s *Server) databaseError(w http.ResponseWriter, err error) {
	s.logger.Error("database operation failed", "error", err)
	fail(w, 503, "database temporarily unavailable")
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}
