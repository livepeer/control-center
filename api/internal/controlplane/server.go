package controlplane

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	fleet "github.com/livepeer/control-center/api/internal/controlplane/discovery"
	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
	"github.com/livepeer/control-center/api/internal/migrations"
)

//go:embed migrations/*.sql
var MigrationFiles embed.FS

type Machine struct {
	NodeID            string     `json:"node_id"`
	OwnerID           string     `json:"-"`
	Fingerprint       string     `json:"fingerprint"`
	Hostname          string     `json:"hostname"`
	InstallDir        string     `json:"install_dir"`
	K3sVersion        string     `json:"k3s_version"`
	CreatedAt         time.Time  `json:"created_at"`
	LastConfigFetchAt *time.Time `json:"last_config_fetch_at"`
	Epoch             string     `json:"-"`
	CredentialVersion int64      `json:"-"`
	Terminal          bool       `json:"-"`
	DevelopmentHTTP   bool       `json:"development_http,omitempty"`
}

type Server struct {
	db            *sql.DB
	params        Params
	logger        *slog.Logger
	client        *http.Client
	build         func(machineconfig.Desired) ([]byte, string, error)
	denialMu      sync.Mutex
	denials       map[AdminAction]denialWindow
	tunnels       *tunnel.Manager
	configs       *machineconfig.Manager
	discovery     *fleet.Manager
	reconcileWake chan struct{}
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
		respond(w, 200, map[string]string{"supabase_url": s.params.SupabaseURL, "supabase_publishable_key": s.params.SupabasePublishableKey, "public_api_url": s.params.PublicAPIURL})
	})
	mux.HandleFunc("POST /api/bootstrap-token", s.bootstrapToken)
	mux.HandleFunc("GET /api/machines", s.listMachines)
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("GET /api/admin/administrators", s.adminRead(s.listAdministrators))
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

func (s *Server) bootstrapToken(w http.ResponseWriter, r *http.Request) {
	owner, err := s.user(r.Context(), bearer(r))
	if err != nil {
		s.respondError(w, err)
		return
	}
	token, expires, err := signEnrollment(s.params.JWTSigningSecret, owner.ID, time.Now())
	if err != nil {
		fail(w, 500, "could not issue enrollment token")
		return
	}
	respond(w, 200, map[string]any{"token": token, "expires_at": expires})
}

func (s *Server) listMachines(w http.ResponseWriter, r *http.Request) {
	owner, err := s.user(r.Context(), bearer(r))
	if err != nil {
		s.respondError(w, err)
		return
	}
	rows, err := s.db.QueryContext(r.Context(), `SELECT node_id,hostname,install_dir,k3s_version,created_at,last_config_fetch_at FROM lpcc.machines WHERE owner_id=$1 ORDER BY created_at DESC`, owner.ID)
	if err != nil {
		s.databaseError(w, err)
		return
	}
	defer rows.Close()
	machines := []Machine{}
	for rows.Next() {
		var m Machine
		if err := rows.Scan(&m.NodeID, &m.Hostname, &m.InstallDir, &m.K3sVersion, &m.CreatedAt, &m.LastConfigFetchAt); err != nil {
			s.databaseError(w, err)
			return
		}
		machines = append(machines, m)
	}
	if err := rows.Err(); err != nil {
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
	owner, err := verifyEnrollment(s.params.JWTSigningSecret, bearer(r))
	if err != nil {
		fail(w, 401, err.Error())
		return
	}
	var m Machine
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		fail(w, 400, "invalid machine registration")
		return
	}
	if decoder.Decode(new(any)) != io.EOF || !validMachine(m) {
		fail(w, 400, "invalid machine metadata")
		return
	}
	m.NodeID = "lp-" + m.Fingerprint[:16]
	m.OwnerID = owner
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.databaseError(w, err)
		return
	}
	defer tx.Rollback()
	// The unique node ID also catches truncated fingerprint collisions. An existing
	// row is reusable only by the same owner with the same installation identity.
	row := tx.QueryRowContext(r.Context(), `INSERT INTO lpcc.machines(node_id,fingerprint,owner_id,hostname,install_dir,k3s_version,credential_version,tunnel_eligible) VALUES($1,$2,$3,$4,$5,$6,1,$7)
 ON CONFLICT(node_id) DO UPDATE SET hostname=EXCLUDED.hostname,updated_at=now()
 WHERE lpcc.machines.owner_id=EXCLUDED.owner_id AND lpcc.machines.fingerprint=EXCLUDED.fingerprint
	 AND lpcc.machines.install_dir=EXCLUDED.install_dir AND lpcc.machines.k3s_version=EXCLUDED.k3s_version
 RETURNING enrollment_epoch::text,credential_version`, m.NodeID, m.Fingerprint, owner, m.Hostname, m.InstallDir, m.K3sVersion, strings.HasPrefix(s.params.PublicAPIURL, "https://") && !m.DevelopmentHTTP)
	err = row.Scan(&m.Epoch, &m.CredentialVersion)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 409, "machine already registered with a different owner or installation")
		return
	}
	if err != nil {
		s.databaseError(w, err)
		return
	}
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO lpcc.enrollments(node_id,epoch,owner_id,fingerprint,hostname,install_dir,k3s_version,credential_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(node_id,epoch) DO NOTHING`, m.NodeID, m.Epoch, m.OwnerID, m.Fingerprint, m.Hostname, m.InstallDir, m.K3sVersion, m.CredentialVersion); err != nil {
		s.databaseError(w, err)
		return
	}
	data, digest, err := s.build(s.configs.Desired(configurationMachine(m), machineconfig.InitialState(false), nil))
	if err != nil {
		fail(w, 503, "configuration generation failed")
		return
	}
	// Preserve an existing bundle; the backend reconciler owns later updates.
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO lpcc.machine_configs(node_id,bundle,sha256) VALUES($1,$2,$3) ON CONFLICT(node_id) DO NOTHING`, m.NodeID, data, digest); err != nil {
		s.databaseError(w, err)
		return
	}
	if err := tx.Commit(); err != nil {
		s.databaseError(w, err)
		return
	}
	respond(w, 200, s.machineCredentials(m))
}

func (s *Server) machineCredentials(m Machine) map[string]string {
	return map[string]string{"node_id": m.NodeID, "epoch": m.Epoch, "credential_version": strconv.FormatInt(m.CredentialVersion, 10), "token": s.enrollmentToken(m), "config_url": strings.TrimRight(s.params.PublicAPIURL, "/") + "/v1/nodes/" + m.NodeID + "/config"}
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
		err = s.db.QueryRowContext(r.Context(), `SELECT terminal_bundle,terminal_sha256 FROM lpcc.enrollments WHERE node_id=$1 AND epoch=$2 AND terminal_bundle IS NOT NULL`, m.NodeID, m.Epoch).Scan(&data, &digest)
	} else {
		err = s.db.QueryRowContext(r.Context(), `SELECT c.bundle,c.sha256 FROM lpcc.machine_configs c JOIN lpcc.machines m USING(node_id) WHERE m.node_id=$1 AND m.enrollment_epoch=$2`, m.NodeID, m.Epoch).Scan(&data, &digest)
	}
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "machine configuration not found")
		return
	}
	if err != nil {
		s.databaseError(w, err)
		return
	}
	if _, err := s.db.ExecContext(r.Context(), `UPDATE lpcc.machines SET last_config_fetch_at=now() WHERE node_id=$1 AND enrollment_epoch=$2`, m.NodeID, m.Epoch); err != nil {
		s.databaseError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("ETag", `"`+digest+`"`)
	w.Header().Set("X-Livepeer-Epoch", m.Epoch)
	if m.Terminal {
		pending, err := machineapps.Pending(r.Context(), s.db, m.NodeID, m.Epoch)
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
