package controlplane

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

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
}

type Server struct {
	db     *sql.DB
	params Params
	logger *slog.Logger
	client *http.Client
	build  func(Machine) ([]byte, string, error)
}

func New(db *sql.DB, p Params, logger *slog.Logger) *Server {
	return &Server{db: db, params: p, logger: logger, build: buildBundle, client: &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
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
	mux.HandleFunc("POST /v1/nodes/register", s.register)
	mux.HandleFunc("GET /v1/nodes/{node_id}/config", s.configuration)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) bootstrapToken(w http.ResponseWriter, r *http.Request) {
	owner, err := s.user(r.Context(), bearer(r))
	if err != nil {
		fail(w, 401, err.Error())
		return
	}
	token, expires, err := signEnrollment(s.params.JWTSigningSecret, owner, time.Now())
	if err != nil {
		fail(w, 500, "could not issue enrollment token")
		return
	}
	respond(w, 200, map[string]any{"token": token, "expires_at": expires})
}

func (s *Server) listMachines(w http.ResponseWriter, r *http.Request) {
	owner, err := s.user(r.Context(), bearer(r))
	if err != nil {
		fail(w, 401, err.Error())
		return
	}
	rows, err := s.db.QueryContext(r.Context(), `SELECT node_id,hostname,install_dir,k3s_version,created_at,last_config_fetch_at FROM lpcc.machines WHERE owner_id=$1 ORDER BY created_at DESC`, owner)
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
	data, digest, err := s.build(m)
	if err != nil {
		fail(w, 503, "configuration generation failed")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.databaseError(w, err)
		return
	}
	defer tx.Rollback()
	// The unique node ID also catches truncated fingerprint collisions. An existing
	// row is reusable only by the same owner with the same installation identity.
	result, err := tx.ExecContext(r.Context(), `INSERT INTO lpcc.machines(node_id,fingerprint,owner_id,hostname,install_dir,k3s_version) VALUES($1,$2,$3,$4,$5,$6)
 ON CONFLICT(node_id) DO UPDATE SET hostname=EXCLUDED.hostname,updated_at=now()
 WHERE lpcc.machines.owner_id=EXCLUDED.owner_id AND lpcc.machines.fingerprint=EXCLUDED.fingerprint
 AND lpcc.machines.install_dir=EXCLUDED.install_dir AND lpcc.machines.k3s_version=EXCLUDED.k3s_version`, m.NodeID, m.Fingerprint, owner, m.Hostname, m.InstallDir, m.K3sVersion)
	if err != nil {
		s.databaseError(w, err)
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		fail(w, 409, "machine already registered with a different owner or installation")
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
	respond(w, 200, map[string]string{"node_id": m.NodeID, "token": machineToken(s.params.MachineTokenSecret, owner, m.NodeID), "config_url": strings.TrimRight(s.params.PublicAPIURL, "/") + "/v1/nodes/" + m.NodeID + "/config"})
}

func (s *Server) configuration(w http.ResponseWriter, r *http.Request) {
	var owner, digest string
	var data []byte
	err := s.db.QueryRowContext(r.Context(), `SELECT m.owner_id::text,c.bundle,c.sha256 FROM lpcc.machines m JOIN lpcc.machine_configs c USING(node_id) WHERE m.node_id=$1`, r.PathValue("node_id")).Scan(&owner, &data, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "machine configuration not found")
		return
	}
	if err != nil {
		s.databaseError(w, err)
		return
	}
	expected := machineToken(s.params.MachineTokenSecret, owner, r.PathValue("node_id"))
	if !hmac.Equal([]byte(bearer(r)), []byte(expected)) {
		fail(w, 401, "invalid machine credential")
		return
	}
	if _, err := s.db.ExecContext(r.Context(), `UPDATE lpcc.machines SET last_config_fetch_at=now() WHERE node_id=$1`, r.PathValue("node_id")); err != nil {
		s.databaseError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("ETag", `"`+digest+`"`)
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
