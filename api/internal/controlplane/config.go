package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/j0sh/boa/pkg/boa"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func init() {
	boa.RegisterConfigFormat(".toml", toml.Unmarshal)
}

type DatabaseParams struct {
	PGConnstr      string `env:"PG_CONNSTR" secret:"true" persistent:"true" descr:"PostgreSQL connection URI"`
	PGConnstrFile  string `env:"PG_CONNSTR_FILE" secretfor:"PGConnstr" basepath:"source" persistent:"true" descr:"File containing the PostgreSQL connection URI"`
	PGPassword     string `env:"PG_PASSWORD" secret:"true" persistent:"true" optional:"true" descr:"Password replacing the connection URI placeholder"`
	PGPasswordFile string `env:"PG_PASSWORD_FILE" secretfor:"PGPassword" basepath:"source" persistent:"true" descr:"File containing the PostgreSQL password"`
}

type Params struct {
	ConfigFile string `name:"config" env:"CONTROL_CENTER_CONFIG" configfile:"optional-default" basepath:"source" default:"config.toml" boa:"noconfig" descr:"Configuration file; empty disables file loading"`
	DatabaseParams
	Listen                  string        `env:"LISTEN_ADDR" default:"localhost:41932" descr:"HTTP listen address"`
	PublicAPIURL            string        `env:"PUBLIC_API_URL" default:"http://localhost:41932" pattern:"^https?://[a-zA-Z0-9_.:-]+(/[a-zA-Z0-9_.-]+)*/?$" descr:"API URL reachable from runtime hosts and pods"`
	SupabaseURL             string        `env:"SUPABASE_URL" min:"1" descr:"Supabase project URL"`
	SupabasePublishableKey  string        `env:"SUPABASE_PUBLISHABLE_KEY" min:"1" descr:"Supabase browser-safe publishable key"`
	DefaultAdminEmail       string        `env:"DEFAULT_ADMIN_EMAIL" optional:"true" descr:"Seed a pending administrator email only when no active grants exist"`
	JWTSigningSecret        string        `env:"JWT_SIGNING_SECRET" secret:"true" min:"32" descr:"Persistent enrollment signing secret (at least 32 bytes)"`
	JWTSigningSecretFile    string        `env:"JWT_SIGNING_SECRET_FILE" secretfor:"JWTSigningSecret" basepath:"source" descr:"File containing the enrollment signing secret"`
	MachineTokenSecret      string        `env:"MACHINE_TOKEN_SECRET" secret:"true" min:"32" descr:"Persistent machine credential secret (at least 32 bytes)"`
	MachineTokenSecretFile  string        `env:"MACHINE_TOKEN_SECRET_FILE" secretfor:"MachineTokenSecret" basepath:"source" descr:"File containing the machine credential secret"`
	ConfigReconcileInterval time.Duration `env:"CONFIG_RECONCILE_INTERVAL" default:"1m" descr:"Desired configuration reconciliation interval"`
}

var passwordPlaceholder = regexp.MustCompile(`(?i)\[(?:your[-_])?password\]|\[PG_PASSWORD\]`)

func OpenDB(ctx context.Context, raw, password string) (*sql.DB, error) {
	if passwordPlaceholder.MatchString(raw) {
		if password == "" {
			return nil, errors.New("PGPassword is required for the PGConnstr placeholder")
		}
		escaped := strings.TrimPrefix(url.UserPassword("", password).String(), ":")
		raw = passwordPlaceholder.ReplaceAllStringFunc(raw, func(string) string { return escaped })
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return nil, errors.New("PGConnstr must be a valid PostgreSQL URI")
	}
	query := u.Query()
	if !query.Has("sslmode") {
		query.Set("sslmode", "require")
	}
	u.RawQuery = query.Encode()
	cfg, err := pgx.ParseConfig(u.String())
	if err != nil {
		return nil, errors.New("invalid PGConnstr; check its URI and password encoding")
	}
	encrypted := cfg.TLSConfig != nil
	for _, fallback := range cfg.Fallbacks {
		encrypted = encrypted && fallback.TLSConfig != nil
	}
	if !encrypted {
		return nil, errors.New("PGConnstr must require TLS")
	}
	// Exec mode also works with Supabase transaction pooling and multi-statement DDL.
	cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(3)
	db.SetConnMaxLifetime(30 * time.Minute)
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, errors.New("database connection failed; check PGConnstr, PGPassword, and network access")
	}
	return db, nil
}

func (p Params) PreValidate() error {
	if p.DefaultAdminEmail != "" {
		if _, err := normalizeEmail(p.DefaultAdminEmail); err != nil {
			return errors.New("DefaultAdminEmail must be a single email address")
		}
	}
	if p.JWTSigningSecret != "" && p.JWTSigningSecret == p.MachineTokenSecret {
		return errors.New("use different enrollment and machine credential secrets")
	}
	if p.ConfigReconcileInterval < time.Second {
		return errors.New("ConfigReconcileInterval must be at least 1s")
	}
	for _, raw := range []string{p.PublicAPIURL, p.SupabaseURL} {
		u, err := url.Parse(raw)
		if raw != "" && (err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "") {
			return errors.New("PublicAPIURL and SupabaseURL must be HTTP(S) base URLs without credentials, query strings, or fragments")
		}
	}
	return nil
}
