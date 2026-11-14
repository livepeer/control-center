// secrets-service runs in a separate deployment/security boundary from controlcenter.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/j0sh/boa/pkg/boa"
	"github.com/livepeer/control-center/api/internal/controlplane"
	"github.com/livepeer/control-center/api/internal/migrations"
	"github.com/livepeer/control-center/api/internal/secretservice"
	protocol "github.com/livepeer/control-center/secrets"
	"github.com/spf13/cobra"
)

type params struct {
	DatabaseURL                string  `secret:"true"`
	DatabaseURLFile            string  `secretfor:"DatabaseURL"`
	Listen                     string  `default:"127.0.0.1:8080"`
	IdentityKey, EncryptionKey string  `secret:"true"`
	IdentityKeyFile            string  `secretfor:"IdentityKey"`
	EncryptionKeyFile          string  `secretfor:"EncryptionKey"`
	SigningKey                 string  `secret:"true" min:"32"`
	SigningKeyFile             string  `secretfor:"SigningKey"`
	SigningKeyID               string  `default:"1"`
	VerifyKeys                 *string `secret:"true"`
	VerifyKeysFile             string  `secretfor:"VerifyKeys"`
	ControlToken, VaultToken   string  `secret:"true"`
	ControlTokenFile           string  `secretfor:"ControlToken"`
	VaultTokenFile             string  `secretfor:"VaultToken"`

	SupabaseURL            string `pattern:"^https://"`
	ControlURL             string `pattern:"^https://"`
	VaultURL               string `pattern:"^https://"`
	SupabaseKey, PublicURL string
	AllowedOrigin          string `optional:"true"`
}

type migrationParams struct {
	DatabaseURL     string `secret:"true" persistent:"true"`
	DatabaseURLFile string `secretfor:"DatabaseURL" persistent:"true"`
}

func run(ctx context.Context, p params) error {
	identityKey, e := protocol.ParsePrivate([]byte(p.IdentityKey))
	if e != nil {
		return errors.New("invalid service identity key")
	}
	encryptionKey, e := protocol.ParseEncryptionPrivate([]byte(p.EncryptionKey))
	if e != nil {
		return errors.New("invalid service X25519 encryption key")
	}
	c := secretservice.Config{SigningKey: p.SigningKey, SigningKeyID: p.SigningKeyID, SupabaseURL: p.SupabaseURL, SupabaseKey: p.SupabaseKey, ControlURL: p.ControlURL, ControlToken: p.ControlToken, VaultURL: p.VaultURL, VaultToken: p.VaultToken, AllowedOrigin: p.AllowedOrigin, PublicURL: strings.TrimSuffix(p.PublicURL, "/")}
	c.IdentityKey = identityKey
	c.EncryptionKey = encryptionKey
	u, e := url.Parse(c.PublicURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("configure SECRETS_PUBLIC_URL as the public HTTPS origin")
	}
	if p.VerifyKeys != nil && json.Unmarshal([]byte(*p.VerifyKeys), &c.SigningKeys) != nil {
		return errors.New("invalid verification keyring")
	}
	db, e := controlplane.OpenDB(ctx, p.DatabaseURL, "")
	if e != nil {
		return e
	}
	defer db.Close()
	s := secretservice.New(db, c)
	if e = s.Migrate(ctx); e != nil {
		return errors.New("secrets database initialization failed")
	}
	srv := &http.Server{Addr: p.Listen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16384}
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case e := <-done:
			return e
		case <-ticker.C:
			_ = s.Collect(ctx)
		case <-ctx.Done():
			stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return srv.Shutdown(stop)
		}
	}
}

func command() *cobra.Command {
	enrich := boa.ParamEnricherCombine(boa.ParamEnricherDefault, boa.ParamEnricherEnv, boa.ParamEnricherEnvPrefix("SECRETS"))
	database := new(migrationParams)
	migrate := migrations.CommandFor(secretservice.Migrator, boa.Cmd[migrationParams]{Params: database, ParamEnrich: enrich}, &database.DatabaseURL, secretservice.MigrationFiles,
		func(ctx context.Context, raw string, _ bool) (*sql.DB, error) {
			return controlplane.OpenDB(ctx, raw, "")
		})
	return boa.Cmd[params]{Use: "secrets-service", Short: "Run the secrets service", Args: cobra.NoArgs, ParamEnrich: enrich,
		RunFuncE: func(p *params, cmd *cobra.Command, _ []string) error { return run(cmd.Context(), *p) }, SubCmds: []*cobra.Command{migrate}}.ToCobra()
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := command().ExecuteContext(ctx); e != nil && !errors.Is(e, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
