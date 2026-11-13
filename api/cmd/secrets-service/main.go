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

func file(name string) ([]byte, error) {
	p := os.Getenv(name)
	if p == "" {
		return nil, fmt.Errorf("configure %s", name)
	}
	return os.ReadFile(p)
}
func run(ctx context.Context) error {
	identity, e := file("SECRETS_IDENTITY_KEY_FILE")
	if e != nil {
		return e
	}
	identityKey, e := protocol.ParsePrivate(identity)
	if e != nil {
		return errors.New("invalid service identity key")
	}
	encryption, e := file("SECRETS_ENCRYPTION_KEY_FILE")
	if e != nil {
		return e
	}
	encryptionKey, e := protocol.ParseEncryptionPrivate(encryption)
	if e != nil {
		return errors.New("invalid service X25519 encryption key")
	}
	signing, e := file("SECRETS_SIGNING_KEY_FILE")
	if e != nil || len(signing) < 32 {
		return errors.New("configure a signing key file with at least 32 bytes")
	}
	pg, e := file("SECRETS_DATABASE_URL_FILE")
	if e != nil {
		return e
	}
	vault, e := file("VAULT_TOKEN_FILE")
	if e != nil {
		return e
	}
	control, e := file("CONTROL_METADATA_TOKEN_FILE")
	if e != nil {
		return e
	}
	c := secretservice.Config{SigningKey: string(signing), SigningKeyID: os.Getenv("SECRETS_SIGNING_KEY_ID"), SupabaseURL: os.Getenv("SUPABASE_URL"), SupabaseKey: os.Getenv("SUPABASE_PUBLISHABLE_KEY"), ControlURL: os.Getenv("CONTROL_API_URL"), ControlToken: string(control), VaultURL: os.Getenv("VAULT_ADDR"), VaultToken: string(vault), AllowedOrigin: os.Getenv("SECRETS_ALLOWED_ORIGIN"), PublicURL: strings.TrimSuffix(os.Getenv("SECRETS_PUBLIC_URL"), "/")}
	c.IdentityKey = identityKey
	c.EncryptionKey = encryptionKey
	u, e := url.Parse(c.PublicURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("configure SECRETS_PUBLIC_URL as the public HTTPS origin")
	}
	if c.SigningKeyID == "" {
		c.SigningKeyID = "1"
	}
	if p := os.Getenv("SECRETS_VERIFY_KEYS_FILE"); p != "" {
		v, e := os.ReadFile(p)
		if e != nil || json.Unmarshal(v, &c.SigningKeys) != nil {
			return errors.New("invalid verification keyring")
		}
	}
	if e := validateUpstreams(c); e != nil {
		return e
	}
	db, e := controlplane.OpenDB(ctx, string(pg), "")
	if e != nil {
		return e
	}
	defer db.Close()
	s := secretservice.New(db, c)
	if e = s.Migrate(ctx); e != nil {
		return errors.New("secrets database initialization failed")
	}
	addr := os.Getenv("SECRETS_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	srv := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16384}
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

func validateUpstreams(c secretservice.Config) error {
	for _, u := range []string{c.SupabaseURL, c.ControlURL} {
		if !strings.HasPrefix(u, "https://") {
			return errors.New("service upstreams require HTTPS")
		}
	}
	if c.VaultURL != "http://vault:8200" && !strings.HasPrefix(c.VaultURL, "https://") {
		return errors.New("Vault requires HTTPS or the private Compose origin http://vault:8200")
	}
	return nil
}

func command() *cobra.Command {
	var path string
	migrate := migrations.CommandFor(secretservice.Migrator, boa.Cmd[boa.NoParams]{}, &path, secretservice.MigrationFiles,
		func(ctx context.Context, _ string, _ bool) (*sql.DB, error) {
			pg, err := file("SECRETS_DATABASE_URL_FILE")
			if err != nil {
				return nil, err
			}
			return controlplane.OpenDB(ctx, string(pg), "")
		})
	root := &cobra.Command{Use: "secrets-service", Short: "Run the secrets service", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return run(cmd.Context()) }, SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(migrate)
	return root
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := command().ExecuteContext(ctx); e != nil && !errors.Is(e, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
