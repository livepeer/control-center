// secrets-service runs in a separate deployment/security boundary from controlcenter.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/livepeer/control-center/api/internal/controlplane"
	"github.com/livepeer/control-center/api/internal/secretservice"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func file(name string) ([]byte, error) {
	p := os.Getenv(name)
	if p == "" {
		return nil, fmt.Errorf("configure %s", name)
	}
	return os.ReadFile(p)
}
func run(ctx context.Context) error {
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
	for _, u := range []string{c.SupabaseURL, c.ControlURL, c.VaultURL} {
		if len(u) < 8 || u[:8] != "https://" {
			return errors.New("service upstreams require HTTPS")
		}
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
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := run(ctx); e != nil && !errors.Is(e, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
