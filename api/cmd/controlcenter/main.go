package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/j0sh/boa/pkg/boa"
	"github.com/livepeer/control-center/api/internal/controlplane"
	"github.com/livepeer/control-center/api/internal/migrations"
	"github.com/spf13/cobra"
)

type migrationParams struct {
	ConfigFile string `name:"config" env:"CONTROL_CENTER_CONFIG" configfile:"optional-default" basepath:"source" default:"config.toml" boa:"noconfig" persistent:"true" descr:"Configuration file; empty disables file loading"`
	controlplane.DatabaseParams
}

func command() *cobra.Command {
	serve := boa.Cmd[controlplane.Params]{
		Use: "serve", Short: "Run the Livepeer Control Center API and configuration reconciler", Args: cobra.NoArgs,
		RunFuncE: func(p *controlplane.Params, cmd *cobra.Command, _ []string) error { return serve(cmd.Context(), *p) },
	}.ToCobra()
	database := new(migrationParams)
	migrate := migrations.Command(boa.Cmd[migrationParams]{Params: database}, &database.PGConnstr, controlplane.MigrationFiles,
		func(ctx context.Context, raw string, _ bool) (*sql.DB, error) {
			return controlplane.OpenDB(ctx, raw, database.PGPassword)
		})
	root := boa.Cmd[boa.NoParams]{Use: "controlcenter", Short: "Livepeer machine control plane", SubCmds: []*cobra.Command{serve, migrate}}.ToCobra()
	root.SilenceUsage, root.SilenceErrors = true, true
	return root
}

func serve(ctx context.Context, p controlplane.Params) error {
	db, err := controlplane.OpenDB(ctx, p.PGConnstr, p.PGPassword)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := controlplane.Migrate(ctx, db); err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	app := controlplane.New(db, p, logger)
	if err := app.ConfigureMode(ctx); err != nil {
		return fmt.Errorf("initialize Control Center mode: %w", err)
	}
	if err := app.ConfigureTunnels(); err != nil {
		return fmt.Errorf("initialize tunnel provisioning: %w", err)
	}
	if err := app.ConfigureDiscovery(); err != nil {
		return fmt.Errorf("initialize fleet discovery: %w", err)
	}
	defer app.CloseDiscovery()
	if err := app.BootstrapAdmin(ctx); err != nil {
		return fmt.Errorf("initialize administrator policy: %w", err)
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	workers.Go(func() { app.RunTunnels(workCtx) })
	workers.Go(func() { app.RunDiscovery(workCtx) })
	workers.Go(func() { app.Reconcile(workCtx) })
	newServer := func(addr string, handler http.Handler) *http.Server {
		return &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	}
	// Listen serves every route for private networks. PublicListen, when set,
	// is the tunnel-facing listener without internal callbacks or metrics.
	servers := []*http.Server{newServer(p.Listen, app.Handler())}
	if p.PublicListen != "" {
		servers = append(servers, newServer(p.PublicListen, app.PublicHandler()))
	}
	done := make(chan error, len(servers))
	for i, server := range servers {
		scope := "private"
		if i > 0 {
			scope = "public"
		} else if len(servers) == 1 {
			scope = "all"
		}
		go func() {
			logger.Info("API listening", "address", server.Addr, "scope", scope)
			done <- server.ListenAndServe()
		}()
	}
	shutdown := func() error {
		shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		var errs []error
		for _, server := range servers {
			errs = append(errs, server.Shutdown(shutdownCtx))
		}
		return errors.Join(errs...)
	}
	select {
	case err := <-done:
		cancel()
		_ = shutdown()
		app.CloseDiscovery()
		workers.Wait()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		cancel()
		err := shutdown()
		app.CloseDiscovery()
		workers.Wait()
		return err
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := command().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
