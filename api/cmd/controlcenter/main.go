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
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); app.Reconcile(workCtx) }()
	server := &http.Server{Addr: p.Listen, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	done := make(chan error, 1)
	go func() { logger.Info("API listening", "address", p.Listen); done <- server.ListenAndServe() }()
	select {
	case err := <-done:
		cancel()
		<-workerDone
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		cancel()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		err := server.Shutdown(shutdownCtx)
		<-workerDone
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
