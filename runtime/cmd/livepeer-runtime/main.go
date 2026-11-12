package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/livepeer/control-center/runtime/appreconciler"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/connector"
	"github.com/livepeer/control-center/runtime/httpsource"
	"github.com/livepeer/control-center/runtime/management"
	"github.com/livepeer/control-center/runtime/orchestrator"
	"github.com/livepeer/control-center/runtime/transport"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("choose http-source, app-reconciler, connector-start, or connector-probe")
	}
	switch args[0] {
	case "orchestrator-start":
		return orchestrator.Start(ctx, args[1:])
	case "orchestrator-probe":
		if !orchestrator.Probe(ctx) {
			return errors.New("orchestrator not ready")
		}
		return nil
	case "http-source":
		return httpSource(ctx, args[1:])
	case "app-reconciler":
		return appReconciler(ctx, args[1:])
	case "connector-start", "connector-probe":
		return connectorCommand(ctx, args[0], args[1:])
	default:
		return errors.New("unsupported Runtime command")
	}
}

func connectorCommand(ctx context.Context, command string, args []string) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	socket := flags.String("socket", "", "Scoped management socket")
	token := flags.String("token-path", "/run/tunnel/private/token", "Private memory-backed credential path")
	marker := flags.String("launch-file", "/run/tunnel/private/launch.json", "Nonsecret current launch association")
	name := flags.String("pod-name", os.Getenv("POD_NAME"), "Current Pod name")
	uid := flags.String("pod-uid", os.Getenv("POD_UID"), "Current Pod UID")
	if flags.Parse(args) != nil || *socket == "" {
		return errors.New("invalid connector configuration")
	}
	if command == "connector-start" {
		return connector.Start(ctx, *socket, *token, *name, *uid)
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if !connector.Probe(ctx, *socket, *marker) {
		return errors.New("connector not ready")
	}
	return nil
}
func appReconciler(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("app-reconciler", flag.ContinueOnError)
	configURL := flags.String("url", "", "Machine configuration URL")
	configURLFile := flags.String("config-url-file", "", "Installed machine configuration URL file")
	managementSocket := flags.String("management-socket", "", "Scoped management reporting socket")
	identity := flags.String("identity-file", "", "Installed enrollment identity")
	directory := flags.String("directory", "", "Durable owner-only state directory")
	sourceURL := flags.String("adapter-url", "http://livepeer-http-source.flux-system.svc.cluster.local:8080", "Management artifact service")
	artifactURL := flags.String("artifact-url", "http://livepeer-app-reconciler.flux-system.svc.cluster.local:8080", "Private app artifact service")
	nodeURL := flags.String("node-url", "http://orchestrator.livepeer.svc.cluster.local:8935", "Private Node control URL")
	bootstrapFile := flags.String("bootstrap-secret-file", "", "Runner bootstrap credential")
	listen := flags.String("listen", ":8080", "Private artifact listener")
	mode := flags.String("transport", "https", "https or development-http")
	if flags.Parse(args) != nil || *directory == "" || *identity == "" || *bootstrapFile == "" || *managementSocket == "" || (*mode != "https" && *mode != "development-http") {
		return errors.New("invalid app-reconciler configuration")
	}
	for _, value := range []string{*sourceURL, *artifactURL, *nodeURL} {
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("invalid private Runtime URL")
		}
	}
	if *configURLFile != "" {
		b, err := os.ReadFile(*configURLFile)
		if err != nil || len(b) > 4096 {
			return errors.New("machine_config_url")
		}
		*configURL = strings.TrimSpace(string(b))
	}
	control, err := transport.NewControl(*configURL, "", *mode == "development-http")
	if err != nil {
		return err
	}
	var reports transport.Requester = transport.NewLocal(*managementSocket)
	reports = &transport.Reports{Client: reports, Directory: filepath.Join(*directory, "reports")}
	kube, err := transport.InCluster()
	if err != nil {
		return err
	}
	secret, err := os.ReadFile(*bootstrapFile)
	if err != nil || strings.TrimSpace(string(secret)) == "" {
		return errors.New("runner_bootstrap_credential")
	}
	owner, err := appreconciler.NewSDKOwner(*nodeURL, strings.TrimSpace(string(secret)), transport.HTTPClient())
	if err != nil {
		return err
	}
	journal, err := appreconciler.OpenJournal(filepath.Join(*directory, "state"))
	if err != nil {
		// Keep the artifact/probe endpoint alive for diagnostics and independent management repair.
		slog.Error("App Reconciler state recovery failed")
		store := artifact.Store{Directory: filepath.Join(*directory, "artifacts")}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/readyz" {
				http.Error(w, "state_recovery_failed", http.StatusServiceUnavailable)
				return
			}
			store.ServeHTTP(w, r)
		})
		input := appreconciler.Source{Kube: kube, Client: transport.HTTPClient(), ArtifactURL: *sourceURL, IdentityFile: *identity, NodeID: control.NodeID}
		return serve(ctx, *listen, handler, func(ctx context.Context) {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				appreconciler.Diagnose(ctx, input, appreconciler.ControlReporter{Client: reports}, "state_recovery_failed")
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		})
	}
	defer journal.Close()
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		_ = owner.Close(stop)
	}()
	store := artifact.Store{Directory: filepath.Join(*directory, "artifacts")}
	probes := appreconciler.NewProbes()
	probes.OnChange = owner.Refresh
	controller := appreconciler.Controller{Journal: journal, Input: appreconciler.Source{Kube: kube, Client: transport.HTTPClient(), ArtifactURL: *sourceURL, IdentityFile: *identity, NodeID: control.NodeID}, Cluster: appreconciler.Kubernetes{Client: kube, NodeID: control.NodeID}, Owner: owner, Store: store, ArtifactURL: *artifactURL, Reporter: appreconciler.ControlReporter{Client: reports}, Probes: probes}
	var stateLost atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" && stateLost.Load() {
			http.Error(w, "state_recovery_failed", http.StatusServiceUnavailable)
			return
		}
		store.ServeHTTP(w, r)
	})
	return serve(ctx, *listen, handler, func(ctx context.Context) {
		go probes.Run(ctx)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		lastDiagnosis := "starting"
		var nextDiagnosis time.Time
		for {
			if err := controller.Tick(ctx); err != nil && ctx.Err() == nil {
				stateLost.Store(errors.Is(err, appreconciler.ErrStateLost))
				slog.Error("App reconciliation pending")
				reason := "observation_pending"
				if errors.Is(err, appreconciler.ErrStateLost) {
					reason = "state_recovery_failed"
				}
				if errors.Is(err, appreconciler.ErrClock) {
					reason = "clock_uncertain"
				}
				if reason != lastDiagnosis || !time.Now().Before(nextDiagnosis) {
					m := journal.View().Metadata
					if m.NodeID != "" {
						appreconciler.DiagnoseMetadata(ctx, m, controller.Reporter, reason)
					} else {
						appreconciler.Diagnose(ctx, controller.Input, controller.Reporter, reason)
					}
					lastDiagnosis, nextDiagnosis = reason, time.Now().Add(30*time.Second)
				}
			} else if err == nil {
				stateLost.Store(false)
				if lastDiagnosis != "" || !time.Now().Before(nextDiagnosis) {
					appreconciler.DiagnoseMetadata(ctx, journal.View().Metadata, controller.Reporter, "")
					lastDiagnosis, nextDiagnosis = "", time.Now().Add(30*time.Second)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
}
func httpSource(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("http-source", flag.ContinueOnError)
	configURL := flags.String("url", "", "Control Center machine configuration URL")
	token := flags.String("token-file", "", "Machine credential file")
	identity := flags.String("identity-file", "", "Installed enrollment identity")
	directory := flags.String("directory", "", "Durable artifact directory")
	artifactURL := flags.String("artifact-url", "", "Private artifact service URL")
	listen := flags.String("listen", ":8080", "Private artifact listener")
	mode := flags.String("transport", "https", "https or development-http")
	interval := flags.Duration("interval", time.Minute, "Configuration polling interval")
	socketRoot := flags.String("socket-root", "", "Protected per-consumer socket directories")
	if flags.Parse(args) != nil {
		return errors.New("invalid http-source flags")
	}
	u, err := url.Parse(*artifactURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "http" && u.Scheme != "https") || *directory == "" || *token == "" || *identity == "" || *socketRoot == "" || *interval < time.Second || (*mode != "https" && *mode != "development-http") {
		return errors.New("invalid http-source configuration")
	}
	control, err := transport.NewControl(*configURL, *token, *mode == "development-http")
	if err != nil {
		return err
	}
	kube, err := transport.InCluster()
	if err != nil {
		return err
	}
	store := artifact.Store{Directory: *directory}
	ordered := &transport.Reports{Client: control, Directory: filepath.Join(*directory, "reports")}
	source := httpsource.Source{Reporter: ordered, Control: control, Kube: kube, Store: store, ArtifactURL: *artifactURL, IdentityFile: *identity}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	socketErrors := make(chan error, 1)
	integration := &connector.Integration{Reporter: &transport.Reports{Client: control, Directory: filepath.Join(*directory, "reports")}, Control: control, Kube: kube, Desired: source.Desired, StateFile: filepath.Join(*directory, "connector-grant.json")}
	integration.Restore()
	onchain := &orchestrator.Integration{Control: control, Kube: kube, Desired: source.Desired, TokenFile: *token, StateFile: filepath.Join(*directory, "onchain-grant.json"), AllowHTTP: control.AllowHTTP}
	onchain.Restore()
	source.Onchain = onchain.Observe
	sockets, err := management.Listen(*socketRoot, integration, management.AppReports{Control: control, Desired: source.Desired}, onchain)
	if err != nil {
		return err
	}
	defer sockets.Close()
	go func() {
		if err := sockets.Run(ctx); err != nil {
			socketErrors <- err
			cancel()
		}
	}()
	go reportsLoop(ctx, "connector", 5*time.Second, integration.Report)
	go reportsLoop(ctx, "runtime", 20*time.Second, source.Report)
	err = serve(ctx, *listen, store, func(ctx context.Context) {
		ticker := time.NewTicker(*interval)
		defer ticker.Stop()
		for {
			if source.Sync(ctx) != nil && ctx.Err() == nil {
				slog.Error("Configuration fetch or publication failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
	select {
	case err = <-socketErrors:
	default:
	}
	return err
}

func reportsLoop(ctx context.Context, component string, interval time.Duration, report func(context.Context) error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		attempt, cancel := context.WithTimeout(ctx, 25*time.Second)
		if err := report(attempt); err != nil && ctx.Err() == nil {
			slog.Error("Runtime observation report unavailable", "component", component, "reason", transport.ReportErrorCode(err))
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func serve(ctx context.Context, address string, handler http.Handler, loop func(context.Context)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10}
	done := make(chan error, 1)
	loopDone := make(chan struct{})
	go func() { done <- server.ListenAndServe() }()
	go func() { defer close(loopDone); loop(ctx) }()
	select {
	case err := <-done:
		cancel()
		<-loopDone
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("Runtime listener unavailable")
		}
		return nil
	case <-ctx.Done():
	}
	stop, release := context.WithTimeout(context.Background(), 10*time.Second)
	defer release()
	err := server.Shutdown(stop)
	<-loopDone
	return err
}
