package tunnel

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *Manager) Run(ctx context.Context, interval time.Duration, after func()) {
	if s.provider == nil {
		return
	}
	run := func() {
		if e := s.Reconcile(ctx); e != nil && ctx.Err() == nil {
			s.logger.Error("tunnel reconciliation failed", "reason", "reconcile_failed")
		}
		if after != nil {
			after()
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
func (s *Manager) Reconcile(ctx context.Context) error {
	if s.provider == nil {
		return nil
	}
	rows, e := s.db.QueryContext(ctx, `SELECT e.node_id,e.install_dir,e.k3s_version,e.credential_version,e.retired_at IS NOT NULL FROM lpcc.enrollments e WHERE e.retired_at IS NOT NULL OR EXISTS(SELECT FROM lpcc.machines m WHERE m.node_id=e.node_id)`)
	if e != nil {
		return e
	}
	var machines []Machine
	for rows.Next() {
		var m Machine
		if e = rows.Scan(&m.NodeID, &m.InstallDir, &m.K3sVersion, &m.CredentialVersion, &m.Terminal); e != nil {
			rows.Close()
			return e
		}
		machines = append(machines, m)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, m := range machines {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		safe := false
		if !m.Terminal {
			safe, e = s.SecureRuntime(ctx, m)
			if e != nil {
				return e
			}
			if !safe {
				state, _, err := s.Load(ctx, m.NodeID)
				if err != nil || state.TunnelID == "" && state.Lifecycle != "draining" {
					continue
				}
			}
		}
		pass, cancel := context.WithTimeout(ctx, 60*time.Second)
		l, e := s.claimTunnel(pass, m)
		if errors.Is(e, errRoutingMigrationRequired) {
			cancel()
			s.logger.Error("machine routing requires external migration", "node_id", m.NodeID, "reason", "routing_migration_required")
			continue
		}
		if errors.Is(e, sql.ErrNoRows) {
			cancel()
			continue
		}
		if e != nil {
			cancel()
			return e
		}
		if l.Machine.Terminal {
			e = l.cleanup(pass)
		} else if e = l.sweepAbsentResources(pass, false); e != nil {
			// Retained absent intents also collect provider results that arrive late.
		} else if l.state.Lifecycle == "draining" {
			e = nil // Machine configuration owns drain completion and retirement.
		} else if l.state.Lifecycle != "active" {
			e = errTunnelFenced
		} else if !safe {
			l.state.Ready = false
			l.state.Reason = "runtime_offline"
			e = l.maintainCredentials(pass)
			if e == nil {
				e = l.save(pass)
			}
		} else {
			e = l.provision(pass)
		}
		if e != nil && !errors.Is(e, errTunnelFenced) {
			l.state.Ready = false
			l.state.Reason = "provisioning_pending"
			if !safe && !l.Machine.Terminal {
				l.state.Reason = "runtime_offline"
			}
			if errors.Is(e, ErrResourceConflict) && safe {
				l.state.Reason = "ownership_conflict"
			}
			_ = l.save(pass)
		}
		finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		l.finish(finish, e != nil)
		stop()
		cancel()
	}
	return s.reconcileUnusedCertificates(ctx)
}
func (l *tunnelLease) provision(ctx context.Context) error {
	p := l.s.params
	existingTunnel := l.state.TunnelID != ""
	if existingTunnel && l.state.IngressVersion != 1 {
		return errors.New("existing machine requires the separate ingress migration")
	}
	if existingTunnel {
		if e := l.maintainCredentials(ctx); e != nil {
			return e
		}
	}
	if l.state.AccountID != p.CloudflareAccountID || l.state.ZoneID != p.CloudflareZoneID {
		return errors.New("retire the previous provider scope before changing account or zone")
	}
	desired := RoutingFor(l.Machine.NodeID, p.CloudflareBaseDomain)
	if l.state.Target != "" && l.state.Target != desired.ServiceURL {
		l.state.State.CancelTarget()
		l.state.Ready = false
		if err := l.save(ctx); err != nil {
			return err
		}
	}
	keepCertificates := []string{wildcardHost(l.state.ProxyURLTemplate), wildcardHost(desired.ProxyURLTemplate)}
	// Predecessor routes can outlive endpoint staging. Their DNS intents keep
	// coverage until retirePredecessorRoutes releases it after route cleanup.
	for _, resource := range l.state.Resources {
		if resource.Kind == "dns" && strings.HasPrefix(resource.Host, "*.") {
			keepCertificates = append(keepCertificates, resource.Host)
		}
	}
	if err := l.releaseCertificates(ctx, keepCertificates...); err != nil {
		return err
	}
	certificateReady, err := l.ensureCertificate(ctx, desired.ProxyURLTemplate)
	if err != nil {
		return err
	}
	if !certificateReady {
		l.state.Ready = false
		l.state.Reason = "certificate_pending"
		return l.save(ctx)
	}
	if waiting, e := l.stageEndpoints(ctx, desired); e != nil || waiting {
		return e
	}
	prefix := "g" + strconv.FormatInt(l.state.EndpointGeneration, 10) + "-"
	tunnel, e := l.ensure(ctx, "tunnel", "tunnel", "", "")
	if e != nil {
		return e
	}
	l.state.TunnelID = tunnel.ID
	if !existingTunnel {
		if e = l.maintainCredentials(ctx); e != nil {
			return e
		}
	}
	discoveryHost := endpointHost(l.state.DiscoveryURL)
	rules := ingressFor(l.state.RoutingState)
	version, e := l.provider.Configure(ctx, tunnel.ID, rules)
	if e != nil {
		return e
	}
	l.state.IngressDigest = ingressHash(rules)
	l.state.AppliedIngress = rules
	l.state.ProviderVersion = version
	l.state.Reason = "runtime_pending"
	if e = l.save(ctx); e != nil {
		return e
	}
	if waiting, e := l.gateNodeConfiguration(ctx); e != nil || waiting {
		return e
	}
	runtime, at, e := l.s.report(ctx, l.Machine, "runtime")
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if !runtime.Ready || runtime.Generation != l.state.Generation || runtime.ConfigDigest != l.desiredDigest() || time.Since(at) > p.TunnelStatusTTL {
		l.state.Ready = false
		return l.save(ctx)
	}
	expectedIngress := l.desired(l.state).IngressConfigDigest()
	if expectedIngress == "" || !runtime.IngressReady || runtime.IngressConfigDigest != expectedIngress {
		l.state.Ready = false
		l.state.Reason = "ingress_pending"
		return l.save(ctx)
	}
	connector, at, e := l.s.report(ctx, l.Machine, "connector")
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if !connector.Ready || connector.Generation != l.state.Generation || connector.TokenGeneration != l.state.CredentialGeneration || connector.ProviderVersion != version || time.Since(at) > p.TunnelStatusTTL {
		l.state.Ready = false
		return l.save(ctx)
	}
	hosts := []string{endpointHost(l.state.ServiceURL), discoveryHost, "*." + l.Machine.NodeID + "." + p.CloudflareBaseDomain}
	for i, host := range hosts {
		if _, e = l.ensure(ctx, prefix+"dns-"+strconv.Itoa(i), "dns", host, tunnel.ID); e != nil {
			return e
		}
	}
	if l.s.signDiscovery == nil {
		return errors.New("discovery signer is unavailable")
	}
	credential, e := l.s.signDiscovery(l.Machine.NodeID)
	if e != nil {
		return e
	}
	verify := l.s.endpointVerifier
	if verify == nil {
		verify = l.s.verifyEndpoints
	}
	if e = verify(ctx, l.state.RoutingState, credential); e != nil {
		l.state.Ready = false
		l.state.Reason = "tls_or_route_pending"
		return l.save(ctx)
	}
	l.state.Ready = p.CloudflareIngressApproved
	l.state.ReadyGeneration = l.state.Generation
	l.state.VerifiedAt = time.Now().UTC()
	l.state.IngressAuthDigest = l.desired(l.state).IngressConfigDigest()
	l.state.Reason = "ingress_validation_required"
	if l.state.Ready {
		l.state.Reason = "ready"
		l.state.VerifiedGeneration = l.state.SourceGeneration
	}
	if e = l.retirePreviousEndpoints(ctx); e != nil {
		return e
	}
	return l.save(ctx)
}

// Security maintenance is independent of adapter freshness and endpoint rollout.
// It operates only on this enrollment's already-owned tunnel state.
func (l *tunnelLease) maintainCredentials(ctx context.Context) error {
	err := l.rotateConnector(ctx)
	if err != nil && !errors.Is(err, errTunnelFenced) {
		l.state.RotationReason = "connector_rotation_failed"
	}
	return err
}

func (l *tunnelLease) rotateConnector(ctx context.Context) error {
	if !l.state.RotateTunnel {
		return nil
	}
	token, e := l.provider.ConnectorToken(ctx, l.state.TunnelID)
	if e != nil {
		return e
	}
	h := sha256.Sum256([]byte(token))
	fingerprint := hex.EncodeToString(h[:])
	if !l.state.RotationStarted {
		l.state.TokenFingerprint = fingerprint
		l.state.RotationStarted = true
		if e = l.save(ctx); e != nil {
			return e
		}
	}
	if fingerprint == l.state.TokenFingerprint {
		if e = l.provider.RotateConnector(ctx, l.state.TunnelID); e != nil {
			return e
		}
		token, e = l.provider.ConnectorToken(ctx, l.state.TunnelID)
		if e != nil {
			return e
		}
		h = sha256.Sum256([]byte(token))
		fingerprint = hex.EncodeToString(h[:])
	}
	if fingerprint == l.state.TokenFingerprint {
		return errors.New("connector rotation outcome pending")
	}
	if l.state.Compromised {
		if e = l.provider.Disconnect(ctx, l.state.TunnelID); e != nil {
			return e
		}
	}
	l.state.CredentialGeneration++
	l.state.Generation++
	l.state.RotateTunnel = false
	l.state.RotationStarted = false
	l.state.Compromised = false
	l.state.TokenFingerprint = ""
	l.state.RotationReason = ""
	l.state.Ready = false
	if l.state.Lifecycle == "removed" {
		l.state.ConnectorRevoked = true
	}
	return l.save(ctx)
}
func (l *tunnelLease) retirePreviousEndpoints(ctx context.Context) error {
	prefix := "g" + strconv.FormatInt(l.state.EndpointGeneration, 10) + "-"
	var keys []string
	for key, r := range l.state.Resources {
		if r.Kind == "dns" && !r.Absent && !strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := l.retireResource(ctx, key); err != nil {
			return err
		}
	}
	return l.releaseCertificates(ctx, wildcardHost(l.state.ProxyURLTemplate))
}
func (l *tunnelLease) cleanup(ctx context.Context) error {
	if !l.state.Compromised && !l.state.ConnectorRevoked {
		pending, err := machineapps.Pending(ctx, l.s.db, l.Machine.NodeID)
		if err != nil {
			return err
		}
		if pending {
			if l.state.Reason != "app_cleanup_pending" {
				l.state.Ready = false
				l.state.Reason = "app_cleanup_pending"
				return l.save(ctx)
			}
			return nil
		}
	}
	if l.state.CleanupComplete {
		complete, e := l.auditCompletedCleanup(ctx)
		if e != nil || complete {
			return e
		}
	}
	l.state.Lifecycle = "removed"
	l.state.Ready = false
	l.state.Reason = "removing"
	if e := l.save(ctx); e != nil {
		return e
	}
	// A deny-only remote config and connection teardown protect even cached DNS.
	if l.state.TunnelID != "" && !l.state.CleanupComplete {
		tunnel := l.state.Resources["tunnel"]
		found, e := l.provider.FindOwned(ctx, tunnel)
		if e != nil {
			return e
		}
		present := false
		for _, r := range found {
			if r.ID == l.state.TunnelID {
				present = true
			}
		}
		if present {
			if _, e := l.provider.Configure(ctx, l.state.TunnelID, []IngressRule{{Service: "http_status:404"}}); e != nil {
				var f *ProviderError
				if !errors.As(e, &f) || f.Status != 404 {
					return e
				}
			}
			if !l.state.ConnectorRevoked {
				l.state.RotateTunnel = true
				l.state.Compromised = true
				if e = l.save(ctx); e != nil {
					return e
				}
				if e = l.rotateConnector(ctx); e != nil {
					return e
				}
			}
			if e := l.provider.Disconnect(ctx, l.state.TunnelID); e != nil {
				return e
			}
		}
	}
	for _, kind := range []string{"dns", "tunnel"} {
		var keys []string
		for key, r := range l.state.Resources {
			if r.Kind == kind {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			if e := l.retireResource(ctx, key); e != nil {
				return e
			}
		}
	}
	if err := l.releaseCertificates(ctx, ""); err != nil {
		return err
	}
	l.state.CleanupComplete = true
	l.state.Reason = "removed"
	return l.save(ctx)
}

func (s *Manager) verifyEndpoints(ctx context.Context, state RoutingState, credential string) error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return verifyEndpointClient(ctx, state, credential, client)
}

func verifyEndpointClient(ctx context.Context, state RoutingState, credential string, client *http.Client) error {
	// Only the configured discovery HTTPS origin may receive the bearer.
	discoveryHost := endpointHost(state.DiscoveryURL)
	for _, raw := range []string{state.ServiceURL, state.DiscoveryURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("invalid protected endpoint")
		}
	}
	// Enforce redirect rejection even for injected test transports.
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &copy
	get := func(raw, method string, auth bool) (int, json.RawMessage, error) {
		req, e := http.NewRequestWithContext(ctx, method, raw, nil)
		if e != nil {
			return 0, nil, e
		}
		if auth {
			if req.URL.User != nil || req.URL.Scheme != "https" || req.URL.Host != discoveryHost || credential == "" {
				return 0, nil, errors.New("request is outside protected endpoint scope")
			}
			req.Header.Set("Authorization", "Bearer "+credential)
		}

		res, e := client.Do(req)
		if e != nil {
			return 0, nil, errors.New("HTTPS endpoint unavailable")
		}
		defer res.Body.Close()
		var b json.RawMessage
		if res.StatusCode == 200 {
			dec := json.NewDecoder(http.MaxBytesReader(nil, res.Body, 1<<20))
			if e = dec.Decode(&b); e != nil {
				return res.StatusCode, nil, errors.New("invalid endpoint response")
			}
		}
		return res.StatusCode, b, nil
	}
	code, b, e := get(state.DiscoveryURL, "GET", true)
	if e != nil || code != 200 {
		return errors.New("authorized discovery is not ready")
	}
	var records []struct {
		Address string `json:"address"`
	}
	if json.Unmarshal(b, &records) != nil || len(records) != 1 || records[0].Address != state.ServiceURL {
		return errors.New("discovery address mismatch")
	}
	code, _, e = get(state.DiscoveryURL, "GET", false)
	if e != nil || code != 401 {
		return errors.New("discovery ingress bearer protection is not verified")
	}
	originalBearer := credential
	credential += "invalid"
	code, _, e = get(state.DiscoveryURL, "GET", true)
	credential = originalBearer
	if e != nil || code != 401 {
		return errors.New("invalid discovery bearer was not rejected")
	}
	// This route accepts POST only. GET exercises public Node routing
	// without reserving a session or requiring an installed app.
	apiProbe := strings.TrimRight(state.ServiceURL, "/") + "/apps/lpcc-readiness/session"
	code, _, e = get(apiProbe, "GET", false)
	if e != nil || code != http.StatusMethodNotAllowed {
		return errors.New("public API is not ready")
	}
	code, _, e = get(strings.TrimSuffix(state.DiscoveryURL, "/discovery")+"/apps/lpcc-readiness/session", "GET", true)
	if e != nil || code != 404 {
		return errors.New("discovery route isolation is not verified")
	}
	hosts := []string{state.ServiceURL, strings.Replace(state.ProxyURLTemplate, "{proxy}", "lpcc-readiness", 1)}
	for _, host := range hosts {
		for _, check := range []struct {
			path            string
			allowBadRequest bool
		}{
			{"/discovery", false}, {"/%64iscovery", true}, {"/./discovery", true}, {"//discovery", true},
			{"/apps/x/app/../../discovery", true}, {"/ai/trickle/private/0", false}, {"/runners/heartbeat", false},
			{"/runner/x/session/y/channels", false}, {"/metrics", false}, {"/readyz", false},
		} {
			path := check.path
			method := "GET"
			if strings.Contains(path, "runners") || strings.Contains(path, "channels") {
				method = "POST"
			}
			u, e := url.Parse(host)
			if e != nil {
				return e
			}
			probe, e := url.ParseRequestURI(path)
			if e != nil {
				return e
			}
			u.Path = probe.Path
			u.RawPath = probe.RawPath
			code, _, e = get(u.String(), method, false)
			if e != nil || code != 404 && !(check.allowBadRequest && code == 400) {
				return fmt.Errorf("public route isolation is not verified")
			}
		}
	}
	return nil
}
