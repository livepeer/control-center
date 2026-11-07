package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *Server) RunTunnels(ctx context.Context) {
	if s.provider == nil {
		return
	}
	run := func() {
		if e := s.reconcileTunnels(ctx); e != nil && ctx.Err() == nil {
			s.logger.Error("tunnel reconciliation failed", "reason", "reconcile_failed")
		}
		s.requestReconcile()
	}
	run()
	ticker := time.NewTicker(s.params.ConfigReconcileInterval)
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
func (s *Server) reconcileTunnels(ctx context.Context) error {
	if s.provider == nil {
		return nil
	}
	if e := s.ReencryptAccessCredentials(ctx); e != nil {
		return e
	}
	rows, e := s.db.QueryContext(ctx, `SELECT e.node_id,e.epoch::text,e.owner_id::text,e.fingerprint,e.hostname,e.install_dir,e.k3s_version,e.credential_version,e.retired_at IS NOT NULL FROM lpcc.enrollments e WHERE e.retired_at IS NOT NULL OR EXISTS(SELECT FROM lpcc.machines m WHERE m.node_id=e.node_id AND m.enrollment_epoch=e.epoch)`)
	if e != nil {
		return e
	}
	var machines []Machine
	for rows.Next() {
		var m Machine
		if e = rows.Scan(&m.NodeID, &m.Epoch, &m.OwnerID, &m.Fingerprint, &m.Hostname, &m.InstallDir, &m.K3sVersion, &m.CredentialVersion, &m.Terminal); e != nil {
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
			if m.CredentialVersion == 0 {
				continue
			}
			safe, e = s.secureRuntime(ctx, m)
			if e != nil {
				return e
			}
			if !safe {
				state, _, err := s.loadTunnel(ctx, m.NodeID, m.Epoch)
				if err != nil || state.TunnelID == "" && state.Lifecycle != "draining" {
					continue
				}
			}
		}
		pass, cancel := context.WithTimeout(ctx, 60*time.Second)
		l, e := s.claimTunnel(pass, m)
		if errors.Is(e, sql.ErrNoRows) {
			cancel()
			continue
		}
		if e != nil {
			cancel()
			return e
		}
		if l.m.Terminal {
			e = l.cleanup(pass)
		} else if e = l.sweepAbsentResources(pass, false); e != nil {
			// Retained absent intents also collect provider results that arrive late.
		} else if l.state.Lifecycle == "draining" {
			e = l.finishDrain(pass)
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
			if !safe && !l.m.Terminal {
				l.state.Reason = "runtime_offline"
			}
			if errors.Is(e, errResourceConflict) && safe {
				l.state.Reason = "ownership_conflict"
			}
			_ = l.save(pass)
		}
		finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		l.finish(finish, e != nil)
		stop()
		cancel()
	}
	return nil
}
func (l *tunnelLease) provision(ctx context.Context) error {
	p := l.s.params.TunnelParams
	existingTunnel := l.state.TunnelID != ""
	if existingTunnel {
		if e := l.maintainCredentials(ctx); e != nil {
			return e
		}
	}
	if l.state.AccountID != p.CloudflareAccountID || l.state.ZoneID != p.CloudflareZoneID || l.state.TeamName != p.CloudflareTeamName {
		return problem(409, "cloudflare_scope_changed", "Retire the previous provider scope before changing account, zone or team.")
	}
	var predecessor bool
	if e := l.s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.machine_tunnels WHERE node_id=$1 AND epoch<>$2 AND COALESCE((state->>'cleanup_complete')::boolean,false)=false)`, l.m.NodeID, l.m.Epoch).Scan(&predecessor); e != nil {
		return e
	}
	if predecessor {
		l.state.Ready = false
		l.state.Reason = "predecessor_cleanup_pending"
		return l.save(ctx)
	}
	desired := routingFor(l.m.NodeID, p.CloudflareBaseDomain)
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
	tokenKey := "token-" + strconv.FormatInt(l.state.AccessVersion, 10)
	token := l.state.Resources[tokenKey] // Validated by credential maintenance above.
	discoveryHost := strings.TrimSuffix(strings.TrimPrefix(l.state.DiscoveryURL, "https://"), "/discovery")
	app, e := l.ensure(ctx, prefix+"app", "app", discoveryHost, "")
	if e != nil {
		return e
	}
	if app.Audience == "" {
		return errors.New("Access application audience is missing")
	}
	policy, e := l.ensure(ctx, prefix+"policy", "policy", app.ID, token.ID)
	if e != nil {
		return e
	}
	tokens, e := l.s.activeAccessIDs(ctx, l.m)
	if e != nil {
		return e
	}
	if e = l.protectPolicy(ctx, policy, tokens); e != nil {
		return e
	}
	l.credentialPoliciesReady(len(tokens))
	rules := ingressFor(l.m.NodeID, p, app.Audience)
	// Keep predecessor discovery hosts protected throughout endpoint replacement.
	keys := make([]string, 0, len(l.state.Resources))
	for key := range l.state.Resources {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		r := l.state.Resources[key]
		if r.Kind == "app" && !r.Absent && !strings.HasPrefix(key, prefix) && r.ID != "" && r.Audience != "" {
			rules = append(rules[:len(rules)-1], IngressRule{Hostname: r.Host, Path: `^/discovery$`, Service: privateOrchestrator, OriginRequest: &OriginRequest{Access: &IngressAccess{Required: true, TeamName: p.CloudflareTeamName, Audience: []string{r.Audience}}}}, IngressRule{Service: "http_status:404"})
		}
	}
	version, e := l.provider.Configure(ctx, tunnel.ID, rules)
	if e != nil {
		return e
	}
	l.state.IngressDigest = ingressHash(rules)
	l.state.AppliedIngress = rules
	l.state.Quarantined = false
	l.state.ProviderVersion = version
	l.state.Reason = "runtime_pending"
	if e = l.save(ctx); e != nil {
		return e
	}
	if waiting, e := l.gateNodeConfiguration(ctx); e != nil || waiting {
		return e
	}
	m := l.m
	m.Routing = &l.state
	runtime, at, e := l.s.report(ctx, l.m, "runtime")
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if !runtime.Ready || runtime.Generation != l.state.Generation || runtime.ConfigDigest != orchestratorDigest(m) || time.Since(at) > p.TunnelStatusTTL {
		l.state.Ready = false
		return l.save(ctx)
	}
	connector, at, e := l.s.report(ctx, l.m, "connector")
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if !connector.Ready || connector.Generation != l.state.Generation || connector.TokenGeneration != l.state.CredentialGeneration || connector.ProviderVersion != version || time.Since(at) > p.TunnelStatusTTL {
		l.state.Ready = false
		return l.save(ctx)
	}
	hosts := []string{strings.TrimPrefix(l.state.ServiceURL, "https://"), discoveryHost, "*.apps-" + l.m.NodeID + "." + p.CloudflareBaseDomain}
	for i, host := range hosts {
		if _, e = l.ensure(ctx, prefix+"dns-"+strconv.Itoa(i), "dns", host, tunnel.ID); e != nil {
			return e
		}
	}
	credential, e := l.s.ResolveAccessCredential(ctx, credentialRef(l.m.NodeID, l.m.Epoch, l.state.AccessVersion))
	if e != nil {
		return e
	}
	verify := l.s.endpointVerifier
	if verify == nil {
		verify = l.s.verifyEndpoints
	}
	if e = verify(ctx, l.state, credential); e != nil {
		l.state.Ready = false
		l.state.Reason = "tls_or_route_pending"
		return l.save(ctx)
	}
	l.state.Ready = p.CloudflareIngressApproved
	l.state.VerifiedAt = time.Now().UTC()
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
// It operates only on this enrollment's already-owned tunnel/protection state.
func (l *tunnelLease) maintainCredentials(ctx context.Context) (result error) {
	defer func() {
		if result == nil || errors.Is(result, errTunnelFenced) {
			return
		}
		if l.state.RotationReason == "access_credential_expired" {
			return
		}
		if l.state.RotateTunnel || l.state.RotationStarted {
			l.state.RotationReason = "connector_rotation_failed"
		} else if l.state.RotationReason != "" || l.state.CompromisedAccess || l.state.RotateAccess {
			l.state.RotationReason = "access_rotation_failed"
		}
	}()
	if e := l.rotateConnector(ctx); e != nil {
		return e
	}
	if e := l.retireAcknowledgedCredentials(ctx); e != nil {
		return e
	}
	if e := l.prepareAccessRotation(ctx); e != nil {
		return e
	}
	if _, e := l.ensure(ctx, "token-"+strconv.FormatInt(l.state.AccessVersion, 10), "token", "", ""); e != nil {
		return e
	}
	ids, e := l.s.activeAccessIDs(ctx, l.m)
	if e != nil {
		return e
	}
	protected, e := l.applyAccessPolicies(ctx, ids)
	if e != nil {
		return e
	}
	if protected {
		l.credentialPoliciesReady(len(ids))
		return l.restoreProtectedIngress(ctx)
	}
	return nil
}

func (l *tunnelLease) credentialPoliciesReady(tokens int) {
	l.state.RotationReason = ""
	if tokens > 1 {
		l.state.RotationReason = "rotation_ack_pending"
	}
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
	l.state.Ready = false
	if l.state.Lifecycle == "removed" {
		l.state.ConnectorRevoked = true
	}
	return l.save(ctx)
}
func (l *tunnelLease) prepareAccessRotation(ctx context.Context) error {
	var expires time.Time
	var revoked bool
	e := l.s.db.QueryRowContext(ctx, `SELECT expires_at,revoked_at IS NOT NULL FROM lpcc.access_credentials WHERE node_id=$1 AND epoch=$2 AND version=$3`, l.m.NodeID, l.m.Epoch, l.state.AccessVersion).Scan(&expires, &revoked)
	missing := errors.Is(e, sql.ErrNoRows)
	if e != nil && !missing {
		return e
	}
	if !missing && !expires.After(time.Now()) {
		l.state.RotationReason = "access_credential_expired"
	}
	if l.state.CompromisedAccess {
		if l.state.RotationReason != "access_credential_expired" {
			l.state.RotationReason = "access_rotation_pending"
		}
		if e = l.save(ctx); e != nil {
			return e
		}
		if e = l.retireAccessTokens(ctx, false); e != nil {
			return e
		}
		return l.advanceAccessVersion(ctx)
	}
	if l.state.RotationReason == "access_credential_expired" {
		if e = l.save(ctx); e != nil {
			return e
		}
	}
	if e = l.retireAccessTokens(ctx, true); e != nil {
		return e
	}
	if missing || !revoked && time.Until(expires) > l.s.params.CloudflareRotateBefore && !l.state.RotateAccess {
		return nil
	}
	var count int
	if e = l.s.db.QueryRowContext(ctx, `SELECT count(*) FROM lpcc.access_credentials WHERE node_id=$1 AND epoch=$2 AND revoked_at IS NULL AND expires_at>now()`, l.m.NodeID, l.m.Epoch).Scan(&count); e != nil {
		return e
	}
	if count > 1 {
		l.state.RotationReason = "rotation_ack_pending"
		return nil
	}
	if l.state.RotationReason != "access_credential_expired" {
		l.state.RotationReason = "access_rotation_pending"
	}
	return l.advanceAccessVersion(ctx)
}

func (l *tunnelLease) advanceAccessVersion(ctx context.Context) error {
	l.state.AccessVersion++
	l.state.SourceGeneration++
	l.state.Ready = false
	l.state.RotateAccess = false
	l.state.CompromisedAccess = false
	return l.save(ctx)
}

func (l *tunnelLease) retireAccessTokens(ctx context.Context, expiredOnly bool) error {
	for key, r := range l.state.Resources {
		if r.Kind != "token" || r.Absent {
			continue
		}
		if expiredOnly {
			var expired bool
			if e := l.s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.access_credentials WHERE node_id=$1 AND epoch=$2 AND version=$3 AND (expires_at<=now() OR revoked_at IS NOT NULL))`, l.m.NodeID, l.m.Epoch, r.CredentialVersion).Scan(&expired); e != nil {
				return e
			}
			if !expired {
				continue
			}
		}
		if e := l.retireResource(ctx, key); e != nil {
			return e
		}
	}
	return nil
}
func (s *Server) activeAccessIDs(ctx context.Context, m Machine) ([]string, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT provider_id FROM lpcc.access_credentials WHERE node_id=$1 AND epoch=$2 AND revoked_at IS NULL AND expires_at>now() ORDER BY version`, m.NodeID, m.Epoch)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func (l *tunnelLease) retirePreviousEndpoints(ctx context.Context) error {
	ack, e := l.accessAcknowledged(ctx)
	if e != nil || !ack {
		return e
	}
	prefix := "g" + strconv.FormatInt(l.state.EndpointGeneration, 10) + "-"
	var keys []string
	for key, r := range l.state.Resources {
		if r.Kind != "token" && r.Kind != "tunnel" && !r.Absent && !strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	app := l.state.Resources[prefix+"app"]
	rules := ingressFor(l.m.NodeID, l.s.params.TunnelParams, app.Audience)
	version, e := l.provider.Configure(ctx, l.state.TunnelID, rules)
	if e != nil {
		return e
	}
	l.state.ProviderVersion = version
	l.state.IngressDigest = ingressHash(rules)
	l.state.AppliedIngress = rules
	l.state.Quarantined = false
	for _, kind := range []string{"dns", "policy", "app"} {
		for _, key := range keys {
			r, exists := l.state.Resources[key]
			if !exists || r.Kind != kind {
				continue
			}
			if e = l.retireResource(ctx, key); e != nil {
				return e
			}
		}
	}
	return nil
}
func (l *tunnelLease) cleanup(ctx context.Context) error {
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
				var f *cloudflareFailure
				if !errors.As(e, &f) || f.status != 404 {
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
	for _, kind := range []string{"dns", "tunnel", "policy", "app", "token"} {
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
	if _, e := l.s.db.ExecContext(ctx, `UPDATE lpcc.access_credentials SET revoked_at=COALESCE(revoked_at,now()) WHERE node_id=$1 AND epoch=$2`, l.m.NodeID, l.m.Epoch); e != nil {
		return e
	}
	l.state.CleanupComplete = true
	l.state.Reason = "removed"
	return l.save(ctx)
}

func (s *Server) verifyEndpoints(ctx context.Context, state RoutingState, credential AccessCredential) error {
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if s.endpointClient != nil {
		copy := *s.endpointClient
		copy.Timeout = 3 * time.Second
		copy.CheckRedirect = client.CheckRedirect
		client = &copy
	}
	get := func(raw, method string, auth bool) (int, json.RawMessage, error) {
		req, e := http.NewRequestWithContext(ctx, method, raw, nil)
		if e != nil {
			return 0, nil, e
		}
		if auth {
			req.Header.Set("CF-Access-Client-Id", credential.ClientID)
			req.Header.Set("CF-Access-Client-Secret", credential.ClientSecret)
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
	code, _, _ = get(state.DiscoveryURL, "GET", false)
	if code != 401 && code != 403 && code != 302 {
		return errors.New("discovery is not Access protected")
	}
	hosts := []string{state.ServiceURL, strings.Replace(state.ProxyURLTemplate, "{proxy}", "lpcc-readiness", 1)}
	for _, host := range hosts {
		for _, path := range []string{"/discovery", "/%64iscovery", "/./discovery", "//discovery", "/apps/x/app/../../discovery", "/ai/trickle/private/0", "/runners/heartbeat", "/runner/x/session/y/channels", "/metrics", "/readyz"} {
			method := "GET"
			if strings.Contains(path, "runners") || strings.Contains(path, "channels") {
				method = "POST"
			}
			u, e := url.Parse(host)
			if e != nil {
				return e
			}
			probe, _ := url.Parse(path)
			u.Path = probe.Path
			u.RawPath = probe.RawPath
			code, _, e = get(u.String(), method, false)
			if e != nil || code != 404 && code != 403 && code != 400 {
				return fmt.Errorf("public route isolation is not verified")
			}
		}
	}
	return nil
}
