package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"uuid"
)

func TestArtifactPublicationFencesAfterLockWait(t *testing.T) {
	for _, credentialChange := range []bool{false, true} {
		name := "routing"
		if credentialChange {
			name = "credential"
		}
		t.Run(name, func(t *testing.T) {
			s := newTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("3", 64))
			m, e := s.authenticateMachine(t.Context(), c["node_id"], c["token"], false)
			if e != nil {
				t.Fatal(e)
			}
			old := routingFor(m.NodeID, "example.invalid")
			raw, _ := json.Marshal(old)
			execSQL(t, s.db, `INSERT INTO lpcc.machine_tunnels(node_id,epoch,state) VALUES($1,$2,$3)`, m.NodeID, m.Epoch, raw)
			if e = s.reconcile(t.Context()); e != nil {
				t.Fatal(e)
			}
			newer := old
			if credentialChange {
				m.CredentialVersion++
			} else {
				newer.Generation++
			}
			m.Routing = &newer
			m.ControlAPIURL = s.params.PublicAPIURL
			m.TunnelConfig = &s.params.TunnelParams
			bundle, digest, e := buildBundle(m)
			if e != nil {
				t.Fatal(e)
			}
			tx, e := s.db.Begin()
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			if _, e = tx.Exec(`SELECT FROM lpcc.machine_configs WHERE node_id=$1 FOR UPDATE`, m.NodeID); e != nil {
				t.Fatal(e)
			}
			if credentialChange {
				if _, e = tx.Exec(`UPDATE lpcc.machines SET credential_version=$2 WHERE node_id=$1`, m.NodeID, m.CredentialVersion); e != nil {
					t.Fatal(e)
				}
				if _, e = tx.Exec(`UPDATE lpcc.enrollments SET credential_version=$3 WHERE node_id=$1 AND epoch=$2`, m.NodeID, m.Epoch, m.CredentialVersion); e != nil {
					t.Fatal(e)
				}
			} else {
				raw, _ = json.Marshal(newer)
				if _, e = tx.Exec(`UPDATE lpcc.machine_tunnels SET state=$3,revision=revision+1 WHERE node_id=$1 AND epoch=$2`, m.NodeID, m.Epoch, raw); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = tx.Exec(`UPDATE lpcc.machine_configs SET bundle=$2,sha256=$3 WHERE node_id=$1`, m.NodeID, bundle, digest); e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- s.reconcile(t.Context()) }()
			deadline := time.Now().Add(5 * time.Second)
			blocked := false
			for time.Now().Before(deadline) {
				if e = s.db.QueryRow(`SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock')`).Scan(&blocked); e != nil {
					t.Fatal(e)
				}
				if blocked {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !blocked {
				t.Fatal("publisher did not wait behind concurrent commit")
			}
			if e = tx.Commit(); e != nil {
				t.Fatal(e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			var data []byte
			if e = s.db.QueryRow(`SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, m.NodeID).Scan(&data); e != nil {
				t.Fatal(e)
			}
			var desired runtimeDesired
			if e = json.Unmarshal([]byte(archiveFiles(t, data)["runtime.json"]), &desired); e != nil {
				t.Fatal(e)
			}
			if desired.Generation != newer.Generation || desired.CredentialVersion != m.CredentialVersion {
				t.Fatalf("stale publisher replaced newer committed artifact: generation=%d credential=%d", desired.Generation, desired.CredentialVersion)
			}
		})
	}
}

func TestCloudflareDNSRecordEnvelopes(t *testing.T) {
	var record map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result any
		switch r.Method {
		case "POST", "PUT":
			if e := json.NewDecoder(r.Body).Decode(&record); e != nil {
				t.Error(e)
			}
			record["id"] = "dns-id"
			record["tags"] = []string{}
			result = record
		case "DELETE":
			record = nil
			result = map[string]string{"id": "dns-id"}
		case "GET":
			if strings.HasSuffix(r.URL.Path, "/dns-id") {
				if record == nil {
					w.WriteHeader(404)
					return
				}
				result = record
			} else if record != nil {
				result = []any{record}
			} else {
				result = []any{}
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	defer server.Close()
	c := &cloudflareHTTP{client: server.Client(), base: server.URL, params: TunnelParams{CloudflareZoneID: "zone"}}
	r := CFResource{Kind: "dns", Name: "owned-epoch-dns", Host: "api.example.invalid"}
	created, _, _, e := c.Create(t.Context(), r, "tunnel-id")
	if e != nil {
		t.Fatal(e)
	}
	for _, input := range []CFResource{r, created} {
		found, e := c.Find(t.Context(), input)
		if e != nil || len(found) != 1 || !found[0].Proxied {
			t.Fatal(found, e)
		}
	}
	if e = c.Route(t.Context(), created, "replacement"); e != nil {
		t.Fatal(e)
	}
	if e = c.Delete(t.Context(), created, ""); e != nil {
		t.Fatal(e)
	}
	if found, e := c.FindOwned(t.Context(), r); e != nil || len(found) != 0 {
		t.Fatal(found, e)
	}
}

func TestCreateRecoveryRetainsSelectionAndAbsentWatch(t *testing.T) {
	for _, kind := range []string{"tunnel", "token"} {
		t.Run(kind, func(t *testing.T) {
			s, f := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("6", 64))
			l := claimTestTunnel(t, s, c)
			m := l.m
			var e error
			defer l.finish(t.Context(), false)
			key := kind
			if kind == "token" {
				key = "token-1"
			}
			// Durable intent with no provider effect covers crash-before-send and a
			// lost response whose create never took effect.
			r := CFResource{Kind: kind, Name: resourceName(m, key), Pending: true, AttemptAt: time.Now().Add(-time.Hour), Attempts: 1, OperationVersion: 1}
			if kind == "token" {
				r.CredentialVersion = 1
				r.Duration = "24h0m0s"
			}
			l.state.Resources[key] = r
			if e = l.save(t.Context()); e != nil {
				t.Fatal(e)
			}
			selected, e := l.ensure(t.Context(), key, kind, "", "")
			if e != nil {
				t.Fatal(e)
			}
			if selected.ID == "" || !selected.Watch || f.creates[kind] != 1 {
				t.Fatal(selected, f.creates)
			}
			var original AccessCredential
			if kind == "token" {
				original, e = s.ResolveAccessCredential(t.Context(), credentialRef(m.NodeID, m.Epoch, 1))
				if e != nil {
					t.Fatal(e)
				}
			}
			late := selected
			late.ID = "000-late-result"
			f.resources[late.ID] = late
			again, e := l.ensure(t.Context(), key, kind, "", "")
			if e != nil {
				t.Fatal(e)
			}
			if again.ID != selected.ID || len(f.resources) != 1 {
				t.Fatal("late result replaced selected identity", again, f.resources)
			}
			if kind == "token" {
				current, e := s.ResolveAccessCredential(t.Context(), credentialRef(m.NodeID, m.Epoch, 1))
				if e != nil || current != original {
					t.Fatal("immutable secret changed", e)
				}
			}
			if e = l.retireResource(t.Context(), key); e != nil {
				t.Fatal(e)
			}
			if !l.state.Resources[key].ObservedAbsent || len(f.resources) != 0 {
				t.Fatal("absence not recorded")
			}
			// A delayed result after absence is still owned and must be swept. A
			// replacement enrollment's differently owned resource is left alone.
			f.resources[late.ID] = late
			foreign := late
			foreign.ID = "new-enrollment"
			foreign.Name += "-new"
			f.resources[foreign.ID] = foreign
			if e = l.sweepAbsentResources(t.Context(), true); e != nil {
				t.Fatal(e)
			}
			if len(f.resources) != 1 || f.resources[foreign.ID].ID == "" {
				t.Fatal("late cleanup crossed ownership", f.resources)
			}
		})
	}
}

type rotationFailures struct {
	*simulatedCloudflare
	reject int
	lose   bool
	calls  int
}

func (f *rotationFailures) RotateConnector(ctx context.Context, id string) error {
	f.calls++
	if f.reject > 0 {
		f.reject--
		return &cloudflareFailure{status: 429}
	}
	if e := f.simulatedCloudflare.RotateConnector(ctx, id); e != nil {
		return e
	}
	if f.lose {
		f.lose = false
		return &cloudflareFailure{ambiguous: true}
	}
	return nil
}

func TestOfflineSecurityMaintenanceAndRotationRecovery(t *testing.T) {
	for _, lose := range []bool{false, true} {
		t.Run(fmt.Sprint("lost-response-", lose), func(t *testing.T) {
			s, base := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("7", 64))
			initial := readyTunnel(t, s, c)
			f := &rotationFailures{simulatedCloudflare: base, lose: lose}
			if !lose {
				f.reject = 1
			}
			s.provider = f
			adminA(t, s)
			path := "/api/admin/machines/" + c["node_id"] + "/tunnel/rotate"
			for _, kind := range []string{"connector", "access"} {
				requireStatus(t, request(t, s, "POST", path, "session-a", map[string]any{"epoch": c["epoch"], "kind": kind, "compromised": true}), 202)
			}
			execSQL(t, s.db, `UPDATE lpcc.machine_reports SET received_at=now()-interval '1 hour'`)
			driveTunnels(t, s)
			driveTunnels(t, s)
			current, _, e := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
			if e != nil || current.CredentialGeneration != initial.CredentialGeneration+1 || current.AccessVersion != initial.AccessVersion+1 || current.Ready || base.disconnected != 1 {
				t.Fatal(current, base.disconnected, e)
			}
			if f.calls != map[bool]int{false: 2, true: 1}[lose] {
				t.Fatal("rotation replayed after success", f.calls)
			}
			if _, e = s.ResolveAccessCredential(t.Context(), credentialRef(c["node_id"], c["epoch"], initial.AccessVersion)); e == nil {
				t.Fatal("compromised credential still resolves")
			}
			requireStatus(t, request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/tunnel/connector-token", c["token"], map[string]any{}), 409)
		})
	}
}

func TestExpiredUnacknowledgedAccessVersionsRecover(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("5", 64))
	initial := readyTunnel(t, s, c)
	adminA(t, s)
	requireStatus(t, request(t, s, "POST", "/api/admin/machines/"+c["node_id"]+"/tunnel/rotate", "session-a", map[string]any{"epoch": c["epoch"], "kind": "access"}), 202)
	driveTunnels(t, s)
	if n := count(t, s, `SELECT count(*) FROM lpcc.access_credentials WHERE revoked_at IS NULL`); n != 2 {
		t.Fatal(n)
	}
	execSQL(t, s.db, `UPDATE lpcc.access_credentials SET expires_at=now()-interval '1 minute'`)
	driveTunnels(t, s)
	current, _, _ := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if current.AccessVersion != initial.AccessVersion+2 {
		t.Fatal(current)
	}
	if _, e := s.ResolveAccessCredential(t.Context(), credentialRef(c["node_id"], c["epoch"], current.AccessVersion)); e != nil {
		t.Fatal(e)
	}
	sources, e := s.DiscoverySources(t.Context())
	if e != nil || len(sources) != 1 {
		t.Fatal(e, sources)
	}
	if e = s.AcknowledgeDiscovery(t.Context(), sources[0]); e != nil {
		t.Fatal(e)
	}
	if n := count(t, s, `SELECT count(*) FROM lpcc.access_credentials WHERE revoked_at IS NULL`); n != 1 {
		t.Fatal(n)
	}
}

type appCreateFailure struct{ *simulatedCloudflare }

func (f *appCreateFailure) Create(ctx context.Context, r CFResource, target string) (CFResource, *AccessCredential, time.Time, error) {
	if r.Kind == "app" {
		return r, nil, time.Time{}, &cloudflareFailure{status: 403}
	}
	return f.simulatedCloudflare.Create(ctx, r, target)
}
func TestEndpointFailurePreservesConnectorAndRollbackReusesOwnership(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("4", 64))
	initial := readyTunnel(t, s, c)
	appID := initial.Resources["g1-app"].ID
	s.params.CloudflareBaseDomain = "replacement.example.invalid"
	driveTunnels(t, s)
	reportRuntime(t, s, c, "runner", true)
	s.provider = &appCreateFailure{f}
	driveTunnels(t, s)
	state, _, _ := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	bundle := request(t, s, "GET", "/v1/nodes/"+c["node_id"]+"/config", c["token"], nil)
	files := archiveFiles(t, bundle.Body.Bytes())
	if state.IngressDigest != initial.IngressDigest || files["tunnel.yaml"] == "" || files["tunnel-network.yaml"] == "" {
		t.Fatal("failed replacement pruned last connector", state, files["kustomization.yaml"])
	}
	s.provider = f
	s.endpointVerifier = func(context.Context, RoutingState, AccessCredential) error { return errors.New("TLS pending") }
	driveTunnels(t, s)
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	reportRuntime(t, s, c, "runtime", true)
	reportRuntime(t, s, c, "connector", true)
	driveTunnels(t, s)
	s.params.CloudflareBaseDomain = "fleet.example.invalid"
	s.endpointVerifier = func(context.Context, RoutingState, AccessCredential) error { return nil }
	driveTunnels(t, s)
	restored := readyTunnel(t, s, c)
	key := fmt.Sprintf("g%d-app", restored.EndpointGeneration)
	if restored.Resources[key].ID != appID || restored.TunnelID != initial.TunnelID || f.creates["app"] != 2 {
		t.Fatal("rollback recreated or conflicted with owned predecessor", restored, f.creates)
	}
}

func TestLateDrainReportNeedsAuditedRetry(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("2", 64))
	readyTunnel(t, s, c)
	adminA(t, s)
	path := "/api/admin/machines/" + c["node_id"]
	requireStatus(t, request(t, s, "DELETE", path, "session-a", map[string]any{"epoch": c["epoch"]}), 202)
	execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET state=jsonb_set(state,'{drain_started_at}',to_jsonb($1::text))`, time.Now().Add(-time.Hour).Format(time.RFC3339Nano))
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	state, _, _ := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if state.Reason != "drain_timeout" || count(t, s, `SELECT count(*) FROM lpcc.machines`) != 1 {
		t.Fatal("late report crossed drain deadline", state)
	}
	requireStatus(t, request(t, s, "POST", path+"/drain/retry", "session-a", map[string]any{"epoch": c["epoch"], "generation": state.Generation - 1}), 409)
	requireStatus(t, request(t, s, "POST", path+"/drain/retry", "session-a", map[string]any{"epoch": c["epoch"], "generation": state.Generation}), 202)
	driveTunnels(t, s)
	if count(t, s, `SELECT count(*) FROM lpcc.machines`) != 1 {
		t.Fatal("old drain report satisfied new generation")
	}
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	driveTunnels(t, s)
	if count(t, s, `SELECT count(*) FROM lpcc.machines`) != 0 || count(t, s, `SELECT count(*) FROM lpcc.admin_audit_events WHERE action='machine.drain.retry' AND outcome='success'`) != 1 {
		t.Fatal("audited retry did not finish removal")
	}
}

func TestDevelopmentEnrollmentNeedsExplicitRefresh(t *testing.T) {
	s, _ := tunnelTestServer(t)
	jwt, _, _ := signEnrollment(s.params.JWTSigningSecret, ownerA, time.Now())
	fp := strings.Repeat("1", 64)
	w := request(t, s, "POST", "/v1/nodes/register", jwt, map[string]any{"fingerprint": fp, "hostname": "worker-01", "install_dir": "/opt/livepeer", "k3s_version": "v1.37.2+k3s1", "development_http": true})
	requireStatus(t, w, 200)
	var c map[string]string
	if e := json.Unmarshal(w.Body.Bytes(), &c); e != nil {
		t.Fatal(e)
	}
	reportRuntime(t, s, c, "runtime", false)
	driveTunnels(t, s)
	// An ordinary enrollment retry over the production URL must not upgrade a
	// credential previously released to development HTTP consumers.
	enroll(t, s, ownerA, fp)
	driveTunnels(t, s)
	if count(t, s, `SELECT count(*) FROM lpcc.machines WHERE tunnel_eligible`) != 0 || count(t, s, `SELECT count(*) FROM lpcc.machine_tunnels`) != 0 {
		t.Fatal("development enrollment became live")
	}
	w = request(t, s, "POST", "/v1/nodes/"+c["node_id"]+"/credentials/refresh", jwt, map[string]any{"fingerprint": fp, "install_dir": "/opt/livepeer", "operation_id": uuid.New().String(), "expected_credential_version": 1})
	requireStatus(t, w, 200)
	if count(t, s, `SELECT count(*) FROM lpcc.machines WHERE tunnel_eligible AND credential_version=2`) != 1 {
		t.Fatal("explicit refresh did not enable secure enrollment")
	}
}

type lostTokenCheckpoint struct {
	*simulatedCloudflare
	afterCreate func()
	lostDelete  bool
}

func (f *lostTokenCheckpoint) Create(ctx context.Context, r CFResource, target string) (CFResource, *AccessCredential, time.Time, error) {
	created, secret, expiry, e := f.simulatedCloudflare.Create(ctx, r, target)
	if r.Kind == "token" && f.afterCreate != nil {
		f.afterCreate()
		f.afterCreate = nil
	}
	return created, secret, expiry, e
}
func (f *lostTokenCheckpoint) Delete(ctx context.Context, r CFResource, target string) error {
	if e := f.simulatedCloudflare.Delete(ctx, r, target); e != nil {
		return e
	}
	if r.Kind == "token" && f.lostDelete {
		f.lostDelete = false
		return &cloudflareFailure{ambiguous: true}
	}
	return nil
}
func TestAccessSecretCheckpointAndStrandedDeletionRecovery(t *testing.T) {
	s, base := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("0", 64))
	l := claimTestTunnel(t, s, c)
	m := l.m
	var e error
	f := &lostTokenCheckpoint{simulatedCloudflare: base, lostDelete: true}
	l.provider = f
	f.afterCreate = func() {
		execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET revision=revision+1 WHERE node_id=$1`, m.NodeID)
	}
	if _, e = l.ensure(t.Context(), "token-1", "token", "", ""); !errors.Is(e, errTunnelFenced) {
		t.Fatal("failed checkpoint accepted", e)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.access_credentials`) != 0 {
		t.Fatal("secret committed without selected resource")
	}
	l.finish(t.Context(), false)
	execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET next_attempt_at=now()`)
	l, e = s.claimTunnel(t.Context(), m)
	if e != nil {
		t.Fatal(e)
	}
	defer l.finish(t.Context(), false)
	l.provider = f
	r := l.state.Resources["token-1"]
	r.AttemptAt = time.Now().Add(-time.Hour)
	l.state.Resources["token-1"] = r
	if e = l.save(t.Context()); e != nil {
		t.Fatal(e)
	}
	if _, e = l.ensure(t.Context(), "token-1", "token", "", ""); e == nil {
		t.Fatal("lost deletion response not injected")
	}
	// The provider has deleted the stranded token, but the worker never saved
	// that observation. Retrying the persisted operation must still converge.
	selected, e := l.ensure(t.Context(), "token-1", "token", "", "")
	if e != nil {
		t.Fatal(e)
	}
	var bound string
	if e = s.db.QueryRow(`SELECT provider_id FROM lpcc.access_credentials WHERE node_id=$1 AND epoch=$2 AND version=1`, m.NodeID, m.Epoch).Scan(&bound); e != nil || bound != selected.ID || len(base.resources) != 1 {
		t.Fatal("resource/secret binding did not converge", bound, selected, e)
	}
}

type policyDeleteFailure struct {
	*simulatedCloudflare
	fail  bool
	after bool
}

func (f *policyDeleteFailure) Delete(ctx context.Context, r CFResource, target string) error {
	if f.fail && r.Kind == "policy" {
		f.fail = false
		if f.after {
			if e := f.simulatedCloudflare.Delete(ctx, r, target); e != nil {
				return e
			}
		}
		return &cloudflareFailure{ambiguous: true}
	}
	return f.simulatedCloudflare.Delete(ctx, r, target)
}
func TestSupersededCreateHandoffSurvivesCleanupFailure(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint("lost-delete-response-", after), func(t *testing.T) {
			s, base := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("a", 64))
			l := claimTestTunnel(t, s, c)
			m := l.m
			var e error
			key := "g1-policy"
			old := CFResource{Kind: "policy", Name: resourceName(m, key), Host: "app-id", Pending: true, Attempts: 1, OperationVersion: 1, CreationTarget: "token-a"}
			l.state.Resources[key] = old
			if e = l.save(t.Context()); e != nil {
				t.Fatal(e)
			}
			providerOld := old
			providerOld.ID = "old-policy"
			providerOld.Pending = false
			base.resources[providerOld.ID] = providerOld
			l.provider = &policyDeleteFailure{simulatedCloudflare: base, fail: true, after: after}
			if _, e = l.ensure(t.Context(), key, "policy", "app-id", "token-b"); e == nil {
				t.Fatal("cleanup failure not injected")
			}
			persisted, _, e := s.loadTunnel(t.Context(), m.NodeID, m.Epoch)
			if e != nil {
				t.Fatal(e)
			}
			if persisted.Resources[key].Absent || persisted.Resources[key].CreationTarget != "token-b" || !persisted.Resources["retired:"+old.Name].Absent {
				t.Fatal("handoff was not atomic", persisted.Resources)
			}
			l.finish(t.Context(), true)
			execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET next_attempt_at=now()`)
			l, e = s.claimTunnel(t.Context(), m)
			if e != nil {
				t.Fatal(e)
			}
			defer l.finish(t.Context(), false)
			selected, e := l.ensure(t.Context(), key, "policy", "app-id", "token-b")
			if e != nil {
				t.Fatal(e)
			}
			if selected.OperationVersion != 2 || selected.ID == "old-policy" || len(base.resources) != 1 {
				t.Fatal("replacement did not converge", selected, base.resources)
			}
		})
	}
}

type tokenCreateFailure struct {
	*simulatedCloudflare
	fail bool
}

func (f *tokenCreateFailure) Create(ctx context.Context, r CFResource, target string) (CFResource, *AccessCredential, time.Time, error) {
	if r.Kind == "token" && f.fail {
		return r, nil, time.Time{}, &cloudflareFailure{status: 503, ambiguous: true}
	}
	return f.simulatedCloudflare.Create(ctx, r, target)
}
func TestOfflineAccessReplacementStatusSurvivesFailure(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint("expired-", expired), func(t *testing.T) {
			s, base := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("b", 64))
			initial := readyTunnel(t, s, c)
			f := &tokenCreateFailure{simulatedCloudflare: base, fail: true}
			s.provider = f
			execSQL(t, s.db, `UPDATE lpcc.machine_reports SET received_at=now()-interval '1 hour'`)
			reason, recovered := "access_rotation_failed", "rotation_ack_pending"
			if expired {
				execSQL(t, s.db, `UPDATE lpcc.access_credentials SET expires_at=now()-interval '1 minute'`)
				reason, recovered = "access_credential_expired", ""
			} else {
				adminA(t, s)
				requireStatus(t, request(t, s, "POST", "/api/admin/machines/"+c["node_id"]+"/tunnel/rotate", "session-a", map[string]any{"epoch": c["epoch"], "kind": "access"}), 202)
			}
			for i := 0; i < 2; i++ {
				driveTunnels(t, s)
				state, _, _ := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
				if state.AccessVersion != initial.AccessVersion+1 || state.Reason != "runtime_offline" || state.RotationReason != reason {
					t.Fatal("lost credential failure cause", state)
				}
			}
			f.fail = false
			// Allow the persisted retry deadline without waiting in the test.
			execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET state=jsonb_set(state,'{resources,token-2,attempt_at}',to_jsonb($1::text))`, time.Now().Add(-time.Hour).Format(time.RFC3339Nano))
			driveTunnels(t, s)
			state, _, _ := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
			if state.Reason != "runtime_offline" || state.RotationReason != recovered || state.Ready {
				t.Fatal("recovery lost independent Runtime state", state)
			}
		})
	}
}

type dnsDeleteFailure struct{ *simulatedCloudflare }

func (f *dnsDeleteFailure) Delete(ctx context.Context, r CFResource, target string) error {
	if r.Kind == "dns" {
		return &cloudflareFailure{status: 503, ambiguous: true}
	}
	return f.simulatedCloudflare.Delete(ctx, r, target)
}
func TestLateRetiredResultWithdrawsSuccessorReadiness(t *testing.T) {
	s, base := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("c", 64))
	old := readyTunnel(t, s, c)
	late := old.Resources["g1-dns-0"]
	// Only ambiguous operations need periodic late-result inventories.
	execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET state=jsonb_set(state,'{resources,g1-dns-0,watch}','true')`)
	if e := s.RetireMachine(t.Context(), c["node_id"]); e != nil {
		t.Fatal(e)
	}
	driveTunnels(t, s)
	newC := enroll(t, s, ownerA, strings.Repeat("c", 64))
	readyTunnel(t, s, newC)
	late.ID = "late-old-dns"
	base.resources[late.ID] = late
	execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET state=jsonb_set(state,'{resources,g1-dns-0,audit_after}',to_jsonb($1::text)) WHERE epoch=$2`, time.Now().Add(-time.Hour).Format(time.RFC3339Nano), c["epoch"])
	s.provider = &dnsDeleteFailure{base}
	// Two passes remove dependence on enrollment row enumeration order.
	driveTunnels(t, s)
	driveTunnels(t, s)
	sources, e := s.DiscoverySources(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	for _, source := range sources {
		if source.Epoch == newC["epoch"] && (source.Ready || source.Reason != "predecessor_cleanup_pending") {
			t.Fatal("advertised successor with unresolved predecessor", source)
		}
	}
	s.provider = base
	driveTunnels(t, s)
	driveTunnels(t, s)
	readyTunnel(t, s, newC)
}

func TestSecureEnrollmentBeforeEnablementCanProvision(t *testing.T) {
	s, f := tunnelTestServer(t)
	s.params.CloudflareEnabled = false
	s.provider = nil
	c := enroll(t, s, ownerA, strings.Repeat("d", 64))
	if count(t, s, `SELECT count(*) FROM lpcc.machines WHERE tunnel_eligible`) != 1 || count(t, s, `SELECT count(*) FROM lpcc.machine_tunnels`) != 0 {
		t.Fatal("secure issuance coupled to enablement")
	}
	s.params.CloudflareEnabled = true
	s.provider = f
	readyTunnel(t, s, c)
}

func TestOfflineAcknowledgementRetiresOverlapAndPermitsNextRotation(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("e", 64))
	readyTunnel(t, s, c)
	adminA(t, s)
	path := "/api/admin/machines/" + c["node_id"] + "/tunnel/rotate"
	rotate := map[string]any{"epoch": c["epoch"], "kind": "access"}
	requireStatus(t, request(t, s, "POST", path, "session-a", rotate), 202)
	driveTunnels(t, s)
	sources, e := s.DiscoverySources(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	if e = s.AcknowledgeDiscovery(t.Context(), sources[0]); e != nil {
		t.Fatal(e)
	}
	execSQL(t, s.db, `UPDATE lpcc.machine_reports SET received_at=now()-interval '1 hour'`)
	driveTunnels(t, s)
	state, _, _ := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	current := state.Resources["token-2"].ID
	if count(t, s, `SELECT count(*) FROM lpcc.access_credentials WHERE revoked_at IS NULL`) != 1 {
		t.Fatal("acknowledged predecessor retained offline")
	}
	for _, ids := range f.policies {
		if len(ids) != 1 || ids[0] != current {
			t.Fatal("policy overlap survived acknowledgement", ids)
		}
	}
	requireStatus(t, request(t, s, "POST", path, "session-a", rotate), 202)
	driveTunnels(t, s)
	state, _, _ = s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if state.AccessVersion != 3 {
		t.Fatal("acknowledged overlap blocked next rotation", state)
	}
}

func TestRollbackReusesUnselectedOwnedOperation(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("f", 64))
	l := claimTestTunnel(t, s, c)
	m := l.m
	var e error
	defer l.finish(t.Context(), false)
	old := CFResource{Kind: "app", Name: resourceName(m, "g1-app"), Host: "discovery.example.invalid", Pending: true, Attempts: 1, OperationVersion: 1}
	l.state.Resources["g1-app"] = old
	if e = l.save(t.Context()); e != nil {
		t.Fatal(e)
	}
	observed := old
	observed.ID = "late-app"
	observed.Audience = "aud"
	observed.Pending = false
	f.resources[observed.ID] = observed
	r, e := l.ensure(t.Context(), "g3-app", "app", old.Host, "")
	if e != nil || r.ID != observed.ID || r.Name != old.Name || f.creates["app"] != 0 {
		t.Fatal("rollback lost unselected ownership", r, e)
	}
}

func TestEndpointDrainCancellationAndFailedStageRollback(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(fmt.Sprint("completed-", completed), func(t *testing.T) {
			s, f := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("a", 64))
			initial := readyTunnel(t, s, c)
			s.params.CloudflareBaseDomain = "replacement.example.invalid"
			driveTunnels(t, s)
			if completed {
				reportRuntime(t, s, c, "runner", true)
				s.provider = &appCreateFailure{f}
				driveTunnels(t, s)
			}
			execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET state=jsonb_set(state,'{drain_started_at}',to_jsonb($1::text))`, time.Now().Add(-time.Hour).Format(time.RFC3339Nano))
			s.params.CloudflareBaseDomain = "fleet.example.invalid"
			s.provider = f
			driveTunnels(t, s)
			current, _, _ := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
			if current.DrainRequested || current.EndpointDrainURL != "" || current.ServiceURL != initial.ServiceURL {
				t.Fatal("obsolete endpoint drain survived rollback", current)
			}
			// No fresh runner report is needed to retain the already applied A workload.
			reportRuntime(t, s, c, "runtime", true)
			reportRuntime(t, s, c, "connector", true)
			driveTunnels(t, s)
			current, _, _ = s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
			if !current.Ready {
				t.Fatal("rollback to applied workload imposed another drain", current)
			}
		})
	}
}
func TestUnfinishedEndpointDrainCannotResetItsDeadline(t *testing.T) {
	s, _ := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("b", 64))
	initial := readyTunnel(t, s, c)
	s.params.CloudflareBaseDomain = "replacement.example.invalid"
	driveTunnels(t, s)
	old := time.Now().UTC().Add(-time.Hour)
	execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET state=jsonb_set(state,'{drain_started_at}',to_jsonb($1::text))`, old.Format(time.RFC3339Nano))
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	state, _, _ := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if state.Reason != "drain_timeout" || state.ServiceURL != initial.ServiceURL || !state.DrainStartedAt.Equal(old) {
		t.Fatal("same-target retry revived expired drain", state)
	}
	adminA(t, s)
	requireStatus(t, request(t, s, "POST", "/api/admin/machines/"+c["node_id"]+"/drain/retry", "session-a", map[string]any{"epoch": c["epoch"], "generation": state.Generation}), 202)
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	state, _, _ = s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if state.ServiceURL == initial.ServiceURL {
		t.Fatal("audited endpoint retry did not proceed", state)
	}
}

type protectFailure struct {
	*simulatedCloudflare
	failure error
}

func (f *protectFailure) Protect(ctx context.Context, r CFResource, ids []string) error {
	if f.failure != nil {
		return f.failure
	}
	return f.simulatedCloudflare.Protect(ctx, r, ids)
}
func TestProtectionFailuresPreserveOrRestoreAppliedIngressOffline(t *testing.T) {
	s, base := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("c", 64))
	initial := readyTunnel(t, s, c)
	f := &protectFailure{simulatedCloudflare: base}
	s.provider = f
	execSQL(t, s.db, `UPDATE lpcc.machine_reports SET received_at=now()-interval '1 hour'`)
	for _, code := range []int{503, 429} {
		f.failure = &cloudflareFailure{status: code}
		driveTunnels(t, s)
		if ingressHash(base.configurations[initial.TunnelID]) != initial.IngressDigest {
			t.Fatal("transient failure erased working ingress")
		}
	}
	f.failure = errUnsafeProtection
	driveTunnels(t, s)
	state, _, _ := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if !state.Quarantined || len(base.configurations[initial.TunnelID]) != 1 {
		t.Fatal("unsafe policy left routes exposed", state)
	}
	f.failure = nil
	driveTunnels(t, s)
	state, _, _ = s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if state.Quarantined || state.Reason != "runtime_offline" || ingressHash(base.configurations[initial.TunnelID]) != initial.IngressDigest {
		t.Fatal("verified offline protection did not restore applied ingress", state)
	}
}

type reconnectingConnector struct {
	*rotationFailures
	original string
}

func (f *reconnectingConnector) Delete(ctx context.Context, r CFResource, target string) error {
	if r.Kind == "tunnel" && f.tokens[r.ID] == f.original {
		return &cloudflareFailure{status: 409}
	}
	return f.simulatedCloudflare.Delete(ctx, r, target)
}
func TestRemovalRevokesReconnectingConnectorAndResumesLostResponse(t *testing.T) {
	for _, alreadyAbsent := range []bool{false, true} {
		t.Run(fmt.Sprint("already-absent-", alreadyAbsent), func(t *testing.T) {
			s, base := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("d", 64))
			initial := readyTunnel(t, s, c)
			f := &reconnectingConnector{rotationFailures: &rotationFailures{simulatedCloudflare: base, lose: true}, original: base.tokens[initial.TunnelID]}
			s.provider = f
			if alreadyAbsent {
				delete(base.resources, initial.TunnelID)
			} else {
				// An interrupted old cleanup may already have persisted an absent intent.
				execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET state=jsonb_set(state,'{resources,tunnel,absent}','true')`)
			}
			if e := s.RetireMachine(t.Context(), c["node_id"]); e != nil {
				t.Fatal(e)
			}
			driveTunnels(t, s)
			driveTunnels(t, s)
			state, _, _ := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
			if !state.CleanupComplete || len(base.resources) != 0 {
				t.Fatal("connector could reauthenticate during deletion", state, base.resources)
			}
			if !alreadyAbsent && (f.calls != 1 || !state.ConnectorRevoked || base.tokens[initial.TunnelID] == f.original) {
				t.Fatal("lost rotation response did not converge", state, f.calls)
			}
			if alreadyAbsent && f.calls != 0 {
				t.Fatal("rotation required an already deleted tunnel")
			}
		})
	}
}
func TestModernIneligibleMachineCanCompleteRemoval(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("e", 64))
	execSQL(t, s.db, `UPDATE lpcc.machines SET tunnel_eligible=false`)
	adminA(t, s)
	requireStatus(t, request(t, s, "DELETE", "/api/admin/machines/"+c["node_id"], "session-a", map[string]any{"epoch": c["epoch"]}), 202)
	reportRuntime(t, s, c, "runner", true)
	driveTunnels(t, s)
	driveTunnels(t, s)
	if count(t, s, `SELECT count(*) FROM lpcc.machines`) != 0 || f.creates["tunnel"] != 0 {
		t.Fatal("removal depended on provisioning eligibility")
	}
}

func TestAcknowledgedRetirementCheckpointCanResumeReplacement(t *testing.T) {
	for _, compromised := range []bool{false, true} {
		t.Run(fmt.Sprint("compromised-", compromised), func(t *testing.T) {
			s, base := tunnelTestServer(t)
			c := enroll(t, s, ownerA, strings.Repeat("f", 64))
			initial := readyTunnel(t, s, c)
			sources, e := s.DiscoverySources(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			if e = s.AcknowledgeDiscovery(t.Context(), sources[0]); e != nil {
				t.Fatal(e)
			}
			if compromised {
				adminA(t, s)
				requireStatus(t, request(t, s, "POST", "/api/admin/machines/"+c["node_id"]+"/tunnel/rotate", "session-a", map[string]any{"epoch": c["epoch"], "kind": "access", "compromised": true}), 202)
			} else {
				execSQL(t, s.db, `UPDATE lpcc.access_credentials SET expires_at=now()-interval '1 minute'`)
			}
			s.provider = &lostTokenCheckpoint{simulatedCloudflare: base, lostDelete: true}
			driveTunnels(t, s)
			checkpoint, _, _ := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
			if checkpoint.AccessVersion != initial.AccessVersion || !checkpoint.Resources["token-1"].Absent || count(t, s, `SELECT count(*) FROM lpcc.access_credentials WHERE revoked_at IS NOT NULL AND acknowledged_at IS NOT NULL`) != 1 {
				t.Fatal("retirement checkpoint was not reached", checkpoint)
			}
			// driveTunnels reloads the lease and JSON, including the retained old ack.
			driveTunnels(t, s)
			recovered, _, _ := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
			if recovered.AccessVersion != initial.AccessVersion+1 {
				t.Fatal("old acknowledgement blocked replacement", recovered)
			}
			if _, e = s.ResolveAccessCredential(t.Context(), credentialRef(c["node_id"], c["epoch"], recovered.AccessVersion)); e != nil {
				t.Fatal(e)
			}
		})
	}
}

type cleanupAudits struct {
	*simulatedCloudflare
	inventories, rotations int
	selected, lateToken    string
	failDelete             bool
}

func (f *cleanupAudits) FindOwned(ctx context.Context, r CFResource) ([]CFResource, error) {
	f.inventories++
	return f.simulatedCloudflare.FindOwned(ctx, r)
}
func (f *cleanupAudits) RotateConnector(ctx context.Context, id string) error {
	f.rotations++
	return f.simulatedCloudflare.RotateConnector(ctx, id)
}
func (f *cleanupAudits) Delete(ctx context.Context, r CFResource, target string) error {
	if r.Kind == "tunnel" && r.ID == f.selected {
		if f.tokens[r.ID] == f.lateToken {
			return errors.New("late connector was not revoked before deletion")
		}
		if f.failDelete {
			f.failDelete = false
			return &cloudflareFailure{status: 503}
		}
	}
	return f.simulatedCloudflare.Delete(ctx, r, target)
}
func TestCompletedCleanupAuditsDueWatchesBeforeDeletingLateTunnel(t *testing.T) {
	s, base := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("1", 64))
	initial := readyTunnel(t, s, c)
	execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET state=jsonb_set(state,'{resources,tunnel,watch}','true')`)
	if e := s.RetireMachine(t.Context(), c["node_id"]); e != nil {
		t.Fatal(e)
	}
	driveTunnels(t, s)
	state, revision, e := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if e != nil || !state.CleanupComplete {
		t.Fatal(state, e)
	}
	f := &cleanupAudits{simulatedCloudflare: base, selected: initial.TunnelID}
	s.provider = f
	driveTunnels(t, s)
	_, after, _ := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if f.inventories != 0 || after != revision {
		t.Fatal("completed retirement ignored audit interval", f.inventories, revision, after)
	}
	overdue := time.Now().Add(-time.Hour).Format(time.RFC3339Nano)
	execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET state=jsonb_set(state,'{resources,tunnel,audit_after}',to_jsonb($1::text))`, overdue)
	driveTunnels(t, s)
	if f.inventories == 0 {
		t.Fatal("due watch was never inventoried")
	}
	state, _, _ = s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if !state.CleanupComplete || !time.Now().Before(state.Resources["tunnel"].AuditAfter) {
		t.Fatal("empty audit did not reschedule", state)
	}
	// A selected tunnel reappears with usable authentication. Audit must reopen
	// cleanup, not delete it before revocation; a failed delete must then resume.
	base.resources[initial.TunnelID] = initial.Resources["tunnel"]
	f.lateToken = "late-usable-connector-token"
	base.tokens[initial.TunnelID] = f.lateToken
	f.failDelete = true
	execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET state=jsonb_set(state,'{resources,tunnel,audit_after}',to_jsonb($1::text))`, overdue)
	driveTunnels(t, s)
	state, _, _ = s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if state.CleanupComplete || !state.ConnectorRevoked || f.rotations != 1 {
		t.Fatal("late tunnel bypassed revocation", state, f.rotations)
	}
	driveTunnels(t, s)
	state, _, _ = s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if !state.CleanupComplete || len(base.resources) != 0 || f.rotations != 1 {
		t.Fatal("reopened cleanup did not resume", state, f.rotations)
	}
}
