package tunnel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/api/internal/migrations"
	"github.com/livepeer/control-center/api/internal/testdb"
)

type recoveryCloudflare struct {
	// Unused provider methods panic if recovery unexpectedly calls them.
	TunnelProvider
	resources map[string]CFResource
	creates   map[string]int
}

func newRecoveryCloudflare() *recoveryCloudflare {
	return &recoveryCloudflare{resources: map[string]CFResource{}, creates: map[string]int{}}
}
func (f *recoveryCloudflare) Find(_ context.Context, r CFResource) ([]CFResource, error) {
	return f.find(r, false)
}
func (f *recoveryCloudflare) FindOwned(_ context.Context, r CFResource) ([]CFResource, error) {
	return f.find(r, true)
}
func (f *recoveryCloudflare) find(r CFResource, ownedOnly bool) ([]CFResource, error) {
	var found []CFResource
	if r.ID != "" {
		v, ok := f.resources[r.ID]
		if ok && (v.Kind != r.Kind || v.Name != r.Name || v.Host != r.Host) {
			return nil, ErrResourceConflict
		}
		if !r.Watch {
			if ok {
				r.Target = v.Target
				r.Proxied = v.Proxied
				r.Pending = false
				return []CFResource{r}, nil
			}
			return nil, nil
		}
	}
	for _, v := range f.resources {
		if !ownedOnly && r.ID == "" && r.Kind == "dns" && v.Kind == r.Kind && v.Host == r.Host && v.Name != r.Name {
			return nil, ErrResourceConflict
		}
		if v.Kind == r.Kind && v.Name == r.Name && v.Host == r.Host {
			copy := r
			copy.ID = v.ID
			copy.Target = v.Target
			copy.Proxied = v.Proxied
			copy.Pending = false
			found = append(found, copy)
		}
	}
	return found, nil
}
func (f *recoveryCloudflare) Create(_ context.Context, r CFResource, target string) (CFResource, error) {
	r.ID = uuid.New().String()
	r.Pending = false
	f.creates[r.Kind]++

	if r.Kind == "dns" {
		r.Target = target + ".cfargotunnel.com"
		r.Proxied = true
	}
	f.resources[r.ID] = r

	return r, nil
}
func (f *recoveryCloudflare) Delete(_ context.Context, r CFResource, _ string) error {
	delete(f.resources, r.ID)
	return nil
}
func TestTunnelIngressContract(t *testing.T) {
	rules := ingressFor(RoutingFor("vkvkvkvkvkvkuaaaaaaaaaaaaa", "example.invalid").RoutingState)
	match := func(host, path string) IngressRule {
		for _, r := range rules {
			hostOK := r.Hostname == "" || r.Hostname == host || strings.HasPrefix(r.Hostname, "*.") && strings.HasSuffix(host, r.Hostname[1:])
			if hostOK && (r.Path == "" || regexp.MustCompile(r.Path).MatchString(path)) {
				return r
			}
		}
		t.Fatal("no catch-all")
		return IngressRule{}
	}
	api := "api.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid"
	app := "proxy.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid"
	for _, host := range []string{api, app} {
		for _, path := range []string{"/discovery", "/prefix/discovery", "/runners/heartbeat", "/runner/a/session/b/channels", "/ai/trickle/x/0", "/metrics", "/readyz"} {
			if match(host, path).Service != "http_status:404" {
				t.Fatalf("exposed %s %s", host, path)
			}
		}
	}
	for _, path := range []string{"/apps/a/session", "/apps/a/session/b/stop", "/apps/a/session/b/payment", "/refresh-payment"} {
		rule := match(api, path)
		if rule.Service != machineconfig.PrivateIngressAPI || rule.OriginRequest == nil || rule.OriginRequest.HTTPHostHeader != endpointHost(PrivateOrchestrator) {
			t.Fatalf("missing client path %s", path)
		}
	}
	for _, path := range []string{"/apps/a/app", "/apps/a/app/v1/complete", "/apps/a/session/b/app", "/apps/a/session/b/app/ws", "/run/abc/media", "/proxy/abc"} {
		if rule := match(api, path); rule.Service != "http_status:404" {
			t.Fatalf("application data reached API Host: %s", path)
		}
	}
	for _, host := range []string{api, "discovery.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid", "api.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid", "discovery.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid"} {
		if match(host, "/unknown").Service != "http_status:404" {
			t.Fatal("exact hostname fell through to wildcard", host)
		}
	}
	if rule := match(app, "/v1/completions"); rule.Service != machineconfig.PrivateIngressApps || rule.OriginRequest != nil {
		t.Fatal("proxy Host was not preserved")
	}
	if match("alias.example.invalid", "/discovery").Service != "http_status:404" {
		t.Fatal("alias bypass")
	}
	for _, r := range rules {
		if r.Service != machineconfig.PrivateIngressAPI && r.Service != machineconfig.PrivateIngressDiscovery && r.Service != machineconfig.PrivateIngressApps && !strings.HasPrefix(r.Service, "http_status:") {
			t.Fatal("direct app ingress")
		}
	}
}
func TestCloudflareClientBoundsAndRedaction(t *testing.T) {
	marker := "never-log-provider-secret"
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer backend" {
			t.Error("missing provisioning auth")
		}
		w.WriteHeader(503)
		w.Write([]byte(marker))
	}))
	defer api.Close()
	cf := &cloudflareHTTP{base: api.URL, client: api.Client(), params: Config{CloudflareAccountID: strings.Repeat("a", 32), CloudflareAPIToken: "backend"}}
	_, e := cf.ConnectorToken(t.Context(), "tunnel")
	if e == nil || strings.Contains(e.Error(), marker) {
		t.Fatal("provider body exposed", e)
	}
}

func TestCloudflareOwnershipAndDeletionReadback(t *testing.T) {
	var removed, renamed, settled atomic.Bool
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			removed.Store(settled.Load())
			w.WriteHeader(204)
			return
		}
		if removed.Load() {
			w.WriteHeader(404)
			return
		}
		name := "node-owner"
		if renamed.Load() {
			name = "foreign-owner"
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": "tunnel-id", "name": name, "config_src": "cloudflare"}})
	}))
	defer api.Close()
	cf := &cloudflareHTTP{base: api.URL, client: api.Client(), params: Config{CloudflareAccountID: strings.Repeat("a", 32)}}
	r := CFResource{Kind: "tunnel", ID: "tunnel-id", Name: "node-owner"}
	if e := cf.Delete(t.Context(), r, ""); e == nil {
		t.Fatal("unconfirmed provider deletion counted as absent")
	}
	renamed.Store(true)
	if _, e := cf.Find(t.Context(), r); !errors.Is(e, ErrResourceConflict) {
		t.Fatal("resource identity change was adopted", e)
	}
	renamed.Store(false)
	settled.Store(true)
	if e := cf.Delete(t.Context(), r, ""); e != nil {
		t.Fatal(e)
	}
	if e := cf.Delete(t.Context(), r, ""); e != nil {
		t.Fatal("deletion retry not idempotent", e)
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
	c := &cloudflareHTTP{client: server.Client(), base: server.URL, params: Config{CloudflareZoneID: "zone"}}
	r := CFResource{Kind: "dns", Name: "owned-node-dns", Host: "api.example.invalid"}
	created, e := c.Create(t.Context(), r, "tunnel-id")
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

func claimTestTunnel(t *testing.T) (*Manager, *recoveryCloudflare, *tunnelLease) {
	t.Helper()
	db := testdb.Open(t)
	if err := migrations.Up(t.Context(), db, os.DirFS("../migrations")); err != nil {
		t.Fatal(err)
	}
	owner := "11111111-1111-4111-8111-111111111111"
	execSQL(t, db, `INSERT INTO auth.users(id) VALUES($1)`, owner)
	m := Machine{NodeID: "vkvkvkvkvkvkuaaaaaaaaaaaaa", InstallDir: "/srv/livepeer", K3sVersion: "v1.37.2+k3s1", CredentialVersion: 1}
	owner = "0x1111111111111111111111111111111111111111"
	execSQL(t, db, `INSERT INTO lpcc.orchestrators(address,claimed_by_user_id) VALUES($1,$2)`, owner, "11111111-1111-4111-8111-111111111111")
	err := db.QueryRow(`INSERT INTO lpcc.machines(node_id,orchestrator_address,enrolled_by_user_id,fingerprint,hostname,install_dir,k3s_version,credential_version,tunnel_eligible) VALUES($1,$2,$3,$4,'test',$5,$6,1,true) RETURNING node_id::text`, m.NodeID, owner, "11111111-1111-4111-8111-111111111111", strings.Repeat("a", 64), m.InstallDir, m.K3sVersion).Scan(&m.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	execSQL(t, db, `INSERT INTO lpcc.enrollments(node_id,orchestrator_address,enrolled_by_user_id,fingerprint,hostname,install_dir,k3s_version,credential_version) SELECT node_id,orchestrator_address,enrolled_by_user_id,fingerprint,hostname,install_dir,k3s_version,credential_version FROM lpcc.machines`)
	fake := newRecoveryCloudflare()
	s := New(Config{CloudflareBaseDomain: "fleet.example.invalid"}, Dependencies{DB: db, Provider: fake, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	l, err := s.claimTunnel(t.Context(), m)
	if err != nil {
		t.Fatal(err)
	}
	return s, fake, l
}

func execSQL(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, s *Manager, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLeaseFencingOnRetirement(t *testing.T) {
	s, _, lease := claimTestTunnel(t)
	if _, err := s.claimTunnel(t.Context(), lease.Machine); err == nil {
		t.Fatal("concurrent lease acquired")
	}
	execSQL(t, s.db, `DELETE FROM lpcc.machines`)
	if err := lease.save(t.Context()); !errors.Is(err, errTunnelFenced) {
		t.Fatal("retired worker was not fenced", err)
	}
	lease.finish(t.Context(), false)
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET next_attempt_at=now()`)
	retired, err := s.claimTunnel(t.Context(), lease.Machine)
	if err != nil {
		t.Fatal("fenced worker did not release lease for cleanup", err)
	}
	defer retired.finish(t.Context(), false)
	if !retired.Machine.Terminal {
		t.Fatal("cleanup worker did not observe retirement")
	}
}

func TestCreateRecoveryRetainsSelectionAndAbsentWatch(t *testing.T) {
	for _, kind := range []string{"tunnel", "dns"} {
		t.Run(kind, func(t *testing.T) {
			_, f, l := claimTestTunnel(t)
			m := l.Machine
			var e error
			defer l.finish(t.Context(), false)
			key := kind

			// Durable intent with no provider effect covers crash-before-send and a
			// lost response whose create never took effect.
			r := CFResource{Kind: kind, Name: resourceName(m, key), Pending: true, AttemptAt: time.Now().Add(-time.Hour), Attempts: 1, OperationVersion: 1}

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

type routeDeleteFailure struct {
	*recoveryCloudflare
	fail  bool
	after bool
}

func (f *routeDeleteFailure) Delete(ctx context.Context, r CFResource, target string) error {
	if f.fail && r.Kind == "dns" {
		f.fail = false
		if f.after {
			if e := f.recoveryCloudflare.Delete(ctx, r, target); e != nil {
				return e
			}
		}
		return &ProviderError{Ambiguous: true}
	}
	return f.recoveryCloudflare.Delete(ctx, r, target)
}
func TestSupersededCreateHandoffSurvivesCleanupFailure(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint("lost-delete-response-", after), func(t *testing.T) {
			s, base, l := claimTestTunnel(t)
			m := l.Machine
			var e error
			key := "g1-dns"
			old := CFResource{Kind: "dns", Name: resourceName(m, key), Host: "host.example.invalid", Pending: true, Attempts: 1, OperationVersion: 1, CreationTarget: "tunnel-a"}
			l.state.Resources[key] = old
			if e = l.save(t.Context()); e != nil {
				t.Fatal(e)
			}
			providerOld := old
			providerOld.ID = "old-dns"
			providerOld.Pending = false
			base.resources[providerOld.ID] = providerOld
			l.provider = &routeDeleteFailure{recoveryCloudflare: base, fail: true, after: after}
			if _, e = l.ensure(t.Context(), key, "dns", "host.example.invalid", "tunnel-b"); e == nil {
				t.Fatal("cleanup failure not injected")
			}
			persisted, _, e := s.Load(t.Context(), m.NodeID)
			if e != nil {
				t.Fatal(e)
			}
			if persisted.Resources[key].Absent || persisted.Resources[key].CreationTarget != "tunnel-b" || !persisted.Resources["retired:"+old.Name].Absent {
				t.Fatal("handoff was not atomic", persisted.Resources)
			}
			l.finish(t.Context(), true)
			execSQL(t, s.db, `UPDATE lpcc.machine_states SET next_attempt_at=now()`)
			l, e = s.claimTunnel(t.Context(), m)
			if e != nil {
				t.Fatal(e)
			}
			defer l.finish(t.Context(), false)
			selected, e := l.ensure(t.Context(), key, "dns", "host.example.invalid", "tunnel-b")
			if e != nil {
				t.Fatal(e)
			}
			if selected.OperationVersion != 2 || selected.ID == "old-dns" || len(base.resources) != 1 {
				t.Fatal("replacement did not converge", selected, base.resources)
			}
		})
	}
}

func TestRollbackReusesUnselectedOwnedOperation(t *testing.T) {
	_, f, l := claimTestTunnel(t)
	m := l.Machine
	var e error
	defer l.finish(t.Context(), false)
	old := CFResource{Kind: "dns", Name: resourceName(m, "g1-dns"), Host: "discovery.example.invalid", Pending: true, Attempts: 1, OperationVersion: 1}
	l.state.Resources["g1-dns"] = old
	if e = l.save(t.Context()); e != nil {
		t.Fatal(e)
	}
	observed := old
	observed.ID = "late-dns"
	observed.Pending = false
	f.resources[observed.ID] = observed
	r, e := l.ensure(t.Context(), "g3-dns", "dns", old.Host, "")
	if e != nil || r.ID != observed.ID || r.Name != old.Name || f.creates["dns"] != 0 {
		t.Fatal("rollback lost unselected ownership", r, e)
	}
}

func (f *recoveryCloudflare) Route(_ context.Context, r CFResource, target string) error {
	r.Target = target + ".cfargotunnel.com"
	r.Proxied = true
	f.resources[r.ID] = r
	return nil
}

func TestUnsupportedRoutingRequiresExternalMigration(t *testing.T) {
	for _, raw := range []string{`{"resources":{"legacy":{"kind":"unsupported"}}}`, `{"applied_ingress":[{"originRequest":{"unsupported":{"required":true}}}]}`} {
		if !errors.Is(requireMigratedRouting([]byte(raw)), errRoutingMigrationRequired) {
			t.Fatal("unsupported persisted routing accepted")
		}
	}
	if err := requireMigratedRouting([]byte(`{"resources":{"tunnel":{"kind":"tunnel"}},"applied_ingress":[{"originRequest":{"httpHostHeader":"private:8935"}}]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestUnmigratedRoutingDoesNotBlockOtherMachines(t *testing.T) {
	s, _, lease := claimTestTunnel(t)
	bad := lease.Machine.NodeID
	lease.Release(t.Context())
	execSQL(t, s.db, `DELETE FROM lpcc.machines WHERE node_id=$1`, bad)
	const unsupported = `{"resources":{"legacy":{"kind":"unsupported","id":"owned-legacy"}}}`
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=$2,next_attempt_at=now() WHERE node_id=$1`, bad, unsupported)
	healthy := strings.Repeat("b", 26)
	execSQL(t, s.db, `INSERT INTO lpcc.enrollments(node_id,orchestrator_address,enrolled_by_user_id,fingerprint,hostname,install_dir,k3s_version,credential_version,retired_at) SELECT $1,orchestrator_address,enrolled_by_user_id,fingerprint,hostname,install_dir,k3s_version,credential_version,now() FROM lpcc.enrollments WHERE node_id=$2`, healthy, bad)
	// No provider call is valid: the unsupported machine must be held, and the
	// other retired enrollment has no external resources to remove.
	s.provider = struct{ TunnelProvider }{}
	if err := s.Reconcile(t.Context()); err != nil {
		t.Fatal("one machine blocked fleet reconciliation", err)
	}
	state, _, err := s.Load(t.Context(), healthy)
	if err != nil || !state.CleanupComplete {
		t.Fatal("other machine did not reconcile", state, err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.machine_states WHERE node_id=$1 AND state=$2::jsonb`, bad, unsupported) != 1 {
		t.Fatal("unmigrated provider state was converted")
	}
}
