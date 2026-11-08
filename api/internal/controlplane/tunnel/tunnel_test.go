package tunnel

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
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
				r.Audience = v.Audience
				r.Target = v.Target
				r.Proxied = v.Proxied
				r.Pending = false
				return []CFResource{r}, nil
			}
			return nil, nil
		}
	}
	for _, v := range f.resources {
		if !ownedOnly && r.ID == "" && (r.Kind == "app" || r.Kind == "dns") && v.Kind == r.Kind && v.Host == r.Host && v.Name != r.Name {
			return nil, ErrResourceConflict
		}
		if v.Kind == r.Kind && v.Name == r.Name && v.Host == r.Host {
			copy := r
			copy.ID = v.ID
			copy.Audience = v.Audience
			copy.Target = v.Target
			copy.Proxied = v.Proxied
			copy.Pending = false
			found = append(found, copy)
		}
	}
	return found, nil
}
func (f *recoveryCloudflare) Create(_ context.Context, r CFResource, target string) (CFResource, *AccessCredential, time.Time, error) {
	r.ID = uuid.New().String()
	r.Pending = false
	f.creates[r.Kind]++
	if r.Kind == "app" {
		r.Audience = "aud-" + r.ID
	}
	if r.Kind == "dns" {
		r.Target = target + ".cfargotunnel.com"
		r.Proxied = true
	}
	f.resources[r.ID] = r
	if r.Kind == "token" {
		return r, &AccessCredential{ClientID: "client-" + r.ID, ClientSecret: "secret-" + r.ID}, time.Now().Add(24 * time.Hour), nil
	}
	return r, nil, time.Time{}, nil
}
func (f *recoveryCloudflare) Delete(_ context.Context, r CFResource, _ string) error {
	delete(f.resources, r.ID)
	return nil
}
func TestTunnelIngressContract(t *testing.T) {
	rules := ingressFor("lp-aaaaaaaaaaaaaaaa", Config{CloudflareBaseDomain: "example.invalid", CloudflareTeamName: "team"}, "aud")
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
	api := "api-lp-aaaaaaaaaaaaaaaa.example.invalid"
	app := "proxy.apps-lp-aaaaaaaaaaaaaaaa.example.invalid"
	for _, host := range []string{api, app} {
		for _, path := range []string{"/discovery", "/prefix/discovery", "/runners/heartbeat", "/runner/a/session/b/channels", "/ai/trickle/x/0", "/metrics", "/readyz"} {
			if match(host, path).Service != "http_status:404" {
				t.Fatalf("exposed %s %s", host, path)
			}
		}
	}
	for _, path := range []string{"/apps/a/session", "/apps/a/session/b/stop", "/apps/a/session/b/payment", "/refresh-payment", "/apps/a/app/v1/complete", "/apps/a/session/b/app/ws", "/run/abc/media", "/proxy/abc"} {
		if match(api, path).Service != PrivateOrchestrator {
			t.Fatalf("missing client path %s", path)
		}
	}
	protected := match("discovery-lp-aaaaaaaaaaaaaaaa.example.invalid", "/discovery")
	if protected.OriginRequest == nil || !protected.OriginRequest.Access.Required || protected.OriginRequest.Access.Audience[0] != "aud" {
		t.Fatal("discovery not audience protected")
	}
	if match("alias.example.invalid", "/discovery").Service != "http_status:404" {
		t.Fatal("alias bypass")
	}
	for _, r := range rules {
		if r.Service != PrivateOrchestrator && !strings.HasPrefix(r.Service, "http_status:") {
			t.Fatal("direct app ingress")
		}
	}
}
func TestAccessKeyringBindingAndRotation(t *testing.T) {
	k, e := parseAccessKeyring(`{"current":"a","keys":{"a":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + `"}}`)
	if e != nil {
		t.Fatal(e)
	}
	ref := "access/node/epoch/1"
	secret := AccessCredential{"id", "high-entropy-secret"}
	id, b, e := k.seal(ref, secret)
	if e != nil || bytes.Contains(b, []byte(secret.ClientSecret)) {
		t.Fatal("plaintext secret", e)
	}
	if v, e := k.open(id, ref, b); e != nil || v != secret {
		t.Fatal(e)
	}
	for _, wrong := range []string{"access/other/epoch/1", "access/node/epoch/2"} {
		if _, e := k.open(id, wrong, b); e == nil {
			t.Fatal("credential reference substitution")
		}
	}
	b[len(b)-1] ^= 1
	if _, e := k.open(id, ref, b); e == nil {
		t.Fatal("accepted ciphertext tampering")
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
		name := "epoch-owner"
		if renamed.Load() {
			name = "foreign-owner"
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": "tunnel-id", "name": name, "config_src": "cloudflare"}})
	}))
	defer api.Close()
	cf := &cloudflareHTTP{base: api.URL, client: api.Client(), params: Config{CloudflareAccountID: strings.Repeat("a", 32)}}
	r := CFResource{Kind: "tunnel", ID: "tunnel-id", Name: "epoch-owner"}
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

func claimTestTunnel(t *testing.T) (*Manager, *recoveryCloudflare, *tunnelLease) {
	t.Helper()
	db := testdb.Open(t)
	if err := migrations.Up(t.Context(), db, os.DirFS("../migrations")); err != nil {
		t.Fatal(err)
	}
	owner := "11111111-1111-4111-8111-111111111111"
	execSQL(t, db, `INSERT INTO auth.users(id) VALUES($1)`, owner)
	m := Machine{NodeID: "lp-aaaaaaaaaaaaaaaa", InstallDir: "/srv/livepeer", K3sVersion: "v1.37.2+k3s1", CredentialVersion: 1}
	err := db.QueryRow(`INSERT INTO lpcc.machines(node_id,owner_id,fingerprint,hostname,install_dir,k3s_version,credential_version,tunnel_eligible) VALUES($1,$2,$3,'test',$4,$5,1,true) RETURNING enrollment_epoch::text`, m.NodeID, owner, strings.Repeat("a", 64), m.InstallDir, m.K3sVersion).Scan(&m.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	execSQL(t, db, `INSERT INTO lpcc.enrollments(node_id,epoch,owner_id,fingerprint,hostname,install_dir,k3s_version,credential_version) SELECT node_id,enrollment_epoch,owner_id,fingerprint,hostname,install_dir,k3s_version,credential_version FROM lpcc.machines`)
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	fake := newRecoveryCloudflare()
	s := New(Config{CloudflareBaseDomain: "fleet.example.invalid", CloudflareAccessLifetime: 24 * time.Hour,
		CloudflareKeyring: `{"current":"one","keys":{"one":"` + key + `"}}`}, Dependencies{DB: db, Provider: fake, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := s.ConfigureCredentials(); err != nil {
		t.Fatal(err)
	}
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
	if _, err := s.claimTunnel(t.Context(), lease.m); err == nil {
		t.Fatal("concurrent lease acquired")
	}
	execSQL(t, s.db, `DELETE FROM auth.users`)
	if err := lease.save(t.Context()); !errors.Is(err, errTunnelFenced) {
		t.Fatal("retired worker was not fenced", err)
	}
	lease.finish(t.Context(), false)
	execSQL(t, s.db, `UPDATE lpcc.machine_tunnels SET next_attempt_at=now()`)
	retired, err := s.claimTunnel(t.Context(), lease.m)
	if err != nil {
		t.Fatal("fenced worker did not release lease for cleanup", err)
	}
	defer retired.finish(t.Context(), false)
	if !retired.m.Terminal {
		t.Fatal("cleanup worker did not observe retirement")
	}
}

func TestCreateRecoveryRetainsSelectionAndAbsentWatch(t *testing.T) {
	for _, kind := range []string{"tunnel", "token"} {
		t.Run(kind, func(t *testing.T) {
			s, f, l := claimTestTunnel(t)
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

type lostTokenCheckpoint struct {
	*recoveryCloudflare
	afterCreate func()
	lostDelete  bool
}

func (f *lostTokenCheckpoint) Create(ctx context.Context, r CFResource, target string) (CFResource, *AccessCredential, time.Time, error) {
	created, secret, expiry, e := f.recoveryCloudflare.Create(ctx, r, target)
	if r.Kind == "token" && f.afterCreate != nil {
		f.afterCreate()
		f.afterCreate = nil
	}
	return created, secret, expiry, e
}
func (f *lostTokenCheckpoint) Delete(ctx context.Context, r CFResource, target string) error {
	if e := f.recoveryCloudflare.Delete(ctx, r, target); e != nil {
		return e
	}
	if r.Kind == "token" && f.lostDelete {
		f.lostDelete = false
		return &ProviderError{Ambiguous: true}
	}
	return nil
}
func TestAccessSecretCheckpointAndStrandedDeletionRecovery(t *testing.T) {
	s, base, l := claimTestTunnel(t)
	m := l.m
	var e error
	f := &lostTokenCheckpoint{recoveryCloudflare: base, lostDelete: true}
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
	*recoveryCloudflare
	fail  bool
	after bool
}

func (f *policyDeleteFailure) Delete(ctx context.Context, r CFResource, target string) error {
	if f.fail && r.Kind == "policy" {
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
			l.provider = &policyDeleteFailure{recoveryCloudflare: base, fail: true, after: after}
			if _, e = l.ensure(t.Context(), key, "policy", "app-id", "token-b"); e == nil {
				t.Fatal("cleanup failure not injected")
			}
			persisted, _, e := s.Load(t.Context(), m.NodeID, m.Epoch)
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

func TestRollbackReusesUnselectedOwnedOperation(t *testing.T) {
	_, f, l := claimTestTunnel(t)
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
