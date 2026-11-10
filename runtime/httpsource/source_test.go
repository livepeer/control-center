package httpsource

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/internal/testutil"
	"github.com/livepeer/control-center/runtime/transport"
)

type fakeKube struct {
	last       *transport.Artifact
	ready      bool
	reply      func(string) any
	err        error
	publishErr error
}

func cacheBundle(t *testing.T, store artifact.Store, m contract.Metadata, files map[string][]byte) string {
	t.Helper()
	files = maps.Clone(files)
	if files["kustomization.yaml"] == nil {
		files["kustomization.yaml"] = []byte("resources: []\n")
	}
	files["runtime.json"], _ = json.Marshal(m)
	data, err := artifact.Pack(files)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := store.Put(data)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestDownloadsDoNotHoldPublishedAuthorityOrObservationReporting(t *testing.T) {
	f := newFixture(t)
	if err := f.source.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	f.source.Control.Client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/config") {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return http.DefaultTransport.RoundTrip(r)
	})
	done := make(chan error, 1)
	go func() { done <- f.source.Sync(t.Context()) }()
	<-entered
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	if _, ok := f.source.Desired(); !ok {
		t.Fatal("slow fetch revoked valid delivered authority")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := f.source.Report(ctx); err != nil {
		t.Fatal("download blocked reporting", err)
	}
}

func TestNodeReadinessIgnoresBrokenPeerReconciliation(t *testing.T) {
	f := newFixture(t)
	m := f.meta
	m.BundleFormat = contract.BundleFormat
	cache := func(connector string) string {
		return cacheBundle(t, f.source.Store, m, map[string][]byte{"system/node/node.yaml": []byte("same Node inputs"), "system/connector/connector.yaml": []byte(connector)})
	}
	old, current := cache("healthy peer"), cache("broken peer")
	f.kube.reply = func(path string) any {
		switch {
		case path == fluxPath+"livepeer-node":
			return map[string]any{"metadata": map[string]any{"generation": 1}, "status": map[string]any{"observedGeneration": 1, "lastAppliedRevision": old, "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}}
		case strings.Contains(path, "/deployments/orchestrator"):
			return map[string]any{"metadata": map[string]any{"generation": 1}, "spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"annotations": map[string]any{"livepeer.io/config-sha256": m.ConfigDigest}}}}, "status": map[string]any{"observedGeneration": 1, "updatedReplicas": 1, "readyReplicas": 1, "availableReplicas": 1}}
		case strings.Contains(path, "/pods?"):
			return map[string]any{"items": []any{map[string]any{"metadata": map[string]any{"annotations": map[string]any{"livepeer.io/config-sha256": m.ConfigDigest}}, "status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}}}}
		default:
			return nil
		}
	}
	f.source.Control.Client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "orchestrator.livepeer.svc.cluster.local" {
			body := "ok"
			if r.URL.Path == "/discovery" {
				body = `[{"address":"https://machine.example"}]`
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		return http.DefaultTransport.RoundTrip(r)
	})
	if err := f.source.report(t.Context(), m, current, ""); err != nil {
		t.Fatal(err)
	}
	if report := f.lastReport(); report["ready"] != true || report["bundle_sha256"] != old[7:] {
		t.Fatal("peer failure suppressed Node or invented its applied archive", report)
	}
}

func (k *fakeKube) Publish(_ context.Context, _ string, a *transport.Artifact, ready bool, _ string) error {
	if k.publishErr != nil {
		return k.publishErr
	}
	if a != nil {
		copy := *a
		k.last = &copy
	}
	k.ready = ready
	return nil
}
func (k *fakeKube) Request(_ context.Context, _ string, path string, _ any, out any) error {
	if k.err != nil {
		return k.err
	}
	if k.reply == nil {
		return &transport.HTTPError{Status: 404}
	}
	v := k.reply(path)
	if v == nil {
		return &transport.HTTPError{Status: 404}
	}
	b, _ := json.Marshal(v)
	return transport.Decode(b, out)
}

func TestCacheRetainsPeerAppliedAndAttemptedInputs(t *testing.T) {
	f := newFixture(t)
	cache := func(label string, age time.Duration) string {
		digest := cacheBundle(t, f.source.Store, f.meta, map[string][]byte{"label": []byte(label)})
		stamp := time.Now().Add(-age)
		if err := os.Chtimes(filepath.Join(f.source.Store.Directory, digest[7:]+".tar.gz"), stamp, stamp); err != nil {
			t.Fatal(err)
		}
		return digest
	}
	var current string
	for n := 0; n < 10; n++ {
		current = cache(formatInt(int64(n)), 0)
	}
	applied, attempted, orphan := cache("applied", 3*time.Hour), cache("attempted", 3*time.Hour), cache("orphan", 4*time.Hour)
	f.kube.reply = func(path string) any {
		if path == fluxPath+"livepeer-node" {
			return map[string]any{"status": map[string]any{"lastAppliedRevision": applied, "lastAttemptedRevision": attempted}}
		}
		return nil
	}
	f.kube.err = &transport.HTTPError{Status: 500}
	f.source.gc(t.Context(), current)
	if _, err := f.source.Store.Get(orphan); err != nil {
		t.Fatal("unknown references allowed collection")
	}
	f.kube.err = nil
	f.source.gc(t.Context(), current)
	for _, digest := range []string{applied, attempted} {
		if _, err := f.source.Store.Get(digest); err != nil {
			t.Fatal("peer input collected", err)
		}
	}
	if _, err := f.source.Store.Get(orphan); !os.IsNotExist(err) {
		t.Fatal("unreferenced expired archive retained", err)
	}
}

type sourceFixture struct {
	source       *Source
	kube         *fakeKube
	mu           sync.Mutex
	data         []byte
	status       int
	meta         contract.Metadata
	reports      []map[string]any
	cleanupReady bool
}

func newFixture(t *testing.T) *sourceFixture {
	t.Helper()
	set := testutil.Assignment(t)
	f := &sourceFixture{status: 200, kube: &fakeKube{}, meta: contract.Metadata{NodeID: set.NodeID, Epoch: set.Epoch, CredentialVersion: 1, Generation: 1, BundleFormat: contract.BundleFormat, ConfigDigest: strings.Repeat("a", 64), ServiceURL: "https://machine.example"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("b", 64) {
			t.Error("wrong service credential")
		}
		if r.Method == "GET" {
			if f.cleanupReady {
				w.Header().Set("X-Livepeer-App-Cleanup-Ready", "true")
			}
			w.Header().Set("X-Livepeer-Epoch", f.meta.Epoch)
			w.Header().Set("X-Livepeer-Credential-Version", "1")
			w.WriteHeader(f.status)
			w.Write(f.data)
			return
		}
		var report map[string]any
		if json.NewDecoder(r.Body).Decode(&report) != nil {
			t.Error("invalid report")
		}
		f.reports = append(f.reports, report)
		w.Write([]byte("{}"))
	}))
	t.Cleanup(server.Close)
	root := t.TempDir()
	token := filepath.Join(root, "token")
	os.WriteFile(token, []byte(strings.Repeat("b", 64)), 0600)
	identity := filepath.Join(root, "identity")
	b, _ := json.Marshal(map[string]any{"epoch": set.Epoch, "credential_version": 1})
	os.WriteFile(identity, b, 0600)
	control, err := transport.NewControl(server.URL+"/v1/nodes/"+set.NodeID+"/config", token, true)
	if err != nil {
		t.Fatal(err)
	}
	f.source = &Source{Control: control, Kube: f.kube, Store: artifact.Store{Directory: filepath.Join(root, "cache")}, ArtifactURL: "http://artifacts.private:8080", IdentityFile: identity}
	f.set(t, map[string][]byte{"kustomization.yaml": []byte("resources: []\n"), "orchestrator.yaml": []byte("node")}, f.meta)
	return f
}

func TestTerminalSelectionIsGatedAndNeverRepublishesRetainedWorkload(t *testing.T) {
	f := newFixture(t)
	m := f.meta
	m.Terminal = true
	m.BundleFormat = contract.BundleFormat
	p := appbundle.Unavailable()
	m.AppsPayloadDigest = p.Digest()
	files := map[string][]byte{"kustomization.yaml": []byte("resources: []\n"), "node.txt": []byte("retained")}
	for name, b := range p.Files {
		files[name] = b
	}
	final := m
	final.TerminalCleanup = true
	files["terminal-cleanup/kustomization.yaml"] = []byte("resources: []\n")
	files["terminal-cleanup/runtime.json"], _ = json.Marshal(final)
	for name, b := range p.Files {
		files["terminal-cleanup/"+name] = b
	}
	f.set(t, files, m)
	original := artifact.Digest(f.data)
	if err := f.source.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.kube.last.Digest != original {
		t.Fatal("cleanup bypassed backend app receipt gate")
	}
	f.mu.Lock()
	f.cleanupReady = true
	f.mu.Unlock()
	if err := f.source.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	cleanup := f.kube.last.Digest
	if cleanup == original {
		t.Fatal("did not select central cleanup phase")
	}
	raw, _ := f.source.Store.Get(cleanup)
	selected, _ := artifact.Read(raw)
	if selected["node.txt"] != nil {
		t.Fatal("Node retained after cleanup gate")
	}
	f.mu.Lock()
	f.cleanupReady = false
	f.mu.Unlock()
	if err := f.source.Sync(t.Context()); err != nil || f.kube.last.Digest != cleanup {
		t.Fatal("terminal phase rolled back", err)
	}
}
func (f *sourceFixture) set(t *testing.T, files map[string][]byte, m contract.Metadata) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal(m)
	files["runtime.json"] = b
	data, err := artifact.Pack(files)
	if err != nil {
		t.Fatal(err)
	}
	f.data = data
	f.meta = m
	f.status = 200
}
func (f *sourceFixture) lastReport() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reports[len(f.reports)-1]
}
func TestSourcePreservesArtifactAndIsolatesInvalidAppInput(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.source.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	first := f.kube.last.Digest
	observed := f.source.reporting.Load().DownloadedAt
	if err := f.source.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.source.reporting.Load().DownloadedAt.Equal(observed) {
		t.Fatal("unchanged validated download renewed original observation")
	}
	f.mu.Lock()
	f.status = 503
	f.mu.Unlock()
	if err := f.source.Sync(ctx); err == nil || f.kube.last.Digest != first || f.kube.ready {
		t.Fatal("fetch failure changed artifact")
	}
	if _, err := f.source.Store.Get(first); err != nil {
		t.Fatal("last artifact unavailable", err)
	}
	m := f.meta
	m.Generation = 2
	m.BundleFormat = contract.BundleFormat
	m.AppsGeneration = 7
	m.AppsDigest = "sha256:" + strings.Repeat("f", 64)
	f.set(t, map[string][]byte{"kustomization.yaml": []byte("resources: []\n"), "orchestrator.yaml": []byte("management repair")}, m)
	if err := f.source.Sync(ctx); err != nil {
		t.Fatal("app input blocked management", err)
	}
	if err := f.source.Report(ctx); err != nil {
		t.Fatal(err)
	}
	if f.kube.last.Digest == first || !f.kube.ready || f.lastReport()["apps_error"] == "" {
		t.Fatal("missing management repair/app diagnostic")
	}
	b, _ := os.ReadFile(filepath.Join(f.source.Store.Directory, "enrollment.json"))
	watermark, err := transport.ReadMetadata(b)
	if err != nil || watermark.Generation != 2 || watermark.AppsGeneration != 0 {
		t.Fatal("bad app advanced watermark", watermark, err)
	}
	set := testutil.Assignment(t)
	p, err := appbundle.Render(set, appbundle.Options{})
	if err != nil {
		t.Fatal(err)
	}
	m.Generation = 3
	m.AppsGeneration = set.Generation
	m.AppsDigest = p.Index.IntentDigest
	m.AppsPayloadDigest = p.Digest()
	files := map[string][]byte{"kustomization.yaml": []byte("resources: []\n")}
	for name, b := range p.Files {
		files[name] = b
	}
	f.set(t, files, m)
	if err = f.source.Sync(ctx); err != nil {
		t.Fatal("invalid predecessor fenced valid app generation", err)
	}
	if !f.source.reporting.Load().DownloadedAt.After(observed) {
		t.Fatal("changed artifact kept predecessor download time")
	}
	// A restarted adapter retains both terminal and generation fences.
	m.Generation = 1
	f.set(t, files, m)
	restarted := Source{Control: f.source.Control, Kube: f.source.Kube, Store: f.source.Store, ArtifactURL: f.source.ArtifactURL, IdentityFile: f.source.IdentityFile}
	if err = restarted.Sync(ctx); err == nil {
		t.Fatal("accepted older generation after restart")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestAppOnlyApplicationReportsActualAppliedArchive(t *testing.T) {
	f := newFixture(t)
	set := testutil.Assignment(t)
	cache := func(generation int64, node string) (contract.Metadata, string) {
		set.Generation = generation
		p, err := appbundle.Render(set, appbundle.Options{})
		if err != nil {
			t.Fatal(err)
		}
		m := f.meta
		m.BundleFormat = contract.BundleFormat
		m.AppsGeneration = generation
		m.AppsDigest = p.Index.IntentDigest
		m.AppsPayloadDigest = p.Digest()
		files := map[string][]byte{"kustomization.yaml": []byte("resources:\n- management\n"), "system/node/orchestrator.yaml": []byte(node)}
		for name, b := range p.Files {
			files[name] = b
		}
		return m, cacheBundle(t, f.source.Store, m, files)
	}
	_, old := cache(1, "same node")
	m, current := cache(2, "same node")
	if !f.source.componentUnchanged("livepeer-node", old, current) {
		t.Fatal("did not isolate app-only payload change")
	}
	f.kube.reply = func(path string) any {
		if strings.HasPrefix(path, fluxPath) {
			return map[string]any{"metadata": map[string]any{"generation": 1}, "status": map[string]any{"observedGeneration": 1, "lastAppliedRevision": old, "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}}
		}
		if strings.Contains(path, "/deployments/orchestrator") {
			return map[string]any{"metadata": map[string]any{"generation": 1}, "spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"annotations": map[string]any{"livepeer.io/config-sha256": m.ConfigDigest}}}}, "status": map[string]any{"observedGeneration": 1, "updatedReplicas": 1, "readyReplicas": 1, "availableReplicas": 1}}
		}
		if strings.Contains(path, "/pods?") {
			return map[string]any{"items": []any{map[string]any{"metadata": map[string]any{"annotations": map[string]any{"livepeer.io/config-sha256": m.ConfigDigest}}, "status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}}}}
		}
		return nil
	}
	f.source.Control.Client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "orchestrator.livepeer.svc.cluster.local" {
			body := "ok"
			if r.URL.Path == "/discovery" {
				body = `[{"address":"https://machine.example"}]`
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		return http.DefaultTransport.RoundTrip(r)
	})
	if err := f.source.report(context.Background(), m, current, ""); err != nil {
		t.Fatal(err)
	}
	report := f.lastReport()
	if report["ready"] != true || report["bundle_sha256"] != old[7:] {
		t.Fatal("invented applied archive", report)
	}
	// A failed render can retain the same app generation while metadata changes.
	// Failed publication must not revoke readiness of verified identical management.
	data, err := f.source.Store.Get(old)
	if err != nil {
		t.Fatal(err)
	}
	files, err := artifact.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := transport.ReadMetadata(files["runtime.json"])
	if err != nil {
		t.Fatal(err)
	}
	f.set(t, files, retained)
	if err := f.source.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	retained.AppsError, retained.RequestedAppsGeneration = "generation_failed", 2
	f.set(t, files, retained)
	f.kube.publishErr = errors.New("publication_failed")
	if err := f.source.Sync(t.Context()); err == nil {
		t.Fatal("fixture publication succeeded")
	}
	if err := f.source.Report(t.Context()); err != nil {
		t.Fatal(err)
	}
	if report := f.lastReport(); report["ready"] != true || report["bundle_sha256"] != old[7:] || report["delivery_reason"] != "fetch_or_publication_failed" || report["apps_error"] != "generation_failed" {
		t.Fatal("retained app input suppressed management reporting", report)
	}
	f.kube.publishErr = nil
	_, changed := cache(3, "changed node")
	if f.source.componentUnchanged("livepeer-node", old, changed) {
		t.Fatal("ignored infrastructure change")
	}
	os.WriteFile(filepath.Join(f.source.Store.Directory, old[7:]+".tar.gz"), []byte("corrupt"), 0600)
	if err := f.source.report(context.Background(), m, current, ""); err != nil {
		t.Fatal(err)
	}
	if f.lastReport()["ready"] != false {
		t.Fatal("trusted corrupt cache")
	}
}

func TestComponentComparisonCannotBorrowCrossEnrollmentOrCorruptEvidence(t *testing.T) {
	s := &Source{Store: artifact.Store{Directory: t.TempDir()}}
	cache := func(epoch, node, connector string) string {
		m := contract.Metadata{NodeID: "lp-aaaaaaaaaaaaaaaa", Epoch: epoch, CredentialVersion: 1, Generation: 1, BundleFormat: contract.BundleFormat}
		return cacheBundle(t, s.Store, m, map[string][]byte{"system/node/kustomization.yaml": []byte(node), "system/connector/kustomization.yaml": []byte(connector)})
	}
	old := cache("11111111-1111-4111-8111-111111111111", "same node", "old connector")
	current := cache("11111111-1111-4111-8111-111111111111", "same node", "broken connector")
	if !s.componentUnchanged("livepeer-node", old, current) || s.componentUnchanged("livepeer-connector", old, current) {
		t.Fatal("component evidence coupled")
	}
	if s.componentUnchanged("livepeer-node", old, cache("22222222-2222-4222-8222-222222222222", "same node", "old connector")) {
		t.Fatal("borrowed old enrollment proof")
	}
	os.WriteFile(filepath.Join(s.Store.Directory, old[7:]+".tar.gz"), []byte("corrupt"), 0600)
	if s.componentUnchanged("livepeer-node", old, current) {
		t.Fatal("trusted corrupt archive")
	}
}

func TestAppValidationFailureRemainsReportableWithoutPayloadExcerpt(t *testing.T) {
	f := newFixture(t)
	if err := f.source.report(t.Context(), f.meta, "", "payload excerpt credential-sentinel"); err != nil {
		t.Fatal(err)
	}
	report := f.lastReport()
	if report["apps_error"] != "invalid_app_payload" {
		t.Fatal("raw validation error crossed status wire", report)
	}
}
