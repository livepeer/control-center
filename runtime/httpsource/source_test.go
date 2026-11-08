package httpsource

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/internal/testutil"
	"github.com/livepeer/control-center/runtime/transport"
)

type fakeKube struct {
	last  *transport.Artifact
	ready bool
	reply func(string) any
}

func (k *fakeKube) Publish(_ context.Context, _ string, a *transport.Artifact, ready bool, _ string) error {
	if a != nil {
		copy := *a
		k.last = &copy
	}
	k.ready = ready
	return nil
}
func (k *fakeKube) Request(_ context.Context, _ string, path string, _ any, out any) error {
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
	f := &sourceFixture{status: 200, kube: &fakeKube{}, meta: contract.Metadata{NodeID: set.NodeID, Epoch: set.Epoch, CredentialVersion: 1, Generation: 1, ConfigDigest: strings.Repeat("a", 64), ServiceURL: "https://machine.example"}}
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
	b, _ := json.Marshal(map[string]any{"epoch": set.Epoch, "credential_version": "1"})
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
	m.BundleFormat = 2
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
	m.BundleFormat = 2
	m.AppsGeneration = 7
	m.AppsDigest = "sha256:" + strings.Repeat("f", 64)
	f.set(t, map[string][]byte{"kustomization.yaml": []byte("resources: []\n"), "orchestrator.yaml": []byte("management repair")}, m)
	if err := f.source.Sync(ctx); err != nil {
		t.Fatal("app input blocked management", err)
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
		m.BundleFormat = 2
		m.AppsGeneration = generation
		m.AppsDigest = p.Index.IntentDigest
		m.AppsPayloadDigest = p.Digest()
		files := map[string][]byte{"kustomization.yaml": []byte("resources:\n- management\n"), "management/orchestrator.yaml": []byte(node)}
		for name, b := range p.Files {
			files[name] = b
		}
		raw, _ := json.Marshal(m)
		files["runtime.json"] = raw
		b, err := artifact.Pack(files)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := f.source.Store.Put(b)
		if err != nil {
			t.Fatal(err)
		}
		return m, digest
	}
	_, old := cache(1, "same node")
	m, current := cache(2, "same node")
	if !f.source.appOnlyChange(old, current) {
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
	_, changed := cache(3, "changed node")
	if f.source.appOnlyChange(old, changed) {
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
