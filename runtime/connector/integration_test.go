package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
)

type podFixture struct {
	container string
	calls     int
	onLookup  func(int)
}

func (p *podFixture) Request(_ context.Context, method, path string, _ any, result any) error {
	p.calls++
	if p.onLookup != nil {
		p.onLookup(p.calls)
	}
	if method != http.MethodGet || path != "/api/v1/namespaces/flux-system/pods/tunnel-pod" {
		return &transport.HTTPError{Status: 404}
	}
	b, _ := json.Marshal(map[string]any{"metadata": map[string]any{"uid": "pod-uid", "labels": map[string]string{"app": "livepeer-tunnel"}}, "status": map[string]any{"containerStatuses": []any{map[string]any{"name": "connector", "containerID": p.container, "state": map[string]any{"running": map[string]string{"startedAt": "2026-11-08T00:00:00Z"}}}}}})
	return transport.Decode(b, result)
}

func TestOverlappingStartsCannotOverwriteTheNewerLaunch(t *testing.T) {
	f := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.mutate = func() {
		if f.fetched == 1 {
			close(entered)
			<-release
		}
	}
	oldDone, newDone := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
	oldLaunch := Launch{PodName: "tunnel-pod", PodUID: "pod-uid", LaunchID: strings.Repeat("a", 32), ProcessID: strings.Repeat("a", 64)}
	newLaunch := oldLaunch
	newLaunch.LaunchID = strings.Repeat("c", 32)
	newLaunch.ProcessID = strings.Repeat("c", 64)
	go func() { oldDone <- operation(t, f.i, "tunnel/connector-token", oldLaunch) }()
	<-entered
	go func() { newDone <- operation(t, f.i, "tunnel/connector-token", newLaunch) }()
	var newer *httptest.ResponseRecorder
	select {
	case newer = <-newDone:
	case <-time.After(5 * time.Second):
		close(release)
		<-oldDone
		t.Fatal("new launch blocked behind its predecessor's fetch")
	}
	close(release)
	<-oldDone // An older request may finish before validation or be superseded.
	var grant Grant
	if newer.Code != 200 || transport.Decode(newer.Body.Bytes(), &grant) != nil {
		t.Fatal("new start failed")
	}
	if operation(t, f.i, "tunnel/observation", Observation{Association: grant.Association, Ready: true, ProviderVersion: 10}).Code != 200 {
		t.Fatal("old fetch displaced the new process grant")
	}
	f.i.Restore()
	if f.i.grant == nil || f.i.grant.Launch != newLaunch {
		t.Fatal("new launch was not durable")
	}
}

func TestFailedNewLaunchDurablyInvalidatesTheOldAssociation(t *testing.T) {
	f := fixture(t)
	first := f.launch(t, "a")
	bad := first.Launch
	bad.PodUID = "unrelated-pod"
	if _, err := f.i.fetch(t.Context(), bad); err == nil || f.i.grant == nil || f.i.grant.Launch != first.Launch {
		t.Fatal("unverified Pod invalidated the current grant")
	}
	f.mutate = func() { f.m.TokenGeneration++ }
	if w := operation(t, f.i, "tunnel/connector-token", Launch{PodName: "tunnel-pod", PodUID: "pod-uid", LaunchID: strings.Repeat("c", 32), ProcessID: strings.Repeat("c", 64)}); w.Code == 200 {
		t.Fatal("changed grant accepted")
	}
	f.i.Restore()
	if f.i.grant != nil {
		t.Fatal("restart restored the previous process association")
	}
}

func TestReportRechecksGrantAndObservationAfterPodLookup(t *testing.T) {
	for _, replacement := range []bool{true, false} {
		f := fixture(t)
		first := f.launch(t, "a")
		operation(t, f.i, "tunnel/observation", Observation{Association: first.Association, Ready: true, ProviderVersion: 10})
		f.pod.onLookup = func(int) {
			f.pod.onLookup = nil
			if replacement {
				f.launch(t, "c")
			} else {
				operation(t, f.i, "tunnel/observation", Observation{Association: first.Association, Ready: false})
			}
		}
		token := int64(2)
		if replacement {
			token = 0
		}
		f.report(t, false, token, 0)
	}
}

func TestGrantRevalidatesAuthorityAfterFinalKubernetesLookup(t *testing.T) {
	for _, change := range []string{"generation", "credential", "terminal"} {
		t.Run(change, func(t *testing.T) {
			f := fixture(t)
			f.pod.onLookup = func(call int) {
				if call != 2 {
					return
				}
				switch change {
				case "generation":
					f.m.TokenGeneration++
				case "credential":
					os.WriteFile(f.i.Control.TokenFile, []byte(strings.Repeat("c", 64)), 0600)
				case "terminal":
					f.m.TerminalCleanup = true
				}
			}
			w := operation(t, f.i, "tunnel/connector-token", Launch{PodName: "tunnel-pod", PodUID: "pod-uid", LaunchID: strings.Repeat("a", 32)})
			if w.Code == 200 {
				t.Fatal("released a grant after its authority changed during lookup")
			}
		})
	}
}

type integrationFixture struct {
	i       *Integration
	m       contract.Metadata
	pod     *podFixture
	fetched int
	mutate  func()
	reports []map[string]any
}

func fixture(t *testing.T) *integrationFixture {
	t.Helper()
	f := &integrationFixture{pod: &podFixture{container: "containerd://first"}, m: contract.Metadata{NodeID: "lp-aaaaaaaaaaaaaaaa", Epoch: "epoch", CredentialVersion: 1, Generation: 7, BundleFormat: contract.BundleFormat, TunnelID: "tunnel", TokenGeneration: 2, ProviderVersion: 10, ConnectorTokenRef: "/v1/nodes/lp-aaaaaaaaaaaaaaaa/tunnel/connector-token"}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("b", 64) {
			t.Error("wrong machine credential")
		}
		if strings.HasSuffix(r.URL.Path, "/connector-token") {
			f.fetched++
			old := f.m
			if f.mutate != nil {
				f.mutate()
			}
			json.NewEncoder(w).Encode(map[string]any{"token": strings.Repeat("x", 63) + string(rune('a'+f.fetched)), "epoch": old.Epoch, "tunnel_id": old.TunnelID, "credential_generation": old.TokenGeneration})
			return
		}
		var report map[string]any
		if json.NewDecoder(r.Body).Decode(&report) != nil {
			t.Error("bad report")
		}
		f.reports = append(f.reports, report)
		w.Write([]byte("{}"))
	}))
	t.Cleanup(server.Close)
	root := t.TempDir()
	token := filepath.Join(root, "machine-token")
	if err := os.WriteFile(token, []byte(strings.Repeat("b", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	control, err := transport.NewControl(server.URL+"/v1/nodes/"+f.m.NodeID+"/config", token, false)
	if err != nil {
		t.Fatal(err)
	}
	control.Client.Transport = server.Client().Transport
	f.i = &Integration{Control: control, Kube: f.pod, Desired: func() (contract.Metadata, bool) { return f.m, true }, StateFile: filepath.Join(root, "grant.json")}
	return f
}

func operation(t *testing.T, i *Integration, path string, value any) *httptest.ResponseRecorder {
	t.Helper()
	if launch, ok := value.(Launch); ok && launch.ProcessID == "" {
		launch.ProcessID = strings.Repeat("d", 64)
		value = launch
	}
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "http://management/"+path, strings.NewReader(string(b)))
	w := httptest.NewRecorder()
	i.ServeHTTP(w, r)
	return w
}

func (f *integrationFixture) launch(t *testing.T, nonce string) Grant {
	t.Helper()
	w := operation(t, f.i, "tunnel/connector-token", Launch{PodName: "tunnel-pod", PodUID: "pod-uid", LaunchID: strings.Repeat(nonce, 32), ProcessID: strings.Repeat(nonce, 64)})
	var grant Grant
	if w.Code != 200 || transport.Decode(w.Body.Bytes(), &grant) != nil {
		t.Fatalf("grant failed: %d %s", w.Code, w.Body.String())
	}
	return grant
}

func (f *integrationFixture) report(t *testing.T, ready bool, token, version int64) {
	t.Helper()
	if err := f.i.Report(t.Context()); err != nil {
		t.Fatal(err)
	}
	r := f.reports[len(f.reports)-1]
	if r["ready"] != ready || r["token_generation"] != float64(token) || r["provider_version"] != float64(version) {
		t.Fatalf("incorrect attestation: %v", r)
	}
}

func TestGrantAssociationSurvivesAgentRestartButRequiresFreshEvidence(t *testing.T) {
	f := fixture(t)
	first := f.launch(t, "a")
	b, _ := os.ReadFile(f.i.StateFile)
	if strings.Contains(string(b), first.Token) || strings.Contains(string(b), strings.Repeat("b", 64)) {
		t.Fatal("credential persisted")
	}
	f.report(t, false, first.TokenGeneration, 0)
	observation := Observation{Association: first.Association, Ready: true, ProviderVersion: 10}
	if operation(t, f.i, "tunnel/observation", observation).Code != 200 {
		t.Fatal("observation refused")
	}
	f.report(t, true, 2, 10)
	old := f.i
	f.i = &Integration{Control: old.Control, Kube: old.Kube, Desired: old.Desired, StateFile: old.StateFile}
	f.i.Restore()
	f.report(t, false, 2, 0)
	if operation(t, f.i, "tunnel/observation", observation).Code != 200 {
		t.Fatal("surviving process could not revalidate")
	}
	f.report(t, true, 2, 10)
	if f.fetched != 1 || f.pod.container != "containerd://first" {
		t.Fatal("agent restart changed the connector")
	}
	// Kubernetes still describes the predecessor while a new PID 1 fetches its grant.
	second := f.launch(t, "c")
	if second.Token == first.Token || second.ProcessID == first.ProcessID {
		t.Fatal("restart reused a process grant")
	}
	if operation(t, f.i, "tunnel/observation", observation).Code != http.StatusConflict {
		t.Fatal("old launch could attest new process")
	}
	observation = Observation{Association: second.Association, Ready: true, ProviderVersion: 9}
	operation(t, f.i, "tunnel/observation", observation)
	f.report(t, false, 2, 9)
	observation.ProviderVersion = 10
	operation(t, f.i, "tunnel/observation", observation)
	f.report(t, true, 2, 10)
	f.pod.container = "containerd://restarted"
	f.report(t, true, 2, 10) // Catching-up API status cannot strand the healthy process.
	f.i.observation.observedAt = time.Now().Add(-2 * observationTTL)
	f.report(t, false, 2, 0)
}

func TestGrantFetchFencesConcurrentSecurityAndProcessChanges(t *testing.T) {
	for _, change := range []string{"epoch", "generation", "credential", "terminal_cleanup"} {
		t.Run(change, func(t *testing.T) {
			f := fixture(t)
			f.mutate = func() {
				switch change {
				case "epoch":
					f.m.Epoch = "new-epoch"
				case "generation":
					f.m.TokenGeneration++
				case "credential":
					os.WriteFile(f.i.Control.TokenFile, []byte(strings.Repeat("c", 64)), 0600)
				case "terminal_cleanup":
					f.m.TerminalCleanup = true
				}
			}
			w := operation(t, f.i, "tunnel/connector-token", Launch{PodName: "tunnel-pod", PodUID: "pod-uid", LaunchID: strings.Repeat("a", 32)})
			if w.Code == 200 {
				t.Fatal("changed grant escaped fencing")
			}
			if _, err := os.Stat(f.i.StateFile); !os.IsNotExist(err) {
				t.Fatal("unaccepted grant association committed")
			}
		})
	}
}

func TestTerminalRetainedGrantStillRequiresBackendAuthorization(t *testing.T) {
	f := fixture(t)
	f.m.Terminal = true
	f.launch(t, "a")
	f.m.TerminalCleanup = true
	w := operation(t, f.i, "tunnel/connector-token", Launch{PodName: "tunnel-pod", PodUID: "pod-uid", LaunchID: strings.Repeat("b", 32)})
	if w.Code == 200 || f.fetched != 1 {
		t.Fatal("final cleanup could obtain a connector credential")
	}
	w = operation(t, f.i, "status", map[string]any{})
	if w.Code != http.StatusForbidden {
		t.Fatal("connector socket became an authenticated proxy")
	}
}
