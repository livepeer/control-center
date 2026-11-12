package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/onchain"
	"github.com/livepeer/control-center/runtime/transport"
)

type podFixture struct {
	profile   Profile
	metadata  *contract.Metadata
	container string
	calls     int
	onLookup  func(int)
}

func TestDeliveryKeepsSecretsOutOfStateAndRejectsInsecureTransport(t *testing.T) {
	for _, profile := range []Profile{Connector, Orchestrator} {
		f := fixture(t, profile)
		grant := f.launch(t, "a")
		state, err := os.ReadFile(f.i.StateFile)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{grant.Token, grant.RPCURL, grant.Headers, strings.Repeat("b", 64)} {
			if secret != "" && strings.Contains(string(state), secret) {
				t.Fatal("credential persisted in consumer state")
			}
		}
		f.i.Control.AllowHTTP = true
		if _, err := f.i.fetch(t.Context(), grant.Launch); err == nil {
			t.Fatal("insecure credential delivery allowed")
		}
	}
}

func (p *podFixture) Request(_ context.Context, method, path string, _ any, result any) error {
	p.calls++
	if p.onLookup != nil {
		p.onLookup(p.calls)
	}
	if method != http.MethodGet || path != "/api/v1/namespaces/"+map[Profile]string{Connector: "flux-system", Orchestrator: "livepeer"}[p.profile]+"/pods/tunnel-pod" {
		return &transport.HTTPError{Status: 404}
	}
	b, _ := json.Marshal(map[string]any{"metadata": map[string]any{"uid": "pod-uid", "labels": map[string]string{"app": map[Profile]string{Connector: "livepeer-tunnel", Orchestrator: "orchestrator"}[p.profile]}, "annotations": map[string]string{"livepeer.io/config-sha256": p.metadata.ConfigDigest}}, "status": map[string]any{"containerStatuses": []any{map[string]any{"name": "connector", "containerID": p.container, "state": map[string]any{"running": map[string]string{"startedAt": "2026-11-08T00:00:00Z"}}}}}})
	return transport.Decode(b, result)
}

func TestOverlappingStartsCannotOverwriteTheNewerLaunch(t *testing.T) {
	for _, profile := range []Profile{Connector, Orchestrator} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			f := fixture(t, profile)
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
		})
	}
}

func TestFailedNewLaunchDurablyInvalidatesTheOldAssociation(t *testing.T) {
	for _, profile := range []Profile{Connector, Orchestrator} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			f := fixture(t, profile)
			first := f.launch(t, "a")
			bad := first.Launch
			bad.PodUID = "unrelated-pod"
			if _, err := f.i.fetch(t.Context(), bad); err == nil || f.i.grant == nil || f.i.grant.Launch != first.Launch {
				t.Fatal("unverified Pod invalidated the current grant")
			}
			f.mutate = func() { f.m.TokenGeneration++; f.m.Onchain.Generation++ }
			if w := operation(t, f.i, "tunnel/connector-token", Launch{PodName: "tunnel-pod", PodUID: "pod-uid", LaunchID: strings.Repeat("c", 32), ProcessID: strings.Repeat("c", 64)}); w.Code == 200 {
				t.Fatal("changed grant accepted")
			}
			f.i.Restore()
			if f.i.grant != nil {
				t.Fatal("restart restored the previous process association")
			}
		})
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

type integrationFixture struct {
	i       *Integration
	m       contract.Metadata
	pod     *podFixture
	fetched int
	mutate  func()
	reports []map[string]any
}

func fixture(t *testing.T, profiles ...Profile) *integrationFixture {
	t.Helper()
	f := &integrationFixture{pod: &podFixture{container: "containerd://first"}, m: contract.Metadata{NodeID: "aaaaaaaaaaaaaaaaaaaaaaaaaa", CredentialVersion: 1, Generation: 7, BundleFormat: contract.BundleFormat, TunnelID: "tunnel", TokenGeneration: 2, ProviderVersion: 10, ConnectorTokenRef: "/v1/nodes/aaaaaaaaaaaaaaaaaaaaaaaaaa/tunnel/connector-token"}}
	profile := Connector
	if len(profiles) > 0 {
		profile = profiles[0]
	}
	f.m.Onchain = onchain.Config{Mode: "onchain", Generation: 2}
	f.m.ConfigDigest = strings.Repeat("a", 64)
	f.m.OnchainCredentialsRef = "/v1/nodes/" + f.m.NodeID + "/onchain/credentials"
	f.pod.profile, f.pod.metadata = profile, &f.m
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("b", 64) {
			t.Error("wrong machine credential")
		}
		if strings.HasSuffix(r.URL.Path, "/"+profile.endpoint()) {
			f.fetched++
			old := f.m
			if f.mutate != nil {
				f.mutate()
			}
			if profile == Orchestrator {
				var request Request
				json.NewDecoder(r.Body).Decode(&request)
				json.NewEncoder(w).Encode(Grant{Association: Association{Launch: request.Launch, NodeID: old.NodeID, CredentialVersion: old.CredentialVersion, OnchainGeneration: old.Onchain.Generation, ConfigDigest: old.ConfigDigest, GrantID: "grant-" + request.LaunchID}, RPCURL: "https://rpc.example/private", Headers: "Authorization: Bearer submission-secret"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"token": strings.Repeat("x", 63) + string(rune('a'+f.fetched)), "node_id": old.NodeID, "tunnel_id": old.TunnelID, "credential_generation": old.TokenGeneration})
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
	f.i = &Integration{Profile: profile, Control: control, Kube: f.pod, Desired: func() (contract.Metadata, bool) { return f.m, true }, StateFile: filepath.Join(root, "grant.json")}
	return f
}

func operation(t *testing.T, i *Integration, path string, value any) *httptest.ResponseRecorder {
	t.Helper()
	if launch, ok := value.(Launch); ok && launch.ProcessID == "" {
		launch.ProcessID = strings.Repeat("d", 64)
		value = launch
	}
	if o, ok := value.(Observation); ok && o.ObservedAt.IsZero() {
		o.ObservedAt = time.Now()
		value = o
	}
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path = strings.ReplaceAll(path, "tunnel/connector-token", i.Profile.endpoint())
	path = strings.ReplaceAll(path, "tunnel/observation", strings.TrimPrefix(i.Profile.observationPath(), "/"))
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
	for _, profile := range []Profile{Connector, Orchestrator} {
		for _, checkpoint := range []string{"fetch", "final-pod-lookup"} {
			for _, change := range []string{"node_id", "generation", "credential", "terminal_cleanup"} {
				t.Run(fmt.Sprintf("%d/%s/%s", profile, checkpoint, change), func(t *testing.T) {
					f := fixture(t, profile)
					mutate := func() {
						switch change {
						case "node_id":
							f.m.NodeID = "new-node_id"
						case "generation":
							f.m.TokenGeneration++
							f.m.Onchain.Generation++
						case "credential":
							os.WriteFile(f.i.Control.TokenFile, []byte(strings.Repeat("c", 64)), 0600)
						case "terminal_cleanup":
							f.m.TerminalCleanup = true
						}
					}
					if checkpoint == "fetch" {
						f.mutate = mutate
					} else {
						f.pod.onLookup = func(call int) {
							if call == 2 {
								mutate()
							}
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
