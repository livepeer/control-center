package httpsource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
	"go.yaml.in/yaml/v3"
)

// Model Flux inventory updates, ownership labels and prune decisions separately
// from workload health. A skipped deletion on an old owner stays observable.
type transferKube struct {
	states       map[string]fluxState
	paths        map[string]string
	waits        map[string]bool
	objects      map[string]manifestObject
	owners       map[string]string
	adopted      map[string]bool
	unsafeDelete bool
	source       string
}

func (k *transferKube) Publish(context.Context, string, *transport.Artifact, bool, string) error {
	return nil
}
func (k *transferKube) Request(_ context.Context, method, p string, value, out any) error {
	var result any
	if strings.HasPrefix(p, fluxPath) {
		name := strings.TrimPrefix(p, fluxPath)
		state, ok := k.states[name]
		if !ok {
			return &transport.HTTPError{Status: 404}
		}
		if method == http.MethodPatch {
			state.Spec.Prune = value.(map[string]any)["spec"].(map[string]any)["prune"].(bool)
			state.Metadata.Generation++
			k.states[name] = state
			return nil
		}
		result = state
	} else if strings.Contains(p, "externalartifacts/") {
		result = map[string]any{"status": map[string]any{"artifact": map[string]any{"revision": k.source}}}
	} else {
		found := false
		for id, o := range k.objects {
			if objectPath, _ := o.apiPath(); objectPath == p {
				result = map[string]any{"metadata": map[string]any{"labels": map[string]string{"kustomize.toolkit.fluxcd.io/name": k.owners[id], "kustomize.toolkit.fluxcd.io/namespace": "flux-system"}}}
				found = true
				break
			}
		}
		if !found {
			return &transport.HTTPError{Status: 404}
		}
	}
	b, _ := json.Marshal(result)
	return json.Unmarshal(b, out)
}
func (k *transferKube) apply(t *testing.T, name string, files map[string][]byte, digest string) {
	t.Helper()
	state := k.states[name]
	objects, err := manifestObjects(files, k.paths[name])
	if err != nil {
		t.Fatal(err)
	}
	desired := map[string]bool{}
	for _, o := range objects {
		desired[o.id()] = true
	}
	for _, entry := range state.Status.Inventory.Entries {
		o := k.objects[entry.ID]
		if !desired[entry.ID] && state.Spec.Prune && k.owners[entry.ID] == name && o.Metadata.Annotations["kustomize.toolkit.fluxcd.io/prune"] != "disabled" {
			if (o.Kind == "Deployment") && !k.adopted[entry.ID] {
				k.unsafeDelete = true
			}
			delete(k.objects, entry.ID)
			delete(k.owners, entry.ID)
		}
	}
	state.Status.Inventory.Entries = nil
	for _, o := range objects {
		state.Status.Inventory.Entries = append(state.Status.Inventory.Entries, struct {
			ID string `json:"id"`
		}{o.id()})
		k.objects[o.id()] = o
		k.owners[o.id()] = name
		if name != "livepeer" {
			k.adopted[o.id()] = true
		}
		if o.Kind == "Kustomization" {
			var def struct {
				Spec struct {
					Path  string `yaml:"path"`
					Prune bool   `yaml:"prune"`
					Wait  bool   `yaml:"wait"`
				} `yaml:"spec"`
			}
			yaml.Unmarshal(o.data, &def)
			child := k.states[o.Metadata.Name]
			child.Metadata.Generation++
			child.Spec.Prune = def.Spec.Prune
			child.Spec.Path = def.Spec.Path
			k.states[o.Metadata.Name] = child
			k.paths[o.Metadata.Name] = strings.TrimPrefix(def.Spec.Path, "./")
			k.waits[o.Metadata.Name] = def.Spec.Wait
		}
	}
	state.Status.LastAttemptedRevision = digest
	if !k.waits[name] {
		state.Status.LastAppliedRevision = digest
	}
	state.Status.ObservedGeneration = state.Metadata.Generation
	// All managed workloads stay unhealthy throughout these tests.
	state.Status.Conditions = []transport.Condition{{Type: "Ready", Status: "False"}}
	k.states[name] = state
}

func transferFixture(t *testing.T) (*Source, *transferKube, map[string][]byte, contract.Metadata) {
	t.Helper()
	root := fluxState{}
	root.Spec.Prune = true
	root.Metadata.Generation = 1
	k := &transferKube{states: map[string]fluxState{"livepeer": root}, paths: map[string]string{"livepeer": ""}, waits: map[string]bool{}, objects: map[string]manifestObject{}, owners: map[string]string{}, adopted: map[string]bool{}}
	s := &Source{SystemWorkloads: true, Kube: k, Store: artifact.Store{Directory: t.TempDir()}}
	m := contract.Metadata{NodeID: "lp-aaaaaaaaaaaaaaaa", Epoch: "epoch", CredentialVersion: 1, Generation: 1, BundleFormat: 3}
	metadata, _ := json.Marshal(m)
	files := map[string][]byte{"runtime.json": metadata, "kustomization.yaml": kustomization("management"), "management/kustomization.yaml": kustomization("app-reconciler.yaml", "system.yaml"), "management/app-reconciler.yaml": []byte("")}
	legacy := map[string][]byte{"runtime.json": metadata, "kustomization.yaml": kustomization("management"), "management/kustomization.yaml": kustomization("orchestrator.yaml", "tunnel.yaml")}
	for _, c := range systemComponents {
		b := []byte(fmt.Sprintf("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: %s, namespace: flux-system}\n", c))
		files["system/"+c+"/workload.yaml"] = b
		files["system/"+c+"/kustomization.yaml"] = kustomization("workload.yaml")
		files["management/system.yaml"] = append(files["management/system.yaml"], []byte(fmt.Sprintf("---\napiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata: {name: livepeer-%s, namespace: flux-system}\nspec:\n  path: ./system/%s\n  prune: true\n  wait: %t\n", c, c, c == "upgrade-controller"))...)
		if c == "node" {
			legacy["management/orchestrator.yaml"] = b
		}
		if c == "connector" {
			legacy["management/tunnel.yaml"] = b
		}
	}
	legacy["management/tunnel.yaml"] = append(legacy["management/tunnel.yaml"], []byte("---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: livepeer-tunnel, namespace: flux-system}\ndata: {routing.json: legacy}\n")...)
	data, _ := artifact.Pack(legacy)
	digest, err := s.Store.Put(data)
	if err != nil {
		t.Fatal(err)
	}
	k.source = digest
	k.apply(t, "livepeer", legacy, digest)
	return s, k, files, m
}

func TestTransferPreservesWithdrawnResourcesAtEveryBoundary(t *testing.T) {
	for _, withdrawAt := range []string{"before", "handoff", "adopting", "releasing", "pruning", "complete"} {
		t.Run(withdrawAt, func(t *testing.T) {
			s, k, files, m := transferFixture(t)
			withdrawn := false
			done := false
			resets := map[string]bool{}
			for iteration := 0; iteration < 30; iteration++ {
				b, _ := os.ReadFile(filepath.Join(s.Store.Directory, "system-layout.json"))
				var state layoutState
				json.Unmarshal(b, &state)
				if !withdrawn && (withdrawAt == "before" || state.Stage == withdrawAt) {
					files = copyFiles(files)
					// Models both ordinary route withdrawal and final terminal Node cleanup.
					files["system/connector/kustomization.yaml"] = kustomization()
					files["system/node/kustomization.yaml"] = kustomization()
					delete(files, "system/connector/workload.yaml")
					delete(files, "system/node/workload.yaml")
					m.Terminal = true
					m.TerminalCleanup = true
					m.ConnectorTokenRef = ""
					m.TokenGeneration = 0
					files["runtime.json"], _ = json.Marshal(m)
					files["app-desired/current"] = []byte("current tombstones")
					withdrawn = true
				}
				data, _ := artifact.Pack(files)
				output, handoff, err := s.systemLayout(t.Context(), files, data, m)
				if err != nil {
					t.Fatal(iteration, state.Stage, err)
				}
				// Lose the process after its durable stage commit but before source
				// publication. The resumed publisher must serve the same transfer.
				s = &Source{SystemWorkloads: true, Kube: k, Store: s.Store}
				replay, _, err := s.systemLayout(t.Context(), files, data, m)
				if err != nil || artifact.Digest(replay) != artifact.Digest(output) {
					t.Fatal("publication boundary changed transfer", err)
				}
				digest, err := s.Store.Put(output)
				if err != nil {
					t.Fatal(err)
				}
				published, _ := artifact.Read(output)
				var outputState layoutState
				stateBytes, _ := os.ReadFile(filepath.Join(s.Store.Directory, "system-layout.json"))
				json.Unmarshal(stateBytes, &outputState)
				if !resets[outputState.Stage] {
					root := k.states["livepeer"]
					root.Spec.Prune = false
					root.Metadata.Generation++
					k.states["livepeer"] = root
					resets[outputState.Stage] = true
				}
				if withdrawn && string(published["runtime.json"]) != string(files["runtime.json"]) {
					t.Fatal("restored old credential authority")
				}
				if withdrawn && string(published["app-desired/current"]) != "current tombstones" {
					t.Fatal("froze app cleanup")
				}
				k.source = digest
				k.apply(t, "livepeer", published, digest)
				for _, c := range systemComponents {
					if _, ok := k.states["livepeer-"+c]; ok {
						k.apply(t, "livepeer-"+c, published, digest)
					}
				}
				// Restart after every publication and stage commit.
				s = &Source{SystemWorkloads: true, Kube: k, Store: s.Store}
				if withdrawn && !handoff {
					done = true
					break
				}
			}
			if !done || k.unsafeDelete {
				t.Fatal("transfer failed to converge safely", done, k.unsafeDelete)
			}
			for _, o := range k.objects {
				if o.Kind == "Deployment" && (o.Metadata.Name == "node" || o.Metadata.Name == "connector") {
					t.Fatal("withdrawn deployment orphaned")
				}
			}
			if !k.states["livepeer"].Spec.Prune {
				// A repair can race even the final publication; completed layouts
				// restore pruning on their next sync without rewinding ownership.
				data, _ := artifact.Pack(files)
				if _, _, err := s.systemLayout(t.Context(), files, data, m); err != nil || !k.states["livepeer"].Spec.Prune {
					t.Fatal("parent prune was not restored", err)
				}
			}
		})
	}
}

func TestTransferRequiresActualOwnershipAndPriorDefinitions(t *testing.T) {
	s, k, files, m := transferFixture(t)
	data, _ := artifact.Pack(files)
	output, _, err := s.systemLayout(t.Context(), files, data, m)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := s.Store.Put(output)
	published, _ := artifact.Read(output)
	k.apply(t, "livepeer", published, digest)
	output, _, err = s.systemLayout(t.Context(), files, data, m)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ = s.Store.Put(output)
	published, _ = artifact.Read(output)
	k.apply(t, "livepeer", published, digest)
	for _, c := range systemComponents {
		k.apply(t, "livepeer-"+c, published, digest)
	}
	for id := range k.owners {
		if strings.HasSuffix(id, "_Deployment") {
			k.owners[id] = "unrelated-owner"
			break
		}
	}
	if _, _, err = s.systemLayout(t.Context(), files, data, m); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(s.Store.Directory, "system-layout.json"))
	var state layoutState
	json.Unmarshal(b, &state)
	if state.Stage != "adopting" || k.states["livepeer"].Spec.Prune {
		t.Fatal("trusted inventory without actual ownership")
	}
	s, k, files, m = transferFixture(t)
	os.Remove(filepath.Join(s.Store.Directory, k.source[7:]+".tar.gz"))
	if _, _, err = s.systemLayout(t.Context(), files, data, m); err == nil {
		t.Fatal("silently discarded an unavailable prior inventory")
	}
}
