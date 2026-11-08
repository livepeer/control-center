package appbundle

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/internal/testutil"
	"github.com/livepeer/control-center/schema"
)

func fixture(t *testing.T) schema.AppAssignmentSetV1 { return testutil.Assignment(t) }
func metadata(p Payload) contract.Metadata {
	return contract.Metadata{NodeID: p.Intent.NodeID, Epoch: p.Intent.Epoch, AppsGeneration: p.Intent.Generation, AppsDigest: p.Index.IntentDigest, AppsPayloadDigest: p.Digest()}
}
func TestRenderedGroupsAndIncarnations(t *testing.T) {
	set := fixture(t)
	p, err := Render(set, Options{})
	if err != nil {
		t.Fatal(err)
	}
	q, err := Read(p.Files, metadata(p))
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Index.Groups) != 2 {
		t.Fatal("replica grouping")
	}
	g := q.Index.Groups[0]
	a, name, err := q.Instantiate(g, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	b, other, err := q.Instantiate(g, strings.Repeat("b", 32))
	if err != nil || name == other {
		t.Fatal("replacement identity", err)
	}
	if len(name) > 63 || len(a) != 2 || len(b) != 2 {
		t.Fatal("resource identity")
	}
	var pod map[string]any
	json.Unmarshal(a["instances/"+name+"/pod.json"], &pod)
	spec := pod["spec"].(map[string]any)
	meta := pod["metadata"].(map[string]any)
	if spec["runtimeClassName"] != "gvisor" || spec["restartPolicy"] != "Never" || spec["automountServiceAccountToken"] != false || meta["finalizers"].([]any)[0] != Finalizer {
		t.Fatal("isolation/finalizer policy")
	}
	container := spec["containers"].([]any)[0].(map[string]any)
	if container["image"] != set.Entries[0].Revision.Definition.Container.Image || container["securityContext"].(map[string]any)["readOnlyRootFilesystem"] != true {
		t.Fatal("container mapping")
	}
	var svc map[string]any
	json.Unmarshal(a["instances/"+name+"/service.json"], &svc)
	if svc["spec"].(map[string]any)["publishNotReadyAddresses"] != true || svc["spec"].(map[string]any)["selector"].(map[string]any)["livepeer.io/instance"] != name {
		t.Fatal("private endpoint retention")
	}
	if !strings.Contains(string(p.Files[g.Files[0]]), g.Name) || strings.Contains(string(p.Files[g.Files[0]]), name) {
		t.Fatal("mutated central template")
	}
	again, _ := Render(set, Options{})
	if p.Digest() != again.Digest() {
		t.Fatal("non-deterministic payload")
	}
}
func TestPayloadValidationAndUnsupportedSettings(t *testing.T) {
	set := fixture(t)
	p, _ := Render(set, Options{})
	m := metadata(p)
	p.Files[p.Index.Groups[0].Files[0]] = append(p.Files[p.Index.Groups[0].Files[0]], ' ')
	if _, err := Read(p.Files, m); err == nil {
		t.Fatal("accepted changed resource")
	}
	p, _ = Render(set, Options{})
	m.Epoch = "33333333-3333-4333-8333-333333333333"
	if _, err := Read(p.Files, m); err == nil {
		t.Fatal("accepted foreign enrollment")
	}
	set.Entries[0].Revision.Definition.Instances.Mode = "single-session"
	set.Entries[0].Revision.Definition.Instances.CapacityPerInstance = 1
	raw, _ := schema.CanonicalBytes(set.Entries[0].Revision.Definition)
	set.Entries[0].Revision.Digest = schema.Digest(raw)
	set.Entries[0].Digest = schema.Digest(raw)
	if _, err := Render(set, Options{}); err == nil {
		t.Fatal("pretended to support single-session")
	}
	set = fixture(t)
	signal := "SIGUSR1"
	set.Entries[0].Revision.Definition.Lifecycle.StopSignal = &signal
	set.Entries[0].Cleanup.StopSignal = &signal
	raw, _ = schema.CanonicalBytes(set.Entries[0].Revision.Definition)
	set.Entries[0].Revision.Digest = schema.Digest(raw)
	set.Entries[0].Digest = schema.Digest(raw)
	if _, err := Render(set, Options{}); err == nil {
		t.Fatal("silently ignored unenforceable signal")
	}
	if _, err := Render(set, Options{StopSignals: true}); err != nil {
		t.Fatal(err)
	}
}
