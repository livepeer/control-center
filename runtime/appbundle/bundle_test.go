package appbundle

import (
	"encoding/json"
	"fmt"
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
	if spec["dnsPolicy"] != "None" || fmt.Sprint(spec["dnsConfig"].(map[string]any)["nameservers"]) != "[1.1.1.1 1.0.0.1]" {
		t.Fatal("workload DNS must not use cluster services")
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

func TestPodSpecializationChecksAcceptedResourceShape(t *testing.T) {
	for _, tc := range []struct {
		spec  string
		valid bool
	}{
		{`null`, false},
		{`{}`, false},
		{`{"containers":[]}`, false},
		{`{"containers":[null]}`, false},
		{`{"containers":[{"env":false}]}`, false},
		{`{"containers":[{"env":[false]}]}`, false},
		{`{"containers":[{}]}`, true},
		{`{"containers":[{"env":null}]}`, true},
	} {
		p, err := Render(fixture(t), Options{})
		if err != nil {
			t.Fatal(err)
		}
		g := p.Index.Groups[0]
		var pod object
		json.Unmarshal(p.Files[g.Files[0]], &pod)
		var spec any
		json.Unmarshal([]byte(tc.spec), &spec)
		pod["spec"] = spec
		p.Files[g.Files[0]], _ = json.Marshal(pod)
		p.Index.Hashes[g.Files[0]] = schema.Digest(p.Files[g.Files[0]])
		p.Files[IndexFile], _ = json.Marshal(p.Index)
		q, err := Read(p.Files, metadata(p))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = q.Instantiate(g, strings.Repeat("a", 32))
		if (err == nil) != tc.valid {
			t.Fatalf("spec %s: %v", tc.spec, err)
		}
	}
}

func TestRegistrationBudgetCountsAppsAndReplicas(t *testing.T) {
	set := fixture(t)
	d := &set.Entries[0].Revision.Definition
	d.Apps = make([]schema.App, 256)
	for n := range d.Apps {
		d.Apps[n] = schema.App{Name: fmt.Sprintf("app-%d", n), Path: fmt.Sprintf("/o/%d", n), Capacity: 1, Price: d.Price}
	}
	testutil.Refresh(&set.Entries[0])
	check := func(groups int) {
		t.Helper()
		admission := schema.CheckAssignmentBudget(set)
		payload, rendered := Render(set, Options{})
		if groups < 0 {
			if admission == nil || rendered == nil || rendered.Error() != "resource_refused" {
				t.Fatal("registration overflow admitted", admission, rendered)
			}
		} else if admission != nil || rendered != nil || len(payload.Index.Groups) != groups {
			t.Fatal("registration budget or physical grouping", admission, rendered, len(payload.Index.Groups))
		}
	}
	check(2)
	set.Entries[0].Replicas = 3
	check(-1)
	set.Entries[0].Replicas = 2
	extra := set.Entries[0]
	extra.RevisionID = "33333333-3333-4333-8333-333333333333"
	revision := *extra.Revision
	extra.Revision = &revision
	extra.Replicas = 1
	extra.Revision.Definition.Apps = extra.Revision.Definition.Apps[:1]
	testutil.Refresh(&extra)
	set.Entries = append(set.Entries, extra)
	check(-1)
	set.Entries[0] = set.Entries[0].Absent()
	check(1)
}
