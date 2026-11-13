package httpsource

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
	"github.com/livepeer/control-center/runtime/version"
)

func softwarePod(workload, uid, id string) transport.Pod {
	var p transport.Pod
	p.Metadata.Name, p.Metadata.UID = workload+"-pod", uid
	p.Metadata.Labels = map[string]string{"app": workload}
	p.Spec.NodeName, p.Status.PodIP = "host", "10.42.0.2"
	var c transport.ContainerStatus
	c.Name, c.ContainerID, c.Image = workload, id, "registry.invalid/"+workload+":mutable"
	c.ImageID, c.Ready = "containerd://sha256:"+strings.Repeat("a", 64), true
	_ = json.Unmarshal([]byte(`{"running":{"startedAt":"2026-11-13T00:00:00Z"}}`), &c.State)
	p.Status.ContainerStatuses = []transport.ContainerStatus{c}
	return p
}

func TestSoftwareObservesProcessesAndResolvedImages(t *testing.T) {
	f := newFixture(t)
	oldVersion, oldCommit := version.Version, version.Commit
	version.Version, version.Commit = "v1.2.3", "abcdef1234567"
	t.Cleanup(func() { version.Version, version.Commit = oldVersion, oldCommit })
	nodeCommit := "abcdef1234567"
	node := softwarePod("orchestrator", "node-pod", "containerd://node")
	flux := softwarePod("source-controller", "flux-pod", "containerd://flux")
	old := softwarePod("source-controller", "old-flux-pod", "containerd://old")
	deleting := "2026-11-13T00:01:00Z"
	old.Metadata.DeletionTimestamp = &deleting
	otherHost := softwarePod("kustomize-controller", "other-host", "containerd://other")
	otherHost.Spec.NodeName = "other-host"
	app := softwarePod("unrelated-app", "app", "containerd://app")
	dns := softwarePod("dns", "dns-pod", "containerd://dns")
	dns.Metadata.Labels = map[string]string{"k8s-app": "kube-dns"}
	storage := softwarePod("local-path-provisioner", "storage-pod", "containerd://storage")
	upgrade := softwarePod("upgrade", "upgrade-pod", "containerd://upgrade")
	upgrade.Metadata.Labels = map[string]string{"upgrade.cattle.io/plan": "livepeer-k3s"}
	f.kube.reply = func(path string) any {
		switch {
		case strings.Contains(path, "labelSelector=app"):
			return transport.PodList{Items: []transport.Pod{node}}
		case strings.Contains(path, "/flux-system/pods?"):
			return transport.PodList{Items: []transport.Pod{flux, old, otherHost, app}}
		case strings.Contains(path, "/kube-system/pods?"):
			return transport.PodList{Items: []transport.Pod{dns, storage, app}}
		case strings.Contains(path, "/system-upgrade/pods?"):
			return transport.PodList{Items: []transport.Pod{upgrade, app}}
		case strings.Contains(path, "/livepeer/pods?"):
			return transport.PodList{Items: []transport.Pod{node}}
		default:
			return transport.PodList{}
		}
	}
	f.source.Control.Client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "10.42.0.2:8936" || r.URL.Path != "/metrics" || r.Header.Get("Authorization") != "" {
			t.Fatalf("unexpected Node build request: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("# TYPE livepeer_build_info gauge\nlivepeer_build_info{component=\"orchestrator\",version=\"v1.2.3\",revision=\"" + nodeCommit + "\"} 1\n"))}, nil
	})
	h := contract.HostSoftware{NodeID: f.meta.NodeID, CredentialVersion: f.meta.CredentialVersion, ObservedAt: time.Now().UTC(), FluxCLI: "v2.7.0", GVisorInstalled: "release-20261101", GVisorRunning: []string{"release-20261001"}}
	f.source.HostSoftwareFile = filepath.Join(t.TempDir(), "software.json")
	b, _ := json.Marshal(h)
	if err := os.WriteFile(f.source.HostSoftwareFile, b, 0600); err != nil {
		t.Fatal(err)
	}
	o := f.source.software(t.Context(), f.meta, "host")
	if o.Incomplete || o.Node == nil || o.Node.Version != "v1.2.3" || o.Node.Commit != "abcdef1234567" || o.Node.ContainerID != "containerd://node" || o.Node.PodUID != "node-pod" || len(o.Containers) != 6 || o.Host == nil || !o.Valid(f.meta.NodeID, f.meta.CredentialVersion) {
		t.Fatalf("lost software observations: %+v", o)
	}
	for _, c := range o.Containers {
		if c.Digest != "sha256:"+strings.Repeat("a", 64) || !strings.HasSuffix(c.Image, ":mutable") {
			t.Fatalf("lost resolved image: %+v", c)
		}
	}
	// Partial identities on other running workloads must be marked incomplete.
	for _, missing := range []string{"pod_uid", "container_id", "started_at"} {
		switch missing {
		case "pod_uid":
			flux.Metadata.UID = ""
		case "container_id":
			flux.Status.ContainerStatuses[0].ContainerID = ""
		case "started_at":
			flux.Status.ContainerStatuses[0].State.Running.StartedAt = time.Time{}
		}
		o = f.source.software(t.Context(), f.meta, "host")
		if !o.Incomplete || o.Node == nil || o.Host == nil || len(o.Containers) != 5 {
			t.Fatalf("missing %s lost partial observation: %+v", missing, o)
		}
		flux = softwarePod("source-controller", "flux-pod", "containerd://flux")
	}
	// Unknown commits remain unknown while preserving the observed version.
	nodeCommit = "unknown"
	o = f.source.software(t.Context(), f.meta, "host")
	if !o.Incomplete || o.Node == nil || o.Node.Commit != "" || o.Node.Version != "v1.2.3" || o.Host == nil {
		t.Fatalf("unknown Node build was presented as complete: %+v", o)
	}
	nodeCommit = "abcdef1234567"
	// A missing Node start time leaves independent host/Flux observations intact.
	node.Status.ContainerStatuses[0].State.Running.StartedAt = time.Time{}
	o = f.source.software(t.Context(), f.meta, "host")
	if o.Node != nil || o.Host == nil || len(o.Containers) != 5 || !o.Incomplete {
		t.Fatalf("partial Node state discarded other observations: %+v", o)
	}
	node = softwarePod("orchestrator", "node-pod", "containerd://node")
	// A fresh report must not refresh an old host observation or a prior enrollment.
	for _, mutate := range []func(){func() { h.ObservedAt = time.Now().Add(-time.Minute) }, func() { h.ObservedAt = time.Now(); h.CredentialVersion++ }} {
		mutate()
		b, _ := json.Marshal(h)
		_ = os.WriteFile(f.source.HostSoftwareFile, b, 0600)
		if o := f.source.software(t.Context(), f.meta, "host"); o.Host != nil || !o.Incomplete || o.Node == nil {
			t.Fatalf("host failure contaminated independent observations: %+v", o)
		}
	}
}

func TestNodeBuildRejectsRestartAndAmbiguousPod(t *testing.T) {
	for _, change := range []string{"restart", "replacement", "ambiguous", "missing_metric", "invalid_metric"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			pod := softwarePod("orchestrator", "pod", "containerd://old")
			reads := 0
			f.kube.reply = func(string) any {
				reads++
				if reads > 1 {
					if change == "restart" {
						pod.Status.ContainerStatuses[0].ContainerID = "containerd://new"
					}
					if change == "replacement" {
						pod.Metadata.UID = "replacement"
					}
				}
				pods := []transport.Pod{pod}
				if change == "ambiguous" {
					pods = append(pods, pod)
				}
				return transport.PodList{Items: pods}
			}
			f.source.Control.Client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
				body := "# TYPE livepeer_build_info gauge\nlivepeer_build_info{component=\"orchestrator\",version=\"v1\",revision=\"abcdef1234567\"} 1\n"
				if change == "missing_metric" {
					body = ""
				}
				if change == "invalid_metric" {
					body = "not prometheus"
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			if o := f.source.nodeBuild(t.Context(), "host"); o != nil {
				t.Fatalf("unfenced process identity: %+v", o)
			}
		})
	}
}

func TestSoftwareFailureStillReportsExistingStatus(t *testing.T) {
	f := newFixture(t)
	if err := f.source.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.kube.err = context.DeadlineExceeded
	if err := f.source.Report(t.Context()); err != nil {
		t.Fatal(err)
	}
	report := f.lastReport()
	software := report["software"].(map[string]any)
	if software["incomplete"] != true || report["generation"] != float64(f.meta.Generation) || report["node_id"] != f.meta.NodeID {
		t.Fatal(report)
	}
	if _, ok := software["node"]; ok {
		t.Fatal("invented Node version", software)
	}
	if _, ok := software["host"]; ok {
		t.Fatal("invented host versions", software)
	}
}
