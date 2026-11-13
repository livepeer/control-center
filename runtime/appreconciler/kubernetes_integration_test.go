package appreconciler

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/transport"
)

type reconcilerPrincipal struct{ http.RoundTripper }

func (p reconcilerPrincipal) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Impersonate-User", "system:serviceaccount:flux-system:livepeer-app-reconciler")
	return p.RoundTripper.RoundTrip(r)
}

// Run only against an isolated disposable cluster with Flux ExternalArtifact
// support and the repository-pinned gVisor runtime. The owner is a contract double;
// TestMergedNodeSDKDrain separately exercises the actual Node and SDK.
func TestLinuxFluxGvisorCleanup(t *testing.T) {
	base, host := os.Getenv("LIVEPEER_KUBE_TEST_API"), os.Getenv("LIVEPEER_KUBE_TEST_ARTIFACT_HOST")
	if base == "" || host == "" {
		t.Skip("set LIVEPEER_KUBE_TEST_API and LIVEPEER_KUBE_TEST_ARTIFACT_HOST for an isolated Flux/gVisor cluster")
	}
	kube := &transport.Kube{Base: base, Client: transport.HTTPClient()}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	var nodes struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := kube.Request(ctx, "GET", "/api/v1/nodes", nil, &nodes); err != nil || len(nodes.Items) != 1 {
		t.Fatal("require isolated single-node cluster", err)
	}
	create := func(resource string, payload any) error {
		err := kube.PatchType(ctx, http.MethodPost, resource, payload, nil, "application/json")
		if transport.IsStatus(err, 409) {
			return nil
		}
		return err
	}
	c, input, _, owner, _, _ := fixtureController(t)
	c.Now = nil
	if err := kube.Request(ctx, "PATCH", "/api/v1/nodes/"+nodes.Items[0].Metadata.Name, map[string]any{"metadata": map[string]any{"labels": map[string]string{"livepeer.io/node-id": input.value.Metadata.NodeID}}}, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"livepeer-apps", "flux-system"} {
		err := create("/api/v1/namespaces", map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]string{"name": name}})
		if err != nil && !transport.IsStatus(err, 409) {
			t.Fatal(err)
		}
	}
	if err := create("/api/v1/namespaces/livepeer-apps/serviceaccounts", map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]string{"name": "livepeer-app"}}); err != nil {
		t.Fatal(err)
	}
	if err := create("/apis/source.toolkit.fluxcd.io/v1/namespaces/flux-system/externalartifacts", map[string]any{"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "ExternalArtifact", "metadata": map[string]string{"name": "livepeer-apps"}, "spec": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if err := create("/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/flux-system/kustomizations", map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": map[string]string{"name": "livepeer-apps"}, "spec": map[string]any{"interval": "1s", "retryInterval": "1s", "timeout": "20s", "path": "./", "prune": true, "wait": false, "deletionPolicy": "Orphan", "sourceRef": map[string]string{"kind": "ExternalArtifact", "name": "livepeer-apps"}}}); err != nil {
		t.Fatal(err)
	}
	runtimeKube, client := *kube, *kube.Client
	client.Transport = reconcilerPrincipal{http.DefaultTransport}
	runtimeKube.Client = &client
	c.Cluster = Kubernetes{Client: &runtimeKube, NodeID: input.value.Metadata.NodeID}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(c.Store.ServeHTTP))
	server.Listener = listener
	server.Start()
	defer server.Close()
	c.ArtifactURL = "http://" + net.JoinHostPort(host, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
	if c.Probes == nil {
		c.Probes = NewProbes()
	}
	c.Probes.Address = func(i *Instance) string {
		var service struct {
			Spec struct {
				ClusterIP string `json:"clusterIP"`
			} `json:"spec"`
		}
		if kube.Request(ctx, "GET", "/api/v1/namespaces/livepeer-apps/services/"+i.Name, nil, &service) != nil {
			return "http://127.0.0.1:1"
		}
		return "http://" + net.JoinHostPort(service.Spec.ClusterIP, fmt.Sprint(i.Definition.HTTP.Port))
	}
	set := *input.value.Payload.Intent
	set.Entries[0].Replicas = 1
	input.set(t, set)
	wait := func(label string, predicate func() bool) {
		t.Helper()
		for {
			if predicate() {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	var last error
	wait("ready gVisor instance", func() bool {
		last = c.Tick(ctx)
		s := c.Journal.View()
		if last != nil {
			return false
		}
		for _, i := range s.Instances {
			if i.AppID != "" && c.Probes.Ready(i.ID, i.PodUID) {
				return true
			}
		}
		return false
	})
	s := c.Journal.View()
	var instance *Instance
	for _, i := range s.Instances {
		instance = i
	}
	var pod struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
		Spec struct {
			RuntimeClassName string `json:"runtimeClassName"`
		} `json:"spec"`
	}
	resource := "/api/v1/namespaces/livepeer-apps/pods/" + instance.Name
	if err := kube.Request(ctx, "GET", resource, nil, &pod); err != nil || pod.Spec.RuntimeClassName != "gvisor" {
		t.Fatal("not a running gVisor workload", err, pod)
	}
	uid := pod.Metadata.UID
	if err := kube.Request(ctx, "DELETE", resource, nil, nil); err != nil {
		t.Fatal(err)
	}
	// Pause the actual controller: Flux cannot replace the held incarnation.
	time.Sleep(1500 * time.Millisecond)
	if err := kube.Request(ctx, "GET", resource, nil, &pod); err != nil || pod.Metadata.UID != uid {
		t.Fatal("successor appeared behind the Service while controller paused", err)
	}
	view, err := c.Cluster.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	held := view.Pods[instance.Name]
	wrong := held
	wrong.UID = "wrong-incarnation"
	if err := c.Cluster.Release(ctx, instance.Name, wrong); err == nil {
		t.Fatal("finalizer guard accepted wrong UID")
	}
	set.Generation++
	set.Entries[0] = set.Entries[0].Absent()
	set.Entries[0].Generation++
	input.set(t, set)
	owner.sessions = map[string][]string{}
	wait("exact exclusion, finalizer release and actual absence", func() bool {
		last = c.Tick(ctx)
		if last != nil {
			return false
		}
		view, err := c.Cluster.Read(ctx)
		if err != nil {
			return false
		}
		state := c.Journal.View()
		return len(view.Pods) == 0 && len(view.Services) == 0 && state.Identity.RunnerID == "" && strings.TrimSpace(state.Published) != ""
	})
	t.Log("real Flux exclusion, guarded finalizer and actual gVisor Pod/Service absence verified")
}
