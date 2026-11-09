package appreconciler

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/livepeer/control-center/runtime/transport"
)

func TestKubernetesWorkloadFailuresExportOnlySupportedCodes(t *testing.T) {
	for _, test := range []struct{ name, status, want string }{
		{"image", `{"phase":"Pending","containerStatuses":[{"state":{"waiting":{"reason":"ImagePullBackOff","message":"secret-sentinel"}}}]}`, "image_pull_failed"},
		{"scheduling", `{"phase":"Pending","conditions":[{"type":"PodScheduled","status":"False","reason":"Unschedulable"},{"type":"Ready","status":"False","reason":"ContainersNotReady"}],"containerStatuses":[{"state":{"waiting":{"reason":"ContainerCreating","message":"secret-sentinel"}}}]}`, "scheduling_refused"},
		{"sandbox", `{"phase":"Pending","conditions":[{"type":"PodReadyToStartContainers","status":"False"},{"type":"Ready","status":"False","reason":"ContainersNotReady"}],"containerStatuses":[{"state":{"waiting":{"reason":"ContainerCreating","message":"secret-sentinel"}}}]}`, "sandbox_pending"},
		{"memory", `{"phase":"Failed","containerStatuses":[{"state":{"terminated":{"reason":"OOMKilled","message":"secret-sentinel"}}}]}`, "memory_limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := transport.HTTPClient()
			client.Transport = reviewRoundTripper(func(r *http.Request) (*http.Response, error) {
				body := `{}`
				switch r.URL.Path {
				case "/api/v1/nodes":
					body = `{"items":[{"status":{"allocatable":{"cpu":"4","memory":"8Gi","ephemeral-storage":"20Gi"}}}]}`
				case "/api/v1/namespaces/livepeer-apps/pods":
					body = `{"items":[{"metadata":{"name":"app-one","uid":"pod-one"},"status":` + test.status + `}]}`
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			k := Kubernetes{Client: &transport.Kube{Base: "http://kube.invalid", Client: client}, NodeID: "machine"}
			view, err := k.Read(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if view.Pods["app-one"].Reason != test.want || view.Pods["app-one"].UID != "pod-one" {
				t.Fatal("workload classification lost", view.Pods)
			}
			if strings.Contains(fmt.Sprint(view), "secret-sentinel") {
				t.Fatal("raw Kubernetes message escaped")
			}
		})
	}
}
