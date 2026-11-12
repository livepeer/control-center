package appreconciler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/onchain"
	"github.com/livepeer/control-center/runtime/transport"
)

type onchainTransport func(*http.Request) (*http.Response, error)

func (f onchainTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestForcedRetirementRequiresAuthoritativeNodeAbsence(t *testing.T) {
	c, input, cluster, owner, reporter, _ := fixtureController(t)
	input.value.Metadata.Onchain = onchain.Config{Mode: "onchain"}
	input.value.Metadata.OnchainActive = true
	registerApps(t, c, cluster)
	input.value.Metadata.Terminal = true
	owner.unregisterFail = true
	owner.down = true
	if c.Tick(t.Context()) == nil {
		t.Fatal("missing Node was silently accepted")
	}
	for _, i := range c.Journal.View().Instances {
		if i.RegistrationGone {
			t.Fatal("unknown Node state established registration absence")
		}
	}
	input.value.NodeAbsent = true
	tick(t, c)
	for _, i := range c.Journal.View().Instances {
		if !i.RegistrationGone || i.RegistrationPending {
			t.Fatal("authoritative Node absence did not release forced cleanup")
		}
	}
	if reporter.reports[len(reporter.reports)-1].Drained {
		t.Fatal("forced retirement claimed ordinary app drain")
	}
}

func TestOnchainAdmissionRequiresLiveMatchingNode(t *testing.T) {
	digest := strings.Repeat("a", 64)
	pods := 1
	ready := 200
	deployment, lookup := 200, 200
	kube := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/deployments/") {
			w.WriteHeader(deployment)
			return
		}
		if lookup != 200 {
			w.WriteHeader(lookup)
			return
		}
		items := []any{}
		for range pods {
			items = append(items, map[string]any{"metadata": map[string]any{"uid": "node-pod", "annotations": map[string]string{"livepeer.io/config-sha256": digest}}})
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items})
	}))
	defer kube.Close()
	token := filepath.Join(t.TempDir(), "token")
	os.WriteFile(token, []byte("fixture"), 0600)
	source := Source{Kube: &transport.Kube{Base: kube.URL, TokenFile: token, Client: kube.Client()}, Client: &http.Client{Transport: onchainTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: ready, Body: io.NopCloser(strings.NewReader("ready")), Header: make(http.Header)}, nil
	})}}
	m := contract.Metadata{ConfigDigest: digest}
	if !source.onchainActive(context.Background(), m) {
		t.Fatal("matching ready Node rejected")
	}
	ready = 503
	if source.onchainActive(context.Background(), m) {
		t.Fatal("cached approval admitted on unready Node")
	}
	ready = 200
	digest = strings.Repeat("b", 64)
	if source.onchainActive(context.Background(), m) {
		t.Fatal("different generation admitted")
	}
	digest = m.ConfigDigest
	pods = 2
	if source.onchainActive(context.Background(), m) {
		t.Fatal("ambiguous Node incarnation admitted")
	}
	for _, test := range []struct {
		deployment, lookup, pods int
		absent                   bool
	}{{404, 200, 0, true}, {200, 200, 0, false}, {404, 200, 1, false}, {404, 503, 0, false}, {503, 200, 0, false}} {
		deployment, lookup, pods = test.deployment, test.lookup, test.pods
		if source.nodeAbsent(t.Context()) != test.absent {
			t.Fatal("Node absence inferred without authoritative workload removal", test)
		}
	}
}
func TestPendingOnchainTargetDoesNotAllocateOrAdmit(t *testing.T) {
	c, input, cluster, owner, _, _ := fixtureController(t)
	input.value.Metadata.Onchain = onchain.Config{Mode: "onchain", Generation: 1}
	input.value.Metadata.OnchainActive = false
	tick(t, c)
	if len(c.Journal.View().Instances) != 0 {
		t.Fatal("pending onchain target allocated work")
	}
	input.value.Metadata.OnchainActive = true
	registerApps(t, c, cluster)
	input.value.Metadata.OnchainActive = false
	tick(t, c)
	for _, entry := range owner.accepted.Entries {
		if entry.Options.Status == "ready" {
			t.Fatal("readiness loss admitted new work")
		}
	}
	for _, instance := range c.Journal.View().Instances {
		if instance.WithdrawalID != "" {
			t.Fatal("temporary onchain readiness loss became terminal withdrawal")
		}
	}
}
