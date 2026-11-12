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

func TestOnchainEmptyOwnerStillRequiresNodeDrainAcknowledgement(t *testing.T) {
	c, input, _, owner, reporter, _ := fixtureController(t)
	input.value.Metadata.Onchain = onchain.Config{Version: 1, Mode: "onchain"}
	input.value.Metadata.DrainRequested = true
	input.value.Metadata.DrainTarget = "drain-target"
	owner.unregisterFail = true
	tick(t, c)
	if reporter.reports[len(reporter.reports)-1].Drained || owner.unregisters == 0 {
		t.Fatal("empty owner bypassed Node's durable handoff drain")
	}
	owner.unregisterFail = false
	tick(t, c)
	if !reporter.reports[len(reporter.reports)-1].Drained {
		t.Fatal("Node's normal drain acknowledgement did not release maintenance")
	}
}

func TestEmptySDKOwnerUnregisterChecksNodeInsteadOfSkippingRequest(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/unregister") || r.Header.Get("Authorization") != "bootstrap" {
			t.Error("invalid normal unregister request")
		}
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	owner, err := NewSDKOwner(server.URL, "bootstrap", nil)
	if err != nil {
		t.Fatal(err)
	}
	if owner.Unregister(t.Context(), Identity{}) == nil {
		t.Fatal("pending handoff was acknowledged")
	}
	if err := owner.Unregister(t.Context(), Identity{}); err != nil || calls != 2 {
		t.Fatal("Node acknowledgement was not observed", err, calls)
	}
}
func TestOnchainAdmissionRequiresLiveMatchingNode(t *testing.T) {
	digest := strings.Repeat("a", 64)
	pods := 1
	ready := 200
	kube := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		items := []any{}
		for range pods {
			items = append(items, map[string]any{"metadata": map[string]any{"annotations": map[string]string{"livepeer.io/config-sha256": digest}}})
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
