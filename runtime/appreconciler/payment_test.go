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
	"github.com/livepeer/control-center/runtime/payment"
	"github.com/livepeer/control-center/runtime/transport"
)

type paymentTransport func(*http.Request) (*http.Response, error)

func (f paymentTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestPaidAdmissionRequiresLiveMatchingNode(t *testing.T) {
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
	source := Source{Kube: &transport.Kube{Base: kube.URL, TokenFile: token, Client: kube.Client()}, Client: &http.Client{Transport: paymentTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: ready, Body: io.NopCloser(strings.NewReader("ready")), Header: make(http.Header)}, nil
	})}}
	m := contract.Metadata{ConfigDigest: digest}
	if !source.paymentActive(context.Background(), m) {
		t.Fatal("matching ready Node rejected")
	}
	ready = 503
	if source.paymentActive(context.Background(), m) {
		t.Fatal("cached approval admitted on unready Node")
	}
	ready = 200
	digest = strings.Repeat("b", 64)
	if source.paymentActive(context.Background(), m) {
		t.Fatal("different generation admitted")
	}
	digest = m.ConfigDigest
	pods = 2
	if source.paymentActive(context.Background(), m) {
		t.Fatal("ambiguous Node incarnation admitted")
	}
}
func TestPendingPaidTargetDoesNotAllocateOrAdmit(t *testing.T) {
	c, input, cluster, owner, _, _ := fixtureController(t)
	input.value.Metadata.Payment = payment.Config{Mode: "paid", Generation: 1}
	input.value.Metadata.PaymentActive = false
	tick(t, c)
	if len(c.Journal.View().Instances) != 0 {
		t.Fatal("pending paid target allocated work")
	}
	input.value.Metadata.PaymentActive = true
	registerApps(t, c, cluster)
	input.value.Metadata.PaymentActive = false
	tick(t, c)
	for _, entry := range owner.accepted.Entries {
		if entry.Options.Status == "ready" {
			t.Fatal("readiness loss admitted new work")
		}
	}
	for _, instance := range c.Journal.View().Instances {
		if instance.WithdrawalID != "" {
			t.Fatal("temporary payment readiness loss became terminal withdrawal")
		}
	}
}
