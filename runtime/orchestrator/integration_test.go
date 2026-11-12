package orchestrator

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
	"time"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/payment"
)

type kubeFunc func(context.Context, string, string, any, any) error

func (f kubeFunc) Request(c context.Context, m, p string, in, out any) error {
	return f(c, m, p, in, out)
}

type controlFunc func(context.Context, string, any, int64) ([]byte, http.Header, error)

func (f controlFunc) Request(c context.Context, p string, in any, n int64) ([]byte, http.Header, error) {
	return f(c, p, in, n)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func integrationFixture(t *testing.T) (*Integration, contract.Metadata, Launch) {
	t.Helper()
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	os.WriteFile(token, []byte("machine-secret"), 0600)
	m := contract.Metadata{NodeID: "lp-aaaaaaaaaaaaaaaa", Epoch: "11111111-1111-4111-8111-111111111111", CredentialVersion: 1, Generation: 5, ConfigDigest: strings.Repeat("a", 64), Payment: payment.Config{Mode: "onchain", Generation: 2}, PaymentCredentialsRef: "/v1/nodes/lp-aaaaaaaaaaaaaaaa/payment/credentials"}
	l := Launch{PodName: "orchestrator-test", PodUID: "uid", LaunchID: strings.Repeat("b", 32), ProcessID: strings.Repeat("c", 64)}
	i := &Integration{TokenFile: token, StateFile: filepath.Join(dir, "grant.json"), Desired: func() (contract.Metadata, bool) { return m, true }}
	i.Kube = kubeFunc(func(_ context.Context, _, p string, _ any, out any) error {
		if !strings.Contains(p, "/livepeer/pods/") {
			t.Fatal(p)
		}
		b, _ := json.Marshal(map[string]any{"metadata": map[string]any{"uid": l.PodUID, "labels": map[string]string{"app": "orchestrator"}, "annotations": map[string]string{"livepeer.io/config-sha256": m.ConfigDigest}}})
		return json.Unmarshal(b, out)
	})
	i.Control = controlFunc(func(_ context.Context, p string, in any, _ int64) ([]byte, http.Header, error) {
		if p != "payment/credentials" {
			t.Fatal(p)
		}
		b, _ := json.Marshal(Grant{Association: Association{Launch: l, Epoch: m.Epoch, CredentialVersion: 1, PaymentGeneration: 2, ConfigDigest: m.ConfigDigest, GrantID: "grant"}, RPCURL: "https://rpc.example/secret", Headers: "Authorization: Bearer redemption-secret"})
		return b, nil, nil
	})
	return i, m, l
}
func TestPaymentDeliveryFencesAndSecretPersistence(t *testing.T) {
	i, _, l := integrationFixture(t)
	g, e := i.fetch(t.Context(), l)
	if e != nil || g.Headers == "" {
		t.Fatal(e)
	}
	b, e := os.ReadFile(i.StateFile)
	if e != nil || strings.Contains(string(b), "redemption-secret") || strings.Contains(string(b), "rpc.example") {
		t.Fatal("persisted secret", e)
	}
	old := i.Control
	i.Control = controlFunc(func(ctx context.Context, p string, in any, n int64) ([]byte, http.Header, error) {
		b, h, e := old.Request(ctx, p, in, n)
		os.WriteFile(i.TokenFile, []byte("refreshed"), 0600)
		return b, h, e
	})
	if _, e = i.fetch(t.Context(), l); e == nil {
		t.Fatal("refresh raced delivery")
	}
	i.AllowHTTP = true
	if _, e = i.fetch(t.Context(), l); e == nil {
		t.Fatal("insecure delivery")
	}
}
func TestPaymentQueueEvidenceAndHandoffAreIndependent(t *testing.T) {
	i, m, l := integrationFixture(t)
	g, e := i.fetch(t.Context(), l)
	if e != nil {
		t.Fatal(e)
	}
	if i.Observe(t.Context(), m, true, true, l.PodUID).Applied {
		t.Fatal("Pod UID alone renewed an earlier process grant")
	}
	processProof(t, i, g.Association, true)
	old := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = old })
	body := "# TYPE livepeer_collector_healthy gauge\n# TYPE livepeer_redemption_queue_tickets gauge\n# TYPE livepeer_redemption_transitions_total counter\nlivepeer_collector_healthy{component=\"orchestrator\",collector=\"redemptions\"} 1\n"
	for _, s := range []string{"waiting", "eligible", "in_flight", "awaiting_finality", "rejected", "blocked", "unknown"} {
		body += "livepeer_redemption_queue_tickets{component=\"orchestrator\",state=\"" + s + "\"} 0\n"
	}
	metrics := body
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(metrics)), Header: make(http.Header)}, nil
	})}
	o := i.Observe(t.Context(), m, true, true, l.PodUID)
	if !o.QueueKnown || o.Unsettled != 0 || !o.Ready || o.Handoff != "unverified" {
		t.Fatal(o)
	}
	metrics = body + "livepeer_redemption_transitions_total{component=\"orchestrator\",event=\"retryable\"} 1\n"
	o = i.Observe(t.Context(), m, true, true, l.PodUID)
	if !o.Ready || o.Handoff != "degraded" {
		t.Fatal(o)
	}
	i.errAt = time.Now().Add(-3 * time.Minute)
	if i.Observe(t.Context(), m, true, true, l.PodUID).Handoff != "unverified" {
		t.Fatal("repeated metrics renewed old failed handoff evidence")
	}
	metrics += "livepeer_redemption_transitions_total{component=\"orchestrator\",event=\"acknowledged\"} 1\n"
	o = i.Observe(t.Context(), m, true, true, l.PodUID)
	if o.Handoff != "healthy" {
		t.Fatal(o)
	}
	restarted := &Integration{Kube: i.Kube, Desired: i.Desired, StateFile: i.StateFile}
	restarted.Restore()
	processProof(t, restarted, g.Association, true)
	if restarted.Observe(t.Context(), m, true, true, l.PodUID).Handoff != "unverified" {
		t.Fatal("management restart renewed old handoff evidence")
	}

	metrics = "livepeer_collector_healthy{component=\"orchestrator\",collector=\"redemptions\"} 1\n"
	if i.Observe(t.Context(), m, true, true, l.PodUID).QueueKnown {
		t.Fatal("missing samples fabricated empty queue")
	}
	if i.Observe(t.Context(), m, true, true, "replacement").QueueKnown {
		t.Fatal("borrowed replaced pod evidence")
	}
	i.observation.ObservedAt = time.Now().Add(-31 * time.Second)
	if i.Observe(t.Context(), m, true, true, l.PodUID).Applied {
		t.Fatal("expired process evidence remained current")
	}
}

func processProof(t *testing.T, i *Integration, a Association, ready bool) {
	t.Helper()
	b, _ := json.Marshal(ProcessObservation{Association: a, ObservedAt: time.Now(), Ready: ready})
	w := httptest.NewRecorder()
	i.ServeHTTP(w, httptest.NewRequest("POST", "/payment/observation", strings.NewReader(string(b))))
	if w.Code != 200 {
		t.Fatal("process proof rejected", w.Code)
	}
}

func TestProcessObservationCannotBorrowAnotherLaunchOrRenewOldEvidence(t *testing.T) {
	i, _, l := integrationFixture(t)
	g, e := i.fetch(t.Context(), l)
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*ProcessObservation){
		func(o *ProcessObservation) { o.ProcessID = strings.Repeat("e", 64) },
		func(o *ProcessObservation) { o.LaunchID = strings.Repeat("f", 32) },
		func(o *ProcessObservation) { o.ObservedAt = time.Now().Add(-time.Minute) },
	} {
		o := ProcessObservation{Association: g.Association, ObservedAt: time.Now(), Ready: true}
		mutate(&o)
		b, _ := json.Marshal(o)
		w := httptest.NewRecorder()
		i.ServeHTTP(w, httptest.NewRequest("POST", "/payment/observation", strings.NewReader(string(b))))
		if w.Code != 409 || i.observation != nil {
			t.Fatal("stale or foreign process observation accepted", w.Code)
		}
	}
}

func TestInitializedPaymentStateMustSurviveReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payments.sqlite")
	if checkPaymentState(path, false) != nil {
		t.Fatal("fresh installation cannot create its first database")
	}
	if checkPaymentState(path, true) == nil {
		t.Fatal("missing durable state silently recreated")
	}
	if e := os.WriteFile(path, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if checkPaymentState(path, true) == nil {
		t.Fatal("empty durable state accepted")
	}
	if e := os.WriteFile(path, []byte("retained database"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := checkPaymentState(path, true); e != nil {
		t.Fatal(e)
	}
}
