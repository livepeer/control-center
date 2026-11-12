package consumer

import (
	"github.com/livepeer/control-center/runtime/contract"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOnchainReadinessAndHandoffAreIndependent(t *testing.T) {
	i, m, l := nodeFixture(t)
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
	body := "# TYPE livepeer_redemption_transitions_total counter\n"
	metrics := body
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(metrics)), Header: make(http.Header)}, nil
	})}
	o := i.Observe(t.Context(), m, true, true, l.PodUID)
	if !o.Ready || o.Handoff != "unverified" {
		t.Fatal(o)
	}
	metrics = body + "livepeer_redemption_transitions_total{component=\"orchestrator\",event=\"retryable\"} 1\n"
	o = i.Observe(t.Context(), m, true, true, l.PodUID)
	if !o.Ready || o.Handoff != "degraded" {
		t.Fatal(o)
	}
	i.handoffAt = time.Now().Add(-3 * time.Minute)
	if i.Observe(t.Context(), m, true, true, l.PodUID).Handoff != "unverified" {
		t.Fatal("repeated metrics renewed old failed handoff evidence")
	}
	metrics += "livepeer_redemption_transitions_total{component=\"orchestrator\",event=\"acknowledged\"} 1\n"
	o = i.Observe(t.Context(), m, true, true, l.PodUID)
	if o.Handoff != "healthy" {
		t.Fatal(o)
	}
	restarted := &Integration{Profile: Orchestrator, Kube: i.Kube, Desired: i.Desired, StateFile: i.StateFile}
	restarted.Restore()
	processProof(t, restarted, g.Association, true)
	if restarted.Observe(t.Context(), m, true, true, l.PodUID).Handoff != "unverified" {
		t.Fatal("management restart renewed old handoff evidence")
	}

	if i.Observe(t.Context(), m, true, true, "replacement").Applied {
		t.Fatal("borrowed replaced pod evidence")
	}
	i.observation.ObservedAt = time.Now().Add(-31 * time.Second)
	if i.Observe(t.Context(), m, true, true, l.PodUID).Applied {
		t.Fatal("expired process evidence remained current")
	}
}

func processProof(t *testing.T, i *Integration, a Association, ready bool) {
	t.Helper()
	w := operation(t, i, "tunnel/observation", Observation{Association: a, ObservedAt: time.Now(), Ready: ready})
	if w.Code != 200 {
		t.Fatal("process proof rejected", w.Code)
	}
}

func TestObservationCannotBorrowAnotherLaunchOrRenewOldEvidence(t *testing.T) {
	i, _, l := nodeFixture(t)
	g, e := i.fetch(t.Context(), l)
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Observation){
		func(o *Observation) { o.ProcessID = strings.Repeat("e", 64) },
		func(o *Observation) { o.LaunchID = strings.Repeat("f", 32) },
		func(o *Observation) { o.ObservedAt = time.Now().Add(-time.Minute) },
	} {
		o := Observation{Association: g.Association, ObservedAt: time.Now(), Ready: true}
		mutate(&o)
		w := operation(t, i, "tunnel/observation", o)
		if w.Code != 409 || i.observation != nil {
			t.Fatal("stale or foreign process observation accepted", w.Code)
		}
	}
}

func TestInitializedOnchainStateMustSurviveReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "onchain.sqlite")
	if checkOnchainState(path, false) != nil {
		t.Fatal("fresh installation cannot create its first database")
	}
	if checkOnchainState(path, true) == nil {
		t.Fatal("missing durable state silently recreated")
	}
	if e := os.WriteFile(path, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if checkOnchainState(path, true) == nil {
		t.Fatal("empty durable state accepted")
	}
	if e := os.WriteFile(path, []byte("retained database"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := checkOnchainState(path, true); e != nil {
		t.Fatal(e)
	}
}

func nodeFixture(t *testing.T) (*Integration, contract.Metadata, Launch) {
	f := fixture(t, Orchestrator)
	return f.i, f.m, Launch{PodName: "tunnel-pod", PodUID: "pod-uid", LaunchID: strings.Repeat("b", 32), ProcessID: strings.Repeat("c", 64)}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
