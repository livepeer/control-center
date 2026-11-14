package consumer

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
)

func TestOnchainReadinessAndHandoffAreIndependent(t *testing.T) {
	i, m, l := nodeFixture(t)
	g, e := i.fetch(t.Context(), l)
	if e != nil {
		t.Fatal(e)
	}
	body := "# TYPE livepeer_redemption_transitions_total counter\n"
	var metrics atomic.Value
	metrics.Store(body)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, metrics.Load().(string))
	}))
	defer server.Close()
	old := http.DefaultClient
	defer func() { http.DefaultClient = old }()
	http.DefaultClient = server.Client()
	base := http.DefaultClient.Transport.(*http.Transport)
	base.DisableKeepAlives = true
	base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	synctest.Test(t, func(t *testing.T) {
		if i.Observe(t.Context(), m, true, true, l.PodUID).Applied {
			t.Fatal("Pod UID alone renewed an earlier process grant")
		}
		processProof(t, i, g.Association, true)
		o := i.Observe(t.Context(), m, true, true, l.PodUID)
		if !o.Ready || o.Handoff != "unverified" {
			t.Fatal(o)
		}
		metrics.Store(body + "livepeer_redemption_transitions_total{component=\"orchestrator\",event=\"retryable\"} 1\n")
		o = i.Observe(t.Context(), m, true, true, l.PodUID)
		if !o.Ready || o.Handoff != "degraded" {
			t.Fatal(o)
		}
		time.Sleep(3 * time.Minute)
		processProof(t, i, g.Association, true)
		if o := i.Observe(t.Context(), m, true, true, l.PodUID); !o.Ready || o.Handoff != "unverified" {
			t.Fatal("repeated metrics renewed old failed handoff evidence")
		}
		metrics.Store(metrics.Load().(string) + "livepeer_redemption_transitions_total{component=\"orchestrator\",event=\"acknowledged\"} 1\n")
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
		time.Sleep(31 * time.Second)
		if i.Observe(t.Context(), m, true, true, l.PodUID).Applied {
			t.Fatal("expired process evidence remained current")
		}
	})
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
