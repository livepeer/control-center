package appreconciler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/livepeer/control-center/runtime/internal/testutil"
)

func TestCanceledProbeDoesNotBlockReadinessRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		definition := testutil.Assignment(t).Entries[0].Revision.Definition
		instances := map[string]*Instance{"i": {ID: "i", Name: "one", Definition: definition}}
		view := View{Pods: map[string]Pod{"one": {UID: "uid", Phase: "Running"}}, Endpoints: map[string]map[string]bool{"one": {"uid": true}}}
		p := NewProbes()
		p.results = make(chan probeResult, 1)
		started := make(chan struct{})
		calls := 0
		p.Client.Transport = regressionTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				close(started)
				<-r.Context().Done()
				return nil, r.Context().Err()
			}
			return httptest.NewRecorder().Result(), nil
		})
		ctx, cancel := context.WithCancel(t.Context())
		p.Poll(ctx, instances, view, time.Now())
		<-started
		// A completed old probe occupies the result queue when this tick ends.
		p.results <- probeResult{id: "old-pod"}
		cancel()
		synctest.Wait()
		time.Sleep(10 * time.Second)
		p.Poll(t.Context(), instances, view, time.Now())
		synctest.Wait()
		if !p.Poll(t.Context(), instances, view, time.Now())["i"] {
			t.Fatal("canceled probe prevented a later successful readiness check")
		}
	})
}

func TestProbeRefreshOnlyOnReadinessChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		p := NewProbes()
		refreshes := 0
		p.OnChange = func() { refreshes++ }
		p.Client.Transport = regressionTransport(func(*http.Request) (*http.Response, error) {
			return httptest.NewRecorder().Result(), nil
		})
		instance := &Instance{ID: "i", Name: "one", Definition: testutil.Assignment(t).Entries[0].Revision.Definition}
		instances := map[string]*Instance{"i": instance}
		view := View{Pods: map[string]Pod{"one": {UID: "uid", Phase: "Running"}}, Endpoints: map[string]map[string]bool{"one": {"uid": true}}}
		p.Configure(instances, view)
		go p.Run(ctx)
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if !p.Ready("i", "uid") || refreshes != 1 {
			t.Fatalf("successful readiness should refresh once, got %d", refreshes)
		}
		// Reconciliation can consume a readiness change before the independent loop.
		p.Configure(instances, View{})
		p.Poll(ctx, instances, View{}, time.Now())
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if p.Ready("i", "uid") || refreshes != 2 {
			t.Fatalf("endpoint loss should refresh once, got %d", refreshes)
		}
	})
}

func TestProbesHonorThresholdAndOneSuccessRecovery(t *testing.T) {
	var code atomic.Int64
	code.Store(200)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(int(code.Load())) }))
	defer server.Close()
	synctest.Test(t, func(t *testing.T) {
		set := testutil.Assignment(t)
		d := set.Entries[0].Revision.Definition
		d.Health.Readiness.Interval = "1s"
		d.Health.Readiness.Timeout = "1s"
		d.Health.Readiness.FailureThreshold = 2
		i := &Instance{ID: "i", Name: "one", Definition: d}
		instances := map[string]*Instance{"i": i}
		view := View{Pods: map[string]Pod{"one": {UID: "uid", Phase: "Running"}}, Endpoints: map[string]map[string]bool{"one": {"uid": true}}}
		p := NewProbes()
		p.Address = func(*Instance) string { return server.URL }
		p.Client.Transport = &http.Transport{DisableKeepAlives: true}
		poll := func(want bool) {
			t.Helper()
			p.Poll(t.Context(), instances, view, time.Now())
			synctest.Wait()
			if got := p.Poll(t.Context(), instances, view, time.Now())["i"]; got != want {
				t.Fatalf("ready=%v want=%v", got, want)
			}
			time.Sleep(10 * time.Second)
		}
		poll(true)
		code.Store(503)
		poll(true)
		poll(false)
		if !p.Started("i", "uid") {
			t.Fatal("readiness loss erased successful startup")
		}
		code.Store(200)
		poll(true)
		view.Pods["one"] = Pod{UID: "replacement", Phase: "Running"}
		view.Endpoints["one"] = map[string]bool{"replacement": true}
		if p.Poll(t.Context(), instances, view, time.Now())["i"] {
			t.Fatal("health crossed Pod UID")
		}
		if p.Started("i", "replacement") {
			t.Fatal("startup proof crossed Pod UID")
		}
	})
}
func TestBudgetIncludesRetainedInstancesAndRejectsMalformedCapacity(t *testing.T) {
	set := testutil.Assignment(t)
	d := set.Entries[0].Revision.Definition
	one := resources(d.Resources.Limits)
	budget := Resources{one.CPU, one.Memory, one.Storage}
	instances := map[string]*Instance{"old": {Definition: d, Phase: "retired"}}
	if fits(instances, d, budget) {
		t.Fatal("retained resources treated as free")
	}
	instances["old"].Phase = "removed"
	instances["old"].RegistrationGone = true
	if !fits(instances, d, budget) {
		t.Fatal("absent resources not reusable")
	}
	for raw, want := range map[string]int64{"8": 8000, "750m": 750, "1000000000n": 1000} {
		if got, err := quantity(raw, true); err != nil || got != want {
			t.Fatal(raw, got, err)
		}
	}
	if _, err := quantity("unknown", false); err == nil {
		t.Fatal("unknown node capacity accepted")
	}
}
