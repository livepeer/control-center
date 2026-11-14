package appreconciler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/internal/testutil"
)

func TestProbesHonorThresholdAndOneSuccessRecovery(t *testing.T) {
	var code atomic.Int64
	code.Store(200)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(int(code.Load())) }))
	defer server.Close()
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
	now := time.Now()
	poll := func(want bool) {
		t.Helper()
		p.Poll(t.Context(), instances, view, now)
		deadline := time.Now().Add(time.Second)
		for len(p.results) == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if got := p.Poll(t.Context(), instances, view, now)["i"]; got != want {
			t.Fatalf("ready=%v want=%v", got, want)
		}
		now = now.Add(10 * time.Second)
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
	if p.Poll(context.Background(), instances, view, now)["i"] {
		t.Fatal("health crossed Pod UID")
	}
	if p.Started("i", "replacement") {
		t.Fatal("startup proof crossed Pod UID")
	}
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
