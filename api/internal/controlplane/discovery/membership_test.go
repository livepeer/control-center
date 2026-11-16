package discovery

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedBackendMembershipRequiresEveryApp(t *testing.T) {
	source := testSource("one", "https://source.example")
	b := &simulatedDiscoveryBackend{sources: []Source{source}}
	f, _ := testFleet(t, b)
	var body atomic.Value
	body.Store("[]")
	f.transport.base = discoveryRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body.Load().(string)))}, nil
	})
	reconcileFleet(t, f)
	now := time.Now().UTC()
	queries := []MembershipQuery{{"shared", "https://orch.example/apps/first/session", "first", "v1"}, {"shared", "https://orch.example/apps/second/session", "second", "v1"}}
	for _, present := range [][]int{{0, 1}, {0}, {1}, {}} {
		runners := []map[string]string{}
		for _, n := range present {
			q := queries[n]
			runners = append(runners, map[string]string{"url": q.Endpoint, "app": q.App, "version": q.Version, "observed_at": now.Add(time.Duration(n-1) * time.Second).Format(time.RFC3339Nano)})
		}
		raw, err := json.Marshal([]any{map[string]any{"address": source.ServiceURL, "runners": runners}})
		if err != nil {
			t.Fatal(err)
		}
		body.Store(string(raw))
		f.collector.Refresh(t.Context(), false)
		got := f.Memberships(source.NodeID, queries)["shared"]
		want := "absent"
		if len(present) == 2 {
			want = "present"
			if got.ObservedAt == nil || !got.ObservedAt.Equal(now.Add(-time.Second)) {
				t.Fatal("membership did not retain oldest app evidence", got)
			}
		}
		if got.State != want {
			t.Fatalf("published %v: got %s, want %s", present, got.State, want)
		}
	}
}

func TestMembershipFreshnessEmptyAndRecovery(t *testing.T) {
	source := testSource("one", "https://source.example")
	b := &simulatedDiscoveryBackend{sources: []Source{source}}
	f, _ := testFleet(t, b)
	var body atomic.Value
	body.Store(`[{"address":"https://orch.example","runners":[{"url":"https://orch.example/apps/a/session","app":"test","version":"v1","observed_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}]}]`)
	f.transport.base = discoveryRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body.Load().(string)))}, nil
	})
	reconcileFleet(t, f)
	validBody := body.Load()
	body.Store("<html>initial collection failed</html>")
	f.collector.Refresh(t.Context(), false)
	missing := f.Membership(source.NodeID, "https://orch.example/apps/a/session", "test", "v1")
	if missing.State != "uninitialized" || missing.QueriedAt != nil || missing.ExpiresAt != nil || missing.ObservedAt != nil || f.Status().Sources[0].State != "uninitialized" {
		t.Fatal("initial failure fabricated retained inventory", missing)
	}
	body.Store(validBody)
	f.collector.Refresh(t.Context(), false)
	lookup := func() Membership {
		return f.Membership(source.NodeID, "https://orch.example/apps/a/session", "test", "v1")
	}
	batch := f.Memberships(source.NodeID, []MembershipQuery{{InstanceID: "one", Endpoint: "https://orch.example/apps/a/session", App: "test", Version: "v1"}, {InstanceID: "two", Endpoint: "https://orch.example/apps/a/session", App: "test", Version: "v2"}})
	if batch["one"].State != "present" || batch["two"].State != "absent" {
		t.Fatal("batch mixed instance evidence", batch)
	}
	first := lookup()
	if first.State != "present" {
		t.Fatal("did not confirm exact publication", first)
	}
	if other := f.Membership("another-node", "https://orch.example/apps/a/session", "test", "v1"); other.State != "excluded" {
		t.Fatal("cross-enrollment membership", other)
	}
	if wrong := f.Membership(source.NodeID, "https://orch.example/apps/a/session", "test", "v2"); wrong.State != "absent" {
		t.Fatal("version mismatch claimed discovery", wrong)
	}
	b.sources[0].Generation = 2
	b.sources[0].VerifiedGeneration = 2
	body.Store("<html>not discovery</html>")
	reconcileFleet(t, f)
	f.collector.Refresh(t.Context(), false)
	retained := lookup()
	if retained.State != "present" || !retained.QueriedAt.Equal(*first.QueriedAt) {
		t.Fatal("relabeled retained membership after rotation", retained)
	}
	body.Store("[]")
	f.collector.Refresh(t.Context(), false)
	empty := lookup()
	if empty.State != "absent" || empty.QueriedAt.Equal(*first.QueriedAt) {
		t.Fatal("valid empty snapshot was not authoritative", empty)
	}
	raw, _ := json.Marshal(empty)
	for _, secret := range []string{"secret-sentinel", "new-secret", source.URL} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("unsafe membership projection")
		}
	}
	f.collector.MaxFailures = 1
	body.Store("<html>evict inventory</html>")
	f.collector.Refresh(t.Context(), false)
	evicted := lookup()
	status := f.Status().Sources[0]
	if evicted.State != "uninitialized" || evicted.QueriedAt != nil || evicted.ExpiresAt != nil || evicted.ObservedAt != nil || status.State != "evicted" || status.LastSuccess == nil {
		t.Fatal("eviction fabricated retained inventory or lost source history", evicted, status)
	}
	body.Store(validBody)
	f.collector.Refresh(t.Context(), false)
	if recovered := lookup(); recovered.State != "present" {
		t.Fatal("evicted source did not recover", recovered)
	}
}

func TestMembershipMatchesPublicDuplicateWinner(t *testing.T) {
	source := testSource("one", "https://source.example")
	b := &simulatedDiscoveryBackend{sources: []Source{source}}
	f, _ := testFleet(t, b)
	now := time.Now().UTC()
	endpoint := "https://orch.example/apps/a/session"
	record := func(version string, at time.Time) map[string]string {
		return map[string]string{"url": endpoint, "app": "test", "version": version, "observed_at": at.Format(time.RFC3339Nano)}
	}
	body, _ := json.Marshal([]any{map[string]any{"address": "https://orch.example", "runners": []any{record("v2", now), record("v1", now.Add(-time.Hour)), record("v2", now.Add(-time.Hour))}}})
	f.transport.base = discoveryRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})
	reconcileFleet(t, f)
	f.collector.Refresh(t.Context(), false)
	w := httptest.NewRecorder()
	f.ServeHTTP(w, httptest.NewRequest("GET", "/discovery", nil))
	if strings.Contains(w.Body.String(), `"v1"`) || !strings.Contains(w.Body.String(), `"v2"`) {
		t.Fatal("unexpected public winner", w.Body.String())
	}
	if got := f.Membership(source.NodeID, endpoint, "test", "v1"); got.State != "absent" {
		t.Fatal("shadowed version claimed publication", got)
	}
	if got := f.Membership(source.NodeID, endpoint, "test", "v2"); got.State != "present" || !got.ObservedAt.Equal(now) || !got.ExpiresAt.After(now) {
		t.Fatal("winning record lost freshness", got)
	}
}
