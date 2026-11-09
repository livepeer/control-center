package discovery

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMembershipBindsSuccessfulSnapshotToSourceVersion(t *testing.T) {
	source := testSource("one", "https://source.example")
	b := &simulatedDiscoveryBackend{sources: []Source{source}, credentials: map[string]Credential{source.CredentialRef: {"old-client", "secret-sentinel"}}}
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
	missing := f.Membership(source.NodeID, source.Epoch, "https://orch.example/apps/a/session", "test", "v1")
	if missing.State != "uninitialized" || missing.QueriedAt != nil || missing.ExpiresAt != nil || missing.ObservedAt != nil || missing.ProvenanceCurrent || f.Status().Sources[0].State != "uninitialized" {
		t.Fatal("initial failure fabricated retained inventory", missing)
	}
	body.Store(validBody)
	f.collector.Refresh(t.Context(), false)
	lookup := func() Membership {
		return f.Membership(source.NodeID, source.Epoch, "https://orch.example/apps/a/session", "test", "v1")
	}
	batch := f.Memberships(source.NodeID, source.Epoch, []MembershipQuery{{InstanceID: "one", Endpoint: "https://orch.example/apps/a/session", App: "test", Version: "v1"}, {InstanceID: "two", Endpoint: "https://orch.example/apps/a/session", App: "test", Version: "v2"}})
	if batch["one"].State != "present" || batch["two"].State != "absent" {
		t.Fatal("batch mixed instance evidence", batch)
	}
	first := lookup()
	if first.State != "present" || !first.ProvenanceCurrent {
		t.Fatal("did not confirm exact publication", first)
	}
	if other := f.Membership(source.NodeID, "another-epoch", "https://orch.example/apps/a/session", "test", "v1"); other.State != "excluded" {
		t.Fatal("cross-enrollment membership", other)
	}
	if wrong := f.Membership(source.NodeID, source.Epoch, "https://orch.example/apps/a/session", "test", "v2"); wrong.State != "absent" {
		t.Fatal("version mismatch claimed discovery", wrong)
	}
	b.sources[0].Generation = 2
	b.sources[0].VerifiedGeneration = 2
	b.sources[0].CredentialVersion = 2
	b.sources[0].CredentialRef = "new-ref"
	b.credentials["new-ref"] = Credential{"new-client", "new-secret"}
	body.Store("<html>not discovery</html>")
	reconcileFleet(t, f)
	retained := lookup()
	if retained.State != "unverified_provenance" || retained.ProvenanceCurrent || !retained.QueriedAt.Equal(*first.QueriedAt) {
		t.Fatal("relabeled retained membership after rotation", retained)
	}
	body.Store("[]")
	f.collector.Refresh(t.Context(), false)
	empty := lookup()
	if empty.State != "absent" || !empty.ProvenanceCurrent || empty.QueriedAt.Equal(*first.QueriedAt) {
		t.Fatal("valid empty snapshot was not authoritative", empty)
	}
	raw, _ := json.Marshal(empty)
	for _, secret := range []string{"secret-sentinel", "new-secret", source.URL, source.CredentialRef} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("unsafe membership projection")
		}
	}
	f.collector.MaxFailures = 1
	body.Store("<html>evict inventory</html>")
	f.collector.Refresh(t.Context(), false)
	evicted := lookup()
	status := f.Status().Sources[0]
	if evicted.State != "uninitialized" || evicted.QueriedAt != nil || evicted.ExpiresAt != nil || evicted.ObservedAt != nil || evicted.ProvenanceCurrent || status.State != "evicted" || status.LastSuccess == nil {
		t.Fatal("eviction fabricated retained inventory or lost source history", evicted, status)
	}
	body.Store(validBody)
	f.collector.Refresh(t.Context(), false)
	if recovered := lookup(); recovered.State != "present" || !recovered.ProvenanceCurrent {
		t.Fatal("evicted source did not recover", recovered)
	}
}

func TestMembershipMatchesPublicDuplicateWinner(t *testing.T) {
	source := testSource("one", "https://source.example")
	b := &simulatedDiscoveryBackend{sources: []Source{source}, credentials: map[string]Credential{source.CredentialRef: {"client", "secret"}}}
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
	if got := f.Membership(source.NodeID, source.Epoch, endpoint, "test", "v1"); got.State != "absent" {
		t.Fatal("shadowed version claimed publication", got)
	}
	if got := f.Membership(source.NodeID, source.Epoch, endpoint, "test", "v2"); got.State != "present" || !got.ObservedAt.Equal(now) || !got.ExpiresAt.After(now) {
		t.Fatal("winning record lost freshness", got)
	}
}

func TestMembershipProvenanceDoesNotRequireReadBeforeFailedRefresh(t *testing.T) {
	for _, failure := range []string{"timeout", "http_error", "invalid_200"} {
		t.Run(failure, func(t *testing.T) {
			source := testSource("one", "https://source.example")
			b := &simulatedDiscoveryBackend{sources: []Source{source}, credentials: map[string]Credential{source.CredentialRef: {"client", "secret"}}}
			f, _ := testFleet(t, b)
			body := `[{"address":"https://orch.example","runners":[{"url":"https://orch.example/apps/a/session","app":"test","version":"v1","observed_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}]}]`
			status := 200
			var failureErr error
			f.transport.base = discoveryRoundTripFunc(func(*http.Request) (*http.Response, error) {
				if failureErr != nil {
					return nil, failureErr
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			reconcileFleet(t, f)
			f.collector.Refresh(t.Context(), false)
			at := f.collector.Snapshots()[0].QueriedAt
			if failure == "timeout" {
				failureErr = context.DeadlineExceeded
			} else if failure == "http_error" {
				status = 503
			} else {
				body = "<html>invalid inventory</html>"
			}
			f.collector.Refresh(t.Context(), false)
			got := f.Membership(source.NodeID, source.Epoch, "https://orch.example/apps/a/session", "test", "v1")
			if got.State != "present" || !got.ProvenanceCurrent || !got.QueriedAt.Equal(at) {
				t.Fatal("failed refresh erased known source provenance before first status read", got)
			}
			b.sources[0].Generation, b.sources[0].VerifiedGeneration, b.sources[0].CredentialVersion = 2, 2, 2
			b.sources[0].CredentialRef = "replacement"
			b.credentials["replacement"] = Credential{"new-client", "new-secret"}
			reconcileFleet(t, f)
			if got := f.Membership(source.NodeID, source.Epoch, "https://orch.example/apps/a/session", "test", "v1"); got.State != "unverified_provenance" || got.ProvenanceCurrent {
				t.Fatal("rotation borrowed predecessor provenance", got)
			}
		})
	}
}
