package appreconciler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/transport"
	runner "github.com/livepeer/golang-runner"
)

type nativeNode struct {
	rejectEndpoint              string
	rejectAuth                  bool
	failStart                   int
	issued                      string
	mu                          sync.Mutex
	requests                    []runner.HeartbeatRequest
	apps                        map[string]runner.HeartbeatAppStatus
	busy                        bool
	unregisters, failUnregister int
	catchup                     bool
}

func (n *nativeNode) serve(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if r.URL.Path == "/runners/owner/unregister" {
		n.unregisters++
		if n.failUnregister > 0 {
			n.failUnregister--
			http.Error(w, "lost", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(404)
		return
	}
	var req runner.HeartbeatRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad", 400)
		return
	}
	n.requests = append(n.requests, req)
	for _, app := range req.Apps {
		if app.RunnerURL == n.rejectEndpoint {
			http.Error(w, "invalid addition", 400)
			return
		}
	}
	if n.rejectAuth && r.Header.Get("Authorization") != "bootstrap" {
		n.rejectAuth = false
		http.Error(w, "expired owner", http.StatusUnauthorized)
		return
	}
	if n.failStart > 0 {
		n.failStart--
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if n.catchup && r.Header.Get("Authorization") == "issued" {
		n.catchup = false
		w.WriteHeader(409)
		fmt.Fprint(w, `{"seq":7}`)
		return
	}
	apps := []runner.HeartbeatAppStatus{}
	seen := map[string]bool{}
	for j, a := range req.Apps {
		id := a.ID
		if id == "" {
			id = fmt.Sprintf("assigned-%d", j)
		}
		app := runner.HeartbeatAppStatus{ID: id, Status: a.Status, SessionIDs: []string{}}
		apps = append(apps, app)
		seen[id] = true
		n.apps[id] = app
	}
	for id, a := range n.apps {
		if !seen[id] {
			if n.busy {
				a.Status = "draining"
				a.SessionIDs = []string{"work"}
				apps = append(apps, a)
			} else {
				delete(n.apps, id)
			}
		}
	}
	resp := runner.HeartbeatResponse{RunnerID: "owner", Apps: apps, HeartbeatInterval: "5ms", HeartbeatTTL: "30s"}
	if r.Header.Get("Authorization") == "bootstrap" {
		resp.HeartbeatSecret = "issued"
		if n.issued != "" {
			resp.HeartbeatSecret = n.issued
		}
	} else {
		resp.Seq = new(req.Seq)
	}
	json.NewEncoder(w).Encode(resp)
}
func nativeFixture(t *testing.T) (*SDKOwner, *nativeNode, OwnerRequest, OwnerHooks, chan Observation) {
	t.Helper()
	n := &nativeNode{apps: map[string]runner.HeartbeatAppStatus{}}
	srv := httptest.NewServer(http.HandlerFunc(n.serve))
	t.Cleanup(srv.Close)
	o, err := NewSDKOwner(srv.URL, "bootstrap", transport.HTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close(context.Background()) })
	e := Registration{InstanceID: "one", PodUID: "pod", Options: runner.AppOptions{App: "app", RunnerURL: "http://immutable.invalid:8080", Status: "not-ready", Mode: "persistent"}}
	req := OwnerRequest{Identity: Identity{RunnerID: "owner"}, Entries: []Registration{e}, Tracked: []Registration{e}}
	events := make(chan Observation, 1024)
	hooks := OwnerHooks{Observe: func(o Observation) error { events <- o; return nil }}
	return o, n, req, hooks, events
}
func awaitObservation(t *testing.T, ch <-chan Observation, p func(Observation) bool) Observation {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case o := <-ch:
			if p(o) {
				return o
			}
		case <-timer.C:
			t.Fatal("missing native heartbeat observation")
			return Observation{}
		}
	}
}
func TestNativeOwnerSequenceZeroMembershipAndRetirement(t *testing.T) {
	o, n, r, h, ch := nativeFixture(t)
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal(err)
	}
	first := awaitObservation(t, ch, func(o Observation) bool { return o.Accepted })
	if first.Request.Apps[0].ID != "assigned-0" || first.Sequence != 0 || first.Credential != "issued" || first.Entries[0].Options.ID == "" {
		t.Fatal("lost zero sequence or assigned identity", first)
	}
	n.mu.Lock()
	n.busy = true
	n.mu.Unlock()
	e := first.Entries[0]
	e.WithdrawalID = "withdrawal"
	e.WithdrawnAt = time.Now()
	r.Entries = []Registration{}
	r.Tracked = []Registration{e}
	r.Identity = o.Accepted()
	current := o.current
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal(err)
	}
	if o.current != current {
		t.Fatal("membership update replaced loop")
	}
	draining := awaitObservation(t, ch, func(o Observation) bool {
		return len(o.Withdrawals) > 0 && len(o.Apps) > 0 && o.Apps[0].Status == "draining"
	})
	if len(draining.Entries) != 0 {
		t.Fatal("retained apps copied into submitted membership")
	}
	if err := o.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	count := n.unregisters
	n.mu.Unlock()
	if count != 0 {
		t.Fatal("routine shutdown unregistered owner")
	}
	// Restore final empty membership with the issued identity.
	r.Identity = o.Accepted()
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	n.busy = false
	n.failUnregister = 1
	n.mu.Unlock()
	awaitObservation(t, ch, func(o Observation) bool { return o.Accepted && len(o.Apps) == 0 })
	if err := o.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := o.Unregister(t.Context(), r.Identity); err == nil {
		t.Fatal("failed unregister was not retained")
	}
	if err := o.Unregister(t.Context(), r.Identity); err != nil {
		t.Fatal(err)
	}
}
func TestNativeOwnerCatchupAndIndependentHealth(t *testing.T) {
	o, n, r, h, ch := nativeFixture(t)
	n.catchup = true
	var ready atomic.Bool
	ready.Store(true)
	r.Entries[0].Options.Status = "ready"
	h.Eligibility = func(Registration) (bool, bool) { return true, ready.Load() }
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal(err)
	}
	first := awaitObservation(t, ch, func(o Observation) bool { return o.Accepted && o.Sequence == 8 })
	ready.Store(false)
	o.Refresh()
	awaitObservation(t, ch, func(o Observation) bool { return len(o.Apps) > 0 && o.Apps[0].Status == "not-ready" })
	// A health refresh cannot put an omitted app back into membership.
	r.Tracked = first.Entries
	r.Tracked[0].WithdrawalID = "withdrawal"
	r.Tracked[0].WithdrawnAt = time.Now()
	r.Entries = []Registration{}
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal(err)
	}
	ready.Store(true)
	o.Refresh()
	awaitObservation(t, ch, func(o Observation) bool { return o.Accepted && len(o.Apps) == 0 })
}
func TestNativeOwnerInFlightMembershipKeepsAssignedIDs(t *testing.T) {
	o, n, r, h, ch := nativeFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	client := *o.client
	client.Transport = reviewRoundTripper(func(req *http.Request) (*http.Response, error) {
		once.Do(func() { close(entered); <-release })
		return http.DefaultTransport.RoundTrip(req)
	})
	o.client = &client
	result := make(chan error, 1)
	go func() { result <- o.Sync(context.Background(), r, h) }()
	<-entered
	// Simulate an independent health update while Start is in flight.
	o.mu.Lock()
	o.request.Entries[0].Options.Status = "not-ready"
	_ = o.setAppsLocked()
	o.mu.Unlock()
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	awaitObservation(t, ch, func(o Observation) bool { return o.Accepted })
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.requests) < 2 || n.requests[1].Apps[0].ID != "assigned-0" {
		t.Fatal("assigned ID lost across SetApps", n.requests)
	}
}

type reviewRoundTripper func(*http.Request) (*http.Response, error)

func (f reviewRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestNativeOriginGuardRejectsBeforeO2R(t *testing.T) {
	var calls atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(runner.HeartbeatResponse{RunnerID: "owner", Apps: []runner.HeartbeatAppStatus{}, HeartbeatSecret: "issued", HeartbeatTTL: "30s", O2R: &runner.Channel{URL: evil.URL}})
	}))
	defer srv.Close()
	for _, prefix := range []string{"", "/prefix"} {
		t.Run(prefix, func(t *testing.T) {
			o, _ := NewSDKOwner(srv.URL+prefix, "bootstrap", nil)
			defer o.Close(context.Background())
			err := o.Sync(t.Context(), OwnerRequest{Identity: Identity{RunnerID: "owner"}}, OwnerHooks{Observe: func(Observation) error { return nil }})
			if err == nil || calls.Load() != 0 {
				t.Fatal("unsafe O2R response applied", err, calls.Load())
			}
		})
	}
}
func TestNativePersistenceFailureExitsWithoutCloseDeadlock(t *testing.T) {
	if os.Getenv("LPCC_FATAL_CHILD") == "1" {
		o, _, r, h, _ := nativeFixture(t)
		h.Observe = func(Observation) error { return errors.New("disk failed") }
		_ = o.Sync(t.Context(), r, h)
		os.Exit(9)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativePersistenceFailureExitsWithoutCloseDeadlock$")
	cmd.Env = append(os.Environ(), "LPCC_FATAL_CHILD=1")
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || ctx.Err() != nil {
		t.Fatal("persistence failure did not exit promptly", err)
	}
}

func TestNativeAuthenticationRecoveryDowngradesBeforeBootstrapRetry(t *testing.T) {
	o, n, r, h, ch := nativeFixture(t)
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal(err)
	}
	awaitObservation(t, ch, func(o Observation) bool { return o.Accepted })
	r.Entries[0].Options.Status = "ready"
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal(err)
	}
	awaitObservation(t, ch, func(o Observation) bool { return o.Accepted && o.Apps[0].Status == "ready" })
	current := o.current
	n.mu.Lock()
	n.rejectAuth = true
	n.issued = "rotated"
	n.mu.Unlock()
	recovery := awaitObservation(t, ch, func(o Observation) bool { return o.Bootstrap && o.Credential == "rotated" })
	if recovery.Entries[0].Options.Status != "not-ready" || recovery.PreviousCredential != "issued" {
		t.Fatal("bootstrap retried stale readiness or lost credential lineage", recovery)
	}
	confirmed := awaitObservation(t, ch, func(o Observation) bool { return o.Accepted && o.Credential == "rotated" })
	if confirmed.Sequence != 0 || o.current != current {
		t.Fatal("credential recovery replaced loop or lost sequence-zero confirmation")
	}
}

func TestNativeBootstrapCannotUseStaleReadySync(t *testing.T) {
	o, _, r, h, ch := nativeFixture(t)
	r.Identity.Credential = "issued"
	r.Entries[0].Options.ID = "app"
	r.Entries[0].Options.Status = "ready"
	h.Eligibility = func(Registration) (bool, bool) { return true, true }
	// After a 401 the SDK clears its credential before retrying bootstrap.
	// An intervening Sync may still carry the old confirmed, ready snapshot.
	value, err := runner.New(runner.Options{OrchestratorURL: o.base, BootstrapSecret: o.bootstrap, RunnerID: "owner", DisableUnregisterOnClose: true, OnHeartbeat: o.heartbeat})
	if err != nil {
		t.Fatal(err)
	}
	o.current, o.lineage = value, "issued"
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal(err)
	}
	if err := value.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	bootstrap := awaitObservation(t, ch, func(o Observation) bool { return o.Bootstrap })
	if bootstrap.Request.Apps[0].Status != "not-ready" || bootstrap.PreviousCredential != "issued" {
		t.Fatal("stale Sync restored admission during bootstrap", bootstrap)
	}
}

func TestNativeFailedStartReconstructsRunner(t *testing.T) {
	o, n, r, h, ch := nativeFixture(t)
	n.failStart = 1
	if err := o.Sync(t.Context(), r, h); err == nil {
		t.Fatal("startup failure hidden")
	}
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal("could not retry failed Start with a new runner", err)
	}
	awaitObservation(t, ch, func(o Observation) bool { return o.Accepted })
}

func TestRejectedAdditionCannotBlockTerminalOmission(t *testing.T) {
	o, n, r, h, ch := nativeFixture(t)
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal(err)
	}
	first := awaitObservation(t, ch, func(o Observation) bool { return o.Accepted })
	old := first.Entries[0]
	old.WithdrawalID = "withdrawal"
	old.WithdrawnAt = time.Now()
	next := old
	next.InstanceID = "next"
	next.Registered = false
	next.WithdrawalID = ""
	next.WithdrawnAt = time.Time{}
	next.Options.ID = "r-next-0"
	next.Options.RunnerURL = "http://rejected.invalid:8080"
	n.mu.Lock()
	n.rejectEndpoint = next.Options.RunnerURL
	n.mu.Unlock()
	r.Entries = []Registration{next}
	r.Tracked = []Registration{old, next}
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal(err)
	}
	observation := awaitObservation(t, ch, func(o Observation) bool { return o.Accepted && len(o.Apps) == 0 })
	if len(observation.Withdrawals) != 1 || observation.Withdrawals[0].InstanceID != old.InstanceID {
		t.Fatal("rejected addition masked withdrawal context", observation)
	}
}

func TestNativeStaleSyncPreservesAssignedID(t *testing.T) {
	o, _, r, h, ch := nativeFixture(t)
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal(err)
	}
	first := awaitObservation(t, ch, func(o Observation) bool { return o.Accepted })
	// r represents a controller snapshot captured before the callback saved its ID.
	at := time.Now()
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal(err)
	}
	next := awaitObservation(t, ch, func(o Observation) bool { return o.Accepted && o.At.After(at) })
	if next.Request.Apps[0].ID != first.Entries[0].Options.ID {
		t.Fatalf("stale Sync erased assigned ID: next submitted %q, want %q", next.Request.Apps[0].ID, first.Entries[0].Options.ID)
	}
}

func TestNativeCredentiallessRetirementRequiresNodeAbsence(t *testing.T) {
	var expired atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/runners/owner/unregister" || r.Header.Get("Authorization") != "bootstrap" {
			t.Errorf("unexpected retirement request: %s", r.URL.Path)
		}
		if !expired.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	o, err := NewSDKOwner(srv.URL, "bootstrap", nil)
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{RunnerID: "owner", Retiring: true}
	if err := o.Unregister(t.Context(), id); err == nil {
		t.Fatal("unknown issued credential was treated as successful retirement")
	}
	expired.Store(true)
	if err := o.Unregister(t.Context(), id); err != nil {
		t.Fatal("could not retry retirement after Node expiry", err)
	}
}

func TestNativeRestoredMembershipRejectionPreservesSibling(t *testing.T) {
	for _, rejection := range []struct {
		name   string
		status int
		body   string
	}{
		{"bad-request", http.StatusBadRequest, "invalid addition"},
		{"ownership-conflict", http.StatusConflict, "app id belongs to another runner"},
		{"capacity", http.StatusServiceUnavailable, "app capacity reached"},
	} {
		t.Run(rejection.name, func(t *testing.T) {
			oldOwner, node, r, hooks, events := nativeFixture(t)
			controller, _, _, _, _, _ := fixtureController(t)
			controller.Now = nil
			if err := controller.Journal.Update(func(s *State) error {
				s.Identity = r.Identity
				s.Instances["one"] = &Instance{ID: "one", PodUID: "pod"}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			observe := hooks.Observe
			hooks.Observe = func(o Observation) error {
				if err := controller.observe(o); err != nil {
					return err
				}
				return observe(o)
			}
			hooks.Failure = controller.failed
			if err := oldOwner.Sync(t.Context(), r, hooks); err != nil {
				t.Fatal(err)
			}
			first := awaitObservation(t, events, func(o Observation) bool { return o.Accepted })
			if err := oldOwner.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			saved := oldOwner.Accepted()
			known := first.Entries[0]
			added := known
			added.InstanceID, added.PodUID = "new-instance", "new-pod"
			added.Registered = false
			added.Options.ID = "r-new-instance-0"
			added.Options.RunnerURL = "http://rejected.invalid:8080"
			node.mu.Lock()
			node.rejectEndpoint = added.Options.RunnerURL
			node.mu.Unlock()
			client := &http.Client{Transport: reviewRoundTripper(func(req *http.Request) (*http.Response, error) {
				resp, err := http.DefaultTransport.RoundTrip(req)
				if err == nil && resp.StatusCode == http.StatusBadRequest {
					resp.Body.Close()
					w := httptest.NewRecorder()
					w.WriteHeader(rejection.status)
					fmt.Fprint(w, rejection.body)
					return w.Result(), nil
				}
				return resp, err
			})}
			restored, err := NewSDKOwner(oldOwner.base, "bootstrap", client)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close(context.Background())
			r.Identity, r.Entries, r.Tracked = saved, []Registration{known, added}, []Registration{known, added}
			at := time.Now()
			if err := restored.Sync(t.Context(), r, hooks); err == nil {
				t.Fatal("expected membership rejection")
			}
			if restored.Accepted().Credential != "" {
				t.Fatal("restored IDs implied a fresh accepted snapshot")
			}
			if err := restored.Sync(t.Context(), r, hooks); err != nil {
				t.Fatal(err)
			}
			obs := awaitObservation(t, events, func(o Observation) bool { return o.Accepted && o.At.After(at) })
			if len(obs.Request.Apps) != 1 || obs.Request.Apps[0].ID != known.Options.ID {
				t.Fatalf("rejected addition erased restored sibling: %+v", obs.Request.Apps)
			}
			// Observe runs before the partial-rejection diagnostic. Wait for both,
			// so the test cannot pass before a later callback clears the proof.
			kept := false
			for end := time.Now().Add(3 * time.Second); time.Now().Before(end); {
				controller.mu.Lock()
				p, exists := controller.proofs[known.InstanceID]
				kept = exists && p.App.ID == known.Options.ID && controller.fault != ""
				controller.mu.Unlock()
				if kept {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if !kept {
				t.Fatal("partial rejection discarded the fresh sibling observation")
			}
			if err := restored.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			controller.failed(OwnerFailure{RunnerID: r.Identity.RunnerID, Reason: "node_unavailable"})
			if len(controller.proofs) != 0 {
				t.Fatal("ordinary failure retained readiness proof")
			}
		})
	}
}
