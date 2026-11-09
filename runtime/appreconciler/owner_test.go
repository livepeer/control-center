package appreconciler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/internal/testutil"
	"github.com/livepeer/control-center/runtime/transport"
)

func TestSDKOwnerPersistsBeforeConfirmationAndKeepsExactOptions(t *testing.T) {
	var mu sync.Mutex
	persisted := false
	var sequence uint64
	var calls int
	var submitted []map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/runners/owner/unregister" {
			w.Write([]byte("{}"))
			return
		}
		var body struct {
			Sequence uint64                       `json:"mutation_sequence"`
			Apps     []map[string]json.RawMessage `json:"apps"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid request")
		}
		calls++
		submitted = body.Apps
		auth := r.Header.Get("Authorization")
		if auth != "bootstrap" && (!persisted || auth != "issued") {
			t.Error("confirmed before persistence")
		}
		apps := []map[string]any{}
		for _, a := range body.Apps {
			var id, status string
			json.Unmarshal(a["id"], &id)
			json.Unmarshal(a["status"], &status)
			if id == "" {
				id = "assigned"
			}
			apps = append(apps, map[string]any{"id": id, "status": status, "session_ids": []string{}})
		}
		credential := ""
		if auth == "bootstrap" {
			credential = "issued"
		}
		json.NewEncoder(w).Encode(map[string]any{"runner_id": "owner", "heartbeat_secret": credential, "heartbeat_interval": "10ms", "heartbeat_ttl": "30s", "mutation_sequence": body.Sequence, "capabilities": Capabilities{true, true, true}, "apps": apps})
	}))
	defer server.Close()
	o, err := NewSDKOwner(server.URL, "bootstrap", transport.HTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close(context.Background())
	set := testutil.Assignment(t)
	i := &Instance{ID: "one", Name: "immutable-instance", Definition: set.Entries[0].Revision.Definition}
	i.Definition.Runner.Mode = "single-shot"
	i.Definition.Price.Amount = "0.0000000000000000001"
	options, err := AppOptions(i, false)
	if err != nil {
		t.Fatal(err)
	}
	r := OwnerRequest{Epoch: "epoch", Entries: []Registration{{InstanceID: i.ID, Options: options}}}
	r.Hash = RequestHash(r)
	observations := make(chan Observation, 64)
	h := OwnerHooks{
		Reserve: func(string) (uint64, error) { mu.Lock(); defer mu.Unlock(); sequence++; return sequence, nil },
		Observe: func(value Observation) error {
			mu.Lock()
			persisted = true
			mu.Unlock()
			observations <- value
			return nil
		},
	}
	if err = o.Sync(context.Background(), r, h); err != nil {
		t.Fatal(err)
	}
	first := <-observations
	if !first.Bootstrap || first.Credential != "issued" {
		t.Fatal("initial identity missing")
	}
	select {
	case second := <-observations:
		if second.Bootstrap || second.Sequence <= first.Sequence {
			t.Fatal("unsequenced confirmation")
		}
	case <-time.After(time.Second):
		t.Fatal("no SDK confirmation")
	}
	if err := o.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	accepted := o.Accepted()
	if accepted.Identity.Credential != "issued" || accepted.Entries[0].Options.ID != "assigned" {
		t.Fatal("lost issued identity", accepted.Identity)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls < 2 || string(submitted[0]["mode"]) != `"single-shot"` || string(submitted[0]["proxy"]) != "true" || string(submitted[0]["capacity"]) != "1" {
		t.Fatal("schema mapping", submitted)
	}
	var price map[string]json.RawMessage
	if json.Unmarshal(submitted[0]["price_info"], &price) != nil || string(price["price"]) != "0.0000000000000000001" {
		t.Fatal("decimal price lost", price)
	}
}

func TestCancellationCapturesDurableTargetAndCommitsBeforeNextMutation(t *testing.T) {
	c, _, _, _, _, now := fixtureController(t)
	c.Journal.Update(func(s *State) error {
		s.Identity = Identity{RunnerID: "owner", Credential: "issued", Confirmed: true}
		s.OwnerHash, s.OwnerEpoch = "current", "epoch"
		s.MutationSequence, s.AcceptedSequence = 7, 7
		s.Instances["target"] = &Instance{ID: "target", AppID: "app", PodUID: "uid", WithdrawalID: "withdrawal", Phase: "removed", Forced: true}
		return nil
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/runners/owner/apps/app/cancel" || r.Header.Get("Authorization") != "issued" {
			t.Error("used stale owner identity/target")
		}
		var body struct {
			Sequence uint64 `json:"mutation_sequence"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(map[string]any{"runner_id": "owner", "mutation_sequence": body.Sequence, "app": map[string]any{"id": "app", "status": "draining", "session_ids": []string{}}})
	}))
	defer server.Close()
	o, err := NewSDKOwner(server.URL, "bootstrap", transport.HTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	o.caps = Capabilities{true, true, true}
	// Cancellation must work even when the target is absent from accepted entries.
	o.accepted = OwnerRequest{Hash: "old", Identity: Identity{RunnerID: "stale", Credential: "stale"}}
	observed, release := make(chan struct{}), make(chan struct{})
	var captured Observation
	h := c.hooks()
	h.Observe = func(value Observation) error {
		captured = value
		err := c.observe(value)
		close(observed)
		<-release
		return err
	}
	done := make(chan error, 1)
	go func() { done <- o.Cancel(t.Context(), "target", h) }()
	<-observed
	next := make(chan struct{})
	go func() { o.mutations.Lock(); close(next); o.mutations.Unlock() }()
	select {
	case <-next:
		t.Fatal("mutation escaped before cancellation observation committed")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-next
	if !c.empty(c.Journal.View().Instances["target"], *now) || c.Journal.View().AcceptedSequence != 8 {
		t.Fatal("lost cancellation proof for an omitted target")
	}
	c.Journal.Update(func(s *State) error { s.AcceptedSequence = 9; return nil })
	if err := c.observe(captured); !errors.Is(err, ErrSuperseded) {
		t.Fatal("older cancellation regressed accepted observation", err)
	}
}

func TestSDKLiveSafetyWithdrawalAndBackgroundPersistenceFailure(t *testing.T) {
	var allow, fail atomic.Bool
	allow.Store(true)
	var requests atomic.Int64
	observations := make(chan Observation, 128)
	failures := make(chan OwnerFailure, 128)
	cached := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var body struct {
			Sequence uint64                       `json:"mutation_sequence"`
			Apps     []map[string]json.RawMessage `json:"apps"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid heartbeat")
		}
		var status string
		json.Unmarshal(body.Apps[0]["status"], &status)
		var sessions []string
		json.Unmarshal(body.Apps[0]["session_ids"], &sessions)
		if len(sessions) == 1 && sessions[0] == "cache-session" {
			select {
			case cached <- struct{}{}:
			default:
			}
		}
		if status == "not-ready" && (len(sessions) != 1 || sessions[0] != "cache-session") {
			t.Error("readiness overlay dropped SDK work fields")
		}
		json.NewEncoder(w).Encode(map[string]any{"runner_id": "owner", "heartbeat_interval": "10ms", "heartbeat_ttl": "30s", "mutation_sequence": body.Sequence, "capabilities": Capabilities{true, true, true}, "apps": []map[string]any{{"id": "app", "status": status, "session_ids": []string{"node-owned-work"}}}})
	}))
	defer server.Close()
	o, _ := NewSDKOwner(server.URL, "bootstrap", transport.HTTPClient())
	defer o.Close(context.Background())
	o.caps = Capabilities{true, true, true}
	set := testutil.Assignment(t)
	options, _ := AppOptions(&Instance{Name: "one", AppID: "app", Definition: set.Entries[0].Revision.Definition}, true)
	r := OwnerRequest{Epoch: "epoch", Hash: "hash", Identity: Identity{RunnerID: "owner", Credential: "issued", Confirmed: true}, Entries: []Registration{{InstanceID: "i", Options: options}}}
	var sequence uint64
	h := OwnerHooks{Reserve: func(string) (uint64, error) { sequence++; return sequence, nil }, PermitReady: func(Registration) bool { return allow.Load() }, Observe: func(o Observation) error {
		if fail.Load() {
			return errors.New("private_persistence_error")
		}
		observations <- o
		return nil
	}, Failure: func(f OwnerFailure) { failures <- f }}
	if err := o.Sync(t.Context(), r, h); err != nil {
		t.Fatal(err)
	}
	<-observations
	o.lifecycle.Lock()
	o.current.HandleO2RMessage(map[string]any{"event": "reserved", "app_id": "app", "session": "cache-session"})
	o.lifecycle.Unlock()
	select {
	case <-cached:
	case <-time.After(time.Second):
		t.Fatal("SDK did not carry its O2R cache")
	}
	allow.Store(false)
	deadline := time.After(time.Second)
	withdrawn := false
	for !withdrawn {
		select {
		case value := <-observations:
			withdrawn = value.Entries[0].Options.Status == "not-ready"
			if len(value.Apps[0].SessionIDs) != 1 {
				t.Fatal("lost authoritative work")
			}
		case <-deadline:
			t.Fatal("blocked main reconciliation kept live SDK ready")
		}
	}
	fail.Store(true)
	select {
	case <-failures:
	case <-time.After(time.Second):
		t.Fatal("no persistence failure notification")
	}
	count := requests.Load()
	time.Sleep(50 * time.Millisecond)
	if requests.Load() != count {
		t.Fatal("background loop sent after persistence failure")
	}
}
func TestSDKOwnerRejectsAutomaticBootstrapAndTerminatesOnPersistenceFailure(t *testing.T) {
	for _, failPersistence := range []bool{false, true} {
		t.Run(map[bool]string{false: "unauthorized", true: "persistence"}[failPersistence], func(t *testing.T) {
			var mu sync.Mutex
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				calls++
				n := calls
				mu.Unlock()
				if r.Header.Get("Authorization") == "bootstrap" {
					t.Error("automatic bootstrap fallback")
				}
				if !failPersistence {
					w.WriteHeader(401)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"runner_id": "owner", "heartbeat_interval": "5ms", "heartbeat_ttl": "30s", "capabilities": Capabilities{true, true, true}, "mutation_sequence": n, "apps": []map[string]any{{"id": "app", "status": "not-ready", "session_ids": []string{}}}})
			}))
			defer server.Close()
			o, _ := NewSDKOwner(server.URL, "bootstrap", transport.HTTPClient())
			defer o.Close(context.Background())
			set := testutil.Assignment(t)
			options, _ := AppOptions(&Instance{Name: "one", AppID: "app", Definition: set.Entries[0].Revision.Definition}, false)
			r := OwnerRequest{Epoch: "epoch", Hash: "hash", Identity: Identity{RunnerID: "owner", Credential: "issued"}, Entries: []Registration{{InstanceID: "i", Options: options}}}
			h := OwnerHooks{Reserve: func(string) (uint64, error) { return 1, nil }, Observe: func(Observation) error { return errors.New("disk_failed_with_private_details") }}
			if err := o.Sync(context.Background(), r, h); err == nil {
				t.Fatal("accepted failure")
			}
			time.Sleep(30 * time.Millisecond)
			mu.Lock()
			defer mu.Unlock()
			if calls != 1 {
				t.Fatal("SDK continued after terminal failure", calls)
			}
		})
	}
}

type reviewRoundTripper func(*http.Request) (*http.Response, error)

func (f reviewRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRegressionRestartedOrderedOwnerSendsSequencedHeartbeat(t *testing.T) {
	var submitted uint64
	client := transport.HTTPClient()
	client.Transport = reviewRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "latest-issued" {
			t.Error("reconstruction ignored durable credential after stop/join")
		}
		var body struct {
			Sequence uint64 `json:"mutation_sequence"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		submitted = body.Sequence
		w := httptest.NewRecorder()
		w.WriteHeader(http.StatusConflict)
		return w.Result(), nil
	})
	owner, _ := NewSDKOwner("http://node.invalid", "bootstrap", client)
	defer owner.Close(context.Background())
	set := testutil.Assignment(t)
	options, _ := AppOptions(&Instance{Name: "one", AppID: "app", Definition: set.Entries[0].Revision.Definition}, false)
	request := OwnerRequest{Epoch: "epoch", Hash: "hash", Identity: Identity{RunnerID: "owner", Credential: "issued", Confirmed: true}, Entries: []Registration{{InstanceID: "i", Options: options}}}
	hooks := OwnerHooks{Identity: func() Identity { return Identity{RunnerID: "owner", Credential: "latest-issued"} }, Reserve: func(string) (uint64, error) { return 8, nil }, Observe: func(Observation) error { return nil }}
	_ = owner.Sync(context.Background(), request, hooks)
	if submitted != 8 {
		t.Fatalf("restored ordered credential sent sequence=%d instead of reserved sequence=8", submitted)
	}
}

func TestSDKOwnerClassifiesAuthenticationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("private-credential-sentinel"))
	}))
	defer server.Close()
	o, err := NewSDKOwner(server.URL, "bootstrap", transport.HTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close(context.Background())
	set := testutil.Assignment(t)
	options, _ := AppOptions(&Instance{Name: "one", AppID: "app", Definition: set.Entries[0].Revision.Definition}, false)
	identity := Identity{RunnerID: "owner", Credential: "issued"}
	request := OwnerRequest{Epoch: "epoch", Hash: "hash", Identity: identity, Entries: []Registration{{InstanceID: "i", Options: options}}}
	var failure OwnerFailure
	hooks := OwnerHooks{Identity: func() Identity { return identity }, Reserve: func(string) (uint64, error) { return 1, nil }, Observe: func(Observation) error { return nil }, Failure: func(f OwnerFailure) { failure = f }}
	if err := o.Sync(t.Context(), request, hooks); err == nil || !transport.IsStatus(err, 401) || failure.Reason != "registration_auth_failed" || !failure.Reset {
		t.Fatal("authentication failure lost its classification", err, failure)
	}
}
