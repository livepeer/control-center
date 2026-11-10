package appreconciler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
			Sequence uint64                       `json:"seq"`
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
			if status != "not-ready" || body.Sequence == 0 {
				t.Error("initial or confirming snapshot was ready or unsequenced")
			}
			if id == "" {
				id = "assigned"
			}
			apps = append(apps, map[string]any{"id": id, "status": status, "session_ids": []string{}})
		}
		credential := ""
		if auth == "bootstrap" {
			credential = "issued"
		}
		result := map[string]any{"runner_id": "owner", "heartbeat_secret": credential, "heartbeat_interval": "10ms", "heartbeat_ttl": "30s", "apps": apps}
		if auth != "bootstrap" {
			result["seq"] = body.Sequence
		}
		json.NewEncoder(w).Encode(result)
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
			if len(value.Apps) != 1 || value.Apps[0].ID != "assigned" || (value.Bootstrap && value.Credential != "issued") {
				t.Error("issued identity missing before persistence", value)
			}
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

func TestSDKOwnerRestoresNonReadyBeforeReadmission(t *testing.T) {
	c, _, cluster, _, _, _ := fixtureController(t)
	registerApps(t, c, cluster)
	before := c.Journal.View()
	ready := map[string]bool{}
	c.Probes = NewProbes()
	known := map[string]bool{}
	for id, i := range before.Instances {
		ready[id], known[i.AppID] = true, true
		c.Probes.values[id] = &health{uid: i.PodUID, ready: true}
	}
	calls := 0
	sequence := before.AcceptedSequence
	client := transport.HTTPClient()
	client.Transport = reviewRoundTripper(func(r *http.Request) (*http.Response, error) {
		var body struct {
			RunnerID string                        `json:"runner_id"`
			Sequence uint64                        `json:"seq"`
			Apps     []struct{ ID, Status string } `json:"apps"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, err
		}
		calls++
		want := "not-ready"
		if calls > 1 {
			want = "ready"
		}
		if r.Header.Get("Authorization") != before.Identity.Credential || body.RunnerID != before.Identity.RunnerID || body.Sequence <= sequence || len(body.Apps) != len(known) {
			t.Error("restored snapshot lost durable identity, sequence or membership", body)
		}
		sequence = body.Sequence
		apps := []map[string]any{}
		for _, app := range body.Apps {
			if !known[app.ID] || app.Status != want {
				t.Error("incorrect restored app identity or admission state", app, want)
			}
			apps = append(apps, map[string]any{"id": app.ID, "status": app.Status, "session_ids": []string{}})
		}
		w := httptest.NewRecorder()
		// Scoped responses retain the issued credential and do not return it again.
		json.NewEncoder(w).Encode(map[string]any{"runner_id": body.RunnerID, "seq": body.Sequence, "heartbeat_interval": "1h", "heartbeat_ttl": "30s", "apps": apps})
		return w.Result(), nil
	})
	owner, err := NewSDKOwner("http://node.invalid", "bootstrap", client)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	c.Owner, c.proofs = owner, nil
	for range 2 {
		if err := c.syncOwner(t.Context(), c.Journal.View(), ready, cluster.view); err != nil {
			t.Fatal(err)
		}
		if owner.Accepted().Identity != before.Identity || c.Journal.View().Identity != before.Identity {
			t.Fatal("accepted scoped identity did not retain the durable issued credential")
		}
	}
	if calls != 2 {
		t.Fatal("restart did not submit non-ready then ready snapshots", calls)
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
			Sequence uint64                       `json:"seq"`
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
		json.NewEncoder(w).Encode(map[string]any{"runner_id": "owner", "heartbeat_interval": "10ms", "heartbeat_ttl": "30s", "seq": body.Sequence, "apps": []map[string]any{{"id": "app", "status": status, "session_ids": []string{"node-owned-work"}}}})
	}))
	defer server.Close()
	o, _ := NewSDKOwner(server.URL, "bootstrap", transport.HTTPClient())
	defer o.Close(context.Background())
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
	for _, testCase := range []struct{ name, credential string }{{"unauthorized", "issued"}, {"persistence", "issued"}, {"bootstrap_persistence", ""}} {
		t.Run(testCase.name, func(t *testing.T) {
			var mu sync.Mutex
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				calls++
				n := calls
				mu.Unlock()
				wantAuth := testCase.credential
				if wantAuth == "" {
					wantAuth = "bootstrap"
				}
				if r.Header.Get("Authorization") != wantAuth {
					t.Error("automatic bootstrap fallback or premature confirmation")
				}
				if testCase.name == "unauthorized" {
					w.WriteHeader(401)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"runner_id": "owner", "heartbeat_secret": "issued", "heartbeat_interval": "5ms", "heartbeat_ttl": "30s", "seq": n, "apps": []map[string]any{{"id": "app", "status": "not-ready", "session_ids": []string{}}}})
			}))
			defer server.Close()
			o, _ := NewSDKOwner(server.URL, "bootstrap", transport.HTTPClient())
			defer o.Close(context.Background())
			set := testutil.Assignment(t)
			options, _ := AppOptions(&Instance{Name: "one", AppID: "app", Definition: set.Entries[0].Revision.Definition}, false)
			r := OwnerRequest{Epoch: "epoch", Hash: "hash", Identity: Identity{RunnerID: "owner", Credential: testCase.credential}, Entries: []Registration{{InstanceID: "i", Options: options}}}
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
			if o.Accepted().Identity.Credential != "" {
				t.Fatal("accepted an unpersisted identity")
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
			Sequence uint64 `json:"seq"`
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

func TestSDKOwnerValidatesAcceptedSequence(t *testing.T) {
	set := testutil.Assignment(t)
	options, err := AppOptions(&Instance{Name: "one", AppID: "app", Definition: set.Entries[0].Revision.Definition}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []string{"matching", "missing", "zero", "mismatched"} {
		t.Run(testCase, func(t *testing.T) {
			client := transport.HTTPClient()
			client.Transport = reviewRoundTripper(func(r *http.Request) (*http.Response, error) {
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					return nil, err
				}
				if r.URL.Path != "/runners/heartbeat" || string(body["seq"]) != "8" || r.Header.Get("Authorization") != "issued" {
					t.Error("wrong heartbeat endpoint, reserved sequence or credential", r.URL.Path, body)
				}
				result := map[string]any{"runner_id": "owner", "seq": 8, "heartbeat_ttl": "30s", "apps": []map[string]any{{"id": "app", "status": "not-ready", "session_ids": []string{}}}}
				switch testCase {
				case "missing":
					delete(result, "seq")
				case "zero":
					result["seq"] = 0
				case "mismatched":
					result["seq"] = 7
				}
				w := httptest.NewRecorder()
				json.NewEncoder(w).Encode(result)
				return w.Result(), nil
			})
			owner, err := NewSDKOwner("http://node.invalid", "bootstrap", client)
			if err != nil {
				t.Fatal(err)
			}
			var observed *Observation
			identity := Identity{RunnerID: "owner", Credential: "issued"}
			hooks := OwnerHooks{Reserve: func(string) (uint64, error) { return 8, nil }, Observe: func(value Observation) error { observed = &value; return nil }}
			h := &heartbeatClient{owner: owner, request: OwnerRequest{Identity: identity, Entries: []Registration{{Options: options}}}, hooks: hooks}
			body, _ := json.Marshal(map[string]any{"runner_id": "owner", "apps": []any{options}})
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://node.invalid/runners/heartbeat", strings.NewReader(string(body)))
			req.Header.Set("Authorization", identity.Credential)
			resp, err := h.Do(req)
			if resp != nil {
				resp.Body.Close()
			}
			if testCase == "matching" {
				if err != nil || observed == nil || observed.Sequence != 8 {
					t.Fatal("valid acknowledgment rejected", err, observed)
				}
			} else if err == nil || err.Error() != "heartbeat_response" || observed != nil {
				t.Fatal("invalid acknowledgment became an observation or lost its protocol error", err, observed)
			}
		})
	}
}

func TestSDKOwnerRejectsReadyBootstrapBeforeSubmission(t *testing.T) {
	client := transport.HTTPClient()
	client.Transport = reviewRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("submitted a ready bootstrap snapshot")
		return nil, errors.New("unexpected_request")
	})
	o, _ := NewSDKOwner("http://node.invalid", "bootstrap", client)
	set := testutil.Assignment(t)
	options, err := AppOptions(&Instance{Name: "one", Definition: set.Entries[0].Revision.Definition}, true)
	if err != nil {
		t.Fatal(err)
	}
	r := OwnerRequest{Epoch: "epoch", Hash: "hash", Entries: []Registration{{Options: options}}}
	h := OwnerHooks{Reserve: func(string) (uint64, error) { return 1, nil }, Observe: func(Observation) error {
		t.Error("observed a rejected bootstrap snapshot")
		return nil
	}}
	if err := o.Sync(t.Context(), r, h); err == nil || err.Error() != "sdk_request" {
		t.Fatal("ready bootstrap did not fail as a request error", err)
	}
}
