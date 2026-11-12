package appreconciler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
	runner "github.com/livepeer/golang-runner"
)

var routeID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type Registration struct {
	InstanceID, WithdrawalID, PodUID string
	AppIndex                         int
	Registered                       bool
	WithdrawnAt                      time.Time
	Options                          runner.AppOptions
}
type OwnerRequest struct {
	Epoch    string
	Identity Identity
	Entries  []Registration
	Tracked  []Registration
}

type AppObservation = runner.HeartbeatAppStatus
type Observation struct {
	Request                                         runner.HeartbeatRequest
	Epoch, RunnerID, Credential, PreviousCredential string
	Sequence                                        uint64
	Accepted                                        bool
	Bootstrap                                       bool
	At                                              time.Time
	TTL                                             time.Duration
	Entries, Withdrawals                            []Registration
	Apps                                            []AppObservation
}
type OwnerFailure struct {
	Epoch, Reason  string
	Reset, Partial bool
}
type OwnerHooks struct {
	Observe     func(Observation) error
	Failure     func(OwnerFailure)
	Now         func() time.Time
	Eligibility func(Registration) (member, ready bool)
}
type Owner interface {
	Sync(context.Context, OwnerRequest, OwnerHooks) error
	Unregister(context.Context, Identity) error
	Accepted() Identity
	Close(context.Context) error
}

func privateURL(name string, port int) string {
	return "http://" + name + ".livepeer-apps.svc.cluster.local:" + formatPort(port)
}
func formatPort(n int) string { b, _ := json.Marshal(n); return string(b) }

// SDKOwner keeps protocol execution in the SDK. The mutex protects application
// membership, never an HTTP call or a join of SDK callbacks.
type SDKOwner struct {
	lifecycle       sync.Mutex
	mu              sync.Mutex
	base, bootstrap string
	client          *http.Client
	current         *runner.Runner
	request         OwnerRequest
	accepted        Identity
	hooks           OwnerHooks
	registrations   map[string]Registration
	lineage         string
	rejectedUntil   time.Time
	rejectedReason  string
	// Fatal must terminate the process. Production exits without joining the SDK.
	Fatal func(error)
}

func NewSDKOwner(base, bootstrap string, client *http.Client) (*SDKOwner, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Scheme != "http" && u.Scheme != "https") || bootstrap == "" {
		return nil, errors.New("node_configuration")
	}
	if client == nil {
		client = transport.HTTPClient()
	}
	return &SDKOwner{base: strings.TrimRight(base, "/"), bootstrap: bootstrap, client: client, registrations: map[string]Registration{}, Fatal: func(error) { os.Exit(1) }}, nil
}
func copyRequest(r OwnerRequest) OwnerRequest {
	r.Entries = append([]Registration{}, r.Entries...)
	r.Tracked = append([]Registration{}, r.Tracked...)
	return r
}
func (o *SDKOwner) Accepted() Identity {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.accepted
}
func (o *SDKOwner) Close(ctx context.Context) error {
	o.lifecycle.Lock()
	defer o.lifecycle.Unlock()
	o.mu.Lock()
	value := o.current
	o.current = nil
	o.mu.Unlock()
	if value != nil {
		return value.Close(ctx)
	}
	return nil
}
func (o *SDKOwner) Sync(ctx context.Context, r OwnerRequest, h OwnerHooks) error {
	o.lifecycle.Lock()
	defer o.lifecycle.Unlock()
	o.mu.Lock()
	o.request, o.hooks = copyRequest(r), h
	registrations := map[string]Registration{}
	for _, entries := range [][]Registration{r.Tracked, r.Entries} {
		for _, e := range entries {
			known, ok := registrations[e.Options.RunnerURL]
			if !ok {
				known = o.registrations[e.Options.RunnerURL]
			}
			if known.InstanceID == e.InstanceID && known.PodUID == e.PodUID {
				e.Registered = e.Registered || known.Registered
				if e.Options.ID == "" {
					e.Options.ID = known.Options.ID
				}
			}
			registrations[e.Options.RunnerURL] = e
		}
	}
	o.registrations = registrations
	if o.current != nil {
		err := o.setAppsLocked()
		o.mu.Unlock()
		return err
	}
	o.lineage = r.Identity.Credential
	initial := uint64(0)
	if r.Identity.Sequence != nil {
		initial = *r.Identity.Sequence + 1
	}
	apps := o.appsLocked()
	value, err := runner.New(runner.Options{OrchestratorURL: o.base, BootstrapSecret: o.bootstrap, HeartbeatSecret: r.Identity.Credential, RunnerID: r.Identity.RunnerID, Apps: apps, InitialSeq: initial, DisableUnregisterOnClose: true, HTTPClient: originGuard{o.base, o.client}, Timeout: 20 * time.Second, OnHeartbeat: o.heartbeat})
	if err != nil {
		o.mu.Unlock()
		return errors.New("sdk_configuration")
	}
	o.current = value
	o.mu.Unlock()
	// Start invokes OnHeartbeat synchronously; no callback-needed mutex is held.
	if err = value.Start(ctx); err != nil {
		_ = value.Close(context.WithoutCancel(ctx))
		o.mu.Lock()
		o.current = nil
		o.mu.Unlock()
		return err
	}
	return nil
}
func (o *SDKOwner) appsLocked() []runner.AppOptions {
	apps := []runner.AppOptions{}
	backoff := time.Now().Before(o.rejectedUntil)
	credential := o.request.Identity.Credential
	if o.current != nil {
		credential = o.current.HeartbeatSecret()
	}
	for _, entry := range o.request.Entries {
		e := entry
		known := o.registrations[e.Options.RunnerURL]
		if backoff && !known.Registered {
			continue
		}
		if known.Options.ID != "" {
			e.Options.ID = known.Options.ID
		}
		if e.WithdrawalID != "" {
			continue
		}
		member, ready := true, true
		if o.hooks.Eligibility != nil {
			member, ready = o.hooks.Eligibility(e)
		}
		if !member {
			continue
		}
		if credential == "" || !ready {
			e.Options.Status = "not-ready"
		}
		apps = append(apps, e.Options)
	}
	return apps
}
func (o *SDKOwner) setAppsLocked() error {
	if o.current == nil {
		return nil
	}
	return o.current.SetApps(o.appsLocked())
}

// Refresh applies independent probe/lifecycle downgrades without reconciling workloads.
func (o *SDKOwner) Refresh() { o.mu.Lock(); defer o.mu.Unlock(); _ = o.setAppsLocked() }
func (o *SDKOwner) heartbeat(event runner.HeartbeatEvent) {
	o.mu.Lock()
	h, r, lineage := o.hooks, copyRequest(o.request), o.lineage
	fail := func(reason string, reset bool) {
		if h.Failure != nil {
			h.Failure(OwnerFailure{Epoch: r.Epoch, Reason: reason, Reset: reset})
		}
	}
	if event.Err != nil {
		reason, reset := "node_unavailable", false
		var e *runner.HTTPError
		if errors.As(event.Err, &e) {
			reason = "node_request_failed"
			if e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden {
				reason = "registration_auth_failed"
			}
			if e.StatusCode == http.StatusUnauthorized {
				reset = true
			}
			if e.StatusCode == http.StatusServiceUnavailable && (strings.Contains(e.Body, "app capacity reached") || strings.Contains(e.Body, "runner capacity reached")) {
				reason = "resource_refused"
			}
		}
		membershipRejected := e != nil && (e.StatusCode == http.StatusBadRequest || (e.StatusCode == http.StatusConflict && event.AcceptedSeq == nil) || reason == "resource_refused")
		if membershipRejected {
			o.rejectedUntil = time.Now().Add(30 * time.Second)
			o.rejectedReason = reason
		}
		fail(reason, reset)
		_ = o.setAppsLocked()
		o.mu.Unlock()
		return
	}
	resp := event.Response
	// The SDK validates response presence, app identities and request cardinality.
	if event.TTL <= 0 {
		fail("heartbeat_response", false)
		o.mu.Unlock()
		return
	}
	obs := Observation{Request: event.Request, Epoch: r.Epoch, RunnerID: resp.RunnerID, Credential: resp.HeartbeatSecret, PreviousCredential: lineage, Sequence: event.Request.Seq, Accepted: event.AcceptedSeq != nil, Bootstrap: event.Credential == o.bootstrap, At: event.At.UTC(), TTL: event.TTL, Apps: resp.Apps}
	if obs.Credential == "" {
		obs.Credential = event.Credential
	}
	for _, app := range resp.Apps {
		if !routeID.MatchString(app.ID) || contract.ReservedProxyID(app.ID) || app.SessionIDs == nil || (app.Status != "ready" && app.Status != "not-ready" && app.Status != "draining") {
			fail("heartbeat_apps", false)
			o.mu.Unlock()
			return
		}
	}
	submitted := map[string]bool{}
	for n, app := range event.Request.Apps {
		e, ok := o.registrations[app.RunnerURL]
		if !ok {
			fail("app_identity", false)
			o.mu.Unlock()
			return
		}
		e.Options = app.AppOptions
		e.Options.ID = resp.Apps[n].ID
		e.Registered = true
		submitted[e.Options.ID] = true
		obs.Entries = append(obs.Entries, e)
	}
	for _, e := range r.Tracked {
		if e.WithdrawalID != "" && !event.At.Before(e.WithdrawnAt) && !submitted[e.Options.ID] {
			obs.Withdrawals = append(obs.Withdrawals, e)
		}
	}
	o.mu.Unlock()
	if err := h.Observe(obs); err != nil && !errors.Is(err, ErrSuperseded) {
		o.Fatal(errors.New("identity_persistence_failed"))
		panic("fatal handler returned")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lineage = obs.Credential
	for _, e := range obs.Entries {
		current := o.registrations[e.Options.RunnerURL]
		if current.InstanceID == e.InstanceID {
			current.Options.ID = e.Options.ID
			current.Registered = true
			o.registrations[e.Options.RunnerURL] = current
		}
	}
	o.accepted = Identity{RunnerID: resp.RunnerID, Credential: obs.Credential, Confirmed: obs.Accepted && !obs.Bootstrap, Sequence: event.AcceptedSeq}
	if time.Now().Before(o.rejectedUntil) && len(obs.Entries) < len(o.request.Entries) && h.Failure != nil {
		h.Failure(OwnerFailure{Epoch: r.Epoch, Reason: o.rejectedReason, Partial: true})
	}
	_ = o.setAppsLocked()
}
func (o *SDKOwner) Unregister(ctx context.Context, id Identity) error {
	o.lifecycle.Lock()
	defer o.lifecycle.Unlock()
	credential := id.Credential
	if id.RunnerID == "" {
		// An absent owner still needs Node's normal unregister acknowledgement:
		// a restarted Node may retain winners awaiting durable handoff.
		id.RunnerID = randomID()
	}
	if credential == "" {
		// A lost bootstrap response leaves an unknown issued credential. Retain
		// identity on 401 until Node expires it, then accept 404. Never Start.
		credential = o.bootstrap
	}
	retirement, err := runner.New(runner.Options{OrchestratorURL: o.base, BootstrapSecret: o.bootstrap, HeartbeatSecret: credential, RunnerID: id.RunnerID, Apps: []runner.AppOptions{}, HTTPClient: originGuard{o.base, o.client}})
	if err != nil {
		return err
	}
	if err := retirement.Close(ctx); err != nil {
		return err
	}
	o.mu.Lock()
	o.accepted = Identity{}
	o.registrations = map[string]Registration{}
	o.mu.Unlock()
	return nil
}

// originGuard only validates origins before the SDK applies a response and starts
// O2R. It returns unchanged bytes; all protocol mutation belongs to the SDK.
type originGuard struct {
	base   string
	client *http.Client
}

func (g originGuard) Do(req *http.Request) (*http.Response, error) {
	base, _ := url.Parse(g.base)
	if req.URL.Scheme != base.Scheme || req.URL.Host != base.Host {
		return nil, errors.New("sdk_control_origin")
	}
	resp, err := g.client.Do(req)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 || req.URL.Path != strings.TrimRight(base.Path, "/")+"/runners/heartbeat" {
		return resp, err
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	resp.Body.Close()
	if err != nil || len(data) > 2<<20 {
		return nil, errors.New("heartbeat_response")
	}
	var value runner.HeartbeatResponse
	if json.Unmarshal(data, &value) != nil {
		return nil, errors.New("heartbeat_response")
	}
	if value.Orchestrator != "" && strings.TrimRight(value.Orchestrator, "/") != g.base {
		return nil, errors.New("sdk_control_origin")
	}
	if value.O2R != nil {
		u, err := url.Parse(value.O2R.URL)
		if err != nil || u.Scheme != base.Scheme || u.Host != base.Host || u.User != nil || u.Fragment != "" {
			return nil, errors.New("o2r_origin")
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	return resp, nil
}
