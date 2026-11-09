package appreconciler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
	runner "github.com/livepeer/golang-runner"
)

var routeID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type Capabilities struct {
	Confirmation bool `json:"registration_confirmation"`
	Ordered      bool `json:"ordered_mutations"`
	Cancellation bool `json:"app_cancellation"`
}

func (c Capabilities) AdmissionSafe() bool { return c.Confirmation && c.Ordered }

type Registration struct {
	InstanceID   string
	WithdrawalID string
	PodUID       string
	Options      runner.AppOptions
}
type OwnerRequest struct {
	Epoch, Hash string
	Identity    Identity
	Entries     []Registration
	Recover     bool
}

func RequestHash(r OwnerRequest) string {
	b, _ := json.Marshal(struct {
		RunnerID string
		Entries  []Registration
		Recover  bool
	}{r.Identity.RunnerID, r.Entries, r.Recover})
	return artifact.Digest(b)
}

type AppObservation struct {
	ID, Status string
	SessionIDs []string
}
type Observation struct {
	Epoch, Hash, RunnerID, Credential string
	PreviousCredential                string
	ReservedSequence                  uint64
	Sequence                          uint64
	Bootstrap                         bool
	At                                time.Time
	TTL                               time.Duration
	Capabilities                      Capabilities
	Entries                           []Registration
	Apps                              []AppObservation
	Partial                           bool
}
type OwnerFailure struct {
	Epoch, Hash string
	Reset       bool
	Reason      string
}
type OwnerHooks struct {
	Identity            func() Identity
	Reserve             func(string) (uint64, error)
	ReserveCancellation func(string) (Cancellation, error)
	Observe             func(Observation) error
	Failure             func(OwnerFailure)
	Now                 func() time.Time
	PermitReady         func(Registration) bool
}
type Owner interface {
	Capabilities() Capabilities
	Sync(context.Context, OwnerRequest, OwnerHooks) error
	Cancel(context.Context, string, OwnerHooks) error
	Unregister(context.Context, Identity) error
	Accepted() OwnerRequest
	Close(context.Context) error
}
type Cancellation struct {
	Epoch, Hash, InstanceID, AppID, WithdrawalID, PodUID string
	Identity                                             Identity
	Sequence                                             uint64
}

func AppOptions(i *Instance, ready bool) (runner.AppOptions, error) {
	if contract.ReservedProxyID(i.AppID) {
		return runner.AppOptions{}, errors.New("reserved_app_identity")
	}
	d := i.Definition
	price, err := runner.NewPriceInfo(d.Price.Amount, d.Price.Currency, d.Price.Unit)
	if err != nil {
		return runner.AppOptions{}, err
	}
	status := "not-ready"
	if ready {
		status = "ready"
	}
	if i.WithdrawalID != "" {
		status = "draining"
	}
	return runner.AppOptions{ID: i.AppID, App: d.Name, Version: d.AppVersion, RunnerURL: privateURL(i.Name, d.HTTP.Port), Mode: d.Runner.Mode, PriceInfo: price, Capacity: d.Instances.CapacityPerInstance, Status: status, Proxy: true}, nil
}
func privateURL(name string, port int) string {
	return "http://" + name + ".livepeer-apps.svc.cluster.local:" + formatPort(port)
}
func formatPort(n int) string { b, _ := json.Marshal(n); return string(b) }

// SDKOwner uses the SDK's HTTPClient extension; the SDK still owns heartbeat and O2R loops.
// The middleware supplies the narrow observation/order hooks tracked by golang-runner #7.
type SDKOwner struct {
	lifecycle       sync.Mutex
	mutations       sync.Mutex
	mu              sync.Mutex
	base, bootstrap string
	client          *http.Client
	current         *runner.Runner
	currentHash     string
	currentEpoch    string
	caps            Capabilities
	accepted        OwnerRequest
}

func NewSDKOwner(base, bootstrap string, client *http.Client) (*SDKOwner, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Scheme != "http" && u.Scheme != "https") || bootstrap == "" {
		return nil, errors.New("node_configuration")
	}
	if client == nil {
		client = transport.HTTPClient()
	}
	return &SDKOwner{base: strings.TrimRight(base, "/"), bootstrap: bootstrap, client: client}, nil
}
func (o *SDKOwner) Capabilities() Capabilities { o.mu.Lock(); defer o.mu.Unlock(); return o.caps }
func (o *SDKOwner) Accepted() OwnerRequest {
	o.mu.Lock()
	defer o.mu.Unlock()
	return copyRequest(o.accepted)
}
func copyRequest(r OwnerRequest) OwnerRequest {
	r.Entries = append([]Registration(nil), r.Entries...)
	return r
}
func (o *SDKOwner) Close(ctx context.Context) error {
	o.lifecycle.Lock()
	defer o.lifecycle.Unlock()
	return o.close(ctx)
}
func (o *SDKOwner) close(ctx context.Context) error {
	if o.current != nil {
		err := o.current.Close(ctx)
		o.current = nil
		o.currentHash = ""
		o.currentEpoch = ""
		return err
	}
	return nil
}
func (o *SDKOwner) Sync(ctx context.Context, r OwnerRequest, h OwnerHooks) error {
	o.lifecycle.Lock()
	defer o.lifecycle.Unlock()
	if o.current != nil && o.currentHash == r.Hash && o.currentEpoch == r.Epoch {
		return nil
	}
	if len(r.Entries) == 0 {
		return errors.New("empty_owner_requires_retirement")
	}
	if err := o.close(ctx); err != nil {
		return err
	}
	if h.Identity != nil {
		latest := h.Identity()
		if latest.RunnerID != r.Identity.RunnerID || latest.Retiring {
			return ErrSuperseded
		}
		r.Identity = latest
	}
	apps := make([]runner.AppOptions, len(r.Entries))
	for i, e := range r.Entries {
		apps[i] = e.Options
	}
	credential := r.Identity.Credential
	if r.Recover {
		credential = ""
	}
	mid := &heartbeatClient{owner: o, request: r, hooks: h, bootstrapAllowed: credential == "", credential: credential, lineage: r.Identity.Credential}
	value, err := runner.New(runner.Options{OrchestratorURL: o.base, BootstrapSecret: o.bootstrap, RunnerID: r.Identity.RunnerID, HeartbeatSecret: credential, Apps: apps, DisableUnregisterOnClose: true, HTTPClient: mid, Timeout: 20 * time.Second})
	if err != nil {
		return errors.New("sdk_configuration")
	}
	if err = value.Start(ctx); err != nil {
		_ = value.Close(context.WithoutCancel(ctx))
		return err
	}
	o.current = value
	o.currentHash = r.Hash
	o.currentEpoch = r.Epoch
	return nil
}

type wireApp struct {
	ID         string    `json:"id"`
	Status     string    `json:"status"`
	SessionIDs *[]string `json:"session_ids"`
}
type wireResponse struct {
	RunnerID     string       `json:"runner_id"`
	Credential   string       `json:"heartbeat_secret"`
	Orchestrator string       `json:"orchestrator"`
	TTL          string       `json:"heartbeat_ttl"`
	Sequence     uint64       `json:"mutation_sequence"`
	Capabilities Capabilities `json:"capabilities"`
	Apps         []wireApp    `json:"apps"`
	O2R          *struct {
		URL string `json:"url"`
	} `json:"o2r"`
}
type heartbeatClient struct {
	owner            *SDKOwner
	request          OwnerRequest
	hooks            OwnerHooks
	bootstrapAllowed bool
	credential       string
	lineage          string
	terminal         bool
}

func (h *heartbeatClient) stop() {
	h.terminal = true // Do holds the mutation lock; no later request may have side effects.
	// Close waits for the SDK heartbeat loop, so it must run outside its callback.
	go func() {
		h.owner.lifecycle.Lock()
		defer h.owner.lifecycle.Unlock()
		if h.owner.currentEpoch == h.request.Epoch {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			_ = h.owner.close(ctx)
		}
	}()
}

func (h *heartbeatClient) failure(reason string, reset bool) {
	if h.hooks.Failure != nil {
		h.hooks.Failure(OwnerFailure{Epoch: h.request.Epoch, Hash: h.request.Hash, Reset: reset, Reason: reason})
	}
}
func (h *heartbeatClient) Do(req *http.Request) (*http.Response, error) {
	o := h.owner
	o.mutations.Lock()
	defer o.mutations.Unlock()
	if h.terminal {
		return nil, errors.New("owner_stopped")
	}
	if req.URL.String() != o.base+"/runners/heartbeat" {
		return nil, errors.New("sdk_control_origin")
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, (2<<20)+1))
	req.Body.Close()
	if err != nil || len(raw) > 2<<20 {
		return nil, errors.New("sdk_request_size")
	}
	var body map[string]json.RawMessage
	var apps []runner.AppOptions
	if transport.Decode(raw, &body) != nil || transport.Decode(body["apps"], &apps) != nil || len(apps) != len(h.request.Entries) {
		return nil, errors.New("sdk_request")
	}
	bootstrap := req.Header.Get("Authorization") == o.bootstrap
	caps := o.Capabilities()
	changed := false
	var rawApps []map[string]json.RawMessage
	if transport.Decode(body["apps"], &rawApps) != nil {
		return nil, errors.New("sdk_request")
	}
	if bootstrap && !h.bootstrapAllowed {
		h.failure("registration_reset", true)
		return nil, errors.New("registration_reset")
	}
	reserved, err := h.hooks.Reserve(h.request.Hash)
	if err != nil {
		h.failure("mutation_reservation_failed", false)
		h.stop()
		return nil, errors.New("mutation_reservation_failed")
	}
	// Final safety eligibility is captured after reservation, so a withdrawal
	// cannot be followed by a stale ready payload with a newer sequence.
	for n, app := range apps {
		entry := h.request.Entries[n]
		entry.Options = app
		if app.Status == "ready" && h.hooks.PermitReady != nil && !h.hooks.PermitReady(entry) {
			apps[n].Status = "not-ready"
			rawApps[n]["status"], _ = json.Marshal("not-ready")
			app.Status = "not-ready"
			changed = true
		}
		if app.Status == "ready" && (bootstrap || !caps.AdmissionSafe()) {
			h.failure("dependency_pending", false)
			return nil, ErrDependency
		}
	}
	sequence := uint64(0)
	if caps.Ordered || !bootstrap {
		sequence = reserved
		body["mutation_sequence"], _ = json.Marshal(sequence)
		changed = true
	}
	if changed {
		body["apps"], _ = json.Marshal(rawApps)
		raw, err = json.Marshal(body)
		if err != nil {
			return nil, errors.New("sdk_request")
		}
	}
	request := req.Clone(req.Context())
	request.Body = io.NopCloser(bytes.NewReader(raw))
	request.ContentLength = int64(len(raw))
	request.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
	observedAt := time.Now().UTC()
	if h.hooks.Now != nil {
		observedAt = h.hooks.Now()
	}
	response, err := o.client.Do(request)
	if err != nil {
		h.failure("node_unavailable", false)
		return nil, errors.New("node_unavailable")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure struct {
			Error string `json:"error"`
		}
		body, _ := io.ReadAll(io.LimitReader(response.Body, 16385))
		response.Body.Close()
		if response.StatusCode == http.StatusServiceUnavailable && len(body) <= 16384 && transport.Decode(body, &failure) == nil && (failure.Error == "app capacity reached" || failure.Error == "runner capacity reached") {
			h.failure("resource_refused", false)
			return nil, ErrResourceRefused
		}
		reset := response.StatusCode == 401
		if reset {
			o.mu.Lock()
			o.caps = Capabilities{}
			o.mu.Unlock()
		}
		reason := "node_request_failed"
		if response.StatusCode == 401 || response.StatusCode == 403 {
			reason = "registration_auth_failed"
		}
		h.failure(reason, reset)
		// Returning a sanitized transport error also prevents the SDK's automatic 401 bootstrap retry.
		return nil, &transport.HTTPError{Status: response.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	response.Body.Close()
	if err != nil || len(data) > 2<<20 {
		h.failure("heartbeat_response", false)
		return nil, errors.New("heartbeat_response")
	}
	var wire wireResponse
	if transport.Decode(data, &wire) != nil || !routeID.MatchString(wire.RunnerID) || len(wire.Apps) < len(apps) || (h.request.Identity.RunnerID != "" && wire.RunnerID != h.request.Identity.RunnerID) || (wire.Orchestrator != "" && strings.TrimRight(wire.Orchestrator, "/") != o.base) || (bootstrap && wire.Credential == "") || (!bootstrap && (caps.Ordered || wire.Capabilities.Ordered) && wire.Sequence != sequence) {
		h.failure("heartbeat_response", false)
		return nil, errors.New("heartbeat_response")
	}
	ttl, err := time.ParseDuration(wire.TTL)
	if err != nil || ttl <= 0 {
		h.failure("heartbeat_ttl", false)
		return nil, errors.New("heartbeat_ttl")
	}
	if wire.O2R != nil {
		control, _ := url.Parse(o.base)
		channel, e := url.Parse(wire.O2R.URL)
		if e != nil || channel.Scheme != control.Scheme || channel.Host != control.Host || channel.User != nil || channel.Fragment != "" {
			h.failure("o2r_origin", false)
			return nil, errors.New("o2r_origin")
		}
	}
	if !wire.Capabilities.Ordered {
		sequence = 0
	}
	observation := Observation{Epoch: h.request.Epoch, Hash: h.request.Hash, RunnerID: wire.RunnerID, Credential: wire.Credential, PreviousCredential: h.lineage, ReservedSequence: reserved, Sequence: sequence, Bootstrap: bootstrap, At: observedAt, TTL: ttl, Capabilities: wire.Capabilities, Entries: append([]Registration(nil), h.request.Entries...)}
	seen := map[string]bool{}
	for index, app := range wire.Apps {
		if !routeID.MatchString(app.ID) || (app.Status != "ready" && app.Status != "not-ready" && app.Status != "draining") || app.SessionIDs == nil || seen[app.ID] || (index < len(apps) && apps[index].ID != "" && app.ID != apps[index].ID) {
			h.failure("heartbeat_apps", false)
			return nil, errors.New("heartbeat_apps")
		}
		seen[app.ID] = true
		observation.Apps = append(observation.Apps, AppObservation{app.ID, app.Status, append([]string{}, (*app.SessionIDs)...)})
		if index < len(apps) {
			observation.Entries[index].Options = apps[index]
		}
	}
	if err = h.hooks.Observe(observation); err != nil {
		h.failure("identity_persistence_failed", false)
		h.stop()
		return nil, errors.New("identity_persistence_failed")
	}
	h.bootstrapAllowed = false
	if wire.Credential != "" {
		h.credential = wire.Credential
		h.lineage = wire.Credential
	}
	accepted := copyRequest(h.request)
	accepted.Identity = Identity{RunnerID: wire.RunnerID, Credential: h.credential, Confirmed: !bootstrap}
	for i := range accepted.Entries {
		accepted.Entries[i].Options.ID = wire.Apps[i].ID
	}
	o.mu.Lock()
	o.caps = wire.Capabilities
	o.accepted = accepted
	o.mu.Unlock()
	response.Body = io.NopCloser(bytes.NewReader(data))
	return response, nil
}

func (o *SDKOwner) Cancel(ctx context.Context, instanceID string, h OwnerHooks) error {
	o.mutations.Lock()
	defer o.mutations.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !o.Capabilities().Cancellation || !o.Capabilities().Ordered {
		return ErrDependency
	}
	r, err := h.ReserveCancellation(instanceID)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(map[string]uint64{"mutation_sequence": r.Sequence})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, o.base+"/runners/"+url.PathEscape(r.Identity.RunnerID)+"/apps/"+url.PathEscape(r.AppID)+"/cancel", bytes.NewReader(b))
	req.Header.Set("Authorization", r.Identity.Credential)
	req.Header.Set("Content-Type", "application/json")
	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return errors.New("node_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return &transport.HTTPError{Status: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return errors.New("cancel_response")
	}
	var result struct {
		RunnerID string  `json:"runner_id"`
		Sequence uint64  `json:"mutation_sequence"`
		App      wireApp `json:"app"`
	}
	if transport.Decode(data, &result) != nil || result.RunnerID != r.Identity.RunnerID || result.Sequence != r.Sequence || result.App.ID != r.AppID || result.App.Status != "draining" || result.App.SessionIDs == nil || len(*result.App.SessionIDs) != 0 {
		return errors.New("cancel_response")
	}
	target := Registration{InstanceID: r.InstanceID, WithdrawalID: r.WithdrawalID, PodUID: r.PodUID, Options: runner.AppOptions{ID: r.AppID}}
	return h.Observe(Observation{Epoch: r.Epoch, Hash: r.Hash, RunnerID: r.Identity.RunnerID, PreviousCredential: r.Identity.Credential, ReservedSequence: r.Sequence, Sequence: r.Sequence, At: now.UTC(), TTL: 30 * time.Second, Capabilities: o.Capabilities(), Entries: []Registration{target}, Apps: []AppObservation{{r.AppID, "draining", []string{}}}, Partial: true})
}
func (o *SDKOwner) Unregister(ctx context.Context, identity Identity) error {
	if identity.RunnerID == "" {
		return errors.New("owner_identity_missing")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, o.base+"/runners/"+url.PathEscape(identity.RunnerID)+"/unregister", nil)
	req.Header.Set("Authorization", identity.Credential)
	resp, err := o.client.Do(req)
	if err != nil {
		return errors.New("node_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 404 {
		return &transport.HTTPError{Status: resp.StatusCode}
	}
	return nil
}
