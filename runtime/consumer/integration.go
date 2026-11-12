// Package consumer delivers credentials to the protected connector and Node processes.
package consumer

import (
	"context"
	"crypto/sha256"
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

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
)

const observationTTL = 30 * time.Second

type Profile int

const (
	Connector Profile = iota
	Orchestrator
)

func (p Profile) endpoint() string {
	if p == Orchestrator {
		return "onchain/credentials"
	}
	return "tunnel/connector-token"
}
func (p Profile) observationPath() string {
	if p == Orchestrator {
		return "/onchain/observation"
	}
	return "/tunnel/observation"
}

// Launch identifies one exec in one Kubernetes container incarnation.
type Launch struct {
	PodName   string `json:"pod_name"`
	PodUID    string `json:"pod_uid"`
	LaunchID  string `json:"launch_id"`
	ProcessID string `json:"process_id"`
}

// Association is safe to persist; it contains no connector or machine credential.
type Association struct {
	Launch
	Epoch             string `json:"epoch"`
	CredentialVersion int64  `json:"credential_version"`
	TunnelID          string `json:"tunnel_id"`
	TokenGeneration   int64  `json:"credential_generation"`
	OnchainGeneration int64  `json:"onchain_generation,omitempty"`
	ConfigDigest      string `json:"config_digest,omitempty"`
	GrantID           string `json:"grant_id,omitempty"`
}

type Request struct {
	Launch
	OnchainGeneration int64  `json:"onchain_generation"`
	ConfigDigest      string `json:"config_digest"`
}

type Grant struct {
	Association
	Token        string `json:"token"`
	RPCURL       string `json:"rpc_url,omitempty"`
	Headers      string `json:"headers,omitempty"`
	RequireState bool   `json:"require_state,omitempty"`
}

type Observation struct {
	Association
	Ready           bool      `json:"ready"`
	ProviderVersion int64     `json:"provider_version"`
	ObservedAt      time.Time `json:"observed_at,omitempty"`
	observedAt      time.Time
}

type Integration struct {
	Profile          Profile
	Control          *transport.Control
	Reporter         transport.Requester
	Kube             transport.KubernetesReader
	Desired          func() (contract.Metadata, bool)
	StateFile        string
	mu               sync.Mutex
	fetchOrder       uint64
	validatedOrder   uint64
	grant            *Association
	observation      *Observation
	metricsGrant     string
	lastAck, lastErr float64
	handoff          string
	handoffAt        time.Time
}

// Restore recovers a grant association, never a readiness observation.
func (i *Integration) Restore() {
	b, err := os.ReadFile(i.StateFile)
	var grant Association
	if err == nil && len(b) <= 16384 && transport.Decode(b, &grant) == nil && ValidLaunch(grant.Launch) && grant.Epoch != "" && (grant.TokenGeneration > 0 || grant.GrantID != "") {
		i.mu.Lock()
		i.grant = &grant
		i.observation = nil
		i.mu.Unlock()
	}
}

var podName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
var launchID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var processID = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidLaunch(l Launch) bool {
	return podName.MatchString(l.PodName) && l.PodUID != "" && len(l.PodUID) <= 128 && launchID.MatchString(l.LaunchID) && processID.MatchString(l.ProcessID)
}

func (i *Integration) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		http.Error(w, "operation refused", http.StatusForbidden)
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 16385))
	if err != nil || len(b) > 16384 {
		http.Error(w, "request refused", http.StatusBadRequest)
		return
	}
	switch r.URL.Path {
	case "/" + i.Profile.endpoint():
		var launch Launch
		if transport.Decode(b, &launch) != nil || !ValidLaunch(launch) {
			http.Error(w, "launch refused", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		grant, err := i.fetch(ctx, launch)
		if err != nil {
			http.Error(w, "credential unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(grant)
	case i.Profile.observationPath():
		var observation Observation
		m, ok := i.Desired()
		if transport.Decode(b, &observation) != nil || !ok || !i.matches(observation.Association, m) || (i.Profile == Orchestrator && (time.Since(observation.ObservedAt) > 15*time.Second || observation.ObservedAt.After(time.Now().Add(5*time.Second)) || i.checkPod(r.Context(), observation.Launch) != nil)) {
			http.Error(w, "observation refused", http.StatusConflict)
			return
		}
		i.mu.Lock()
		defer i.mu.Unlock()
		if i.grant == nil || *i.grant != observation.Association || (i.observation != nil && observation.ObservedAt.Before(i.observation.ObservedAt)) {
			http.Error(w, "observation refused", http.StatusConflict)
			return
		}
		observation.observedAt = time.Now()
		i.observation = &observation
		w.Write([]byte("{}\n"))
	default:
		http.Error(w, "operation refused", http.StatusForbidden)
	}
}

func (i *Integration) matches(a Association, m contract.Metadata) bool {
	if m.TerminalCleanup || a.Epoch != m.Epoch {
		return false
	}
	if i.Profile == Orchestrator {
		// A held process may retain its submission grant across management refresh.
		return m.Onchain.Onchain() && a.OnchainGeneration == m.Onchain.Generation && a.ConfigDigest == m.ConfigDigest && a.GrantID != ""
	}
	return a.CredentialVersion == m.CredentialVersion && a.TunnelID != "" && a.TunnelID == m.TunnelID && a.TokenGeneration > 0 && a.TokenGeneration == m.TokenGeneration
}
func (i *Integration) authorized(m contract.Metadata) bool {
	ref := m.ConnectorTokenRef
	if i.Profile == Orchestrator {
		ref = m.OnchainCredentialsRef
	}
	return !m.TerminalCleanup && !i.Control.AllowHTTP && ref == "/v1/nodes/"+m.NodeID+"/"+i.Profile.endpoint()
}

func (i *Integration) fetch(ctx context.Context, launch Launch) (Grant, error) {
	i.mu.Lock()
	i.fetchOrder++
	order := i.fetchOrder
	i.mu.Unlock()
	m, ok := i.Desired()
	if !ok || !i.authorized(m) {
		return Grant{}, errors.New("connector_not_authorized")
	}
	before, err := os.ReadFile(i.Control.TokenFile)
	if err != nil {
		return Grant{}, errors.New("credential_unavailable")
	}
	if err = i.checkPod(ctx, launch); err != nil {
		return Grant{}, err
	}
	i.mu.Lock()
	if order < i.validatedOrder {
		i.mu.Unlock()
		return Grant{}, errors.New("connector_launch_superseded")
	}
	i.validatedOrder = order
	if i.grant != nil && i.grant.Launch != launch {
		i.grant, i.observation = nil, nil
		if err = artifact.AtomicWrite(i.StateFile, []byte("{}"), 0600); err != nil {
			i.mu.Unlock()
			return Grant{}, errors.New("grant_state_unavailable")
		}
	}
	i.mu.Unlock()
	var request any
	if i.Profile == Orchestrator {
		request = Request{launch, m.Onchain.Generation, m.ConfigDigest}
	}
	b, _, err := i.Control.Request(ctx, i.Profile.endpoint(), request, 16384)
	if err != nil {
		return Grant{}, err
	}
	var response Grant
	if transport.Decode(b, &response) != nil {
		return Grant{}, errors.New("stale_connector_grant")
	}
	if i.Profile == Connector {
		response.Launch, response.CredentialVersion = launch, m.CredentialVersion
	}
	a := response.Association
	valid := validToken(response.Token)
	if i.Profile == Orchestrator {
		valid = response.RPCURL != "" && response.Headers != ""
	}
	if !valid || a.Launch != launch || a.CredentialVersion != m.CredentialVersion || !i.matches(a, m) {
		return Grant{}, errors.New("stale_process_grant")
	}
	if i.checkPod(ctx, launch) != nil {
		return Grant{}, errors.New("connector_changed_during_fetch")
	}
	authorized := func() bool {
		after, err := os.ReadFile(i.Control.TokenFile)
		current, ok := i.Desired()
		return ctx.Err() == nil && err == nil && ok && i.authorized(current) && i.matches(a, current) && current.CredentialVersion == m.CredentialVersion && current.Generation == m.Generation && sha256.Sum256(before) == sha256.Sum256(after)
	}
	data, _ := json.Marshal(a)
	i.mu.Lock()
	defer i.mu.Unlock()
	if order != i.validatedOrder || !authorized() {
		return Grant{}, errors.New("connector_changed_during_fetch")
	}
	// Commit the nonsecret association before the token can be delivered.
	if err = artifact.AtomicWrite(i.StateFile, data, 0600); err != nil {
		return Grant{}, errors.New("grant_state_unavailable")
	}
	if !authorized() {
		i.grant, i.observation = nil, nil
		_ = artifact.AtomicWrite(i.StateFile, []byte("{}"), 0600)
		return Grant{}, errors.New("connector_changed_during_commit")
	}
	i.grant, i.observation = &a, nil
	return response, nil
}

func validToken(token string) bool {
	if len(token) < 20 || len(token) > 8192 {
		return false
	}
	for _, c := range []byte(token) {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}

func (i *Integration) checkPod(ctx context.Context, launch Launch) error {
	var pod struct {
		Metadata struct {
			UID               string            `json:"uid"`
			DeletionTimestamp *string           `json:"deletionTimestamp"`
			Labels            map[string]string `json:"labels"`
			Annotations       map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	namespace, label := "flux-system", "livepeer-tunnel"
	if i.Profile == Orchestrator {
		namespace, label = "livepeer", "orchestrator"
	}
	m, ok := i.Desired()
	if !ValidLaunch(launch) || !ok || i.Kube.Request(ctx, http.MethodGet, "/api/v1/namespaces/"+namespace+"/pods/"+url.PathEscape(launch.PodName), nil, &pod) != nil || pod.Metadata.UID != launch.PodUID || pod.Metadata.DeletionTimestamp != nil || pod.Metadata.Labels["app"] != label || (i.Profile == Orchestrator && pod.Metadata.Annotations["livepeer.io/config-sha256"] != m.ConfigDigest) {
		return errors.New("connector_incarnation")
	}
	return nil
}

// Report requires fresh local evidence and the same live Kubernetes incarnation.
func (i *Integration) Report(ctx context.Context) error {
	m, ok := i.Desired()
	if !ok || m.Terminal || m.TunnelID == "" {
		return nil
	}
	i.mu.Lock()
	grant := i.grant
	i.mu.Unlock()
	podValid := grant != nil && i.checkPod(ctx, grant.Launch) == nil
	m, ok = i.Desired()
	if !ok || m.Terminal || m.TunnelID == "" {
		return nil
	}
	ready := false
	observedAt := time.Time{}
	tokenGeneration, providerVersion := int64(0), int64(0)
	i.mu.Lock()
	if podValid && i.grant == grant && i.matches(*grant, m) {
		tokenGeneration = grant.TokenGeneration
		if observation := i.observation; observation != nil && observation.Association == *grant && !observation.observedAt.IsZero() && time.Since(observation.observedAt) <= observationTTL {
			observedAt = observation.observedAt
			providerVersion = observation.ProviderVersion
			ready = observation.Ready && providerVersion > 0 && providerVersion == m.ProviderVersion
		}
	}
	i.mu.Unlock()
	reason := "offline"
	if ready {
		reason = "ready"
	}
	reporter := i.Reporter
	if reporter == nil {
		reporter = i.Control
	}
	_, _, err := reporter.Request(ctx, "status", map[string]any{"epoch": m.Epoch, "credential_version": m.CredentialVersion, "component": "connector", "generation": m.Generation, "token_generation": tokenGeneration, "provider_version": providerVersion, "ready": ready, "https": strings.HasPrefix(i.Control.ConfigURL, "https://"), "reason": reason, "observed_at": time.Now().UTC(), "connector_observed_at": observedAt, "connector_expires_at": observedAt.Add(observationTTL)}, 16384)
	return err
}
