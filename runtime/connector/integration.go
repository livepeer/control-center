// Package connector contains cloudflared credential delivery and observation integration.
package connector

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

type Kubernetes interface {
	Request(context.Context, string, string, any, any) error
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
}

type Grant struct {
	Association
	Token string `json:"token"`
}

type Observation struct {
	Association
	Ready           bool  `json:"ready"`
	ProviderVersion int64 `json:"provider_version"`
	observedAt      time.Time
}

type Integration struct {
	Control        *transport.Control
	Kube           Kubernetes
	Desired        func() (contract.Metadata, bool)
	StateFile      string
	mu             sync.Mutex
	fetchOrder     uint64
	validatedOrder uint64
	grant          *Association
	observation    *Observation
}

// Restore recovers a grant association, never a readiness observation.
func (i *Integration) Restore() {
	b, err := os.ReadFile(i.StateFile)
	var grant Association
	if err == nil && len(b) <= 16384 && transport.Decode(b, &grant) == nil && validLaunch(grant.Launch) && grant.Epoch != "" && grant.TokenGeneration > 0 {
		i.mu.Lock()
		i.grant = &grant
		i.observation = nil
		i.mu.Unlock()
	}
}

var podName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
var launchID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var processID = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validLaunch(l Launch) bool {
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
	case "/tunnel/connector-token":
		var launch Launch
		if transport.Decode(b, &launch) != nil || !validLaunch(launch) {
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
	case "/tunnel/observation":
		var observation Observation
		m, ok := i.Desired()
		if transport.Decode(b, &observation) != nil || !ok || !matches(observation.Association, m) {
			http.Error(w, "observation refused", http.StatusConflict)
			return
		}
		i.mu.Lock()
		defer i.mu.Unlock()
		if i.grant == nil || *i.grant != observation.Association {
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

func matches(a Association, m contract.Metadata) bool {
	return m.BundleFormat >= contract.SystemBundleFormat && !m.TerminalCleanup && a.Epoch == m.Epoch && a.CredentialVersion == m.CredentialVersion && a.TunnelID != "" && a.TunnelID == m.TunnelID && a.TokenGeneration > 0 && a.TokenGeneration == m.TokenGeneration
}

func (i *Integration) fetch(ctx context.Context, launch Launch) (Grant, error) {
	i.mu.Lock()
	i.fetchOrder++
	order := i.fetchOrder
	i.mu.Unlock()
	m, ok := i.Desired()
	if !ok || m.ConnectorTokenRef != "/v1/nodes/"+m.NodeID+"/tunnel/connector-token" || m.TokenGeneration < 1 || m.TerminalCleanup || i.Control.AllowHTTP {
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
	b, _, err := i.Control.Request(ctx, "tunnel/connector-token", nil, 16384)
	if err != nil {
		return Grant{}, err
	}
	var response struct {
		Token           string `json:"token"`
		Epoch           string `json:"epoch"`
		TunnelID        string `json:"tunnel_id"`
		TokenGeneration int64  `json:"credential_generation"`
	}
	if transport.Decode(b, &response) != nil || !validToken(response.Token) || response.Epoch != m.Epoch || response.TunnelID != m.TunnelID || response.TokenGeneration != m.TokenGeneration {
		return Grant{}, errors.New("stale_connector_grant")
	}
	a := Association{Launch: launch, Epoch: m.Epoch, CredentialVersion: m.CredentialVersion, TunnelID: m.TunnelID, TokenGeneration: m.TokenGeneration}
	if i.checkPod(ctx, launch) != nil {
		return Grant{}, errors.New("connector_changed_during_fetch")
	}
	authorized := func() bool {
		after, err := os.ReadFile(i.Control.TokenFile)
		current, ok := i.Desired()
		return ctx.Err() == nil && err == nil && ok && matches(a, current) && current.Generation == m.Generation && current.ConnectorTokenRef == m.ConnectorTokenRef && sha256.Sum256(before) == sha256.Sum256(after)
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
	return Grant{Association: a, Token: response.Token}, nil
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
		} `json:"metadata"`
	}
	if !validLaunch(launch) || i.Kube.Request(ctx, http.MethodGet, "/api/v1/namespaces/flux-system/pods/"+url.PathEscape(launch.PodName), nil, &pod) != nil || pod.Metadata.UID != launch.PodUID || pod.Metadata.DeletionTimestamp != nil || pod.Metadata.Labels["app"] != "livepeer-tunnel" {
		return errors.New("connector_incarnation")
	}
	return nil
}

// Report requires fresh local evidence and the same live Kubernetes incarnation.
func (i *Integration) Report(ctx context.Context) error {
	m, ok := i.Desired()
	if !ok || m.BundleFormat < contract.SystemBundleFormat || m.Terminal || m.TunnelID == "" {
		return nil
	}
	i.mu.Lock()
	grant := i.grant
	i.mu.Unlock()
	podValid := grant != nil && i.checkPod(ctx, grant.Launch) == nil
	m, ok = i.Desired()
	if !ok || m.BundleFormat < contract.SystemBundleFormat || m.Terminal || m.TunnelID == "" {
		return nil
	}
	ready := false
	tokenGeneration, providerVersion := int64(0), int64(0)
	i.mu.Lock()
	if podValid && i.grant == grant && matches(*grant, m) {
		tokenGeneration = grant.TokenGeneration
		if observation := i.observation; observation != nil && observation.Association == *grant && !observation.observedAt.IsZero() && time.Since(observation.observedAt) <= observationTTL {
			providerVersion = observation.ProviderVersion
			ready = observation.Ready && providerVersion > 0 && providerVersion == m.ProviderVersion
		}
	}
	i.mu.Unlock()
	reason := "offline"
	if ready {
		reason = "ready"
	}
	_, _, err := i.Control.Request(ctx, "status", map[string]any{"epoch": m.Epoch, "credential_version": m.CredentialVersion, "component": "connector", "generation": m.Generation, "token_generation": tokenGeneration, "provider_version": providerVersion, "ready": ready, "https": strings.HasPrefix(i.Control.ConfigURL, "https://"), "reason": reason}, 16384)
	return err
}
