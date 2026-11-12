// Package orchestrator delivers onchain credentials to a verified Node process.
package orchestrator

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
	"sync"
	"time"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/connector"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
)

type Launch = connector.Launch
type Association struct {
	Launch
	NodeID            string `json:"node_id"`
	CredentialVersion int64  `json:"credential_version"`
	OnchainGeneration int64  `json:"onchain_generation"`
	ConfigDigest      string `json:"config_digest"`
	GrantID           string `json:"grant_id"`
}
type Request struct {
	Launch
	OnchainGeneration int64  `json:"onchain_generation"`
	ConfigDigest      string `json:"config_digest"`
}
type Grant struct {
	Association
	RPCURL       string `json:"rpc_url"`
	Headers      string `json:"headers"`
	RequireState bool   `json:"require_state"`
}
type ProcessObservation struct {
	Association
	ObservedAt time.Time `json:"observed_at"`
	Ready      bool      `json:"ready"`
}

type Kubernetes interface {
	Request(context.Context, string, string, any, any) error
}
type Control interface {
	Request(context.Context, string, any, int64) ([]byte, http.Header, error)
}
type Integration struct {
	Control              Control
	Kube                 Kubernetes
	Desired              func() (contract.Metadata, bool)
	TokenFile, StateFile string
	AllowHTTP            bool
	mu                   sync.Mutex
	order                uint64
	metricsGrant         string
	lastAck, lastErr     float64
	ackAt, errAt         time.Time
	grant                *Association
	observation          *ProcessObservation
}

var namePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
var noncePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var processPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidLaunch(l Launch) bool {
	return namePattern.MatchString(l.PodName) && l.PodUID != "" && len(l.PodUID) <= 128 && noncePattern.MatchString(l.LaunchID) && processPattern.MatchString(l.ProcessID)
}
func (i *Integration) Restore() {
	b, e := os.ReadFile(i.StateFile)
	var a Association
	if e == nil && len(b) < 16384 && json.Unmarshal(b, &a) == nil && ValidLaunch(a.Launch) && a.GrantID != "" {
		i.grant = &a
	}
}
func (i *Integration) checkPod(ctx context.Context, l Launch, m contract.Metadata) error {
	var p struct {
		Metadata struct {
			UID               string            `json:"uid"`
			DeletionTimestamp *string           `json:"deletionTimestamp"`
			Labels            map[string]string `json:"labels"`
			Annotations       map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if !ValidLaunch(l) || i.Kube.Request(ctx, "GET", "/api/v1/namespaces/livepeer/pods/"+url.PathEscape(l.PodName), nil, &p) != nil || p.Metadata.UID != l.PodUID || p.Metadata.DeletionTimestamp != nil || p.Metadata.Labels["app"] != "orchestrator" || p.Metadata.Annotations["livepeer.io/config-sha256"] != m.ConfigDigest {
		return errors.New("orchestrator_incarnation")
	}
	return nil
}
func (i *Integration) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.RawQuery != "" {
		http.Error(w, "operation refused", 403)
		return
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 4097))
	if e != nil || len(b) > 4096 {
		http.Error(w, "request refused", 400)
		return
	}
	if r.URL.Path == "/onchain/observation" {
		var o ProcessObservation
		m, ok := i.Desired()
		if transport.Decode(b, &o) != nil || !ok || m.TerminalCleanup || o.NodeID != m.NodeID || o.ConfigDigest != m.ConfigDigest || o.OnchainGeneration != m.Onchain.Generation || time.Since(o.ObservedAt) > 15*time.Second || o.ObservedAt.After(time.Now().Add(5*time.Second)) || i.checkPod(r.Context(), o.Launch, m) != nil {
			http.Error(w, "observation refused", 409)
			return
		}
		i.mu.Lock()
		defer i.mu.Unlock()
		if i.grant == nil || *i.grant != o.Association {
			http.Error(w, "observation refused", 409)
			return
		}
		if i.observation == nil || o.ObservedAt.After(i.observation.ObservedAt) {
			i.observation = &o
		}
		w.Write([]byte("{}\n"))
		return
	}
	if r.URL.Path != "/onchain/credentials" {
		http.Error(w, "operation refused", 403)
		return
	}
	var l Launch
	if transport.Decode(b, &l) != nil || !ValidLaunch(l) {
		http.Error(w, "launch refused", 400)
		return
	}
	grant, e := i.fetch(r.Context(), l)
	if e != nil {
		http.Error(w, "onchain credential unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(grant)
}
func (i *Integration) fetch(ctx context.Context, l Launch) (Grant, error) {
	bad := errors.New("onchain_credential_unavailable")
	m, ok := i.Desired()
	if !ok || i.AllowHTTP || !m.Onchain.Onchain() || m.TerminalCleanup || m.OnchainCredentialsRef != "/v1/nodes/"+m.NodeID+"/onchain/credentials" {
		return Grant{}, bad
	}
	before, e := os.ReadFile(i.TokenFile)
	if e != nil || i.checkPod(ctx, l, m) != nil {
		return Grant{}, bad
	}
	i.mu.Lock()
	i.order++
	order := i.order
	i.mu.Unlock()
	b, _, e := i.Control.Request(ctx, "onchain/credentials", Request{l, m.Onchain.Generation, m.ConfigDigest}, 16384)
	if e != nil {
		return Grant{}, bad
	}
	var g Grant
	if transport.Decode(b, &g) != nil || g.Launch != l || g.NodeID != m.NodeID || g.CredentialVersion != m.CredentialVersion || g.OnchainGeneration != m.Onchain.Generation || g.ConfigDigest != m.ConfigDigest || g.GrantID == "" || g.RPCURL == "" || g.Headers == "" {
		return Grant{}, bad
	}
	if i.checkPod(ctx, l, m) != nil {
		return Grant{}, bad
	}
	authorized := func() bool {
		after, e := os.ReadFile(i.TokenFile)
		n, ok := i.Desired()
		return ctx.Err() == nil && e == nil && ok && n.NodeID == m.NodeID && n.CredentialVersion == m.CredentialVersion && n.Generation == m.Generation && n.ConfigDigest == m.ConfigDigest && n.Onchain.Generation == m.Onchain.Generation && sha256.Sum256(before) == sha256.Sum256(after)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if order != i.order || !authorized() {
		return Grant{}, bad
	}
	b, _ = json.Marshal(g.Association)
	if artifact.AtomicWrite(i.StateFile, b, 0600) != nil {
		return Grant{}, bad
	}
	if !authorized() {
		i.grant = nil
		_ = artifact.AtomicWrite(i.StateFile, []byte("{}"), 0600)
		return Grant{}, bad
	}
	a := g.Association
	i.grant = &a
	i.observation = nil
	return g, nil
}
