package discovery

import (
	"context"
	"errors"
	"github.com/livepeer/control-center/runtime/contract"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	shared "github.com/livepeer/node/discovery/shared"
)

var proxyIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func (f *Manager) Reconcile(ctx context.Context) error {
	f.reconcileMu.Lock()
	defer f.reconcileMu.Unlock()
	sources, err := f.backend.Sources(ctx)
	if err != nil {
		f.reconciliationFailed()
		return errors.New("discovery source reconciliation failed")
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].NodeID < sources[j].NodeID })
	f.mu.Lock()
	old := map[string]Source{}
	for _, source := range f.selected {
		old[source.NodeID] = source
	}
	f.mu.Unlock()
	next := []Source{}
	seenIDs, seenURLs := map[string]bool{}, map[string]bool{}
	for _, source := range sources {
		if source.NodeID == "" || seenIDs[source.NodeID] {
			f.reconciliationFailed()
			return errors.New("ambiguous discovery source identity")
		}
		seenIDs[source.NodeID] = true
		if previous, ok := old[source.NodeID]; ok && source.Generation < previous.Generation {
			f.reconciliationFailed()
			return errors.New("stale discovery source generation")
		}
		if source.Blocked || source.Lifecycle != "active" && source.Lifecycle != "draining" {
			continue
		}
		// Verification is durable proof of prior approval; observation expiry
		// must not disable polling/recovery, including after an API restart.
		approved := source.Generation > 0 && source.VerifiedGeneration == source.Generation
		if !source.Ready && !approved {
			previous, ok := old[source.NodeID]
			if !ok || previous.Generation != source.VerifiedGeneration {
				continue
			}
			previous.Lifecycle = source.Lifecycle
			source = previous // Do not admit an unverified replacement generation.
		}
		u, e := canonicalEndpoint(source.URL)
		if e != nil || source.AuthMode != AuthCloudflare && source.AuthMode != AuthNone || source.AuthMode == AuthCloudflare && u.Scheme != "https" || source.AuthMode == AuthNone && source.CredentialRef != "" {
			f.reconciliationFailed()
			return errors.New("invalid managed discovery source")
		}
		source.URL = u.String()
		if f.ownHost != "" && strings.EqualFold(u.Host, f.ownHost) {
			f.reconciliationFailed()
			return errors.New("discovery cannot collect its own origin")
		}
		if seenURLs[source.URL] {
			f.reconciliationFailed()
			return errors.New("ambiguous discovery endpoint")
		}
		seenURLs[source.URL] = true
		next = append(next, source)
	}
	authorizations := map[string]*authorization{}
	prior := f.transport.selection.Load()
	for _, source := range next {
		auth := &authorization{source: source, available: source.AuthMode == AuthNone}
		if source.AuthMode == AuthCloudflare {
			credential, e := f.backend.Resolve(ctx, source.CredentialRef)
			if e == nil && validCredential(credential) {
				auth.credential = credential
				auth.available = true
			}
		}
		// Reuse confirmation only for the same immutable source authorization.
		if prior != nil {
			old := prior.sources[source.URL]
			if old != nil && old.source.NodeID == source.NodeID && old.source.Generation == source.Generation && old.source.CredentialRef == source.CredentialRef && old.source.CredentialVersion == source.CredentialVersion && old.source.ServiceURL == source.ServiceURL && old.source.AuthMode == source.AuthMode && old.credential == auth.credential && old.available == auth.available {
				auth = old
			}
		}
		authorizations[source.URL] = auth
	}
	if ctx.Err() != nil {
		f.reconciliationFailed()
		return ctx.Err()
	}
	f.mu.Lock()
	f.transport.install(authorizations)
	urls := make([]*url.URL, 0, len(next))
	for _, source := range next {
		u, _ := url.Parse(source.URL)
		urls = append(urls, u)
	}
	f.collector.SetSources(urls)
	if len(urls) == 0 {
		f.collector.AcceptEmpty()
	}
	f.selected = next
	f.configured = sources
	f.reconciledAt = time.Now().UTC()
	f.reconcileFailed = false
	f.mu.Unlock()
	f.acknowledge(ctx)
	return nil
}

func (f *Manager) reconciliationFailed() { f.mu.Lock(); f.reconcileFailed = true; f.mu.Unlock() }

// Acknowledgement asserts that this source authorization decoded successfully.
// The backend rechecks the current credential and deployment generation atomically.
func (f *Manager) acknowledge(ctx context.Context) {
	f.mu.Lock()
	selection := f.transport.selection.Load()
	sources := append([]Source(nil), f.selected...)
	f.mu.Unlock()
	if selection == nil {
		return
	}
	for _, source := range sources {
		auth := selection.sources[source.URL]
		f.transport.mu.Lock()
		ready := auth.confirmed && !auth.acknowledged
		f.transport.mu.Unlock()
		if ready && source.AuthMode == AuthCloudflare && source.Lifecycle == "active" && f.backend.Acknowledge(ctx, source) == nil {
			f.transport.mu.Lock()
			auth.acknowledged = true
			f.transport.mu.Unlock()
		}
	}
}

// Public routing comes from the same managed state as source selection. Do not
// rewrite upstream URLs or publish a private/wrong-machine registration target.
func publicEntry(source Source, entry shared.Entry[runner]) bool {
	if !publicAddress(source, entry.Address) {
		return false
	}
	for _, candidate := range entry.Runners {
		if !publicRunnerURL(source, candidate.URL) {
			return false
		}
	}
	return true
}

func publicAddress(source Source, address string) bool {
	base, err := url.Parse(source.ServiceURL)
	return err == nil && shared.ValidateURL(base) == nil && base.Scheme == "https" && address == source.ServiceURL
}

func publicRunnerURL(source Source, raw string) bool {
	base, err := url.Parse(source.ServiceURL)
	if err != nil || !publicAddress(source, source.ServiceURL) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || shared.ValidateURL(u) != nil || u.Scheme != "https" {
		return false
	}
	if u.Host == base.Host && (u.Path == base.Path || strings.HasPrefix(u.Path, strings.TrimRight(base.Path, "/")+"/")) {
		return u.Path != "" && u.Path != "/"
	}
	before, after, ok := strings.Cut(source.ProxyURLTemplate, "{proxy}")
	if !ok || !strings.HasPrefix(raw, before) || !strings.HasSuffix(raw, after) || len(raw) <= len(before)+len(after) {
		return false
	}
	id := raw[len(before) : len(raw)-len(after)]
	if len(id) > 63 || strings.Contains(id, ".") || !proxyIDPattern.MatchString(id) || contract.ReservedProxyID(id) {
		return false
	}
	return true
}
