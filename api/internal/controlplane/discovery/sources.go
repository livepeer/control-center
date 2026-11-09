package discovery

import (
	"context"
	"errors"
	"github.com/livepeer/control-center/runtime/contract"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	shared "github.com/livepeer/node/discovery/shared"
)

var proxyIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func sameVersion(a, b Source) bool {
	return a.ID == b.ID && a.Epoch == b.Epoch && a.Generation == b.Generation && a.CredentialVersion == b.CredentialVersion && a.CredentialRef == b.CredentialRef && a.URL == b.URL
}

func (f *Manager) Reconcile(ctx context.Context) error {
	f.reconcileMu.Lock()
	defer f.reconcileMu.Unlock()
	sources, err := f.backend.Sources(ctx)
	if err != nil {
		f.reconciliationFailed()
		return errors.New("discovery source reconciliation failed")
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	f.mu.Lock()
	old := map[string]Source{}
	for _, source := range f.selected {
		old[source.ID] = source
	}
	f.mu.Unlock()
	next := []Source{}
	seenIDs, seenURLs := map[string]bool{}, map[string]bool{}
	for _, source := range sources {
		if source.ID == "" || seenIDs[source.ID] {
			f.reconciliationFailed()
			return errors.New("ambiguous discovery source identity")
		}
		seenIDs[source.ID] = true
		if previous, ok := old[source.ID]; ok && previous.Epoch == source.Epoch && source.Generation < previous.Generation {
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
			previous, ok := old[source.ID]
			if !ok || previous.Epoch != source.Epoch || previous.Generation != source.VerifiedGeneration {
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
	authorizations := map[string]authorization{}
	for _, source := range next {
		auth := authorization{source: source, available: source.AuthMode == AuthNone}
		if source.AuthMode == AuthCloudflare {
			credential, e := f.backend.Resolve(ctx, source.CredentialRef)
			if e == nil && validCredential(credential) {
				auth.credential = credential
				auth.available = true
			}
		}
		authorizations[source.URL] = auth
	}
	if ctx.Err() != nil {
		f.reconciliationFailed()
		return ctx.Err()
	}
	f.mu.Lock()
	previousAuth := f.transport.selection.Load()
	changedCredentials := []string{}
	survivors := []*url.URL{}
	for _, source := range f.selected {
		// SetSources keys on URL. Explicitly remove a reused URL when its
		// enrollment identity changes, fencing an obsolete in-flight result.
		auth, ok := authorizations[source.URL]
		if ok && auth.source.ID == source.ID && auth.source.Epoch == source.Epoch {
			u, _ := url.Parse(source.URL)
			survivors = append(survivors, u)
			if previousAuth != nil {
				prior := previousAuth.sources[source.URL]
				if !sameVersion(prior.source, auth.source) || prior.source.AuthMode != auth.source.AuthMode || prior.available != auth.available || prior.credential != auth.credential {
					changedCredentials = append(changedCredentials, source.URL)
				}
			}
		}
	}
	f.collector.SetSources(survivors)
	revision := f.transport.install(authorizations)
	for _, endpoint := range changedCredentials {
		f.pendingRefresh[endpoint] = revision
	}
	for endpoint := range f.pendingRefresh {
		if !seenURLs[endpoint] {
			delete(f.pendingRefresh, endpoint)
		}
	}
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
	for id := range f.provenance {
		if !seenIDs[id] {
			delete(f.provenance, id)
		}
	}
	f.reconciledAt = time.Now().UTC()
	f.reconcileFailed = false
	f.transport.mu.Lock()
	for endpoint := range f.transport.attempts {
		if !seenURLs[endpoint] {
			delete(f.transport.attempts, endpoint)
		}
	}
	f.transport.mu.Unlock()
	ackKeys := map[string]bool{}
	for _, source := range next {
		ackKeys[ackKey(source)] = true
	}
	for key := range f.acknowledged {
		if !ackKeys[key] {
			delete(f.acknowledged, key)
		}
	}
	f.mu.Unlock()
	if len(f.pendingRefresh) > 0 {
		f.collector.Refresh(ctx, false)
		// Refresh may have joined a predecessor batch. A bounded follow-up
		// starts with the installed selection; no second poller/cache is added.
		f.clearAttemptedRefreshes()
		if len(f.pendingRefresh) > 0 && ctx.Err() == nil {
			f.collector.Refresh(ctx, false)
			f.clearAttemptedRefreshes()
		}
	}
	f.acknowledge(ctx)
	return nil
}

// Pending configuration refreshes survive a canceled reconciliation wait. Any
// completed attempt with this or a later immutable selection fulfills the wakeup;
// a failed collection then follows the Collector's ordinary retry/failure policy.
func (f *Manager) clearAttemptedRefreshes() {
	f.transport.mu.Lock()
	defer f.transport.mu.Unlock()
	for endpoint, revision := range f.pendingRefresh {
		if f.transport.attempts[endpoint].revision >= revision {
			delete(f.pendingRefresh, endpoint)
		}
	}
}

func (f *Manager) reconciliationFailed() { f.mu.Lock(); f.reconcileFailed = true; f.mu.Unlock() }

func (f *Manager) acknowledge(ctx context.Context) {
	f.mu.Lock()
	sources := append([]Source(nil), f.selected...)
	attempts := map[string]attempt{}
	f.transport.mu.Lock()
	for endpoint, attempt := range f.transport.attempts {
		attempts[endpoint] = attempt
	}
	// Capture attempts before snapshots under the same lock. A later attempt
	// must not be compared with an older already-copied observation marker.
	snapshots := f.collector.Snapshots()
	f.transport.mu.Unlock()
	f.mu.Unlock()
	for _, source := range sources {
		if source.AuthMode != AuthCloudflare || source.Lifecycle != "active" {
			continue
		}
		f.mu.Lock()
		acked := f.acknowledged[ackKey(source)]
		f.mu.Unlock()
		if acked {
			continue
		}
		attempt, ok := attempts[source.URL]
		if !ok || attempt.status != 200 || !sameVersion(attempt.source, source) {
			continue
		}
		for _, snapshot := range snapshots {
			if snapshot.URL != source.URL || snapshot.QueriedAt.IsZero() || snapshot.QueriedAt.Equal(attempt.before) {
				continue
			}
			valid := true
			for _, entry := range snapshot.Entries {
				valid = valid && publicAddress(source, entry.Address)
			}
			if valid && f.backend.Acknowledge(ctx, source) == nil {
				f.mu.Lock()
				f.acknowledged[ackKey(source)] = true
				f.mu.Unlock()
			}
		}
	}
}

func ackKey(source Source) string {
	return source.ID + "\x00" + source.Epoch + "\x00" + source.URL + "\x00" + source.CredentialRef + "\x00" + strconv.FormatInt(source.Generation, 10) + "/" + strconv.FormatInt(source.CredentialVersion, 10)
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
