// Package httpsource delivers management artifacts independently of app reconciliation.
package httpsource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
	"github.com/livepeer/control-center/schema"
)

const SourceName = "livepeer-service"
const fluxPath = "/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/flux-system/kustomizations/"

type Kubernetes interface {
	Request(context.Context, string, string, any, any) error
	Publish(context.Context, string, *transport.Artifact, bool, string) error
}
type Source struct {
	Control         *transport.Control
	Reporter        transport.Requester
	Kube            Kubernetes
	Store           artifact.Store
	ArtifactURL     string
	IdentityFile    string
	SystemWorkloads bool
	mu              sync.Mutex
	published       atomic.Pointer[delivery]
	reporting       atomic.Pointer[delivery]
	deliveryFailure atomic.Bool
}

type delivery struct {
	Metadata     contract.Metadata
	Digest       string
	AppError     string
	Handoff      bool
	Downloaded   *contract.StageIdentity
	DownloadedAt time.Time
}

// Desired never lends authority from a different installed enrollment.
func (s *Source) Desired() (contract.Metadata, bool) {
	d := s.published.Load()
	if d == nil || !s.installed(d.Metadata) {
		return contract.Metadata{}, false
	}
	return d.Metadata, true
}

func (s *Source) installed(m contract.Metadata) bool {
	if s.IdentityFile == "" {
		return true
	}
	i, err := transport.ReadIdentity(s.IdentityFile)
	return err == nil && ((i.Epoch == m.Epoch && i.CredentialVersion == m.CredentialVersion) || (i.Epoch == "" && i.CredentialVersion == 0 && m.CredentialVersion == 0))
}

// Report runs independently of downloads, credential requests and consumer observations.
func (s *Source) Report(ctx context.Context) error {
	d := s.reporting.Load()
	if d == nil || !s.installed(d.Metadata) {
		return nil
	}
	return s.report(ctx, d.Metadata, d.Digest, d.AppError, d.Handoff)
}

func (s *Source) Sync(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.sync(ctx)
	s.deliveryFailure.Store(err != nil)
	if err != nil {
		_ = s.Kube.Publish(ctx, SourceName, nil, false, "FetchFailed")
	}
	return err
}
func (s *Source) sync(ctx context.Context) error {
	data, headers, err := s.Control.Request(ctx, "config", nil, artifact.MaxArchive)
	if err != nil {
		return err
	}
	files, err := artifact.Read(data)
	if err != nil {
		return err
	}
	m, err := transport.ReadMetadata(files["runtime.json"])
	if err != nil {
		return err
	}
	if m.NodeID != s.Control.NodeID || m.Epoch != headers.Get("X-Livepeer-Epoch") || headers.Get("X-Livepeer-Credential-Version") != formatInt(m.CredentialVersion) {
		return errors.New("enrollment_mismatch")
	}
	if s.IdentityFile != "" {
		i, err := transport.ReadIdentity(s.IdentityFile)
		if err != nil {
			return err
		}
		legacy := i.Epoch == "" && i.CredentialVersion == 0 && m.CredentialVersion == 0
		if !legacy && (i.Epoch != m.Epoch || i.CredentialVersion != m.CredentialVersion) {
			return errors.New("installed_identity_mismatch")
		}
	}
	if err = os.MkdirAll(s.Store.Directory, 0700); err != nil {
		return errors.New("cache_unavailable")
	}
	watermark := filepath.Join(s.Store.Directory, "enrollment.json")
	var previous *contract.Metadata
	if b, err := os.ReadFile(watermark); err == nil {
		old, err := transport.ReadMetadata(b)
		if err != nil {
			return errors.New("cache_identity_corrupt")
		}
		previous = &old
		if old.Epoch != m.Epoch || (old.Terminal && !m.Terminal) || (!m.Terminal && old.Generation > m.Generation) {
			return errors.New("stale_enrollment")
		}
	} else if !os.IsNotExist(err) {
		return errors.New("cache_identity_unavailable")
	}
	if m.BundleFormat > contract.SystemBundleFormat {
		return errors.New("unsupported_bundle_format")
	}
	if m.Terminal && m.BundleFormat >= contract.BundleFormat {
		inputDigest := artifact.Digest(data)
		if m.TerminalInputDigest != "" {
			inputDigest = m.TerminalInputDigest
		}
		if previous != nil && previous.TerminalInputDigest != "" && previous.TerminalInputDigest != inputDigest {
			return errors.New("terminal_bundle_changed")
		}
		if headers.Get("X-Livepeer-App-Cleanup-Ready") == "true" || (previous != nil && previous.TerminalCleanup) {
			cleanup := map[string][]byte{}
			for name, b := range files {
				if strings.HasPrefix(name, "terminal-cleanup/") {
					cleanup[strings.TrimPrefix(name, "terminal-cleanup/")] = b
				}
			}
			final, e := transport.ReadMetadata(cleanup["runtime.json"])
			if e != nil || !final.Terminal || !final.TerminalCleanup || final.NodeID != m.NodeID || final.Epoch != m.Epoch || final.Generation != m.Generation || final.CredentialVersion != m.CredentialVersion || final.AppsDigest != m.AppsDigest || final.AppsGeneration != m.AppsGeneration {
				return errors.New("terminal_cleanup_payload")
			}
			data, err = artifact.Pack(cleanup)
			if err != nil {
				return err
			}
			files, m = cleanup, final
		}
		m.TerminalInputDigest = inputDigest
	}
	appErr := validateApps(files, m, previous)
	if appErr != nil && m.BundleFormat < contract.BundleFormat {
		// Advertise installed format support even when legacy app input is invalid.
		// The backend can then deliver a management-only repair using format 2.
		if !m.Terminal {
			s.reporting.Store(&delivery{Metadata: m, AppError: appErrorReason(appErr.Error())})
		}
		return appErr
	}
	inputDigest := artifact.Digest(data)
	data, handoff, err := s.systemLayout(ctx, files, data, m)
	if err != nil {
		if !m.Terminal {
			s.reporting.Store(&delivery{Metadata: m})
		}
		return err
	}
	digest, err := s.Store.Put(data)
	if err != nil {
		return err
	}
	delivered := m
	if appErr != nil {
		if previous != nil {
			delivered.AppsGeneration = previous.AppsGeneration
			delivered.AppsDigest = previous.AppsDigest
		} else {
			delivered.AppsGeneration = 0
			delivered.AppsDigest = ""
		}
		delivered.AppsError = appErrorReason(appErr.Error())
	}
	b, err := json.Marshal(delivered)
	if err != nil {
		return err
	}
	if err = artifact.AtomicWrite(watermark, b, 0600); err != nil {
		return errors.New("cache_commit_failed")
	}
	info, err := os.Stat(filepath.Join(s.Store.Directory, digest[7:]+".tar.gz"))
	if err != nil {
		return err
	}
	a := transport.Artifact{Digest: digest, Revision: digest, Path: "artifacts/" + digest[7:] + ".tar.gz", URL: strings.TrimRight(s.ArtifactURL, "/") + "/artifacts/" + digest[7:] + ".tar.gz", Size: len(data), LastUpdateTime: info.ModTime().UTC().Format(time.RFC3339)}
	d := &delivery{Metadata: m, Digest: digest, AppError: delivered.AppsError, Handoff: handoff}
	if appErr == nil {
		d.Downloaded = &contract.StageIdentity{Generation: m.AppsGeneration, AppsDigest: m.AppsDigest, ArtifactDigest: inputDigest}
		d.DownloadedAt = time.Now().UTC()
		if prior := s.reporting.Load(); prior != nil && prior.Metadata.Epoch == m.Epoch && prior.Downloaded != nil && *prior.Downloaded == *d.Downloaded {
			d.DownloadedAt = prior.DownloadedAt
		}
	} else if prior := s.reporting.Load(); prior != nil && prior.Metadata.Epoch == m.Epoch {
		d.Downloaded, d.DownloadedAt = prior.Downloaded, prior.DownloadedAt
	}
	s.reporting.Store(d)
	if err = s.Kube.Publish(ctx, SourceName, &a, true, "Succeeded"); err != nil {
		return err
	}
	if err = artifact.AtomicWrite(filepath.Join(s.Store.Directory, digest[7:]+".seen"), []byte(digest), 0600); err != nil {
		return errors.New("cache_publication_commit")
	}
	s.published.Store(d)
	s.reporting.Store(d)
	s.gc(ctx, digest)
	return nil
}
func formatInt(n int64) string { b, _ := json.Marshal(n); return string(b) }

func validateApps(files map[string][]byte, m contract.Metadata, old *contract.Metadata) error {
	if m.AppsGeneration < 0 {
		return errors.New("app_generation")
	}
	if m.BundleFormat >= contract.BundleFormat {
		p, err := appbundle.Read(files, m)
		if err != nil {
			return err
		}
		if !p.Index.Available {
			return errors.New("app_input_unavailable")
		}
	} else {
		raw, ok := files[schema.AppAssignmentsFile]
		if m.AppsGeneration == 0 {
			if ok || m.AppsDigest != "" {
				return errors.New("unexpected_app_input")
			}
			return nil
		}
		if !ok || len(raw) > schema.MaxAppConfigMapBytes {
			return errors.New("missing_app_input")
		}
		var cm struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Metadata   struct {
				Name        string            `json:"name"`
				Namespace   string            `json:"namespace"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Data map[string]string `json:"data"`
		}
		if transport.Decode(raw, &cm) != nil || cm.APIVersion != "v1" || cm.Kind != "ConfigMap" || cm.Metadata.Name != "livepeer-app-assignments" || cm.Metadata.Namespace != "livepeer" || len(cm.Data) != 1 || cm.Metadata.Annotations["livepeer.io/apps-sha256"] != m.AppsDigest {
			return errors.New("app_manifest")
		}
		intent := []byte(cm.Data["desired.json"])
		set, err := schema.DecodeAssignmentSet(intent)
		if err != nil || schema.Digest(intent) != m.AppsDigest || set.NodeID != m.NodeID || set.Epoch != m.Epoch || set.Generation != m.AppsGeneration {
			return errors.New("app_identity")
		}
	}
	if old != nil && (old.AppsGeneration > m.AppsGeneration || (old.AppsGeneration == m.AppsGeneration && old.AppsDigest != m.AppsDigest)) {
		return errors.New("stale_app_input")
	}
	return nil
}

type fluxState struct {
	Metadata struct {
		Generation int64 `json:"generation"`
	} `json:"metadata"`
	Spec struct {
		Prune bool   `json:"prune"`
		Path  string `json:"path"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration    int64  `json:"observedGeneration"`
		LastAppliedRevision   string `json:"lastAppliedRevision"`
		LastAttemptedRevision string `json:"lastAttemptedRevision"`
		Inventory             struct {
			Entries []struct {
				ID string `json:"id"`
			} `json:"entries"`
		} `json:"inventory"`
		Conditions []transport.Condition `json:"conditions"`
	} `json:"status"`
}

func (s *Source) applied(ctx context.Context, name, digest string) (bool, string) {
	var k fluxState
	if s.Kube.Request(ctx, http.MethodGet, fluxPath+name, nil, &k) != nil {
		return false, ""
	}
	ready := false
	for _, c := range k.Status.Conditions {
		ready = ready || (c.Type == "Ready" && c.Status == "True")
	}
	if !artifact.HashPattern.MatchString(k.Status.LastAppliedRevision) {
		return false, ""
	}
	current := k.Status.LastAppliedRevision == digest && ready
	unchanged := digest != "" && k.Status.LastAppliedRevision != digest && (s.componentUnchanged(name, k.Status.LastAppliedRevision, digest) || s.appOnlyChange(k.Status.LastAppliedRevision, digest))
	return k.Status.ObservedGeneration == k.Metadata.Generation && (current || unchanged), k.Status.LastAppliedRevision
}
func (s *Source) appOnlyChange(previous, current string) bool {
	infrastructure := func(digest string) ([]byte, int64, error) {
		data, err := s.Store.Get(digest)
		if err != nil {
			return nil, 0, err
		}
		files, err := artifact.Read(data)
		if err != nil {
			return nil, 0, err
		}
		var metadata map[string]json.RawMessage
		if transport.Decode(files["runtime.json"], &metadata) != nil {
			return nil, 0, errors.New("cache_metadata")
		}
		var generation int64
		_ = json.Unmarshal(metadata["apps_generation"], &generation)
		for _, key := range []string{"apps_generation", "apps_digest", "apps_payload_digest", "apps_error", "requested_apps_generation"} {
			delete(metadata, key)
		}
		files["runtime.json"], err = json.Marshal(metadata)
		if err != nil {
			return nil, 0, err
		}
		delete(files, schema.AppAssignmentsFile)
		for name := range files {
			if strings.HasPrefix(name, "app-desired/") {
				delete(files, name)
			}
		}
		lines := []string{}
		for _, line := range strings.Split(string(files["kustomization.yaml"]), "\n") {
			if line != "- "+schema.AppAssignmentsFile {
				lines = append(lines, line)
			}
		}
		files["kustomization.yaml"] = []byte(strings.TrimRight(strings.Join(lines, "\n"), "\n"))
		b, err := json.Marshal(files)
		return b, generation, err
	}
	a, ga, ea := infrastructure(previous)
	b, gb, eb := infrastructure(current)
	return ea == nil && eb == nil && gb >= ga && bytes.Equal(a, b)
}

func (s *Source) report(ctx context.Context, m contract.Metadata, digest, appError string, handoff bool) error {
	name := "livepeer"
	if m.BundleFormat >= contract.SystemBundleFormat && !handoff {
		name = "livepeer-node"
	}
	applied, revision := s.applied(ctx, name, digest)
	if handoff {
		applied = false
	}
	if m.BundleFormat < contract.SystemBundleFormat || m.Terminal {
		upgrade, _ := s.applied(ctx, "livepeer-upgrade-plan", digest)
		applied = applied && upgrade
	}
	if m.Terminal {
		if m.BundleFormat >= 2 && !m.TerminalCleanup {
			return nil
		}
		if m.BundleFormat >= contract.SystemBundleFormat {
			connector, _ := s.applied(ctx, "livepeer-connector", digest)
			applied = applied && connector && !handoff
		}
		var pods struct {
			Items []json.RawMessage `json:"items"`
		}
		if s.Kube.Request(ctx, http.MethodGet, "/api/v1/namespaces/flux-system/pods?labelSelector=app%3Dlivepeer-tunnel", nil, &pods) != nil {
			return errors.New("terminal_observation")
		}
		var deployment any
		err := s.Kube.Request(ctx, http.MethodGet, "/apis/apps/v1/namespaces/flux-system/deployments/livepeer-tunnel", nil, &deployment)
		var nodePods struct {
			Items []json.RawMessage `json:"items"`
		}
		nodeErr := s.Kube.Request(ctx, http.MethodGet, "/api/v1/namespaces/livepeer/pods?labelSelector=app%3Dorchestrator", nil, &nodePods)
		var nodeDeployment any
		nodeDeploymentErr := s.Kube.Request(ctx, http.MethodGet, "/apis/apps/v1/namespaces/livepeer/deployments/orchestrator", nil, &nodeDeployment)
		if applied && len(pods.Items) == 0 && transport.IsStatus(err, 404) && nodeErr == nil && len(nodePods.Items) == 0 && transport.IsStatus(nodeDeploymentErr, 404) {
			ack := digest
			if m.TerminalInputDigest != "" {
				ack = m.TerminalInputDigest
			}
			_, _, err = s.Control.Request(ctx, "removal-ack", map[string]any{"epoch": m.Epoch, "digest": strings.TrimPrefix(ack, "sha256:"), "connector_absent": true}, 16384)
			return err
		}
		return nil
	}
	ready := false
	actual := ""
	var deployment struct {
		Metadata struct {
			Generation int64 `json:"generation"`
		} `json:"metadata"`
		Spec struct {
			Template struct {
				Metadata struct {
					Annotations map[string]string `json:"annotations"`
				} `json:"metadata"`
			} `json:"template"`
		} `json:"spec"`
		Status struct {
			ObservedGeneration int64 `json:"observedGeneration"`
			UpdatedReplicas    int   `json:"updatedReplicas"`
			ReadyReplicas      int   `json:"readyReplicas"`
			AvailableReplicas  int   `json:"availableReplicas"`
		} `json:"status"`
	}
	if s.Kube.Request(ctx, http.MethodGet, "/apis/apps/v1/namespaces/livepeer/deployments/orchestrator", nil, &deployment) == nil {
		actual = deployment.Spec.Template.Metadata.Annotations["livepeer.io/config-sha256"]
		ready = applied && deployment.Status.ObservedGeneration == deployment.Metadata.Generation && deployment.Status.UpdatedReplicas == 1 && deployment.Status.ReadyReplicas == 1 && deployment.Status.AvailableReplicas == 1 && actual == m.ConfigDigest
		var pods struct {
			Items []struct {
				Metadata struct {
					DeletionTimestamp *string           `json:"deletionTimestamp"`
					Annotations       map[string]string `json:"annotations"`
				} `json:"metadata"`
				Status struct {
					Conditions []transport.Condition `json:"conditions"`
				} `json:"status"`
			} `json:"items"`
		}
		if s.Kube.Request(ctx, http.MethodGet, "/api/v1/namespaces/livepeer/pods?labelSelector=app%3Dorchestrator", nil, &pods) != nil {
			ready = false
		} else {
			count := 0
			podReady := false
			for _, p := range pods.Items {
				if p.Metadata.DeletionTimestamp == nil {
					count++
					actual = p.Metadata.Annotations["livepeer.io/config-sha256"]
					for _, c := range p.Status.Conditions {
						podReady = podReady || (c.Type == "Ready" && c.Status == "True")
					}
				}
			}
			ready = ready && count == 1 && podReady && actual == m.ConfigDigest
			if count != 1 {
				actual = ""
			}
		}
	}
	if ready {
		for _, endpoint := range []string{"http://orchestrator.livepeer.svc.cluster.local:8936/readyz", "http://orchestrator.livepeer.svc.cluster.local:8935/discovery"} {
			probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, endpoint, nil)
			resp, err := s.Control.Client.Do(req)
			if err != nil {
				ready = false
				cancel()
				break
			}
			if resp.StatusCode != 200 {
				ready = false
			}
			if strings.HasSuffix(endpoint, "/discovery") {
				var entries []struct {
					Address string `json:"address"`
				}
				b, err := readBounded(resp, 1<<20)
				if err != nil || transport.Decode(b, &entries) != nil || len(entries) != 1 || entries[0].Address != m.ServiceURL {
					ready = false
				}
			}
			resp.Body.Close()
			cancel()
		}
	}
	k3sVersion := ""
	if m.UpgradeVersion != "" {
		var nodes struct {
			Items []struct {
				Status struct {
					NodeInfo struct {
						Version string `json:"kubeletVersion"`
					} `json:"nodeInfo"`
				} `json:"status"`
			} `json:"items"`
		}
		err := s.Kube.Request(ctx, http.MethodGet, "/api/v1/nodes?labelSelector="+url.QueryEscape("livepeer.io/node-id="+m.NodeID), nil, &nodes)
		if err == nil && len(nodes.Items) == 1 {
			k3sVersion = nodes.Items[0].Status.NodeInfo.Version
		}
		ready = ready && k3sVersion == m.UpgradeVersion
	}
	reason := "applying"
	if ready {
		reason = "ready"
	}
	format := contract.BundleFormat
	if s.SystemWorkloads && (m.BundleFormat >= contract.SystemBundleFormat || s.systemCapable(m, revision)) {
		format = contract.SystemBundleFormat
	}
	reporter := s.Reporter
	if reporter == nil {
		reporter = s.Control
	}
	payload := map[string]any{"epoch": m.Epoch, "credential_version": m.CredentialVersion, "component": "runtime", "generation": m.Generation,
		"bundle_sha256": strings.TrimPrefix(revision, "sha256:"), "config_digest": actual, "k3s_version": k3sVersion, "ready": ready, "https": strings.HasPrefix(s.Control.ConfigURL, "https://"), "reason": reason, "bundle_format": format, "apps_error": appErrorReason(appError), "observed_at": time.Now().UTC()}
	if d := s.reporting.Load(); d != nil {
		payload["downloaded"], payload["downloaded_at"] = d.Downloaded, d.DownloadedAt
	}
	if s.deliveryFailure.Load() {
		payload["delivery_reason"] = "fetch_or_publication_failed"
	}
	_, _, err := reporter.Request(ctx, "status", payload, 16384)
	return err
}

func readBounded(resp *http.Response, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("probe_response_size")
	}
	return b, nil
}
func (s *Source) gc(ctx context.Context, current string) {
	pins := map[string]bool{current: true}
	names := []string{"livepeer", "livepeer-upgrade-plan"}
	if s.SystemWorkloads {
		for _, c := range systemComponents {
			names = append(names, "livepeer-"+c)
		}
	}
	for _, name := range names {
		var k fluxState
		if err := s.Kube.Request(ctx, http.MethodGet, fluxPath+name, nil, &k); err != nil {
			if transport.IsStatus(err, http.StatusNotFound) {
				continue
			}
			return // Retain every archive if any owner's references are unknown.
		}
		pins[k.Status.LastAppliedRevision], pins[k.Status.LastAttemptedRevision] = true, true
	}
	entries, _ := os.ReadDir(s.Store.Directory)
	type file struct {
		name string
		mod  time.Time
	}
	var files []file
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tar.gz") {
			if info, err := e.Info(); err == nil {
				mod := info.ModTime()
				if seen, err := os.Stat(filepath.Join(s.Store.Directory, strings.TrimSuffix(e.Name(), ".tar.gz")+".seen")); err == nil {
					mod = seen.ModTime()
				}
				files = append(files, file{e.Name(), mod})
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.After(files[j].mod) })
	for i, f := range files {
		if i >= 10 && !pins["sha256:"+strings.TrimSuffix(f.name, ".tar.gz")] && time.Since(f.mod) > time.Hour {
			_ = os.Remove(filepath.Join(s.Store.Directory, f.name))
			_ = os.Remove(filepath.Join(s.Store.Directory, strings.TrimSuffix(f.name, ".tar.gz")+".seen"))
		}
	}
}

// Validation errors may contain field paths or payload excerpts. Only bounded
// operational classifications cross the status wire.
func appErrorReason(message string) string {
	switch message {
	case "", "generation_failed", "unsupported_instance_mode", "unsupported_stop_signal", "resource_refused", "app_index", "app_unavailable", "app_digest", "app_identity", "app_groups", "app_group_identity", "app_resource_digest", "app_resource", "app_membership", "app_generation", "unexpected_app_input", "missing_app_input", "app_manifest", "stale_app_input", "invalid_legacy_app_input":
		return message
	default:
		return "invalid_app_payload"
	}
}
