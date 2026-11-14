// Package httpsource delivers management artifacts independently of app reconciliation.
package httpsource

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/onchain"
	"github.com/livepeer/control-center/runtime/transport"
)

const SourceName = "livepeer-service"
const fluxPath = "/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/flux-system/kustomizations/"

type Kubernetes interface {
	Request(context.Context, string, string, any, any) error
	Publish(context.Context, string, *transport.Artifact, bool, string) error
}
type Source struct {
	Onchain         func(context.Context, contract.Metadata, bool, bool, string) *onchain.Observation
	Control         *transport.Control
	Reporter        transport.Requester
	Kube            Kubernetes
	Store           artifact.Store
	ArtifactURL     string
	IdentityFile    string
	mu              sync.Mutex
	published       atomic.Pointer[delivery]
	reporting       atomic.Pointer[delivery]
	deliveryFailure atomic.Bool

	InstalledSoftwareFile string
	NodeName              string
}

type delivery struct {
	Metadata     contract.Metadata
	Digest       string
	AppError     string
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
	i, err := transport.ReadIdentity(s.IdentityFile)
	return err == nil && i.NodeID == m.NodeID && i.CredentialVersion == m.CredentialVersion
}

// Report runs independently of downloads, credential requests and consumer observations.
func (s *Source) Report(ctx context.Context) error {
	d := s.reporting.Load()
	if d == nil || !s.installed(d.Metadata) {
		return nil
	}
	return s.report(ctx, d.Metadata, d.Digest, d.AppError)
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
	if m.NodeID != s.Control.NodeID || m.NodeID != headers.Get("X-Livepeer-Node-ID") || headers.Get("X-Livepeer-Credential-Version") != formatInt(m.CredentialVersion) {
		return errors.New("enrollment_mismatch")
	}
	i, err := transport.ReadIdentity(s.IdentityFile)
	if err != nil {
		return err
	}
	if i.NodeID != m.NodeID || i.CredentialVersion != m.CredentialVersion {
		return errors.New("installed_identity_mismatch")
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
		if old.NodeID != m.NodeID || (old.Terminal && !m.Terminal) || (!m.Terminal && old.Generation > m.Generation) {
			return errors.New("stale_enrollment")
		}
	} else if !os.IsNotExist(err) {
		return errors.New("cache_identity_unavailable")
	}
	if m.Terminal {
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
			if e != nil || !final.Terminal || !final.TerminalCleanup || final.NodeID != m.NodeID || final.Generation != m.Generation || final.CredentialVersion != m.CredentialVersion || final.AppsDigest != m.AppsDigest || final.AppsGeneration != m.AppsGeneration {
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
	inputDigest := artifact.Digest(data)
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
	d := &delivery{Metadata: m, Digest: digest, AppError: delivered.AppsError}
	if appErr == nil {
		d.Downloaded = &contract.StageIdentity{Generation: m.AppsGeneration, AppsDigest: m.AppsDigest, ArtifactDigest: inputDigest}
		d.DownloadedAt = time.Now().UTC()
		if prior := s.reporting.Load(); prior != nil && prior.Metadata.NodeID == m.NodeID && prior.Downloaded != nil && *prior.Downloaded == *d.Downloaded {
			d.DownloadedAt = prior.DownloadedAt
		}
	} else if prior := s.reporting.Load(); prior != nil && prior.Metadata.NodeID == m.NodeID {
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
	p, err := appbundle.Read(files, m)
	if err != nil {
		return err
	}
	if !p.Index.Available {
		return errors.New("app_input_unavailable")
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
	Status struct {
		ObservedGeneration    int64                 `json:"observedGeneration"`
		LastAppliedRevision   string                `json:"lastAppliedRevision"`
		LastAttemptedRevision string                `json:"lastAttemptedRevision"`
		Conditions            []transport.Condition `json:"conditions"`
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
	unchanged := digest != "" && k.Status.LastAppliedRevision != digest && s.componentUnchanged(name, k.Status.LastAppliedRevision, digest)
	return k.Status.ObservedGeneration == k.Metadata.Generation && (current || unchanged), k.Status.LastAppliedRevision
}
func (s *Source) report(ctx context.Context, m contract.Metadata, digest, appError string) error {
	observedAt := time.Now().UTC()
	applied, revision := s.applied(ctx, "livepeer-node", digest)
	if m.Terminal {
		if !m.TerminalCleanup {
			return nil
		}
		upgrade, _ := s.applied(ctx, "livepeer-upgrade-plan", digest)
		connector, _ := s.applied(ctx, "livepeer-connector", digest)
		applied = applied && upgrade && connector
		var pods struct {
			Items []json.RawMessage `json:"items"`
		}
		if s.Kube.Request(ctx, http.MethodGet, "/api/v1/namespaces/flux-system/pods?labelSelector=app%3Dlivepeer-tunnel", nil, &pods) != nil {
			return errors.New("terminal_observation")
		}
		var deployment any
		err := s.Kube.Request(ctx, http.MethodGet, "/apis/apps/v1/namespaces/flux-system/deployments/livepeer-tunnel", nil, &deployment)
		nodePod, nodeErr := transport.ObserveNode(ctx, s.Kube)
		var nodeDeployment any
		nodeDeploymentErr := s.Kube.Request(ctx, http.MethodGet, "/apis/apps/v1/namespaces/livepeer/deployments/orchestrator", nil, &nodeDeployment)
		if applied && len(pods.Items) == 0 && transport.IsStatus(err, 404) && nodeErr == nil && nodePod.Absent && transport.IsStatus(nodeDeploymentErr, 404) {
			ack := digest
			if m.TerminalInputDigest != "" {
				ack = m.TerminalInputDigest
			}
			_, _, err = s.Control.Request(ctx, "removal-ack", map[string]any{"node_id": m.NodeID, "digest": strings.TrimPrefix(ack, "sha256:"), "connector_absent": true}, 16384)
			return err
		}
		return nil
	}
	ingressReady, ingressDigest := false, ""
	if m.IngressConfigDigest != "" {
		ingressApplied, _ := s.applied(ctx, "livepeer-ingress", digest)
		var auth struct {
			Spec struct {
				Template struct {
					Metadata struct {
						Annotations map[string]string `json:"annotations"`
					} `json:"metadata"`
				} `json:"template"`
			} `json:"spec"`
			Metadata struct {
				Generation int64 `json:"generation"`
			} `json:"metadata"`
			Status struct {
				ObservedGeneration int64 `json:"observedGeneration"`
				UpdatedReplicas    int   `json:"updatedReplicas"`
				ReadyReplicas      int   `json:"readyReplicas"`
			} `json:"status"`
		}
		if s.Kube.Request(ctx, http.MethodGet, "/apis/apps/v1/namespaces/livepeer/deployments/ingress-auth", nil, &auth) == nil {
			ingressDigest = auth.Spec.Template.Metadata.Annotations["livepeer.io/ingress-config-sha256"]
			ingressReady = ingressApplied && ingressDigest == m.IngressConfigDigest && auth.Status.ObservedGeneration == auth.Metadata.Generation && auth.Status.UpdatedReplicas == 1 && auth.Status.ReadyReplicas == 1
		}
	}
	ready := false
	actual := ""
	podUID := ""
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
		pod, err := transport.ObserveNode(ctx, s.Kube)
		podUID, actual = pod.UID, pod.ConfigDigest
		ready = ready && err == nil && pod.UID != "" && pod.Ready && actual == m.ConfigDigest
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
	if m.Onchain.Onchain() && applied && actual == m.ConfigDigest && !ready {
		reason = "onchain_not_ready"
	}
	if ready {
		reason = "ready"
	}
	reporter := s.Reporter
	if reporter == nil {
		reporter = s.Control
	}
	payload := map[string]any{"node_id": m.NodeID, "credential_version": m.CredentialVersion, "component": "runtime", "generation": m.Generation,
		"ingress_ready": ingressReady, "ingress_config_digest": ingressDigest, "bundle_sha256": strings.TrimPrefix(revision, "sha256:"), "config_digest": actual, "k3s_version": k3sVersion, "ready": ready, "https": strings.HasPrefix(s.Control.ConfigURL, "https://"), "reason": reason, "bundle_format": contract.BundleFormat, "apps_error": appErrorReason(appError), "observed_at": observedAt, "software": s.software(ctx, s.NodeName)}
	if s.Onchain != nil {
		payload["onchain"] = s.Onchain(ctx, m, applied && actual == m.ConfigDigest && podUID != "", ready, podUID)
	}
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
	for _, c := range []string{"node", "connector", "ingress", "app-reconciler", "upgrade-controller"} {
		names = append(names, "livepeer-"+c)
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
	_ = s.Store.Collect(pins, 1<<63-1, time.Now())
}

// Validation errors may contain field paths or payload excerpts. Only bounded
// operational classifications cross the status wire.
func appErrorReason(message string) string {
	switch message {
	case "", "generation_failed", "unsupported_instance_mode", "unsupported_stop_signal", "resource_refused", "app_index", "app_unavailable", "app_digest", "app_identity", "app_groups", "app_group_identity", "app_resource_digest", "app_resource", "app_membership", "app_generation", "stale_app_input":
		return message
	default:
		return "invalid_app_payload"
	}
}
