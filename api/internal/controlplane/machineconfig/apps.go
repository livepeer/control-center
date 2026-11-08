package machineconfig

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
)

//go:embed app-management.yaml
var appManagement string

func DrainTarget(node, epoch string, state State) string {
	return artifact.Digest([]byte(fmt.Sprintf("%s/%s/%d/%s/%s", node, epoch, state.Generation, state.PendingConfigDigest, state.Target)))
}
func (s *Manager) runtimeSettings(ctx context.Context, m Machine, state *State) {
	// Retirement uses the delivered format captured by the deletion transaction.
	// A capability report alone must not promote its write-once terminal bundle.
	if m.Terminal {
		return
	}
	if s.config.RuntimeImage != "" {
		state.RuntimeImage = s.config.RuntimeImage
	}
	report, _, err := s.store.Report(ctx, m, "runtime")
	if err == nil && report.BundleFormat >= contract.BundleFormat && ValidConnectorImage(state.RuntimeImage) {
		state.BundleFormat = contract.BundleFormat
	}
}

// App lookup/rendering cannot suppress a management repair. Fallback retains its own intent identity.
func (s *Manager) prepareApps(ctx context.Context, m *Desired, lookupErr error) {
	if m.Apps != nil {
		m.RequestedAppsGeneration = m.Apps.Generation
	}
	p := appbundle.Unavailable()
	err := lookupErr
	if err == nil && m.Apps != nil {
		p, err = appbundle.Render(*m.Apps, appbundle.Options{StopSignals: m.StopSignals})
	}
	if err != nil {
		m.AppsError = "generation_failed"
		if err.Error() == "unsupported_instance_mode" || err.Error() == "unsupported_stop_signal" || err.Error() == "resource_refused" {
			m.AppsError = err.Error()
		}
		var prior []byte
		query := `SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`
		args := []any{m.NodeID}
		if m.Terminal {
			query = `SELECT retained_bundle FROM lpcc.enrollments WHERE node_id=$1 AND epoch=$2`
			args = append(args, m.Epoch)
		}
		if s.store.DB.QueryRowContext(ctx, query, args...).Scan(&prior) == nil {
			if files, e := artifact.Read(prior); e == nil {
				if metadata, e := transport.ReadMetadata(files["runtime.json"]); e == nil && metadata.NodeID == m.NodeID && metadata.Epoch == m.Epoch {
					if old, e := appbundle.Read(files, metadata); e == nil {
						p = old
					}
				}
			}
		}
	}
	m.AppPayload = &p
	m.Apps = p.Intent
}

func addManagedApps(files map[string][]byte, m Desired) error {
	if !ValidConnectorImage(m.RuntimeImage) {
		return fmt.Errorf("Go Runtime image is not pinned")
	}
	p := m.AppPayload
	if p == nil {
		value := appbundle.Unavailable()
		if m.Apps != nil {
			var err error
			value, err = appbundle.Render(*m.Apps, appbundle.Options{StopSignals: m.StopSignals})
			if err != nil {
				return err
			}
		}
		p = &value
	}
	// Keep the existing independent upgrade-plan path valid during migration.
	moved := map[string][]byte{}
	for name, data := range files {
		if name != "runtime.json" && !strings.HasPrefix(name, "upgrade-plan/") {
			delete(files, name)
			moved["management/"+name] = data
		}
	}
	for name, data := range moved {
		files[name] = data
	}
	files["kustomization.yaml"] = []byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- management\n")
	mode := "https"
	if strings.HasPrefix(m.ControlAPIURL, "http://") {
		mode = "development-http"
	}
	manifest := strings.NewReplacer("@NODE_ID@", m.NodeID, "@INSTALL_DIR@", m.InstallDir, "@RUNTIME_IMAGE@", m.RuntimeImage, "@CONTROL_TRANSPORT@", mode).Replace(appManagement)
	files["management/app-reconciler.yaml"] = []byte(manifest)
	files["management/kustomization.yaml"] = []byte(strings.Replace(string(files["management/kustomization.yaml"]), "patches:", "- app-reconciler.yaml\npatches:", 1))
	for name, data := range p.Files {
		files[name] = data
	}
	var metadata Runtime
	if err := json.Unmarshal(files["runtime.json"], &metadata); err != nil {
		return err
	}
	metadata.BundleFormat = contract.BundleFormat
	metadata.AppsGeneration = 0
	metadata.AppsDigest = ""
	if p.Intent != nil {
		metadata.AppsGeneration = p.Intent.Generation
		metadata.AppsDigest = p.Index.IntentDigest
	}
	metadata.AppsPayloadDigest = p.Digest()
	var err error
	files["runtime.json"], err = json.Marshal(metadata)
	if err == nil && m.Terminal {
		// Both phases are centrally rendered in the write-once terminal bundle.
		// The adapter selects cleanup only after the backend confirms all app receipts.
		cleanup := map[string][]byte{}
		for name, data := range files {
			cleanup[name] = data
		}
		finalMetadata := metadata
		finalMetadata.TerminalCleanup = true
		cleanup["runtime.json"], err = json.Marshal(finalMetadata)
		for name, data := range cleanup {
			files["terminal-cleanup/"+name] = data
		}
		for _, name := range []string{"orchestrator.yaml", "tunnel.yaml", "tunnel-network.yaml"} {
			data := m.RetainedFiles["management/"+name]
			if data == nil {
				data = m.RetainedFiles[name]
			}
			if data == nil {
				continue
			}
			files["management/"+name] = data
			if name == "tunnel-network.yaml" {
				files["management/"+name] = []byte(tunnelNetwork(m))
			}
			if name != "orchestrator.yaml" {
				files["management/kustomization.yaml"] = []byte(strings.Replace(string(files["management/kustomization.yaml"]), "patches:", "- "+name+"\npatches:", 1))
			}
		}
		if prior, e := transport.ReadMetadata(m.RetainedFiles["runtime.json"]); e == nil {
			metadata.ConfigDigest = prior.ConfigDigest
			files["runtime.json"], err = json.Marshal(metadata)
		}
	}
	return err
}
