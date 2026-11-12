package machineconfig

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
)

func DrainTarget(node, epoch string, state State) string {
	return artifact.Digest([]byte(fmt.Sprintf("%s/%s/%d/%s/%s", node, epoch, state.Generation, state.PendingConfigDigest, state.Target)))
}
func (s *Manager) connectorSettings(m Machine, record *Record) {
	if m.Terminal {
		return
	}
	if s.config.Connector.Image != "" {
		record.ConnectorImage = s.config.Connector.Image
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
		for _, a := range m.Apps.Entries {
			if a.Revision != nil && a.Desired == "present" {
				if e := m.Onchain.Compatible(a.Revision.Definition); e != nil {
					err = e
					break
				}
			}
		}
	}
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
	for name, data := range p.Files {
		files[name] = data
	}
	metadata := DesiredRuntime(m)
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
		for _, name := range []string{"system/connector/tunnel.yaml", "system/connector/network.yaml"} {
			if data := m.RetainedFiles[name]; data != nil {
				files[name] = data
			}
		}
		if prior, e := transport.ReadMetadata(m.RetainedFiles["runtime.json"]); e == nil {
			metadata.ConfigDigest = prior.ConfigDigest
			metadata.Onchain = prior.Onchain
			metadata.OnchainActive = false
			// Retained connectors may restart while the backend still authorizes app cleanup.
			metadata.TunnelID, metadata.TokenGeneration, metadata.ProviderVersion, metadata.ConnectorTokenRef = prior.TunnelID, prior.TokenGeneration, prior.ProviderVersion, prior.ConnectorTokenRef
			files["runtime.json"], err = json.Marshal(metadata)
		}
	}
	return err
}
