package machineconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
	"github.com/livepeer/control-center/schema"
)

func DrainTarget(node string, state State) string {
	return artifact.Digest([]byte(fmt.Sprintf("%s/%d/%s/%s", node, state.Generation, state.PendingConfigDigest, state.Target)))
}

// A safe fallback may have delivered withdrawals at the requested generation.
// Repair receives a fresh generation so older runtimes accept the full intent.
func (s *Manager) fenceAppRepair(ctx context.Context, m *Desired, revision *int64) error {
	if m.Terminal || m.AppsError != "" || m.Apps == nil || m.AppPayload == nil {
		return nil
	}
	var prior []byte
	if e := s.store.DB.QueryRowContext(ctx, `SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, m.NodeID).Scan(&prior); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		return e
	}
	files, e := artifact.Read(prior)
	if e != nil {
		return e
	}
	old, e := transport.ReadMetadata(files["runtime.json"])
	if e != nil {
		return e
	}
	if old.NodeID != m.NodeID || old.AppsError == "" || old.AppsGeneration != m.Apps.Generation || old.AppsDigest == m.AppPayload.Index.IntentDigest {
		return nil
	}
	if e = s.store.DB.QueryRowContext(ctx, `UPDATE lpcc.machine_states SET apps_generation=apps_generation+1,revision=revision+1 WHERE node_id=$1 AND revision=$2 AND apps_generation=$3 AND EXISTS(SELECT FROM lpcc.enrollments WHERE node_id=$1 AND credential_version=$4) RETURNING apps_generation,revision`, m.NodeID, *revision, m.Apps.Generation, m.CredentialVersion).Scan(&m.Apps.Generation, revision); e != nil {
		return e
	}
	p, e := appbundle.Render(*m.Apps, appbundle.Options{StopSignals: m.StopSignals})
	if e != nil {
		return e
	}
	m.RequestedAppsGeneration = m.Apps.Generation
	m.AppPayload = &p
	return nil
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
		if m.Terminal {
			query = `SELECT retained_bundle FROM lpcc.enrollments WHERE node_id=$1`
		}
		if s.store.DB.QueryRowContext(ctx, query, m.NodeID).Scan(&prior) == nil {
			if files, e := artifact.Read(prior); e == nil {
				if metadata, e := transport.ReadMetadata(files["runtime.json"]); e == nil && metadata.NodeID == m.NodeID {
					if old, e := appbundle.Read(files, metadata); e == nil {
						p = old
						if m.Apps != nil && old.Intent != nil {
							safeSet := *old.Intent
							safeSet.Entries = append([]schema.AppAssignment(nil), old.Intent.Entries...)
							withdrawal := false
							for _, a := range m.Apps.Entries {
								if a.Desired != "absent" {
									continue
								}
								for i, prior := range safeSet.Entries {
									if prior.RevisionID == a.RevisionID && (prior.Desired != "absent" || a.Generation > prior.Generation) {
										safeSet.Entries[i] = a
										withdrawal = true
									}
								}
							}
							if withdrawal {
								safeSet.Generation = m.Apps.Generation
								if safe, e := appbundle.Render(safeSet, appbundle.Options{StopSignals: true}); e == nil {
									p = safe
								}
							}
						}
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
		return fmt.Errorf("runtime image is not pinned")
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
