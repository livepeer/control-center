package machineconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/onchain"
	"github.com/livepeer/control-center/schema"
	"log/slog"
	"time"
)

type Config struct {
	APIURL                  string
	Connector               ConnectorConfig
	DrainTimeout, StatusTTL time.Duration
	RuntimeImage            string
	NodeDrainTimeout        *time.Duration
	NodeImage               string
	StopSignals             bool
}

type Dependencies struct {
	Onchain  func(context.Context, Machine) (onchain.Config, error)
	DB       *sql.DB
	Logger   *slog.Logger
	Exposure func(json.RawMessage) (*Exposure, error)
	Build    func(Desired) ([]byte, string, error)
}

type Manager struct {
	config Config
	store  Store
	deps   Dependencies
}

func New(config Config, deps Dependencies) *Manager {
	if config.StatusTTL == 0 {
		config.StatusTTL = 2 * time.Minute
	}
	if deps.Build == nil {
		deps.Build = Build
	}
	return &Manager{config: config, store: Store{deps.DB}, deps: deps}
}

func (s *Manager) Desired(m Machine, state State, exposure *Exposure) Desired {
	connector := s.config.Connector
	connector.Image = state.ConnectorImage
	if s.config.Connector.Image != "" {
		connector.Image = s.config.Connector.Image
	}
	p := onchain.Offchain()
	var err error
	if s.deps.Onchain != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		p, err = s.deps.Onchain(ctx, m)
		cancel()
	}

	d := Desired{Onchain: p, OnchainError: err, Machine: m, State: state, Exposure: exposure, Connector: connector, ControlAPIURL: s.config.APIURL, RuntimeImage: s.config.RuntimeImage, NodeImage: s.config.NodeImage, NodeDrainTimeout: s.config.NodeDrainTimeout, StopSignals: s.config.StopSignals, DrainTimeout: s.drainTimeout()}
	if p.Onchain() && s.store.DB != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		r, at, e := s.store.Report(ctx, m, "runtime")
		cancel()
		d.OnchainReady = e == nil && !r.ClockUncertain && time.Since(ObservationTime(r, at)) <= s.config.StatusTTL && r.Ready && r.Onchain != nil && r.Onchain.Ready && r.Onchain.Applied && r.Onchain.Generation == p.Generation && r.ConfigDigest == Digest(d)
	}
	return d
}
func (s *Manager) drainTimeout() time.Duration {
	if s.config.DrainTimeout <= 0 {
		return 12 * time.Hour
	}
	return s.config.DrainTimeout
}

func (s *Manager) Reconcile(ctx context.Context) error {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT node_id,install_dir,k3s_version,credential_version,retired_at IS NOT NULL FROM lpcc.enrollments ORDER BY node_id`)
	if err != nil {
		return err
	}
	var machines []Machine
	for rows.Next() {
		var m Machine
		if err = rows.Scan(&m.NodeID, &m.InstallDir, &m.K3sVersion, &m.CredentialVersion, &m.Terminal); err != nil {
			rows.Close()
			return err
		}
		machines = append(machines, m)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, m := range machines {
		if err = s.reconcile(ctx, m); err != nil && !errors.Is(err, ErrFenced) {
			return err
		}
	}
	return nil
}

func (s *Manager) reconcile(ctx context.Context, m Machine) error {
	record, err := s.store.Load(ctx, m.NodeID)
	var lease *Lease
	defer func() {
		if lease != nil {
			lease.Release(ctx)
		}
	}()
	if errors.Is(err, sql.ErrNoRows) {
		lease, err = s.store.Claim(ctx, m, nil, false)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		record = lease.Record
	} else if err != nil {
		return err
	}
	m.CredentialVersion = record.CredentialVersion
	m.Terminal = record.Terminal
	before := record.State
	s.connectorSettings(m, &record)
	exposure, remove, err := s.planManagement(ctx, m, &record)
	if err != nil {
		return err
	}
	if lease == nil && (record.State != before || remove) {
		lease, err = s.store.Claim(ctx, m, nil, false)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		record = lease.Record
		m = lease.Machine
		before = record.State
		s.connectorSettings(m, &record)
		exposure, remove, err = s.planManagement(ctx, m, &record)
		if err != nil {
			return err
		}
	}
	if lease != nil {
		lease.State = record.State
		if remove {
			removed, e := s.finishRemoval(ctx, lease)
			if e != nil {
				return e
			}
			if removed {
				m.Terminal = true
				lease.Record, e = s.store.Load(ctx, m.NodeID)
				if e != nil {
					return e
				}
				lease.State.Lifecycle = "removed"
			}
		}
		if lease.State != before && !m.Terminal {
			if err = lease.Save(ctx); err != nil {
				return err
			}
		}
		record = lease.Record
		// Rendering and publication use the revision fence, not the provider lease.
		lease.Release(ctx)
		lease = nil
	}
	// An enrolled machine with no assignments still needs an authoritative empty intent.
	// Reserve its first generation before delivery, so the first edit advances beyond it.
	var revision int64
	err = s.store.DB.QueryRowContext(ctx, `UPDATE lpcc.machine_states SET apps_generation=1,revision=revision+1 WHERE node_id=$1 AND revision=$2 AND apps_generation=0 AND EXISTS(SELECT FROM lpcc.enrollments WHERE node_id=$1 AND credential_version=$3) RETURNING revision`, m.NodeID, record.Revision, m.CredentialVersion).Scan(&revision)
	if err == nil {
		record.Revision = revision
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	desired := s.Desired(m, record.State, exposure)
	if m.Terminal {
		var prior []byte
		if s.store.DB.QueryRowContext(ctx, `SELECT retained_bundle FROM lpcc.enrollments WHERE node_id=$1`, m.NodeID).Scan(&prior) == nil {
			desired.RetainedFiles, _ = artifact.Read(prior)
		}
	}
	desired.Apps, err = machineapps.Snapshot(ctx, s.store.DB, m.NodeID)
	s.prepareApps(ctx, &desired, err)
	data, digest, err := s.deps.Build(desired)
	if err != nil {
		s.deps.Logger.Error("keeping previous configuration", "node_id", m.NodeID, "reason", "generation_failed")
		_, _ = s.store.DB.ExecContext(ctx, `UPDATE lpcc.machine_states SET apps_error='generation_failed' WHERE node_id=$1 AND revision=$2`, m.NodeID, record.Revision)
		return nil
	}
	return s.publish(ctx, m, record.Revision, data, digest, desired.Apps, desired.AppsError)
}

func (s *Manager) planManagement(ctx context.Context, m Machine, record *Record) (*Exposure, bool, error) {
	before := record.State
	exposure, remove, err := s.plan(ctx, m, record)
	if err == nil {
		return exposure, remove, err
	}
	// Lifecycle observations can hold a disruptive target, but cannot veto delivery
	// of a management repair. Reuse the last delivered workload and route identity.
	old, manifest, readErr := s.applied(ctx, m)
	if readErr != nil {
		return nil, false, err
	}
	record.State = before
	record.HeldOrchestrator = manifest
	record.HeldOnchain = onchainJSON(old.Onchain)
	s.holdUpgrade(ctx, m, &record.State)
	record.RolloutReason = "lifecycle_observation_failed"
	if old.IngressDigest != "" {
		exposure = &Exposure{TunnelID: old.TunnelID, ServiceURL: old.ServiceURL, ProxyURLTemplate: old.ProxyURLTemplate, DiscoveryURL: old.DiscoveryURL, IngressDigest: old.IngressDigest, CredentialGeneration: old.TokenGeneration, ProviderVersion: old.ProviderVersion}
	} else {
		exposure = nil
	}
	return exposure, false, nil
}

// Plan from a snapshot first. Mutations are re-planned under a current lease.
func (s *Manager) plan(ctx context.Context, m Machine, record *Record) (*Exposure, bool, error) {
	var exposure *Exposure
	var err error
	if s.deps.Exposure != nil {
		exposure, err = s.deps.Exposure(record.Routing)
		if err != nil {
			return nil, false, err
		}
	}
	if m.Terminal {
		return exposure, false, nil
	}
	if (record.Lifecycle == "draining" || record.Target != "") && record.HeldOrchestrator == "" {
		old, manifest, e := s.applied(ctx, m)
		if e != nil {
			return nil, false, e
		}
		record.HeldOrchestrator = manifest
		record.HeldOnchain = onchainJSON(old.Onchain)
	}
	if record.Lifecycle == "draining" {
		done, e := s.removalComplete(ctx, m, &record.State)
		return exposure, done, e
	}
	if record.Target == "" {
		_, err = s.Gate(ctx, m, &record.State, s.Desired(m, record.State, exposure))
	}
	return exposure, false, err
}

// Publish serializes enrollment changes and artifact writes before reading the
// shared rollout/provider revision, so a lock wait cannot publish a stale plan.
func (s *Manager) publish(ctx context.Context, m Machine, revision int64, data []byte, digest string, apps *schema.AppAssignmentSetV1, appsError string) error {
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var present int
	if m.Terminal {
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM lpcc.enrollments WHERE node_id=$1 AND credential_version=$2 AND retired_at IS NOT NULL FOR UPDATE`, m.NodeID, m.CredentialVersion).Scan(&present)
	} else {
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM lpcc.machines WHERE node_id=$1 AND credential_version=$2 FOR UPDATE`, m.NodeID, m.CredentialVersion).Scan(&present)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !m.Terminal {
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM lpcc.machine_configs WHERE node_id=$1 FOR UPDATE`, m.NodeID).Scan(&present)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM lpcc.machine_states WHERE node_id=$1 FOR SHARE`, m.NodeID).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if current != revision {
		return nil
	}
	if m.Terminal {
		result, e := tx.ExecContext(ctx, `UPDATE lpcc.enrollments SET terminal_bundle=$2,terminal_sha256=$3 WHERE node_id=$1 AND terminal_bundle IS NULL`, m.NodeID, data, digest)
		if e != nil {
			return e
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			return nil
		}
	} else if _, err = tx.ExecContext(ctx, `INSERT INTO lpcc.machine_configs(node_id,bundle,sha256) VALUES($1,$2,$3) ON CONFLICT(node_id) DO UPDATE SET bundle=EXCLUDED.bundle,sha256=EXCLUDED.sha256,generated_at=now() WHERE lpcc.machine_configs.sha256<>EXCLUDED.sha256`, m.NodeID, data, digest); err != nil {
		return err
	}
	if err = machineapps.RecordDelivery(ctx, tx, apps, digest, m.Terminal); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE lpcc.machine_states SET apps_error=NULLIF($2,'') WHERE node_id=$1 AND apps_error IS DISTINCT FROM NULLIF($2,'')`, m.NodeID, appsError); err != nil {
		return err
	}
	return tx.Commit()
}
