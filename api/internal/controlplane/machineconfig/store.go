package machineconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
	"uuid"
)

var ErrFenced = errors.New("machine lease or generation superseded")

// Record keeps provider state separate from rollout state under one revision.
type Record struct {
	State
	Routing           json.RawMessage
	Revision          int64
	CredentialVersion int64
	Terminal          bool
}

type Store struct{ DB *sql.DB }

func (s Store) Load(ctx context.Context, node, epoch string) (Record, error) {
	var r Record
	var raw []byte
	err := s.DB.QueryRowContext(ctx, `SELECT s.rollout,s.state,s.revision,e.credential_version,e.retired_at IS NOT NULL FROM lpcc.machine_states s JOIN lpcc.enrollments e USING(node_id,epoch) WHERE s.node_id=$1 AND s.epoch=$2`, node, epoch).Scan(&raw, &r.Routing, &r.Revision, &r.CredentialVersion, &r.Terminal)
	if err == nil {
		err = json.Unmarshal(raw, &r.State)
	}
	return r, err
}

// Lease serializes configuration and provider transitions for one enrollment.
type Lease struct {
	Record
	Machine Machine
	ID      string
	store   Store
}

func (s Store) Claim(ctx context.Context, m Machine, initial json.RawMessage, due bool) (*Lease, error) {
	if len(initial) == 0 {
		initial = json.RawMessage(`{}`)
	}
	state, _ := json.Marshal(InitialState(m.Terminal))
	insert := `INSERT INTO lpcc.machine_states(node_id,epoch,state,rollout) SELECT $1,$2,$3,$4 FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2 FOR KEY SHARE ON CONFLICT DO NOTHING`
	if m.Terminal {
		insert = `INSERT INTO lpcc.machine_states(node_id,epoch,state,rollout) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`
	}
	if _, err := s.DB.ExecContext(ctx, insert, m.NodeID, m.Epoch, initial, string(state)); err != nil {
		return nil, err
	}
	l := &Lease{Machine: m, ID: uuid.New().String(), store: s}
	var raw []byte
	err := s.DB.QueryRowContext(ctx, `UPDATE lpcc.machine_states SET lease_id=$3,lease_until=now()+interval '90 seconds' WHERE node_id=$1 AND epoch=$2 AND (NOT $4 OR next_attempt_at<=now()) AND (lease_until IS NULL OR lease_until<now()) RETURNING rollout,state,revision`, m.NodeID, m.Epoch, l.ID, due).Scan(&raw, &l.Routing, &l.Revision)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &l.State); err != nil {
		l.Release(ctx)
		return nil, err
	}
	err = s.DB.QueryRowContext(ctx, `SELECT retired_at IS NOT NULL,credential_version FROM lpcc.enrollments WHERE node_id=$1 AND epoch=$2`, m.NodeID, m.Epoch).Scan(&l.Machine.Terminal, &l.Machine.CredentialVersion)
	if err != nil {
		l.Release(ctx)
		return nil, err
	}
	l.Record.CredentialVersion = l.Machine.CredentialVersion
	l.Record.Terminal = l.Machine.Terminal
	return l, nil
}

// Write permits a provider to bind its resource and credential in the same
// transaction as the fenced state update. Apply the returned revision on commit.
func (l *Lease) Write(ctx context.Context, tx *sql.Tx, state State, routing json.RawMessage, active bool) (int64, error) {
	raw, err := json.Marshal(state)
	if err != nil {
		return 0, err
	}
	query := `UPDATE lpcc.machine_states SET state=$4,rollout=$6,revision=revision+1,lease_until=now()+interval '90 seconds' WHERE node_id=$1 AND epoch=$2 AND lease_id=$3 AND revision=$5 AND lease_until>now() AND (NOT $7 OR rollout->>'lifecycle'='active') AND EXISTS(SELECT FROM lpcc.enrollments e WHERE e.node_id=$1 AND e.epoch=$2 AND e.credential_version=$8) RETURNING revision`
	args := []any{l.Machine.NodeID, l.Machine.Epoch, l.ID, routing, l.Revision, string(raw), active, l.Machine.CredentialVersion}
	var row *sql.Row
	if tx == nil {
		row = l.store.DB.QueryRowContext(ctx, query, args...)
	} else {
		row = tx.QueryRowContext(ctx, query, args...)
	}
	var revision int64
	err = row.Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrFenced
	}
	return revision, err
}

func (l *Lease) Save(ctx context.Context) error {
	revision, err := l.Write(ctx, nil, l.State, l.Routing, false)
	if err == nil {
		l.Revision = revision
	}
	return err
}

func (l *Lease) Release(ctx context.Context) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_, _ = l.store.DB.ExecContext(cleanup, `UPDATE lpcc.machine_states SET lease_id=NULL,lease_until=NULL WHERE node_id=$1 AND epoch=$2 AND lease_id=$3`, l.Machine.NodeID, l.Machine.Epoch, l.ID)
}

func (l *Lease) Finish(ctx context.Context, failed bool) {
	delay := 1.0
	if failed {
		delay = 5
	}
	_, _ = l.store.DB.ExecContext(ctx, `UPDATE lpcc.machine_states SET lease_id=NULL,lease_until=NULL,failures=CASE WHEN $4 THEN LEAST(failures+1,8) ELSE 0 END,next_attempt_at=now()+make_interval(secs=>LEAST(300,$5*power(2,CASE WHEN $4 THEN LEAST(failures,6) ELSE 0 END))+random()) WHERE node_id=$1 AND epoch=$2 AND lease_id=$3`, l.Machine.NodeID, l.Machine.Epoch, l.ID, failed, delay)
}

func (s Store) Report(ctx context.Context, m Machine, component string) (Report, time.Time, error) {
	var r Report
	var raw []byte
	var at time.Time
	err := s.DB.QueryRowContext(ctx, `SELECT report,received_at FROM lpcc.machine_reports WHERE node_id=$1 AND epoch=$2 AND component=$3 AND credential_version=$4`, m.NodeID, m.Epoch, component, m.CredentialVersion).Scan(&raw, &at)
	if err == nil {
		err = json.Unmarshal(raw, &r)
		at = ObservationTime(r, at)
		if component == "connector" && (r.ConnectorObservedAt.IsZero() || !time.Now().Before(r.ConnectorExpiresAt)) {
			at = time.Time{}
		}
	}
	return r, at, err
}
