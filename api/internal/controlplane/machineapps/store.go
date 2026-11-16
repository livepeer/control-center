// Package machineapps persists placement intent and its delivery/completion evidence.
// It does not create workloads or implement Runtime lifecycle policy.
package machineapps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/livepeer/control-center/schema"
)

type Querier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type Version struct {
	Requested *schema.AppAssignment `json:"requested,omitempty"`
	schema.AppAssignment
	ActorID        string     `json:"actor_id"`
	AppName        string     `json:"app_name"`
	RevisionNumber int64      `json:"revision_number"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at"`
	Failure        string     `json:"failure,omitempty"`
	ObservedAt     *time.Time `json:"observed_at"`
}

func ReadVersion(row interface{ Scan(...any) error }) (Version, error) {
	var v Version
	var raw, requested []byte
	err := row.Scan(&raw, &v.ActorID, &v.CreatedAt, &v.CompletedAt, &v.Failure, &v.ObservedAt, &v.AppName, &v.RevisionNumber, &requested)
	if err == nil {
		err = json.Unmarshal(raw, &v.AppAssignment)
		if err == nil && len(requested) > 0 {
			v.Requested = new(schema.AppAssignment)
			err = json.Unmarshal(requested, v.Requested)
		}
	}
	return v, err
}

func ReadVersions(rows *sql.Rows) ([]Version, error) {
	defer rows.Close()
	out := []Version{}
	for rows.Next() {
		v, err := ReadVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

const VersionColumns = `v.intent,v.actor_id,v.created_at,c.received_at,CASE WHEN c.received_at IS NULL THEN COALESCE(d.reason,'') ELSE '' END,COALESCE(c.received_at,d.received_at),r.app_name,r.revision,q.intent`
const VersionJoins = ` JOIN lpcc.app_revisions r ON r.revision_id=v.revision_id
 LEFT JOIN lpcc.machine_app_requests q ON q.node_id=v.node_id AND q.revision_id=v.revision_id
 LEFT JOIN lpcc.machine_app_completions c ON c.node_id=v.node_id AND c.revision_id=v.revision_id AND c.generation=v.generation
 LEFT JOIN lpcc.machine_app_diagnostics d ON d.node_id=v.node_id AND d.revision_id=v.revision_id AND d.generation=v.generation `

func Head(ctx context.Context, q Querier, node, id string) (Version, error) {
	return ReadVersion(q.QueryRowContext(ctx, `SELECT `+VersionColumns+` FROM lpcc.machine_app_heads v `+VersionJoins+` WHERE v.node_id=$1 AND v.revision_id=$2`, node, id))
}

func AtGeneration(ctx context.Context, q Querier, node, id string, generation int64) (Version, error) {
	return ReadVersion(q.QueryRowContext(ctx, `SELECT `+VersionColumns+` FROM lpcc.machine_app_versions v `+VersionJoins+` WHERE v.node_id=$1 AND v.revision_id=$2 AND v.generation=$3`, node, id, generation))
}

func Heads(ctx context.Context, q Querier, node string) ([]Version, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+VersionColumns+` FROM lpcc.machine_app_heads v `+VersionJoins+` WHERE v.node_id=$1 ORDER BY v.revision_id`, node)
	if err != nil {
		return nil, err
	}
	return ReadVersions(rows)
}

func CleanupComplete(ctx context.Context, q Querier, node string, p schema.AppStartAfter) (bool, error) {
	var yes bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.machine_app_completions WHERE node_id=$1 AND revision_id=$2 AND generation=$3 AND phase='removed')`, node, p.RevisionID, p.Generation).Scan(&yes)
	return yes, err
}

// StartAllowedSQL and RemovalCompleteSQL share the delivery snapshot's exact
// cleanup fence with the internal secrets authorization projection (alias v).
const StartAllowedSQL = `CASE WHEN v.intent->'start_after' IS NULL OR v.intent->'start_after'='null'::jsonb
 THEN COALESCE((v.intent->>'start_allowed')::boolean,false)
 ELSE EXISTS(SELECT FROM lpcc.machine_app_completions p WHERE p.node_id=v.node_id
 AND p.revision_id=(v.intent#>>'{start_after,source_revision_id}')::uuid
 AND p.generation=(v.intent#>>'{start_after,source_removal_generation}')::bigint AND p.phase='removed') END`

const RemovalCompleteSQL = `(v.intent->>'desired'='absent' AND EXISTS(SELECT FROM lpcc.machine_app_completions c
 WHERE c.node_id=v.node_id AND c.revision_id=v.revision_id AND c.generation=v.generation))`

func Snapshot(ctx context.Context, q Querier, node string) (*schema.AppAssignmentSetV1, error) {
	rows, err := q.QueryContext(ctx, `SELECT s.apps_generation,v.intent,`+StartAllowedSQL+`
 FROM lpcc.machine_states s LEFT JOIN lpcc.machine_app_heads v ON v.node_id=s.node_id
 AND NOT `+RemovalCompleteSQL+` WHERE s.node_id=$1 AND s.apps_generation>0 ORDER BY v.revision_id`, node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var set *schema.AppAssignmentSetV1
	for rows.Next() {
		var gen int64
		var raw []byte
		var allowed bool
		if err = rows.Scan(&gen, &raw, &allowed); err != nil {
			return nil, err
		}
		if set == nil {
			set = &schema.AppAssignmentSetV1{SchemaVersion: 1, NodeID: node, Generation: gen, Entries: []schema.AppAssignment{}}
		}
		if raw == nil {
			continue
		}
		var a schema.AppAssignment
		if err = json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
		a.StartAllowed = allowed
		set.Entries = append(set.Entries, a)
	}
	return set, rows.Err()
}

func Append(ctx context.Context, tx *sql.Tx, node, actor string, a schema.AppAssignment) error {
	raw, e := json.Marshal(a)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO lpcc.machine_app_requests(node_id,revision_id,intent) VALUES($1,$2,$3) ON CONFLICT(node_id,revision_id) DO UPDATE SET intent=EXCLUDED.intent`, node, a.RevisionID, string(raw)); e != nil {
		return e
	}
	var denied bool
	e = tx.QueryRowContext(ctx, `SELECT COALESCE(p.denied,false) FROM lpcc.enrollments m JOIN lpcc.app_revisions r ON r.revision_id=$2 LEFT JOIN lpcc.operator_app_policy p ON p.orchestrator_address=m.orchestrator_address AND p.app_name=r.app_name WHERE m.node_id=$1`, node, a.RevisionID).Scan(&denied)
	if e != nil {
		return e
	}
	if denied {
		a = a.Absent()
	}
	return AppendEffective(ctx, tx, node, actor, a)
}
func AppendEffective(ctx context.Context, tx *sql.Tx, node, actor string, a schema.AppAssignment) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO lpcc.machine_app_versions(node_id,revision_id,generation,intent,actor_id) VALUES($1,$2,$3,$4,$5)`, node, a.RevisionID, a.Generation, string(raw), actor)
	return err
}

func Bump(ctx context.Context, tx *sql.Tx, node string) error {
	_, err := tx.ExecContext(ctx, `UPDATE lpcc.machine_states SET apps_generation=apps_generation+1,revision=revision+1,apps_error=NULL WHERE node_id=$1`, node)
	return err
}

func Pending(ctx context.Context, q Querier, node string) (bool, error) {
	var yes bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.machine_app_heads v WHERE v.node_id=$1 AND (v.intent->>'desired'='present' OR NOT EXISTS(SELECT FROM lpcc.machine_app_completions c WHERE c.node_id=v.node_id AND c.revision_id=v.revision_id AND c.generation=v.generation AND c.phase='removed')))`, node).Scan(&yes)
	return yes, err
}

func RecordDelivery(ctx context.Context, tx *sql.Tx, set *schema.AppAssignmentSetV1, bundle string, terminal bool) error {
	if set == nil {
		return nil
	}
	raw, err := schema.CanonicalAssignmentSet(*set)
	if err != nil {
		return err
	}
	entries := append([]schema.AppAssignment{}, set.Entries...)
	for i := range entries {
		entries[i].Revision = nil
	}
	membership, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO lpcc.machine_app_deliveries(node_id,apps_digest,bundle_sha256,apps_generation,entries,terminal) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, set.NodeID, schema.Digest(raw), bundle, set.Generation, string(membership), terminal)
	return err
}

var ErrRequestedBudget = errors.New("requested assignment budget exceeded")

// Reserve full requested work even while policy masks it from execution.
func CheckRequestedBudget(ctx context.Context, q Querier, node string) error {
	heads, e := Heads(ctx, q, node)
	if e != nil {
		return e
	}
	set := schema.AppAssignmentSetV1{SchemaVersion: 1, NodeID: node, Generation: 1, Entries: []schema.AppAssignment{}}
	for _, h := range heads {
		if h.Requested != nil && h.Requested.Desired == "present" {
			set.Entries = append(set.Entries, *h.Requested)
		} else if h.Desired == "present" || h.CompletedAt == nil {
			set.Entries = append(set.Entries, h.AppAssignment)
		}
	}
	if schema.CheckAssignmentBudget(set) != nil {
		return ErrRequestedBudget
	}
	return nil
}
