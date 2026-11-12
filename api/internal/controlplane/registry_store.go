package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/livepeer/control-center/api/internal/controlplane/payments"
	"github.com/livepeer/control-center/schema"
)

type RevisionState struct {
	Version   int64      `json:"version"`
	RetiredAt *time.Time `json:"retired_at"`
	RetiredBy *string    `json:"retired_by"`
}
type CatalogRevision struct {
	schema.ResolvedRevision
	SourceTOML  string        `json:"source_toml"`
	PublishedBy string        `json:"published_by"`
	PublishedAt time.Time     `json:"published_at"`
	Lifecycle   RevisionState `json:"lifecycle"`
}
type RevisionSummary struct {
	schema.RevisionRef
	Revision      int64         `json:"revision"`
	AppVersion    string        `json:"app_version"`
	SchemaVersion int           `json:"schema_version"`
	PublishedAt   time.Time     `json:"published_at"`
	Lifecycle     RevisionState `json:"lifecycle"`
}

func (r CatalogRevision) target() AdminTarget {
	return AdminTarget{"app_revision", r.RevisionID, fmt.Sprintf("%d:%d", r.Revision, r.Lifecycle.Version)}
}

const revisionColumns = `r.revision_id::text,r.app_name,r.revision,r.app_version,r.schema_version,r.canonical_format,r.canonical,r.digest,r.source_toml,r.published_by::text,r.published_at,s.version,s.retired_at,s.retired_by::text`
const revisionSummaryColumns = `r.revision_id::text,r.digest,r.revision,r.app_version,r.schema_version,r.published_at,s.version,s.retired_at,s.retired_by::text`
const revisionFrom = ` FROM lpcc.app_revisions r JOIN lpcc.app_revision_state s USING(revision_id) `

func readRevision(row scanner) (CatalogRevision, error) {
	var r CatalogRevision
	var b []byte
	err := row.Scan(&r.RevisionID, &r.Name, &r.Revision, &r.AppVersion, &r.SchemaVersion, &r.CanonicalFormat, &b, &r.Digest, &r.SourceTOML, &r.PublishedBy, &r.PublishedAt, &r.Lifecycle.Version, &r.Lifecycle.RetiredAt, &r.Lifecycle.RetiredBy)
	if err != nil {
		return r, err
	}
	r.Definition, err = schema.DecodeCanonical(b)
	if err != nil {
		return r, err
	}
	if err = r.Verify(); err != nil {
		return r, err
	}
	canonical, err := schema.CanonicalBytes(r.Definition)
	if err != nil || !bytes.Equal(canonical, b) {
		return r, errors.New("stored revision is not canonical")
	}
	return r, nil
}
func loadRevision(ctx context.Context, q rowQuerier, name, id string) (CatalogRevision, error) {
	r, err := readRevision(q.QueryRowContext(ctx, `SELECT `+revisionColumns+revisionFrom+`WHERE r.app_name=$1 AND r.revision_id=$2`, name, id))
	if errors.Is(err, sql.ErrNoRows) {
		err = problem(404, "revision_not_found", "App revision not found.")
	}
	return r, err
}

// loadPinnedRevision deliberately allows retirement and historical pricing.
func loadPinnedRevision(ctx context.Context, q rowQuerier, ref schema.RevisionRef) (CatalogRevision, error) {
	id, err := uuid.Parse(ref.RevisionID)
	if err != nil || id == (uuid.UUID{}) || id.String() != ref.RevisionID {
		return CatalogRevision{}, problem(400, "invalid_revision_id", "Provide a canonical, nonzero revision UUID.")
	}
	r, err := readRevision(q.QueryRowContext(ctx, `SELECT `+revisionColumns+revisionFrom+`WHERE r.revision_id=$1`, ref.RevisionID))
	if errors.Is(err, sql.ErrNoRows) {
		return r, problem(404, "revision_not_found", "App revision not found.")
	}
	if err == nil && r.Digest != ref.Digest {
		err = problem(409, "revision_digest_mismatch", "Revision digest does not match.")
	}
	return r, err
}

// revisionForBinding validates a revision within AdminApply. The transaction
// already holds policyTx's lock, and current must come from the persisted
// assignment read using tx, never from a request.
// Unchanged references may scale/recover after retirement or a policy change.
func revisionForBinding(ctx context.Context, tx *sql.Tx, current *schema.RevisionRef, desired schema.RevisionRef, node string) (CatalogRevision, error) {
	r, err := loadPinnedRevision(ctx, tx, desired)
	if err != nil {
		return r, err
	}
	config, err := payments.Load(ctx, tx, node)
	if err != nil {
		return r, err
	}
	if err := config.Compatible(r.Definition); err != nil {
		return r, definitionProblem(err)
	}
	if current != nil && *current == desired {
		return r, nil
	}
	if r.Lifecycle.RetiredAt != nil {
		return r, problem(409, "revision_retired", "Retired revisions cannot receive new bindings.")
	}
	return r, nil
}
func (s *Server) publishRevision(ctx context.Context, tx *sql.Tx, user UserIdentity, d schema.DefinitionV1, source, expected string, create bool, b []byte) (AdminChange, error) {
	digest := schema.Digest(b)
	old, err := readRevision(tx.QueryRowContext(ctx, `SELECT `+revisionColumns+revisionFrom+`WHERE r.app_name=$1 AND r.digest=$2`, d.Name, digest))
	if err == nil {
		return AdminChange{old.target(), false, 200, map[string]any{"revision": old, "changed": false}}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AdminChange{}, err
	}
	var head *string
	var next int64
	err = tx.QueryRowContext(ctx, `SELECT head_revision_id::text,next_revision FROM lpcc.apps WHERE name=$1 FOR UPDATE`, d.Name).Scan(&head, &next)
	if errors.Is(err, sql.ErrNoRows) {
		if !create {
			return AdminChange{}, problem(404, "app_not_found", "App not found.")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO lpcc.apps(name) VALUES($1)`, d.Name); err != nil {
			return AdminChange{}, err
		}
		next = 1
	} else if err != nil {
		return AdminChange{}, err
	} else if create {
		return AdminChange{}, problem(409, "app_exists", "App already exists; publish a new revision.")
	} else if head == nil || *head != expected {
		return AdminChange{}, problem(409, "stale_head", "Another revision has been published. Refresh before publishing.")
	}

	id := uuid.New().String()
	_, err = tx.ExecContext(ctx, `INSERT INTO lpcc.app_revisions(revision_id,app_name,revision,app_version,schema_version,canonical_format,canonical,digest,source_toml,published_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, d.Name, next, d.AppVersion, d.SchemaVersion, schema.CanonicalFormat, b, digest, source, user.ID)
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO lpcc.app_revision_state(revision_id) VALUES($1)`, id)
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `UPDATE lpcc.apps SET head_revision_id=$2,next_revision=next_revision+1 WHERE name=$1`, d.Name, id)
	}
	if err != nil {
		return AdminChange{}, err
	}
	r, err := loadRevision(ctx, tx, d.Name, id)
	return AdminChange{r.target(), true, 201, map[string]any{"revision": r, "changed": true}}, err
}
