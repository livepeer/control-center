package controlplane

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strconv"
	"uuid"

	"github.com/livepeer/control-center/schema"
)

func definitionProblem(err error) error {
	if err == nil {
		return nil
	}
	var validation *schema.ValidationError
	if errors.As(err, &validation) {
		return &apiProblem{status: 400, reason: "invalid_definition", message: "Correct the definition's field errors.", fields: validation.Fields}
	}
	return err
}
func registryInput(r *http.Request, out any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, (512<<10)+1))
	if err != nil || len(b) > 512<<10 || jsonv2.Unmarshal(b, out, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)) != nil {
		return problem(400, "invalid_request", "Provide one bounded JSON request with the documented fields.")
	}
	return nil
}
func (s *Server) validateApp(w http.ResponseWriter, r *http.Request, _ UserIdentity) {
	var input struct {
		Source string `json:"source_toml"`
	}
	err := registryInput(r, &input)
	var d schema.DefinitionV1
	if err == nil {
		d, err = schema.ParseTOML([]byte(input.Source))
		err = definitionProblem(err)
	}
	if err == nil {
		err = definitionProblem(schema.ValidatePolicy(d, s.registryMode()))
	}
	if err != nil {
		s.respondError(w, err)
		return
	}
	b, err := schema.CanonicalBytes(d)
	if err != nil {
		s.respondError(w, err)
		return
	}
	respond(w, 200, map[string]any{"payment_mode": s.registryMode(), "definition": d, "canonical_format": schema.CanonicalFormat, "digest": schema.Digest(b)})
}
func (s *Server) prepareCreateApp(r *http.Request, u UserIdentity) (AdminApply, error) {
	return s.preparePublication(r, true)
}
func (s *Server) preparePublishApp(r *http.Request, u UserIdentity) (AdminApply, error) {
	return s.preparePublication(r, false)
}
func (s *Server) preparePublication(r *http.Request, create bool) (AdminApply, error) {
	var input struct {
		Source   string `json:"source_toml"`
		Expected string `json:"expected_head_revision_id"`
	}
	if err := registryInput(r, &input); err != nil {
		return nil, err
	}
	d, err := schema.ParseTOML([]byte(input.Source))
	if err != nil {
		return nil, definitionProblem(err)
	}
	if !create {
		if parsed, err := uuid.Parse(input.Expected); err != nil || parsed == (uuid.UUID{}) {
			return nil, problem(400, "invalid_precondition", "Provide expected_head_revision_id as a UUID.")
		}
		if d.Name != r.PathValue("name") {
			return nil, problem(400, "app_name_mismatch", "Definition name must match the app path.")
		}
	}
	b, err := schema.CanonicalBytes(d)
	if err != nil {
		return nil, definitionProblem(err)
	}
	if !create {
		parsed, _ := uuid.Parse(input.Expected)
		input.Expected = parsed.String()
	}
	return func(ctx context.Context, tx *sql.Tx, u UserIdentity) (AdminChange, error) {
		return s.publishRevision(ctx, tx, u, d, input.Source, input.Expected, create, b)
	}, nil
}
func (s *Server) prepareRetireApp(r *http.Request, _ UserIdentity) (AdminApply, error) {
	var input struct {
		Expected int64 `json:"expected_state_version"`
	}
	if err := registryInput(r, &input); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(r.PathValue("revision_id"))
	if err != nil || input.Expected < 1 {
		return nil, problem(400, "invalid_precondition", "Provide a revision UUID and positive expected_state_version.")
	}
	name := r.PathValue("name")
	return func(ctx context.Context, tx *sql.Tx, u UserIdentity) (AdminChange, error) {
		rev, err := loadRevision(ctx, tx, name, id.String())
		if err != nil {
			return AdminChange{}, err
		}
		changed := rev.Lifecycle.RetiredAt == nil
		if changed {
			if rev.Lifecycle.Version != input.Expected {
				return AdminChange{}, problem(409, "stale_revision_state", "Revision state changed. Refresh before retiring.")
			}
			if _, err = tx.ExecContext(ctx, `UPDATE lpcc.app_revision_state SET version=2,retired_at=now(),retired_by=$2 WHERE revision_id=$1`, id.String(), u.ID); err != nil {
				return AdminChange{}, err
			}
			rev, err = loadRevision(ctx, tx, name, id.String())
			if err != nil {
				return AdminChange{}, err
			}
		}
		return AdminChange{rev.target(), changed, 200, map[string]any{"revision": rev, "changed": changed}}, nil
	}, nil
}

type AppSummary struct {
	Name                string          `json:"name"`
	Head                RevisionSummary `json:"head"`
	RevisionCount       int64           `json:"revision_count"`
	ActiveRevisionCount int64           `json:"active_revision_count"`
}

const appSummaryColumns = `a.name,a.next_revision-1,(SELECT count(*) FROM lpcc.app_revisions ar JOIN lpcc.app_revision_state ast USING(revision_id) WHERE ar.app_name=a.name AND ast.retired_at IS NULL),` + revisionSummaryColumns
const appSummaryFrom = ` FROM lpcc.apps a JOIN lpcc.app_revisions r ON r.revision_id=a.head_revision_id JOIN lpcc.app_revision_state s USING(revision_id) `

func readAppSummary(row scanner) (AppSummary, error) {
	var a AppSummary
	h := &a.Head
	err := row.Scan(&a.Name, &a.RevisionCount, &a.ActiveRevisionCount, &h.RevisionID, &h.Digest, &h.Revision, &h.AppVersion, &h.SchemaVersion, &h.PublishedAt, &h.Lifecycle.Version, &h.Lifecycle.RetiredAt, &h.Lifecycle.RetiredBy)
	return a, err
}

func (s *Server) appSummary(ctx context.Context, name string) (AppSummary, error) {
	a, err := readAppSummary(s.db.QueryRowContext(ctx, `SELECT `+appSummaryColumns+appSummaryFrom+`WHERE a.name=$1`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return a, problem(404, "app_not_found", "App not found.")
	}
	return a, err
}
func pageLimit(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 50, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 100 {
		return 0, problem(400, "invalid_page", "limit must be between 1 and 100.")
	}
	return n, nil
}
func (s *Server) listApps(w http.ResponseWriter, r *http.Request, _ UserIdentity) {
	limit, err := pageLimit(r)
	if err != nil {
		s.respondError(w, err)
		return
	}
	after := r.URL.Query().Get("after_name")
	if after != "" && !schema.ValidName(after) {
		s.respondError(w, problem(400, "invalid_page", "Invalid app cursor."))
		return
	}
	rows, err := s.db.QueryContext(r.Context(), `SELECT `+appSummaryColumns+appSummaryFrom+`WHERE a.name>$1 COLLATE "C" ORDER BY a.name LIMIT $2`, after, limit+1)
	if err != nil {
		s.respondError(w, err)
		return
	}
	apps := []AppSummary{}
	for rows.Next() {
		var a AppSummary
		if a, err = readAppSummary(rows); err != nil {
			break
		}
		apps = append(apps, a)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		s.respondError(w, err)
		return
	}
	var next *string
	if len(apps) > limit {
		apps = apps[:limit]
		next = &apps[len(apps)-1].Name
	}
	respond(w, 200, map[string]any{"payment_mode": s.registryMode(), "apps": apps, "next_after_name": next})
}
func (s *Server) inspectApp(w http.ResponseWriter, r *http.Request, _ UserIdentity) {
	limit, err := pageLimit(r)
	if err != nil {
		s.respondError(w, err)
		return
	}
	before := int64(9223372036854775807)
	if raw := r.URL.Query().Get("before_revision"); raw != "" {
		before, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || before < 1 {
			s.respondError(w, problem(400, "invalid_page", "Invalid revision cursor."))
			return
		}
	}
	name := r.PathValue("name")
	a, err := s.appSummary(r.Context(), name)
	if err != nil {
		s.respondError(w, err)
		return
	}
	rows, err := s.db.QueryContext(r.Context(), `SELECT `+revisionSummaryColumns+revisionFrom+`WHERE r.app_name=$1 AND r.revision<$2 ORDER BY r.revision DESC LIMIT $3`, name, before, limit+1)
	if err != nil {
		s.respondError(w, err)
		return
	}
	defer rows.Close()
	revisions := []RevisionSummary{}
	for rows.Next() {
		var v RevisionSummary
		if err = rows.Scan(&v.RevisionID, &v.Digest, &v.Revision, &v.AppVersion, &v.SchemaVersion, &v.PublishedAt, &v.Lifecycle.Version, &v.Lifecycle.RetiredAt, &v.Lifecycle.RetiredBy); err != nil {
			break
		}
		revisions = append(revisions, v)
	}
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		s.respondError(w, err)
		return
	}
	var next *int64
	if len(revisions) > limit {
		revisions = revisions[:limit]
		next = &revisions[len(revisions)-1].Revision
	}
	respond(w, 200, map[string]any{"payment_mode": s.registryMode(), "app": a, "revisions": revisions, "next_before_revision": next})
}
func (s *Server) inspectAppRevision(w http.ResponseWriter, r *http.Request, _ UserIdentity) {
	id, err := uuid.Parse(r.PathValue("revision_id"))
	if err != nil {
		s.respondError(w, problem(400, "invalid_revision_id", "Provide a revision UUID."))
		return
	}
	rev, err := loadRevision(r.Context(), s.db, r.PathValue("name"), id.String())
	if err != nil {
		s.respondError(w, err)
		return
	}
	respond(w, 200, rev)
}
