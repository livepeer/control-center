package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"math"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"time"
	"uuid"

	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/schema"
)

func appInput(r *http.Request, out any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 16385))
	if err != nil || len(b) > 16384 || jsonv2.Unmarshal(b, out, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)) != nil {
		return problem(400, "invalid_request", "Provide one bounded JSON request with the documented fields.")
	}
	return nil
}
func appID(id string) bool {
	v, e := uuid.Parse(id)
	return e == nil && v != (uuid.UUID{}) && v.String() == id
}
func appConflict() error {
	return problem(409, "assignment_changed", "Assignment changed. Refresh before retrying.")
}

type assignmentInput struct {
	Epoch    string `json:"epoch"`
	Digest   string `json:"digest"`
	Expected *int64 `json:"expected_generation"`
	Replicas *int   `json:"replicas"`
	Target   *struct {
		RevisionID string `json:"revision_id"`
		Digest     string `json:"digest"`
		Expected   *int64 `json:"expected_generation"`
		Replicas   *int   `json:"replicas"`
	} `json:"target"`
}

// Lock the live enrollment before state/history, shared with configuration
// publication and credential changes. The policy lock is already held.
func lockAppMachine(ctx context.Context, tx *sql.Tx, node, epoch string) (string, error) {
	var current string
	err := tx.QueryRowContext(ctx, `SELECT enrollment_epoch::text FROM lpcc.machines WHERE node_id=$1 FOR UPDATE`, node).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return "", problem(404, "machine_not_found", "Machine not found.")
	}
	if err != nil {
		return "", err
	}
	if current != epoch {
		return "", problem(409, "epoch_changed", "Machine enrollment changed.")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO lpcc.machine_states(node_id,epoch,state) VALUES($1,$2,'{}') ON CONFLICT DO NOTHING`, node, epoch)
	if err != nil {
		return "", err
	}
	var lifecycle string
	err = tx.QueryRowContext(ctx, `SELECT rollout->>'lifecycle' FROM lpcc.machine_states WHERE node_id=$1 AND epoch=$2 FOR UPDATE`, node, epoch).Scan(&lifecycle)
	return lifecycle, err
}

func optionalHead(ctx context.Context, q machineapps.Querier, node, epoch, id string) (machineapps.Version, error) {
	v, err := machineapps.Head(ctx, q, node, epoch, id)
	if errors.Is(err, sql.ErrNoRows) {
		return machineapps.Version{}, nil
	}
	return v, err
}

func sameIntent(a, b schema.AppAssignment) bool {
	// StartAllowed is a derived permission. Compare the durable prerequisite.
	a.StartAllowed = false
	b.StartAllowed = false
	return reflect.DeepEqual(a, b)
}
func retryMatches(v machineapps.Version, expected int64, want schema.AppAssignment) bool {
	if expected < 0 || expected == math.MaxInt64 {
		return false
	}
	if v.Generation != expected && v.Generation != expected+1 {
		return false
	}
	want.Generation = v.Generation
	return sameIntent(v.AppAssignment, want)
}

func (s *Server) prepareAssignment(r *http.Request, _ UserIdentity) (AdminApply, error) {
	var in assignmentInput
	if err := appInput(r, &in); err != nil {
		return nil, err
	}
	node, id, method := r.PathValue("node_id"), r.PathValue("revision_id"), r.Method
	replace := method == "POST"
	if !appID(in.Epoch) || !appID(id) || in.Expected == nil || *in.Expected < 0 || *in.Expected == math.MaxInt64 || (!replace && in.Target != nil) || (method == "DELETE" && (in.Digest != "" || in.Replicas != nil)) {
		return nil, problem(400, "invalid_precondition", "Provide an enrollment epoch, revision UUID and expected_generation.")
	}
	if replace && (in.Digest != "" || in.Replicas != nil || in.Target == nil || !appID(in.Target.RevisionID) || in.Target.RevisionID == id || in.Target.Expected == nil || *in.Target.Expected < 0 || *in.Target.Expected == math.MaxInt64) {
		return nil, problem(400, "invalid_replacement", "Provide a distinct target revision and its expected_generation.")
	}
	return func(ctx context.Context, tx *sql.Tx, u UserIdentity) (AdminChange, error) {
		lifecycle, err := lockAppMachine(ctx, tx, node, in.Epoch)
		if err != nil {
			return AdminChange{}, err
		}
		if lifecycle != "active" {
			return AdminChange{}, problem(409, "machine_inactive", "Machine removal is in progress.")
		}
		old, err := optionalHead(ctx, tx, node, in.Epoch, id)
		if err != nil {
			return AdminChange{}, err
		}
		affected := []string{id}
		changed := false
		if method == "DELETE" || replace {
			if old.Generation == 0 {
				return AdminChange{}, problem(404, "assignment_not_found", "Assignment not found.")
			}
			removal := old.AppAssignment.Absent()
			if old.Desired == "present" {
				removal.Generation++
			}
			if replace {
				if old.Replacement != nil {
					done, e := machineapps.CleanupComplete(ctx, tx, node, in.Epoch, schema.AppStartAfter{RevisionID: old.Replacement.RevisionID, Generation: old.Replacement.Generation})
					if e != nil {
						return AdminChange{}, e
					}
					if !done {
						return AdminChange{}, problem(409, "replacement_blocked", "Wait for rolling source cleanup.")
					}
				}
				if old.StartAfter != nil {
					done, e := machineapps.CleanupComplete(ctx, tx, node, in.Epoch, *old.StartAfter)
					if e != nil {
						return AdminChange{}, e
					}
					if !done {
						return AdminChange{}, problem(409, "replacement_blocked", "Wait for the existing replacement prerequisite.")
					}
				}
				targetID := in.Target.RevisionID
				affected = append(affected, targetID)
				target, e := optionalHead(ctx, tx, node, in.Epoch, targetID)
				if e != nil {
					return AdminChange{}, e
				}
				ref := schema.RevisionRef{RevisionID: targetID, Digest: in.Target.Digest}
				// Exact replacement retry must not bypass generation/target identity checks.
				if old.Desired == "absent" {
					current := old.Generation == *in.Expected && target.Generation == *in.Target.Expected
					desiredReplicas := 0
					if target.Revision != nil {
						desiredReplicas = target.Revision.Definition.Instances.Replicas
					}
					if current {
						desiredReplicas = target.Replicas
					}
					if in.Target.Replicas != nil {
						desiredReplicas = *in.Target.Replicas
					}
					retry := old.Generation == *in.Expected+1 && target.Generation == *in.Target.Expected+1 && target.ActivationGeneration == target.Generation
					if (!current && !retry) || target.Desired != "present" || target.RevisionRef != ref || !replacementMatches(target.AppAssignment, id, old.Generation) || target.Replicas != desiredReplicas {
						return AdminChange{}, appConflict()
					}
				} else {
					if old.Generation != *in.Expected || target.Generation != *in.Target.Expected {
						return AdminChange{}, appConflict()
					}
					if target.Generation != 0 && (target.Desired != "absent" || target.CompletedAt == nil) {
						return AdminChange{}, problem(409, "target_assigned", "Target must be unassigned or fully removed.")
					}
					revision, e := revisionForBinding(ctx, tx, nil, ref, s.registryMode())
					if e != nil {
						return AdminChange{}, e
					}
					if revision.Name != old.Revision.Name {
						return AdminChange{}, problem(400, "app_name_mismatch", "Replace with a revision of the same app.")
					}
					n := revision.Definition.Instances.Replicas
					if in.Target.Replicas != nil {
						n = *in.Target.Replicas
					}
					if schema.ValidateReplicaCount(n) != nil {
						return AdminChange{}, problem(400, "invalid_replicas", "Replicas must be between 1 and 100.")
					}
					a := schema.AppAssignment{RevisionRef: ref, Generation: target.Generation + 1, ActivationGeneration: target.Generation + 1, Desired: "present", Revision: &revision.ResolvedRevision, Replicas: n, Cleanup: schema.CleanupPolicy(revision.Definition), StartAfter: &schema.AppStartAfter{RevisionID: id, Generation: removal.Generation}}
					if old.Replicas == n && n > 1 {
						a.StartAfter = nil
						a.StartAllowed = true
						a.Replacement = &schema.AppReplacement{RevisionID: id, ActivationGeneration: old.ActivationGeneration, Generation: removal.Generation, Replicas: n}
					}
					if e = machineapps.Append(ctx, tx, node, in.Epoch, u.ID, removal); e == nil {
						e = machineapps.Append(ctx, tx, node, in.Epoch, u.ID, a)
					}
					if e != nil {
						return AdminChange{}, e
					}
					changed = true
				}
			} else {
				if old.Desired == "absent" {
					if !retryMatches(old, *in.Expected, removal) {
						return AdminChange{}, appConflict()
					}
				} else {
					if old.Generation != *in.Expected {
						return AdminChange{}, appConflict()
					}
					if err = machineapps.Append(ctx, tx, node, in.Epoch, u.ID, removal); err != nil {
						return AdminChange{}, err
					}
					changed = true
				}
			}
		} else {
			ref := schema.RevisionRef{RevisionID: id, Digest: in.Digest}
			// Read/verify immutable content before deciding whether a request is a retry.
			revision, e := loadPinnedRevision(ctx, tx, ref)
			if e != nil {
				return AdminChange{}, e
			}
			// Omitted fields describe the expected version, not a concurrent head.
			base := old
			if old.Generation != *in.Expected {
				if old.Generation != *in.Expected+1 {
					return AdminChange{}, appConflict()
				}
				base = machineapps.Version{}
				if *in.Expected > 0 {
					base, e = machineapps.AtGeneration(ctx, tx, node, in.Epoch, id, *in.Expected)
					if e != nil {
						return AdminChange{}, e
					}
				}
			}
			n := revision.Definition.Instances.Replicas
			if base.Desired == "present" {
				n = base.Replicas
			}
			if in.Replicas != nil {
				n = *in.Replicas
			}
			if schema.ValidateReplicaCount(n) != nil {
				return AdminChange{}, problem(400, "invalid_replicas", "Replicas must be between 1 and 100.")
			}
			a := schema.AppAssignment{RevisionRef: ref, Generation: *in.Expected + 1, ActivationGeneration: *in.Expected + 1, Desired: "present", Cleanup: schema.CleanupPolicy(revision.Definition), Revision: &revision.ResolvedRevision, Replicas: n, StartAllowed: true}
			if base.Desired == "present" {
				a.ActivationGeneration = base.ActivationGeneration
				a.Replacement = base.Replacement
				if base.Replacement != nil && n != base.Replicas {
					done, e := machineapps.CleanupComplete(ctx, tx, node, in.Epoch, schema.AppStartAfter{RevisionID: base.Replacement.RevisionID, Generation: base.Replacement.Generation})
					if e != nil {
						return AdminChange{}, e
					}
					if !done {
						return AdminChange{}, problem(409, "replacement_blocked", "Wait for rolling source cleanup before scaling.")
					}
					a.Replacement = nil
				}
				a.StartAfter = base.StartAfter
				a.StartAllowed = base.StartAllowed
			}
			if old.Generation > 0 && retryMatches(old, *in.Expected, a) { /* no-op */
			} else {
				if old.Generation != *in.Expected {
					return AdminChange{}, appConflict()
				}
				if old.Desired == "absent" && old.CompletedAt == nil {
					return AdminChange{}, problem(409, "cleanup_pending", "Wait for Runtime cleanup before reassignment.")
				}
				var current *schema.RevisionRef
				if old.Desired == "present" {
					current = &old.RevisionRef
				}
				if _, e = revisionForBinding(ctx, tx, current, ref, s.registryMode()); e != nil {
					return AdminChange{}, e
				}
				if e = machineapps.Append(ctx, tx, node, in.Epoch, u.ID, a); e != nil {
					return AdminChange{}, e
				}
				changed = true
			}
		}
		if changed {
			if err = machineapps.Bump(ctx, tx, node, in.Epoch); err != nil {
				return AdminChange{}, err
			}
			set, e := machineapps.Snapshot(ctx, tx, node, in.Epoch)
			if e != nil {
				return AdminChange{}, e
			}
			if e = schema.CheckAssignmentBudget(*set); e != nil {
				return AdminChange{}, problem(400, "assignment_limit", "Assignments exceed the machine count or delivery size limit.")
			}
		}
		sort.Strings(affected)
		versions := []machineapps.Version{}
		for _, key := range affected {
			v, e := machineapps.Head(ctx, tx, node, in.Epoch, key)
			if e != nil {
				return AdminChange{}, e
			}
			if v.StartAfter != nil {
				v.StartAllowed, e = machineapps.CleanupComplete(ctx, tx, node, in.Epoch, *v.StartAfter)
				if e != nil {
					return AdminChange{}, e
				}
			}
			versions = append(versions, v)
		}
		auditRevision := ""
		for _, v := range versions {
			if v.RevisionID == id {
				auditRevision = strconv.FormatInt(v.Generation, 10)
			}
		}
		if replace {
			for _, v := range versions {
				if v.RevisionID != id {
					auditRevision += ":" + v.RevisionID + ":" + strconv.FormatInt(v.Generation, 10)
				}
			}
		}
		status := 200
		if changed {
			status = 202
		}
		return AdminChange{Target: AdminTarget{Kind: "machine_app", ID: node + ":" + in.Epoch + ":" + id, Revision: auditRevision}, Changed: changed, Status: status, Body: map[string]any{"changed": changed, "epoch": in.Epoch, "assignments": versions}}, nil
	}, nil
}

func (s *Server) listAssignments(w http.ResponseWriter, r *http.Request, _ UserIdentity) {
	ctx := r.Context()
	node := r.PathValue("node_id")
	var epoch string
	var last *time.Time
	err := s.db.QueryRowContext(ctx, `SELECT enrollment_epoch::text,last_config_fetch_at FROM lpcc.machines WHERE node_id=$1`, node).Scan(&epoch, &last)
	if errors.Is(err, sql.ErrNoRows) {
		err = problem(404, "machine_not_found", "Machine not found.")
	}
	if err != nil {
		s.respondError(w, err)
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		s.respondError(w, err)
		return
	}
	after := r.URL.Query().Get("after_revision_id")
	if after != "" && !appID(after) {
		s.respondError(w, problem(400, "invalid_cursor", "Invalid revision cursor."))
		return
	}
	// Read all current heads through a bounded database page, including completed history.
	rows, err := s.db.QueryContext(ctx, `SELECT `+machineapps.VersionColumns+` FROM lpcc.machine_app_heads v `+machineapps.VersionJoins+` WHERE v.node_id=$1 AND v.epoch=$2 AND ($3='' OR v.revision_id::text>$3) ORDER BY v.revision_id LIMIT $4`, node, epoch, after, limit+1)
	if err != nil {
		s.respondError(w, err)
		return
	}
	versions, err := machineapps.ReadVersions(rows)
	if err != nil {
		s.respondError(w, err)
		return
	}
	for i := range versions {
		if versions[i].StartAfter != nil {
			versions[i].StartAllowed, err = machineapps.CleanupComplete(ctx, s.db, node, epoch, *versions[i].StartAfter)
			if err != nil {
				s.respondError(w, err)
				return
			}
		}
	}
	var next *string
	if len(versions) > limit {
		versions = versions[:limit]
		next = &versions[len(versions)-1].RevisionID
	}
	var gen, published int64
	var failure *string
	err = s.db.QueryRowContext(ctx, `SELECT COALESCE((SELECT apps_generation FROM lpcc.machine_states WHERE node_id=$1 AND epoch=$2),0),COALESCE((SELECT max(apps_generation) FROM lpcc.machine_app_deliveries WHERE node_id=$1 AND epoch=$2),0),(SELECT apps_error FROM lpcc.machine_states WHERE node_id=$1 AND epoch=$2)`, node, epoch).Scan(&gen, &published, &failure)
	if err != nil {
		s.respondError(w, err)
		return
	}
	respond(w, 200, map[string]any{"epoch": epoch, "assignments": versions, "apps_generation": gen, "published_generation": published, "delivery_error": failure, "last_config_fetch_at": last, "next_after_revision_id": next})
}

func (s *Server) inspectAssignment(w http.ResponseWriter, r *http.Request, _ UserIdentity) {
	ctx := r.Context()
	node, id := r.PathValue("node_id"), r.PathValue("revision_id")
	if !appID(id) {
		s.respondError(w, problem(400, "invalid_revision_id", "Provide a revision UUID."))
		return
	}
	var epoch string
	// Explicit retained epoch permits administrators to inspect deleted-enrollment history.
	epoch = r.URL.Query().Get("epoch")
	var err error
	if epoch == "" {
		err = s.db.QueryRowContext(ctx, `SELECT enrollment_epoch::text FROM lpcc.machines WHERE node_id=$1`, node).Scan(&epoch)
	} else if !appID(epoch) {
		err = problem(400, "invalid_epoch", "Provide an enrollment UUID.")
	}
	if errors.Is(err, sql.ErrNoRows) {
		err = problem(404, "machine_not_found", "Machine not found.")
	}
	if err != nil {
		s.respondError(w, err)
		return
	}
	head, err := machineapps.Head(ctx, s.db, node, epoch, id)
	if errors.Is(err, sql.ErrNoRows) {
		err = problem(404, "assignment_not_found", "Assignment not found.")
	}
	if err != nil {
		s.respondError(w, err)
		return
	}
	if head.StartAfter != nil {
		head.StartAllowed, err = machineapps.CleanupComplete(ctx, s.db, node, epoch, *head.StartAfter)
		if err != nil {
			s.respondError(w, err)
			return
		}
	}
	revision, err := loadPinnedRevision(ctx, s.db, head.RevisionRef)
	if err != nil {
		s.respondError(w, err)
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		s.respondError(w, err)
		return
	}
	before := int64(math.MaxInt64)
	if raw := r.URL.Query().Get("before_generation"); raw != "" {
		before, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || before < 1 {
			s.respondError(w, problem(400, "invalid_cursor", "Invalid generation cursor."))
			return
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+machineapps.VersionColumns+` FROM lpcc.machine_app_versions v `+machineapps.VersionJoins+` WHERE v.node_id=$1 AND v.epoch=$2 AND v.revision_id=$3 AND v.generation<$4 ORDER BY v.generation DESC LIMIT $5`, node, epoch, id, before, limit+1)
	if err != nil {
		s.respondError(w, err)
		return
	}
	history, err := machineapps.ReadVersions(rows)
	if err != nil {
		s.respondError(w, err)
		return
	}
	var next *int64
	if len(history) > limit {
		history = history[:limit]
		next = &history[len(history)-1].Generation
	}
	respond(w, 200, map[string]any{"epoch": epoch, "assignment": head, "revision": revision, "history": history, "next_before_generation": next})
}

type assignmentReport struct {
	Epoch                string `json:"epoch"`
	CredentialVersion    int64  `json:"credential_version"`
	Generation           int64  `json:"generation"`
	ActivationGeneration int64  `json:"activation_generation"`
	AppsDigest           string `json:"apps_digest"`
	Phase                string `json:"phase"`
	Reason               string `json:"reason"`
}

func (s *Server) assignmentStatus(w http.ResponseWriter, r *http.Request) {
	m, err := s.authenticateMachine(r.Context(), r.PathValue("node_id"), bearer(r), true)
	if err != nil {
		s.respondError(w, err)
		return
	}
	var report assignmentReport
	if err = appInput(r, &report); err != nil {
		s.respondError(w, err)
		return
	}
	id := r.PathValue("revision_id")
	if !appID(id) || report.Epoch != m.Epoch || report.CredentialVersion != m.CredentialVersion || report.Generation < 1 || report.ActivationGeneration < 1 || !digestRefPattern(report.AppsDigest) || (report.Phase != "applied" && report.Phase != "failed" && report.Phase != "removed") {
		s.respondError(w, problem(409, "invalid_app_status", "Status does not match an enrolled assignment."))
		return
	}
	reasons := map[string]bool{"reconcile_failed": true, "invalid_definition": true, "image_pull_failed": true, "startup_failed": true, "isolation_refused": true, "resource_refused": true, "cleanup_failed": true, "registration_cleanup_failed": true}
	if report.Phase == "failed" && !reasons[report.Reason] || report.Phase != "failed" && report.Reason != "" {
		s.respondError(w, problem(400, "invalid_reason", "Use a documented diagnostic classification."))
		return
	}
	ctx := r.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.respondError(w, err)
		return
	}
	defer tx.Rollback()
	// Live publication locks the machine first; old terminal epochs lock only
	// their retained enrollment and cannot block or mutate a new epoch's intents.
	var present int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2 FOR UPDATE`, m.NodeID, m.Epoch).Scan(&present)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.respondError(w, err)
		return
	}
	var version int64
	var terminal bool
	err = tx.QueryRowContext(ctx, `SELECT credential_version,retired_at IS NOT NULL FROM lpcc.enrollments WHERE node_id=$1 AND epoch=$2 FOR NO KEY UPDATE`, m.NodeID, m.Epoch).Scan(&version, &terminal)
	if err != nil {
		s.respondError(w, err)
		return
	}
	if version != m.CredentialVersion || terminal != m.Terminal {
		s.respondError(w, problem(409, "enrollment_changed", "Enrollment changed during reporting."))
		return
	}
	var receiptDigest string
	err = tx.QueryRowContext(ctx, `SELECT apps_digest FROM lpcc.machine_app_completions WHERE node_id=$1 AND epoch=$2 AND revision_id=$3 AND generation=$4 AND activation_generation=$5 AND phase=$6`, m.NodeID, m.Epoch, id, report.Generation, report.ActivationGeneration, report.Phase).Scan(&receiptDigest)
	recorded := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.respondError(w, err)
		return
	}
	if recorded && receiptDigest == report.AppsDigest {
		respond(w, 200, map[string]string{"status": "already_recorded"})
		return
	}
	if m.Terminal && !recorded && report.Phase != "removed" {
		s.respondError(w, problem(403, "terminal_status_only", "Retired credentials authorize cleanup acknowledgements and recorded completion retries only."))
		return
	}
	var membership []byte
	err = tx.QueryRowContext(ctx, `SELECT entries FROM lpcc.machine_app_deliveries WHERE node_id=$1 AND epoch=$2 AND apps_digest=$3 AND (NOT $4 OR terminal) LIMIT 1`, m.NodeID, m.Epoch, report.AppsDigest, m.Terminal && !recorded).Scan(&membership)
	if errors.Is(err, sql.ErrNoRows) {
		err = problem(409, "unknown_delivery", "Status must refer to a published app configuration.")
	}
	if err != nil {
		s.respondError(w, err)
		return
	}
	var entries []schema.AppAssignment
	if err = json.Unmarshal(membership, &entries); err != nil {
		s.respondError(w, err)
		return
	}
	var member *schema.AppAssignment
	for i := range entries {
		a := &entries[i]
		if a.RevisionID == id && a.Generation == report.Generation && a.ActivationGeneration == report.ActivationGeneration {
			member = a
			break
		}
	}
	if member == nil || (report.Phase == "applied" && (member.Desired != "present" || !member.StartAllowed)) || (report.Phase == "removed" && member.Desired != "absent") {
		s.respondError(w, problem(409, "invalid_transition", "Status is not permitted by the published assignment."))
		return
	}
	if recorded {
		respond(w, 200, map[string]string{"status": "already_recorded"})
		return
	}
	head, err := machineapps.Head(ctx, tx, m.NodeID, m.Epoch, id)
	if err != nil {
		s.respondError(w, err)
		return
	}
	if head.Generation != report.Generation || head.ActivationGeneration != report.ActivationGeneration {
		s.respondError(w, appConflict())
		return
	}
	if head.CompletedAt != nil {
		respond(w, 200, map[string]string{"status": "already_recorded"})
		return
	}
	if report.Phase == "failed" {
		_, err = tx.ExecContext(ctx, `INSERT INTO lpcc.machine_app_diagnostics(node_id,epoch,revision_id,generation,reason) VALUES($1,$2,$3,$4,$5) ON CONFLICT(node_id,epoch,revision_id) DO UPDATE SET generation=EXCLUDED.generation,reason=EXCLUDED.reason,received_at=now() WHERE lpcc.machine_app_diagnostics.generation<=EXCLUDED.generation`, m.NodeID, m.Epoch, id, report.Generation, report.Reason)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO lpcc.machine_app_completions(node_id,epoch,revision_id,generation,activation_generation,phase,apps_digest) VALUES($1,$2,$3,$4,$5,$6,$7)`, m.NodeID, m.Epoch, id, report.Generation, report.ActivationGeneration, report.Phase, report.AppsDigest)
		if err == nil && report.Phase == "removed" && !m.Terminal {
			err = machineapps.Bump(ctx, tx, m.NodeID, m.Epoch)
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.respondError(w, err)
		return
	}
	if report.Phase == "removed" {
		s.requestReconcile()
	}
	respond(w, 200, map[string]string{"status": "accepted"})
}
func digestRefPattern(s string) bool {
	return len(s) == 71 && s[:7] == "sha256:" && fingerprintPattern.MatchString(s[7:])
}

func replacementMatches(a schema.AppAssignment, id string, generation int64) bool {
	if a.StartAfter != nil {
		return *a.StartAfter == (schema.AppStartAfter{RevisionID: id, Generation: generation})
	}
	return a.Replacement != nil && a.Replacement.RevisionID == id && a.Replacement.Generation == generation
}
