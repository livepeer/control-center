package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/schema"
	protocol "github.com/livepeer/control-center/secrets"
	"net/http"
)

func (s *Server) secretMachine(w http.ResponseWriter, r *http.Request) {
	if s.params.SecretsMetadataToken == "" || !hmac.Equal([]byte(bearer(r)), []byte(s.params.SecretsMetadataToken)) {
		fail(w, 403, "metadata principal required")
		return
	}
	node := r.PathValue("node_id")
	// Writes retain their enrollment and proof checks before reading the response.
	if r.Method == "POST" {
		m, e := s.machineEnrollment(r.Context(), node)
		if e != nil && errorDetails(e).status >= 500 {
			fail(w, 503, "unavailable")
			return
		}
		if e != nil || m.Terminal || m.tunnelEligible == s.params.DevelopmentHTTP {
			respond(w, 200, protocol.Machine{NodeID: node, Owner: m.OrchestratorAddress})
			return
		}

		var in protocol.MachineBinding
		if boundedInput(r, &in, 16384) != nil || in.NodeID != node || in.Owner != m.OrchestratorAddress {
			fail(w, 400, "invalid enrollment")
			return
		}
		if in.ResetKey != "" { // Idempotent clear of the exact durably retired key.
			_, e = s.db.ExecContext(r.Context(), `UPDATE lpcc.secret_machines SET public_key='' WHERE node_id=$1 AND public_key=$2`, node, in.ResetKey)
			if e != nil {
				fail(w, 503, "unavailable")
				return
			}
		} else if in.Activate && in.AdmissionReady {
			res, err := s.db.ExecContext(r.Context(), `UPDATE lpcc.secret_machines SET managed=true WHERE node_id=$1 AND public_key=$2 AND encryption_ready AND EXISTS(SELECT FROM lpcc.machine_reports r JOIN lpcc.enrollments e USING(node_id) WHERE r.node_id=$1 AND r.credential_version=e.credential_version AND r.received_at>now()-interval '2 minutes' AND r.report->'apps'->>'secrets_protocol'='1')`, node, in.PublicKey)
			if err != nil {
				fail(w, 503, "unavailable")
				return
			}
			n, _ := res.RowsAffected()
			if n != 1 {
				fail(w, 409, "identity conflict")
				return
			}
		} else {
			pub, err := protocol.PublicKey(in.PublicKey)
			if err != nil || !in.EncryptionReady || !in.ValidProof() || !ed25519.Verify(pub, protocol.Proof(node, in.PublicKey), in.Signature) {
				fail(w, 403, "key proof required")
				return
			}
			if !hmacEqual(in.ManagementProof, protocol.EnrollmentProof(s.enrollmentToken(m), node, in.PublicKey, in.Nonce)) {
				fail(w, 403, "machine proof required")
				return
			}
			var capable bool
			if s.db.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT FROM lpcc.machine_reports WHERE node_id=$1 AND component IN ('runner','app-reconciler') AND credential_version=$2 AND received_at>now()-interval '2 minutes' AND report->'apps'->>'secrets_protocol'='1')`, node, m.CredentialVersion).Scan(&capable) != nil || !capable {
				fail(w, 409, "supported runtime capability required")
				return
			}
			res, err := s.db.ExecContext(r.Context(), `INSERT INTO lpcc.secret_machines(node_id,public_key,managed,encryption_ready) VALUES($1,$2,false,$3) ON CONFLICT(node_id) DO UPDATE SET public_key=EXCLUDED.public_key,encryption_ready=EXCLUDED.encryption_ready WHERE lpcc.secret_machines.public_key='' OR lpcc.secret_machines.public_key=EXCLUDED.public_key`, node, in.PublicKey, in.EncryptionReady)
			if err != nil {
				fail(w, 503, "unavailable")
				return
			}
			n, _ := res.RowsAffected()
			if n != 1 {
				fail(w, 409, "identity conflict")
				return
			}
		}
	}
	out, err := s.secretMachineMetadata(r.Context(), s.db, node)
	if err != nil {
		fail(w, 503, "unavailable")
		return
	}
	respond(w, 200, out)
}

func (s *Server) secretMachineMetadata(ctx context.Context, q machineapps.Querier, node string) (protocol.Machine, error) {
	out := protocol.Machine{NodeID: node}
	// Only the secrets service consumes this projection. Runtime snapshots retain
	// full pinned definitions; authorization needs only their secret declarations.
	rows, err := q.QueryContext(ctx, `SELECT e.orchestrator_address::text,e.retired_at IS NOT NULL OR active.tunnel_eligible IS DISTINCT FROM $2,
 COALESCE(m.public_key,''),COALESCE(m.managed,false),COALESCE(m.encryption_ready,false),
 COALESCE(g.generation,0),COALESCE(s.apps_generation,0),v.revision_id::text,COALESCE(p.denied,false),
 CASE WHEN v.intent->'revision' IS NULL OR v.intent->'revision'='null'::jsonb THEN v.intent
 ELSE jsonb_set(v.intent,'{revision,definition}',jsonb_build_object('container',
 jsonb_build_object('secrets',v.intent#>'{revision,definition,container,secrets}'))) END,
 `+machineapps.StartAllowedSQL+`,COALESCE(`+machineapps.RemovalCompleteSQL+`,false),
 CASE WHEN s.apps_generation>0 AND v.intent->>'desired'='absent' AND NOT `+machineapps.RemovalCompleteSQL+`
 THEN convert_from(r.canonical,'UTF8')::jsonb#>'{container,secrets}' END,
 COALESCE(r.digest=v.intent->>'digest',false)
 FROM lpcc.enrollments e
 LEFT JOIN lpcc.machines active USING(node_id)
 LEFT JOIN lpcc.secret_machines m USING(node_id)
 LEFT JOIN lpcc.operator_policy_generation g ON g.orchestrator_address=e.orchestrator_address
 LEFT JOIN lpcc.machine_states s USING(node_id)
 LEFT JOIN lpcc.machine_app_heads v ON v.node_id=e.node_id AND e.retired_at IS NULL
 LEFT JOIN lpcc.app_revisions r ON r.revision_id=v.revision_id
 LEFT JOIN lpcc.operator_app_policy p ON p.orchestrator_address=e.orchestrator_address AND p.app_name=r.app_name
 WHERE e.node_id=$1 ORDER BY v.revision_id`, node, !s.params.DevelopmentHTTP)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var inactive, denied, allowed, completed, digestMatches bool
		var gen int64
		var revision sql.NullString
		var raw, refs []byte
		if err = rows.Scan(&out.Owner, &inactive, &out.PublicKey, &out.Managed, &out.EncryptionReady,
			&out.PolicyGeneration, &gen, &revision, &denied, &raw, &allowed, &completed, &refs, &digestMatches); err != nil {
			return out, err
		}
		if inactive {
			return protocol.Machine{NodeID: node, Owner: out.Owner}, nil
		}
		out.Active = true
		if out.Assignments == nil {
			out.Assignments = []schema.AppAssignment{}
		}
		if denied {
			out.DeniedRevisions = append(out.DeniedRevisions, revision.String)
		}
		if gen == 0 || raw == nil || completed {
			continue
		}
		var a schema.AppAssignment
		if err = json.Unmarshal(raw, &a); err != nil {
			return out, err
		}
		a.StartAllowed = allowed
		out.Assignments = append(out.Assignments, a)
		if a.Desired == "absent" {
			if !digestMatches {
				return out, errors.New("cleanup revision digest mismatch")
			}
			consumer := protocol.SecretConsumer{RevisionID: a.RevisionID}
			if len(refs) > 0 {
				if err = json.Unmarshal(refs, &consumer.References); err != nil {
					return out, err
				}
			}
			if len(consumer.References) > 0 {
				out.Consumers = append(out.Consumers, consumer)
			}
		}
	}
	return out, rows.Err()
}

func (s *Server) operatorApps(w http.ResponseWriter, r *http.Request) {
	u, e := s.user(r.Context(), bearer(r))
	if e != nil {
		s.respondError(w, e)
		return
	}
	address, e := s.orchestrator(r, u.ID)
	if e != nil {
		s.respondError(w, e)
		return
	}
	rows, e := s.db.QueryContext(r.Context(), `SELECT r.app_name,r.canonical,COALESCE(p.denied,false),COALESCE(p.generation,0) FROM lpcc.apps a JOIN lpcc.app_revisions r ON r.revision_id=a.head_revision_id LEFT JOIN lpcc.operator_app_policy p ON p.orchestrator_address=$1 AND p.app_name=r.app_name ORDER BY r.app_name`, address)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	type catalogApp struct {
		name   string
		raw    []byte
		denied bool
		gen    int64
	}
	catalog := []catalogApp{}
	for rows.Next() {
		var app catalogApp
		if e = rows.Scan(&app.name, &app.raw, &app.denied, &app.gen); e != nil {
			break
		}
		catalog = append(catalog, app)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		s.databaseError(w, e)
		return
	}
	type appUsage struct {
		node      string
		canonical []byte
		consuming bool
	}
	usageByApp := map[string][]appUsage{}
	if len(catalog) > 0 {
		names := make([]string, 0, len(catalog))
		for _, app := range catalog {
			names = append(names, app.name)
		}
		usage, err := s.db.QueryContext(r.Context(), `SELECT r.app_name,v.node_id,r.canonical,(v.intent->>'desired'='present' OR c.received_at IS NULL) FROM lpcc.machine_app_heads v JOIN lpcc.machines m USING(node_id) JOIN lpcc.app_revisions r USING(revision_id) LEFT JOIN lpcc.machine_app_requests q ON q.node_id=v.node_id AND q.revision_id=v.revision_id LEFT JOIN lpcc.machine_app_completions c ON c.node_id=v.node_id AND c.revision_id=v.revision_id AND c.generation=v.generation WHERE m.orchestrator_address=$1 AND r.app_name=ANY($2) AND (v.intent->>'desired'='present' OR c.received_at IS NULL OR q.intent->>'desired'='present') ORDER BY v.node_id,v.revision_id`, address, names)
		if err != nil {
			s.databaseError(w, err)
			return
		}
		for usage.Next() {
			var name string
			var item appUsage
			if e = usage.Scan(&name, &item.node, &item.canonical, &item.consuming); e != nil {
				break
			}
			usageByApp[name] = append(usageByApp[name], item)
		}
		if e == nil {
			e = usage.Err()
		}
		usage.Close()
		if e != nil {
			s.databaseError(w, e)
			return
		}
	}
	out := []map[string]any{}
	for _, app := range catalog {
		name, raw, denied, gen := app.name, app.raw, app.denied, app.gen
		d, e := schema.DecodeCanonical(raw)
		if e != nil {
			s.databaseError(w, e)
			return
		}
		machines := []string{}
		requestedMachines := []string{}
		seenMachines := map[string]bool{}
		seenRequested := map[string]bool{}
		aliases := append([]schema.App(nil), d.Apps...)
		references := []schema.SecretEnvironment{}
		for _, item := range usageByApp[name] {
			node, consuming := item.node, item.consuming
			pinned, err := schema.DecodeCanonical(item.canonical)
			if err != nil {
				s.databaseError(w, err)
				return
			}
			if !seenRequested[node] {
				requestedMachines = append(requestedMachines, node)
				seenRequested[node] = true
			}
			if consuming && !seenMachines[node] {
				machines = append(machines, node)
				seenMachines[node] = true
			}
			for _, ref := range pinned.Container.Secrets {
				duplicate := false
				for _, r := range references {
					if r == ref {
						duplicate = true
					}
				}
				if !duplicate {
					references = append(references, ref)
				}
			}
			for _, alias := range pinned.Apps {
				duplicate := false
				for _, a := range aliases {
					if a.Name == alias.Name {
						duplicate = true
					}
				}
				if !duplicate {
					aliases = append(aliases, alias)
				}
			}
		}
		if len(requestedMachines) == 0 {
			references = d.Container.Secrets
		}

		out = append(out, map[string]any{"machines": machines, "requested_machines": requestedMachines, "name": name, "aliases": aliases, "secrets": references, "catalog_secrets": d.Container.Secrets, "denied": denied, "generation": gen})
	}
	respond(w, 200, map[string]any{"apps": out})
}
func (s *Server) operatorPolicy(w http.ResponseWriter, r *http.Request) {
	u, e := s.user(r.Context(), bearer(r))
	if e != nil {
		s.respondError(w, e)
		return
	}
	address, e := protocol.OrchestratorAddress(r.URL.Query().Get("orchestrator_address"))
	if e != nil {
		s.respondError(w, problem(400, "invalid_orchestrator", "Choose an orchestrator."))
		return
	}
	name := r.PathValue("name")
	var in struct {
		Denied   bool  `json:"denied"`
		Expected int64 `json:"expected_generation"`
	}
	if boundedInput(r, &in, 4096) != nil {
		fail(w, 400, "invalid policy")
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	defer tx.Rollback()
	if e = lockMembership(r.Context(), tx, u.ID, address); e != nil {
		s.respondError(w, e)
		return
	}
	if _, e = tx.ExecContext(r.Context(), `SELECT pg_advisory_xact_lock(1129073483,2)`); e != nil {
		s.respondError(w, e)
		return
	}
	var gen int64
	var denied bool
	e = tx.QueryRowContext(r.Context(), `SELECT generation,denied FROM lpcc.operator_app_policy WHERE orchestrator_address=$1 AND app_name=$2 FOR UPDATE`, address, name).Scan(&gen, &denied)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		s.databaseError(w, e)
		return
	}
	if gen != in.Expected {
		fail(w, 409, "policy conflict")
		return
	}
	var exists bool
	if tx.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT FROM lpcc.apps WHERE name=$1)`, name).Scan(&exists) != nil || !exists {
		fail(w, 404, "app not found")
		return
	}
	if gen > 0 && denied == in.Denied {
		respond(w, 200, map[string]any{"generation": gen, "changed": false})
		return
	}
	_, e = tx.ExecContext(r.Context(), `INSERT INTO lpcc.operator_app_policy VALUES($1,$2,$3,1) ON CONFLICT(orchestrator_address,app_name) DO UPDATE SET denied=EXCLUDED.denied,generation=lpcc.operator_app_policy.generation+1`, address, name, in.Denied)
	if e == nil {
		_, e = tx.ExecContext(r.Context(), `INSERT INTO lpcc.operator_policy_generation(orchestrator_address) VALUES($1) ON CONFLICT(orchestrator_address) DO UPDATE SET generation=lpcc.operator_policy_generation.generation+1`, address)
	}
	if e != nil {
		s.databaseError(w, e)
		return
	}
	rows, e := tx.QueryContext(r.Context(), `SELECT node_id FROM lpcc.machines WHERE orchestrator_address=$1 ORDER BY node_id FOR UPDATE`, address)
	if e != nil {
		s.databaseError(w, e)
		return
	}
	nodes := []string{}
	for rows.Next() {
		var node string
		if e = rows.Scan(&node); e != nil {
			break
		}
		nodes = append(nodes, node)
	}
	rows.Close()
	if e != nil {
		s.databaseError(w, e)
		return
	}
	for _, node := range nodes {
		if e = applyOwnerPolicy(r.Context(), tx, node, address, name, in.Denied); e != nil {
			if errors.Is(e, machineapps.ErrRequestedBudget) {
				fail(w, 409, "requested assignments exceed machine limits")
				return
			}
			s.databaseError(w, e)
			return
		}
	}
	action := AdminAction("orchestrator.policy.allow")
	if in.Denied {
		action = "orchestrator.policy.deny"
	}
	if e = writeAudit(r.Context(), tx, "user", u.ID, action, AdminTarget{Kind: "orchestrator_policy", ID: address + "/" + name, Revision: revisionString(gen + 1)}, "success", "changed"); e != nil {
		s.databaseError(w, e)
		return
	}
	if tx.Commit() != nil {
		fail(w, 503, "policy pending")
		return
	}
	select {
	case s.reconcileWake <- struct{}{}:
	default:
	}
	respond(w, 200, map[string]any{"generation": gen + 1, "changed": true})
}
func applyOwnerPolicy(ctx context.Context, tx *sql.Tx, node, owner, name string, denied bool) error {
	if !denied {
		lifecycle, e := lockAppMachine(ctx, tx, node)
		if e != nil {
			return e
		}
		if lifecycle != "active" {
			return nil
		}
		if e = machineapps.CheckRequestedBudget(ctx, tx, node); e != nil {
			return e
		}
	}
	heads, e := machineapps.Heads(ctx, tx, node)
	if e != nil {
		return e
	}
	changed := false
	for _, h := range heads {
		if h.AppName != name {
			continue
		}
		a := h.AppAssignment
		if denied && a.Desired == "present" {
			a = a.Absent()
			a.Generation++
			if e = machineapps.AppendEffective(ctx, tx, node, "operator-policy", a); e != nil {
				return e
			}
			changed = true
		} else if !denied && a.Desired == "absent" && h.CompletedAt != nil {
			pending := false
			for _, source := range heads {
				if source.AppName == name && source.Desired == "absent" && source.CompletedAt == nil {
					pending = true
				}
			}
			if pending {
				continue
			}
			var raw []byte
			e = tx.QueryRowContext(ctx, `SELECT intent FROM lpcc.machine_app_requests WHERE node_id=$1 AND revision_id=$2`, node, a.RevisionID).Scan(&raw)
			if errors.Is(e, sql.ErrNoRows) {
				continue
			}
			if e != nil {
				return e
			}
			var requested schema.AppAssignment
			if json.Unmarshal(raw, &requested) != nil {
				return errors.New("invalid requested intent")
			}
			if requested.Desired != "present" {
				continue
			}
			requested.Generation = a.Generation + 1
			requested.ActivationGeneration = requested.Generation
			requested.Replacement = nil
			requested.StartAfter = nil
			requested.StartAllowed = true
			if e = machineapps.AppendEffective(ctx, tx, node, "operator-policy", requested); e != nil {
				return e
			}
			changed = true
		}
	}
	if changed {
		return machineapps.Bump(ctx, tx, node)
	}
	return nil
}

func hmacEqual(a, b string) bool { return a != "" && hmac.Equal([]byte(a), []byte(b)) }
