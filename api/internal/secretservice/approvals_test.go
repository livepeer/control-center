package secretservice

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/livepeer/control-center/schema"
	protocol "github.com/livepeer/control-center/secrets"
)

func approvalAssignment(t *testing.T) schema.AppAssignment {
	t.Helper()
	raw, e := osReadFixture()
	if e != nil {
		t.Fatal(e)
	}
	d, e := schema.DecodeCanonical(raw)
	if e != nil {
		t.Fatal(e)
	}
	d.Container.Secrets = []schema.SecretEnvironment{{Name: "TOKEN", Secret: "lp-app-provider", Key: "token"}}
	raw, e = schema.CanonicalBytes(d)
	if e != nil {
		t.Fatal(e)
	}
	ref := schema.RevisionRef{RevisionID: "22222222-2222-4222-8222-222222222222", Digest: schema.Digest(raw)}
	return schema.AppAssignment{RevisionRef: ref, Desired: "present", Generation: 1, ActivationGeneration: 1, StartAllowed: true, Revision: &schema.ResolvedRevision{RevisionRef: ref, Name: d.Name, AppVersion: d.AppVersion, Revision: 1, SchemaVersion: 1, CanonicalFormat: schema.CanonicalFormat, Definition: d}}
}
func approveAssignment(t *testing.T, s *Service, a schema.AppAssignment, generation int64) {
	t.Helper()
	w := call(t, s, "/v1/app-approvals/"+a.Revision.Name, "PUT", "operator", map[string]any{"expected_generation": generation, "secrets": approvalReferences(a.Revision.Definition.Container.Secrets)}, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func approvalReferences(refs []schema.SecretEnvironment) []protocol.SecretReference {
	out := []protocol.SecretReference{}
	for _, ref := range refs {
		out = append(out, protocol.SecretReference{Secret: ref.Secret, Key: ref.Key})
	}
	return out
}
func TestAppApprovalCoversFutureRevisionsAndMappings(t *testing.T) {
	a := approvalAssignment(t)
	p := ownerAccess{Apps: []appAccess{{Name: a.Revision.Name, Approvals: []appApproval{{Scope: appSecretScope, Secrets: approvalReferences(a.Revision.Definition.Container.Secrets), Generation: 3}}}}}
	for _, field := range []string{"original", "revision", "mapping", "command", "added_binding", "app", "definition", "reference", "denied", "legacy_grant", "legacy_runtime", "duplicate"} {
		t.Run(field, func(t *testing.T) {
			raw, _ := json.Marshal(a)
			var changed schema.AppAssignment
			_ = json.Unmarshal(raw, &changed)
			policy := p
			version := 1
			allowed := false
			switch field {
			case "original":
				allowed = true
			case "revision":
				changed.RevisionID = "33333333-3333-4333-8333-333333333333"
				allowed = true
			case "mapping":
				changed.Revision.Definition.Container.Secrets[0].Name = "NEW_TOKEN"
				allowed = true
			case "command":
				command := []string{"other-command"}
				changed.Revision.Definition.Container.Command = &command
				allowed = true
			case "added_binding":
				changed.Revision.Definition.Container.Secrets = append(changed.Revision.Definition.Container.Secrets, schema.SecretEnvironment{Name: "OTHER", Secret: "lp-app-other", Key: "token"})
			case "app":
				changed.Revision.Name = "other"
				changed.Revision.Definition.Name = "other"
			case "reference":
				changed.Revision.Definition.Container.Secrets[0].Key = "other"
			case "denied":
				policy = ownerAccess{Apps: []appAccess{{Name: a.Revision.Name, Denied: true, Approvals: p.Apps[0].Approvals}}}
			case "legacy_grant":
				policy = ownerAccess{Apps: []appAccess{{Name: a.Revision.Name, Approvals: []appApproval{{Secrets: approvalReferences(a.Revision.Definition.Container.Secrets), Generation: 3}}}}}
			case "legacy_runtime":
				version = 0
			}
			canonical, e := schema.CanonicalBytes(changed.Revision.Definition)
			if e != nil {
				t.Fatal(e)
			}
			changed.Digest = schema.Digest(canonical)
			changed.Revision.RevisionRef = changed.RevisionRef
			if field == "definition" {
				changed.Revision.Definition.Container.Secrets[0].Key = "unverified"
			}
			assignments := []schema.AppAssignment{changed}
			if field == "duplicate" {
				assignments = append(assignments, changed)
			}
			in := protocol.ResolveRequest{RevisionID: changed.RevisionID, Digest: changed.Digest, Generation: 1, Activation: 1, ApprovalProtocol: version}
			epoch := approvedRequest(policy, protocol.Machine{Assignments: assignments}, in)
			if (epoch == 3) != allowed {
				t.Fatal("unexpected app binding authorization", epoch, allowed)
			}
		})
	}
}

func TestIndependentApprovalDefaultsAndRevocation(t *testing.T) {
	s, key, m, vault := dbService(t)
	identity := enrolled(t, s, key, m)
	a := approvalAssignment(t)
	m.machine.Assignments = []schema.AppAssignment{a}
	in := protocol.ResolveRequest{ApprovalProtocol: 1, RevisionID: a.RevisionID, Generation: 1, Activation: 1, Digest: a.Digest}
	recipient, _ := protocol.EncryptionKEM().GenerateKey()
	delivery := protocol.DeliveryRequest{ResolveRequest: in, RecipientKey: recipient.PublicKey().Bytes()}
	checkBatch := func(body map[string]any, wantDenied, wantTarget bool) {
		t.Helper()
		w := call(t, s, "/v1/runtime/batch", "POST", "", body, identity)
		var batch struct {
			Sets   map[string]protocol.VersionSet `json:"sets"`
			Errors map[string]string              `json:"errors"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &batch) != nil || (batch.Errors[a.RevisionID] == "secrets_denied") != wantDenied || (len(batch.Sets) > 0) != wantTarget {
			t.Fatal("unexpected batch authorization", w.Code, w.Body.String())
		}
	}
	denied := func() {
		t.Helper()
		before := vault.calls.Load()
		for _, endpoint := range []string{"versions", "resolve"} {
			w := call(t, s, "/v1/runtime/"+endpoint, "POST", "", delivery, identity)
			if w.Code != 403 {
				t.Fatal(endpoint, w.Code, w.Body.String())
			}
		}
		checkBatch(map[string]any{"approval_protocol": 1, "assignments": []protocol.ResolveRequest{in}}, true, false)
		if vault.calls.Load() != before {
			t.Fatal("unapproved access reached Transit")
		}

	}

	for _, field := range []string{"reference", "name", "denied", "missing_generation", "legacy_revision"} {
		t.Run(field, func(t *testing.T) {
			path := "/v1/app-approvals/" + a.Revision.Name
			body := map[string]any{"expected_generation": 0, "secrets": approvalReferences(a.Revision.Definition.Container.Secrets)}
			switch field {
			case "reference":
				body["secrets"] = []protocol.SecretReference{{Secret: "not-app-secret", Key: "token"}}
			case "name":
				path = "/v1/app-approvals/" + url.PathEscape(a.Revision.Name+" invalid")
			case "denied":
				body["denied"] = true
			case "missing_generation":
				delete(body, "expected_generation")
			case "legacy_revision":
				body = map[string]any{"expected_generation": 0, "revision": a.Revision}
			}
			w := call(t, s, path, "PUT", "operator", body, nil)
			if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_approval") {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	view := call(t, s, "/v1/app-approvals", "GET", "operator", nil, nil)
	var unchanged ownerAccess
	if view.Code != 200 || json.Unmarshal(view.Body.Bytes(), &unchanged) != nil || unchanged.Generation != 0 || len(unchanged.Apps) != 0 {
		t.Fatal("invalid writes changed grants", view.Code, view.Body.String())
	}
	denied()
	// Another authenticated owner cannot grant this machine owner's access.
	original := s.HTTP.Transport
	s.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: ioBody(`{"id":"33333333-3333-4333-8333-333333333333"}`)}, nil
	})
	approveAssignment(t, s, a, 0)
	s.HTTP.Transport = original
	denied()
	// A previous revision-scoped grant is never promoted to app-wide consent.
	legacy, _ := json.Marshal([]any{map[string]any{"revision_id": a.RevisionID, "digest": a.Digest, "references": a.Revision.Definition.Container.Secrets, "generation": 99}})
	if _, e := s.DB.Exec(`INSERT INTO lpsecrets.app_approvals(owner_id,app_name,denied,approvals) VALUES($1,$2,false,$3)`, testOwner, a.Revision.Name, string(legacy)); e != nil {
		t.Fatal(e)
	}
	denied()
	view = call(t, s, "/v1/app-approvals", "GET", "operator", nil, nil)
	if json.Unmarshal(view.Body.Bytes(), &unchanged) != nil || len(unchanged.Apps) != 1 || len(unchanged.Apps[0].Approvals) != 0 {
		t.Fatal("legacy grant was exposed as consent", view.Body.String())
	}
	approveAssignment(t, s, a, 0)
	w := call(t, s, "/v1/runtime/versions", "POST", "", delivery, identity)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "secret_unprovisioned") {
		t.Fatal(w.Code, w.Body.String())
	}
	path := "/v1/app-approvals/" + a.Revision.Name
	if w = call(t, s, path, "PUT", "operator", map[string]any{"denied": true, "expected_generation": 0}, nil); w.Code != 409 {
		t.Fatal("stale consent write", w.Code)
	}
	if w = call(t, s, path, "PUT", "", map[string]any{"denied": true, "expected_generation": 1}, nil); w.Code != 401 {
		t.Fatal("unauthenticated write", w.Code)
	}
	// Denying revokes app access; clearing deny never restores it.
	for gen, deny := range []bool{true, false} {
		if w = call(t, s, path, "PUT", "operator", map[string]any{"denied": deny, "expected_generation": gen + 1}, nil); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		denied()
	}
	approveAssignment(t, s, a, 3)
	tx, e := s.DB.BeginTx(t.Context(), nil)
	if e != nil {
		t.Fatal(e)
	}
	p, e := readAccess(t.Context(), tx, testOwner, true)
	tx.Rollback()
	if e != nil || approvedRequest(p, m.machine, in) != 4 {
		t.Fatal("reapproval did not establish a new epoch", p, e)
	}
	// Unassigned cleanup consumers are denied after revocation too.
	m.machine.Consumers = []protocol.SecretConsumer{{RevisionID: a.RevisionID, AppName: a.Revision.Name, References: a.Revision.Definition.Container.Secrets}}
	m.machine.Assignments = nil
	if w = call(t, s, path, "PUT", "operator", map[string]any{"denied": true, "expected_generation": 4}, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	checkBatch(map[string]any{"approval_protocol": 1, "assignments": []any{}}, true, false)

	// A locally observed source can miss both operations while offline. Its signed
	// old epoch must still force drain after reapproval, without metadata consumers.
	m.machine.Consumers = nil
	approveAssignment(t, s, a, 5)
	if _, e = s.DB.Exec(`INSERT INTO lpsecrets.secrets(id,owner_id,name,key,head) VALUES($1,$2,$3,$4,$5)`, ident(), testOwner, a.Revision.Definition.Container.Secrets[0].Secret, "token", ident()); e != nil {
		t.Fatal(e)
	}
	for _, assigned := range []bool{true, false} {
		if assigned {
			m.machine.Assignments = []schema.AppAssignment{a}
		} else {
			m.machine.Assignments = nil
		}
		for _, epoch := range []int64{4, 6} {
			consumer := protocol.RuntimeConsumer{RevisionID: a.RevisionID, Name: a.Revision.Name, ApprovalGeneration: epoch}
			requests := []protocol.ResolveRequest{}
			if assigned {
				requests = append(requests, in)
			}
			checkBatch(map[string]any{"approval_protocol": 1, "assignments": requests, "consumers": []protocol.RuntimeConsumer{consumer}}, epoch == 4, assigned && epoch == 6)

		}
	}

	for _, kind := range []string{"metadata", "runtime"} {
		m.machine.Consumers = nil
		consumers := []protocol.RuntimeConsumer{}
		if kind == "metadata" {
			m.machine.Consumers = []protocol.SecretConsumer{{RevisionID: a.RevisionID, AppName: a.Revision.Name, References: a.Revision.Definition.Container.Secrets}}
		} else {
			consumers = append(consumers, protocol.RuntimeConsumer{RevisionID: a.RevisionID, Name: a.Revision.Name, ApprovalGeneration: 6})
		}
		checkBatch(map[string]any{"assignments": []any{}, "consumers": consumers}, true, false)

	}

	// Renewal blocks every revision of this app until old local consumers drain,
	// while preserving independent app grants on the same machine.
	other := approvalAssignment(t)
	other.RevisionID = "44444444-4444-4444-8444-444444444444"
	other.Revision.Name = "other"
	other.Revision.Definition.Name = "other"
	canonical, _ := schema.CanonicalBytes(other.Revision.Definition)
	other.Digest = schema.Digest(canonical)
	other.Revision.RevisionRef = other.RevisionRef
	approveAssignment(t, s, other, 6)
	m.machine.Consumers = nil
	m.machine.Assignments = []schema.AppAssignment{a, other}
	otherRequest := in
	otherRequest.RevisionID = other.RevisionID
	otherRequest.Digest = other.Digest
	old := protocol.RuntimeConsumer{RevisionID: "33333333-3333-4333-8333-333333333333", Name: a.Revision.Name, ApprovalGeneration: 4}
	w = call(t, s, "/v1/runtime/batch", "POST", "", map[string]any{"approval_protocol": 1, "assignments": []protocol.ResolveRequest{in, otherRequest}, "consumers": []protocol.RuntimeConsumer{old}}, identity)
	var batch struct {
		Sets   map[string]protocol.VersionSet `json:"sets"`
		Errors map[string]string              `json:"errors"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &batch) != nil || len(batch.Sets) != 1 || batch.Sets[other.RevisionID].ApprovalGeneration != 7 || batch.Errors[a.RevisionID] != "secrets_denied" || batch.Errors[old.RevisionID] != "secrets_denied" {
		t.Fatal("renewal crossed an app drain barrier", w.Code, w.Body.String())
	}

	checkBatch(map[string]any{"approval_protocol": 1, "assignments": []protocol.ResolveRequest{in}, "consumers": []map[string]any{{"revision_id": a.RevisionID, "digest": a.Digest, "name": a.Revision.Name, "approval_generation": 6}}}, false, true)

}

func TestApprovalReadCannotPassConcurrentRevocation(t *testing.T) {
	s, _, _, _ := dbService(t)
	a := approvalAssignment(t)
	approveAssignment(t, s, a, 0)
	// An authorization snapshot established before a waiting revoke commits
	// must fail serialization, rather than return the old grants after the wait.
	revoke, e := s.DB.BeginTx(t.Context(), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer revoke.Rollback()
	if _, e = revoke.Exec(`UPDATE lpsecrets.app_policy_generation SET generation=generation+1 WHERE owner_id=$1`, testOwner); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		tx, e := s.DB.BeginTx(t.Context(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if e != nil {
			done <- e
			return
		}
		defer tx.Rollback()
		_, e = readAccess(t.Context(), tx, testOwner, true)
		done <- e
	}()
	deadline := time.After(5 * time.Second)
	for {
		var waiting bool
		if e = s.DB.QueryRow(`SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT generation FROM lpsecrets.app_policy_generation%')`).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
		select {
		case <-deadline:
			t.Fatal("approval read did not wait for revocation")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, e = revoke.Exec(`UPDATE lpsecrets.app_approvals SET denied=true,approvals='[]' WHERE owner_id=$1`, testOwner); e != nil {
		t.Fatal(e)
	}
	if e = revoke.Commit(); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e == nil {
		t.Fatal("stale authorization snapshot survived revocation")
	}
}

func TestApprovalUsesAppNameValidation(t *testing.T) {
	s, _, _, _ := dbService(t)
	a := approvalAssignment(t)
	a.Revision.Name = strings.Repeat("a", 128)
	a.Revision.Definition.Name = a.Revision.Name
	canonical, e := schema.CanonicalBytes(a.Revision.Definition)
	if e != nil {
		t.Fatal(e)
	}
	a.Digest = schema.Digest(canonical)
	a.Revision.RevisionRef = a.RevisionRef
	approveAssignment(t, s, a, 0)
	w := call(t, s, "/v1/app-approvals/"+a.Revision.Name, "PUT", "operator", map[string]any{"denied": true, "expected_generation": 1}, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	before := call(t, s, "/v1/app-approvals", "GET", "operator", nil, nil)
	for _, name := range []string{"-app", "app name", "app/name", strings.Repeat("a", 129)} {
		w = call(t, s, "/v1/app-approvals/"+url.PathEscape(name), "PUT", "operator", map[string]any{"denied": true, "expected_generation": 2}, nil)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_approval") {
			t.Fatal(name, w.Code, w.Body.String())
		}
	}
	after := call(t, s, "/v1/app-approvals", "GET", "operator", nil, nil)
	if before.Code != 200 || after.Code != 200 || before.Body.String() != after.Body.String() {
		t.Fatal("invalid app name changed consent", after.Code, after.Body.String())
	}
}
