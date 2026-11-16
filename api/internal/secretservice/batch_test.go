package secretservice

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/livepeer/control-center/api/internal/testdb"
	"github.com/livepeer/control-center/schema"
	protocol "github.com/livepeer/control-center/secrets"
	"uuid"
)

func TestBatchSecretMetadataStatementSnapshot(t *testing.T) {
	s, _, _, _ := dbService(t)
	insert := func(owner, name string, deleted bool, head any) {
		t.Helper()
		if _, err := s.DB.Exec(`INSERT INTO lpsecrets.secrets(id,orchestrator_address,name,key,head,deleted) VALUES($1,$2,$3,'token',$4,$5)`, uuid.New().String(), owner, name, head, deleted); err != nil {
			t.Fatal(err)
		}
	}
	version := uuid.New().String()
	insert(testOwner, "live", false, version)
	insert(testOwner, "deleted", true, nil)
	insert(testOwner, "deleted", true, nil)
	insert(testOwner, "reserved", true, nil)
	insert(testOwner, "reserved", false, nil)
	insert("0x2222222222222222222222222222222222222222", "foreign", true, nil)
	refs := []secretReference{{"live", "token"}, {"live", "token"}, {"deleted", "token"}, {"reserved", "token"}, {"unknown", "token"}, {"foreign", "token"}, {"live", "other-key"}}
	q := &testdb.Observer{DB: s.DB, AfterQuery: func() {
		if _, err := s.DB.Exec(`UPDATE lpsecrets.secrets SET head=NULL,deleted=true,revision=revision+1 WHERE orchestrator_address=$1 AND name='live'`, testOwner); err != nil {
			t.Fatal(err)
		}
	}}
	metadata, err := batchSecretMetadata(t.Context(), q, testOwner, refs)
	if err != nil || q.Reads != 1 || len(metadata) != 6 {
		t.Fatal(metadata, q.Reads, err)
	}
	for ref, m := range metadata {
		want := "secret_unprovisioned"
		switch ref.Name {
		case "live":
			if ref.Key == "token" {
				want = ""
				if m.value.Version != version || m.value.Revision != 1 {
					t.Fatal(m)
				}
			}
		case "deleted":
			want = "secret_missing"
		}
		if m.reason != want {
			t.Fatal(ref, m.reason, want)
		}
	}
	q = &testdb.Observer{DB: s.DB}
	metadata, err = batchSecretMetadata(t.Context(), q, testOwner, refs)
	if err != nil || q.Reads != 1 || metadata[secretReference{"live", "token"}].reason != "secret_missing" {
		t.Fatal(metadata, q.Reads, err)
	}
	q.Reads = 0
	metadata, err = batchSecretMetadata(t.Context(), q, testOwner, nil)
	if err != nil || q.Reads != 0 || len(metadata) != 0 {
		t.Fatal(metadata, q.Reads, err)
	}
}

func TestBatchVersionsPreservesErrorsDigestsAndConsumers(t *testing.T) {
	s, key, m, vault := dbService(t)
	identity := enrolled(t, s, key, m)
	values := []protocol.Resolved{}
	for _, name := range []string{"ready-a", "ready-b"} {
		value := protocol.Resolved{Ciphertext: protocol.Ciphertext{Binding: protocol.Binding{Owner: testOwner, Name: name, Key: "token", ID: uuid.New().String(), Version: uuid.New().String()}}, Revision: 2}
		if _, err := s.DB.Exec(`INSERT INTO lpsecrets.secrets(id,orchestrator_address,name,key,head,revision) VALUES($1,$2,$3,$4,$5,$6)`, value.ID, testOwner, name, value.Key, value.Version, value.Revision); err != nil {
			t.Fatal(err)
		}
		values = append(values, value)
	}
	if _, err := s.DB.Exec(`INSERT INTO lpsecrets.secrets(id,orchestrator_address,name,key,deleted) VALUES($1,$2,'deleted','token',true)`, uuid.New().String(), testOwner); err != nil {
		t.Fatal(err)
	}
	assignment := func(names ...string) schema.AppAssignment {
		a := schema.AppAssignment{RevisionRef: schema.RevisionRef{RevisionID: uuid.New().String(), Digest: "sha256:assignment"}, Generation: 3, ActivationGeneration: 2, Desired: "present", StartAllowed: true, Revision: &schema.ResolvedRevision{}}
		for _, name := range names {
			a.Revision.Definition.Container.Secrets = append(a.Revision.Definition.Container.Secrets, schema.SecretEnvironment{Name: "ENV", Secret: name, Key: "token"})
		}
		m.machine.Assignments = append(m.machine.Assignments, a)
		return a
	}
	ready := assignment("ready-b", "ready-a", "ready-b")
	empty := assignment()
	unprovisioned := assignment("unknown", "deleted")
	missing := assignment("deleted", "unknown")
	blocked := assignment("deleted")
	m.machine.Assignments[len(m.machine.Assignments)-1].StartAllowed = false
	denied := assignment("unknown")
	m.machine.DeniedRevisions = []string{denied.RevisionID}
	consumerID := uuid.New().String()
	m.machine.Consumers = []protocol.SecretConsumer{
		{RevisionID: consumerID, References: []schema.SecretEnvironment{{Secret: "deleted", Key: "token"}}},
		{RevisionID: denied.RevisionID, References: []schema.SecretEnvironment{{Secret: "deleted", Key: "token"}}},
	}
	request := func(a schema.AppAssignment) protocol.ResolveRequest {
		return protocol.ResolveRequest{RevisionID: a.RevisionID, Digest: a.Digest, Generation: a.Generation, Activation: a.ActivationGeneration}
	}
	type result struct {
		Sets   map[string]protocol.VersionSet `json:"sets"`
		Errors map[string]string              `json:"errors"`
	}
	batch := func(requests ...protocol.ResolveRequest) result {
		t.Helper()
		w := call(t, s, "/v1/runtime/batch", "POST", "", map[string]any{"assignments": requests}, identity)
		var out result
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	out := batch(request(ready), request(empty), request(unprovisioned), request(missing), request(blocked), request(denied))
	expected := []protocol.Resolved{values[1], values[0], values[1]}
	set := out.Sets[ready.RevisionID]
	if len(out.Sets) != 2 || !reflect.DeepEqual(set.Values, expected) || set.Digest != protocol.VersionDigest(expected) || set.IdentityGeneration != identity.Generation || set.PolicyGeneration != m.machine.PolicyGeneration || set.Assignment != request(ready) {
		t.Fatal(out)
	}
	if len(out.Sets[empty.RevisionID].Values) != 0 || out.Sets[empty.RevisionID].Digest != protocol.VersionDigest(nil) {
		t.Fatal(out)
	}
	want := map[string]string{unprovisioned.RevisionID: "secret_unprovisioned", missing.RevisionID: "secret_missing", blocked.RevisionID: "assignment_changed", denied.RevisionID: "secrets_denied", consumerID: "secret_missing"}
	if !reflect.DeepEqual(out.Errors, want) {
		t.Fatal(out.Errors, want)
	}
	changed := request(ready)
	changed.Expected = "stale"
	out = batch(changed)
	if out.Errors[ready.RevisionID] != "secret_changed" || len(out.Sets) != 0 {
		t.Fatal(out)
	}
	for _, change := range []func(*protocol.ResolveRequest){func(r *protocol.ResolveRequest) { r.Generation++ }, func(r *protocol.ResolveRequest) { r.Activation++ }, func(r *protocol.ResolveRequest) { r.Digest = "other" }} {
		stale := request(ready)
		change(&stale)
		out = batch(stale)
		if out.Errors[ready.RevisionID] != "assignment_changed" {
			t.Fatal(out)
		}
	}
	// Revision-keyed maps keep prior successes and faults for duplicate inputs.
	stale := request(ready)
	stale.Generation++
	out = batch(request(ready), stale, request(ready))
	if out.Errors[ready.RevisionID] != "assignment_changed" || out.Sets[ready.RevisionID].Digest != protocol.VersionDigest(expected) {
		t.Fatal(out)
	}
	out = batch()
	if len(out.Sets) != 0 || out.Errors[consumerID] != "secret_missing" || out.Errors[denied.RevisionID] != "secrets_denied" {
		t.Fatal(out)
	}
	if w := call(t, s, "/v1/runtime/versions", "POST", "", protocol.ResolveRequest{RevisionID: consumerID}, identity); w.Code != 409 {
		t.Fatal("cleanup observation granted resolution", w.Code, w.Body.String())
	}
	if vault.calls.Load() != 0 {
		t.Fatal("metadata reached Transit")
	}
}
