package controlplane

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/api/internal/testdb"
	"github.com/livepeer/control-center/schema"
	protocol "github.com/livepeer/control-center/secrets"
)

func TestSecretMetadataDefaultsAndAuthorization(t *testing.T) {
	s := newTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("2", 64))
	node := c["node_id"]
	path := "/internal/secrets/nodes/" + node
	requireStatus(t, request(t, s, "GET", path, "", nil), 403)
	s.params.SecretsMetadataToken = strings.Repeat("m", 32)
	requireStatus(t, request(t, s, "GET", path, "session-a", nil), 403)
	execSQL(t, s.db, `DELETE FROM lpcc.secret_machines WHERE node_id=$1`, node)
	for _, n := range []string{node, "missing-node"} {
		q := &testdb.Observer{DB: s.db}
		m, err := secretMachineMetadata(t.Context(), q, n)
		if err != nil || q.Reads != 1 || m.NodeID != n || m.PublicKey != "" || m.Managed || m.EncryptionReady || m.PolicyGeneration != 0 {
			t.Fatal(m, q.Reads, err)
		}
		if n == node {
			if !m.Active || m.Owner != orchA || m.Assignments == nil || len(m.Assignments) != 0 {
				t.Fatal(m)
			}
		} else if m.Active || m.Owner != "" || m.Assignments != nil {
			t.Fatal(m)
		}
	}
	execSQL(t, s.db, `UPDATE lpcc.enrollments SET retired_at=now() WHERE node_id=$1`, node)
	m, err := secretMachineMetadata(t.Context(), s.db, node)
	if err != nil || !reflect.DeepEqual(m, protocol.Machine{NodeID: node, Owner: orchA}) {
		t.Fatal(m, err)
	}
	requireStatus(t, request(t, s, "POST", path, s.params.SecretsMetadataToken, map[string]any{"invalid": "ignored for retired enrollment"}), 200)
}

func TestSecretMetadataProjectionCleanupAndSnapshot(t *testing.T) {
	s := newTestServer(t)
	adminA(t, s)
	c := enroll(t, s, ownerA, strings.Repeat("3", 64))
	node := c["node_id"]
	fixture := strings.Replace(registryFixture(t), `LOG_LEVEL = "info"`, `LOG_LEVEL = "info"`+"\nPAYLOAD = \""+strings.Repeat("nonsecret-payload-", 700)+"\"", 1)
	decl := "\n[[container.secrets]]\nname = \"TOKEN\"\nsecret = \"lp-app-pinned\"\nkey = \"token\"\n"
	first := publishAssignmentRevision(t, s, fixture+decl, "")
	requireStatus(t, putApp(t, s, c, first, 0, 1), 202)
	second := publishAssignmentRevision(t, s, strings.Replace(fixture, `app_version = "1"`, `app_version = "2"`, 1)+strings.Replace(decl, "lp-app-pinned", "lp-app-new", 1), first.RevisionID)
	requireStatus(t, request(t, s, "POST", appPath(c, first)+"/replace", "session-a", map[string]any{"expected_generation": 1, "target": map[string]any{"revision_id": second.RevisionID, "digest": second.Digest, "expected_generation": 0}}), 202)
	q := &testdb.Observer{DB: s.db}
	full, err := machineapps.Snapshot(t.Context(), q, node)
	if err != nil || q.Reads != 1 {
		t.Fatal(q.Reads, err)
	}
	if _, err = schema.CanonicalAssignmentSet(*full); err != nil {
		t.Fatal("runtime snapshot lost full definitions", err)
	}
	q.Reads = 0
	m, err := secretMachineMetadata(t.Context(), q, node)
	if err != nil || q.Reads != 1 || len(m.Assignments) != 2 || len(m.Consumers) != 1 || m.Consumers[0].RevisionID != first.RevisionID || m.Consumers[0].References[0].Secret != "lp-app-pinned" {
		t.Fatal(m, q.Reads, err)
	}
	for i, a := range full.Entries {
		if a.Revision != nil {
			revision := *a.Revision
			revision.Definition = schema.DefinitionV1{}
			revision.Definition.Container.Secrets = a.Revision.Definition.Container.Secrets
			a.Revision = &revision
		}
		if !reflect.DeepEqual(a, m.Assignments[i]) {
			t.Fatal("authorization projection changed identity/eligibility", a, m.Assignments[i])
		}
	}
	raw, _ := json.Marshal(m)
	fullRaw, _ := json.Marshal(full)
	if strings.Contains(string(raw), "nonsecret-payload-") || !strings.Contains(string(fullRaw), "nonsecret-payload-") || len(raw) >= len(fullRaw) {
		t.Fatal("authorization transferred unused definition", len(raw), len(fullRaw))
	}
	t.Logf("full runtime snapshot: %d bytes; authorization metadata: %d bytes", len(fullRaw), len(raw))
	target := func(m protocol.Machine) schema.AppAssignment {
		t.Helper()
		for _, a := range m.Assignments {
			if a.RevisionID == second.RevisionID {
				return a
			}
		}
		t.Fatal("target missing")
		return schema.AppAssignment{}
	}
	if target(m).StartAllowed {
		t.Fatal("pending cleanup allowed a start")
	}
	// Applied evidence and a removal at an older generation cannot release it.
	execSQL(t, s.db, `INSERT INTO lpcc.machine_app_completions(node_id,revision_id,generation,activation_generation,phase,apps_digest) VALUES($1,$2,1,1,'removed',$3),($1,$2,2,1,'applied',$3)`, node, first.RevisionID, "sha256:"+strings.Repeat("a", 64))
	m, err = secretMachineMetadata(t.Context(), s.db, node)
	if err != nil || target(m).StartAllowed || len(m.Consumers) != 0 {
		t.Fatal(m, err)
	}
	execSQL(t, s.db, `INSERT INTO lpcc.machine_app_completions(node_id,revision_id,generation,activation_generation,phase,apps_digest) VALUES($1,$2,2,1,'removed',$3)`, node, first.RevisionID, "sha256:"+strings.Repeat("a", 64))
	m, err = secretMachineMetadata(t.Context(), s.db, node)
	if err != nil || !target(m).StartAllowed || len(m.Assignments) != 1 {
		t.Fatal(m, err)
	}
	// A concurrent policy transaction must not mix old assignments with new policy.
	q = &testdb.Observer{DB: s.db, AfterQuery: func() {
		requireStatus(t, request(t, s, "PUT", "/api/operator/apps/"+first.Name+"/policy?orchestrator_address="+orchA, "session-a", map[string]any{"denied": true, "expected_generation": 0}), 200)
	}}
	before, err := secretMachineMetadata(t.Context(), q, node)
	if err != nil || q.Reads != 1 || before.PolicyGeneration != 0 || len(before.DeniedRevisions) != 0 || target(before).Desired != "present" {
		t.Fatal(before, q.Reads, err)
	}
	after, err := secretMachineMetadata(t.Context(), s.db, node)
	if err != nil || after.PolicyGeneration != 1 || len(after.DeniedRevisions) != 2 || target(after).Desired != "absent" || len(after.Consumers) != 1 {
		t.Fatal(after, err)
	}

	// Denial evidence survives completed-removal filtering and a zero app generation.
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET apps_generation=0 WHERE node_id=$1`, node)
	after, err = secretMachineMetadata(t.Context(), s.db, node)
	if err != nil || len(after.Assignments) != 0 || len(after.DeniedRevisions) != 2 || len(after.Consumers) != 0 {
		t.Fatal(after, err)
	}
}
