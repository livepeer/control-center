package schema

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func assignmentFixture(t *testing.T) AppAssignmentSetV1 {
	t.Helper()
	source, err := os.ReadFile("../runtime/tests/fixtures/whoami.toml")
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseTOML(source)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := CanonicalBytes(d)
	r := ResolvedRevision{RevisionRef: RevisionRef{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Digest(canonical)}, Name: d.Name, AppVersion: d.AppVersion, Revision: 1, SchemaVersion: 1, CanonicalFormat: CanonicalFormat, Definition: d}
	return AppAssignmentSetV1{SchemaVersion: 1, NodeID: "vkvkvkvkvkvkuaaaaaaaaaaaaa", Generation: 1, Entries: []AppAssignment{{RevisionRef: r.RevisionRef, Generation: 2, ActivationGeneration: 1, Desired: "present", Cleanup: CleanupPolicy(d), Revision: &r, Replicas: 3, StartAllowed: true}}}
}
func TestAssignmentContractAndCompactRemoval(t *testing.T) {
	s := assignmentFixture(t)
	canonical, err := CanonicalAssignmentSet(s)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAssignmentSet(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Entries[0].Revision.Definition.Instances.Replicas != 2 || decoded.Entries[0].Replicas != 3 {
		t.Fatal("override mutated revision")
	}
	s.Entries[0] = s.Entries[0].Absent()
	s.Entries[0].Generation++
	b, err := CanonicalAssignmentSet(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "container") || strings.Contains(string(b), "start_after") {
		t.Fatal("tombstone retains definition")
	}
	if _, err = DecodeAssignmentSet(b); err != nil {
		t.Fatal(err)
	}
}
func TestAssignmentContractRejectsMalformedData(t *testing.T) {
	s := assignmentFixture(t)
	b, _ := CanonicalAssignmentSet(s)
	cases := []string{
		strings.Replace(string(b), `"schema_version":1`, `"schema_version":2`, 1),
		strings.Replace(string(b), `"start_allowed":true`, `"start_allowed":false`, 1),
		strings.Replace(string(b), `"generation":2,`, "", 1),
		strings.Replace(string(b), `"replicas":3`, `"replicas":0`, 1),
		strings.Replace(string(b), `"generation":2`, `"generation":2,"generation":3`, 1),
		strings.Replace(string(b), `"entries":`, `"unknown":true,"entries":`, 1),
		strings.Replace(string(b), `"app_version":"1",`, "", 1),
	}
	for i, c := range cases {
		if _, err := DecodeAssignmentSet([]byte(c)); err == nil {
			t.Fatalf("accepted malformed contract %d", i)
		}
	}
	s.Entries = append(s.Entries, s.Entries[0])
	if _, err := CanonicalAssignmentSet(s); err == nil {
		t.Fatal("duplicate revision")
	}
}
func TestAssignmentBudgetReservesRemovalAndCounters(t *testing.T) {
	s := assignmentFixture(t)
	template := s.Entries[0]
	args := make([]string, 64)
	for i := range args {
		args[i] = strings.Repeat("x", 4000)
	}
	template.Revision.Definition.Container.Entrypoint = &args
	b, err := CanonicalBytes(template.Revision.Definition)
	if err != nil {
		t.Fatal(err)
	}
	template.Digest = Digest(b)
	template.Revision.Digest = template.Digest
	s.Entries = nil
	for i := 0; i < 3; i++ {
		a := template
		r := *template.Revision
		r.RevisionID = fmt.Sprintf("%08x-0000-4000-8000-000000000001", i+1)
		a.Revision = &r
		a.RevisionID = r.RevisionID
		s.Entries = append(s.Entries, a)
	}
	if err = CheckAssignmentBudget(s); err != nil {
		t.Fatal(err)
	}
	s.Entries[0] = s.Entries[0].Absent()
	if err = CheckAssignmentBudget(s); err != nil {
		t.Fatal("removal no longer fits", err)
	}
	for len(s.Entries) < 6 {
		a := template
		r := *template.Revision
		r.RevisionID = fmt.Sprintf("%08x-0000-4000-8000-000000000001", len(s.Entries)+1)
		a.Revision = &r
		a.RevisionID = r.RevisionID
		s.Entries = append(s.Entries, a)
	}
	if err = CheckAssignmentBudget(s); err == nil {
		t.Fatal("oversized manifest admitted")
	}
}
