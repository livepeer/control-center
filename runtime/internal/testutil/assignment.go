// Package testutil supplies the canonical Runtime fixture to independent package tests.
package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/livepeer/control-center/schema"
)

func Assignment(t testing.TB) schema.AppAssignmentSetV1 {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../tests/fixtures/whoami.canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := schema.DecodeCanonical(b)
	if err != nil {
		t.Fatal(err)
	}
	d.Lifecycle.StopSignal = nil
	a := schema.AppAssignment{Generation: 1, ActivationGeneration: 1, Desired: "present", Replicas: 2, StartAllowed: true}
	a.RevisionID = "11111111-1111-4111-8111-111111111111"
	a.Revision = &schema.ResolvedRevision{RevisionRef: a.RevisionRef, Name: d.Name, AppVersion: d.AppVersion, Revision: 1, SchemaVersion: 1, CanonicalFormat: schema.CanonicalFormat, Definition: d}
	Refresh(&a)
	return schema.AppAssignmentSetV1{SchemaVersion: 1, NodeID: strings.Repeat("a", 26), Generation: 1, Entries: []schema.AppAssignment{a}}
}
func Refresh(a *schema.AppAssignment) {
	b, err := schema.CanonicalBytes(a.Revision.Definition)
	if err != nil {
		panic(err)
	}
	a.Digest = schema.Digest(b)
	a.Revision.RevisionRef = a.RevisionRef
	a.Cleanup = schema.CleanupPolicy(a.Revision.Definition)
}
