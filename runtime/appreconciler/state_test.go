package appreconciler

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJournalRecoversLatestCommitAndRejectsStaleSequence(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Truncate(time.Second)
	if err = j.Update(func(s *State) error {
		s.OwnerHash = "withdrawn"
		s.Identity = Identity{RunnerID: "runner", Credential: "private"}
		s.Instances["one"] = &Instance{ID: "one", Phase: "draining", Deadline: deadline, WithdrawalID: "withdrawal"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := j.Reserve("withdrawn"); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err := j.Reserve("stale"); !errors.Is(err, ErrSuperseded) {
		t.Fatal("accepted stale allocator", err)
	}
	if _, err := OpenJournal(dir); err == nil {
		t.Fatal("allowed concurrent owner")
	}
	j.Close()
	// A corrupt derived checkpoint cannot roll the authoritative journal record back.
	os.WriteFile(filepath.Join(dir, "checkpoint"), []byte("broken"), 0600)
	j, err = OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	state := j.View()
	if state.MutationSequence != 1 || state.Identity.Credential != "private" || !state.Instances["one"].Deadline.Equal(deadline) {
		t.Fatal("lost committed identity/deadline", state)
	}
	if n, err := j.Reserve("withdrawn"); err != nil || n != 2 {
		t.Fatal("reused sequence", n, err)
	}
	j.Close()
}

func TestHistoryCollectionPinsPendingReceiptsAndPublications(t *testing.T) {
	j, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	store := artifact.Store{Directory: t.TempDir()}
	digests := []string{}
	past := time.Now().Add(-2 * time.Hour)
	for n := 0; n < 40; n++ {
		data, err := artifact.Pack(map[string][]byte{"kustomization.yaml": []byte("resources: []\n"), "snapshot.json": []byte(fmt.Sprint(n))})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := store.Put(data)
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, digest)
		os.Chtimes(filepath.Join(store.Directory, digest[7:]+".tar.gz"), past, past)
	}
	if err := j.Update(func(s *State) error {
		for _, digest := range digests {
			s.Snapshots[digest] = Snapshot{}
		}
		s.Staged = digests[39]
		s.Published = digests[39]
		s.Applied = digests[38]
		s.Receipts["pending"] = Receipt{ArtifactDigest: digests[3]}
		s.Report = &Report{Apps: contract.AppStatus{AppliedDigest: digests[4]}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c := Controller{Journal: j, Store: store}
	if err := c.collect(View{Artifact: digests[39], Applied: digests[38]}, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{3, 4, 38, 39} {
		if _, err := store.Get(digests[index]); err != nil {
			t.Fatal("collected a live reference", index, err)
		}
	}
	if len(j.View().Snapshots) > 4 {
		t.Fatal("unbounded snapshot history")
	}
	entries, _ := os.ReadDir(store.Directory)
	if len(entries) > 14 {
		t.Fatal("unbounded archive history", len(entries))
	}
}
func TestJournalRecoveryRequiresTheLatestFence(t *testing.T) {
	dir := t.TempDir()
	j, _ := OpenJournal(dir)
	j.Update(func(s *State) error { s.OwnerHash = "ready"; return nil })
	old, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	j.Update(func(s *State) error { s.Identity.Retiring = true; s.OwnerHash = "retiring"; return nil })
	latest := j.recordPath(j.head.Sequence)
	j.Close()
	// An exact latest checkpoint can recover one damaged record.
	os.WriteFile(latest, []byte("corrupt"), 0600)
	j, err = OpenJournal(dir)
	if err != nil || !j.View().Identity.Retiring {
		t.Fatal("failed exact recovery", err)
	}
	j.Close()
	// A valid older checkpoint is never evidence that committed retirement did not happen.
	os.WriteFile(latest, []byte("corrupt"), 0600)
	os.WriteFile(filepath.Join(dir, "checkpoint"), old, 0600)
	if _, err = OpenJournal(dir); !errors.Is(err, ErrStateLost) {
		t.Fatal("rolled back committed state", err)
	}
}
func TestUncommittedRecordDoesNotBecomeAnOperation(t *testing.T) {
	dir := t.TempDir()
	j, _ := OpenJournal(dir)
	orphan, _ := json.Marshal(record{Sequence: 1, State: json.RawMessage(`{"version":1,"identity":{"retiring":true}}`)})
	os.WriteFile(j.recordPath(1), orphan, 0600)
	j.Close()
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if j.View().Identity.Retiring {
		t.Fatal("applied uncommitted record")
	}
	for n := 0; n < 5; n++ {
		if err = j.Update(func(s *State) error { s.ReportSequence++; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	records, _ := os.ReadDir(filepath.Join(dir, "commits"))
	if len(records) > 2 {
		t.Fatal("unbounded journal history")
	}
	mode, err := os.Stat(filepath.Join(dir, "HEAD"))
	if err != nil || mode.Mode().Perm() != 0600 {
		t.Fatal("credential state permissions")
	}
}
