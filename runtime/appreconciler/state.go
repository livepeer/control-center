// Package appreconciler coordinates app lifecycles while Flux remains the workload apply engine.
package appreconciler

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/schema"
)

var ErrStateLost = errors.New("state_recovery_failed")
var ErrSuperseded = errors.New("superseded_owner_snapshot")
var ErrClock = errors.New("clock_uncertain")
var ErrResourceRefused = errors.New("resource_refused")

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("random source unavailable")
	}
	return hex.EncodeToString(b[:])
}

type Identity struct {
	RunnerID   string `json:"runner_id"`
	Credential string `json:"credential"`
	Confirmed  bool   `json:"confirmed"`
	Retiring   bool   `json:"retiring"`
}
type Instance struct {
	ID                 string              `json:"id"`
	Group              appbundle.Group     `json:"group"`
	Generation         int64               `json:"generation"`
	Definition         schema.DefinitionV1 `json:"definition"`
	Files              map[string][]byte   `json:"files"`
	Name               string              `json:"name"`
	PodUID             string              `json:"pod_uid,omitempty"`
	StopVerified       bool                `json:"stop_verified"`
	AppID              string              `json:"app_id,omitempty"`
	Phase              string              `json:"phase"`
	Reason             string              `json:"reason,omitempty"`
	CreatedAt          time.Time           `json:"created_at"`
	WithdrawalID       string              `json:"withdrawal_id,omitempty"`
	Deadline           time.Time           `json:"deadline,omitempty"`
	Forced             bool                `json:"forced"`
	RegistrationGone   bool                `json:"registration_gone"`
	RetiredAt          time.Time           `json:"retired_at,omitempty"`
	DrainExpiredAt     time.Time           `json:"drain_expired_at,omitempty"`
	RemovalPublishedAt time.Time           `json:"removal_published_at,omitempty"`
	TerminatedAt       time.Time           `json:"terminated_at,omitempty"`
}
type Snapshot struct {
	Included       map[string]bool `json:"included"`
	Retired        map[string]bool `json:"retired"`
	IntentDigest   string          `json:"intent_digest"`
	AppsGeneration int64           `json:"apps_generation,omitempty"`
}
type Receipt struct {
	RevisionID           string `json:"revision_id"`
	Generation           int64  `json:"generation"`
	ActivationGeneration int64  `json:"activation_generation"`
	AppsDigest           string `json:"apps_digest"`
	Phase                string `json:"phase"`
	Reason               string `json:"reason,omitempty"`
	Done                 bool   `json:"done"`
	ArtifactDigest       string `json:"artifact_digest,omitempty"`
}
type State struct {
	Version                 int                  `json:"version"`
	Metadata                contract.Metadata    `json:"metadata"`
	InputDigest             string               `json:"input_digest"`
	Payload                 appbundle.Payload    `json:"payload"`
	Instances               map[string]*Instance `json:"instances"`
	Heads                   map[string]string    `json:"heads"`
	Identity                Identity             `json:"identity"`
	OwnerEpoch              string               `json:"owner_epoch"`
	OwnerHash               string               `json:"owner_hash"`
	MutationSequence        uint64               `json:"mutation_sequence"`
	AcceptedSequence        uint64               `json:"accepted_sequence"`
	IdentitySequence        uint64               `json:"identity_sequence"`
	ReportSequence          uint64               `json:"report_sequence"`
	MaintenanceID           string               `json:"maintenance_id,omitempty"`
	MaintenanceWithdrawal   string               `json:"maintenance_withdrawal,omitempty"`
	Staged                  string               `json:"staged,omitempty"`
	Published               string               `json:"published,omitempty"`
	Applied                 string               `json:"applied,omitempty"`
	Snapshots               map[string]Snapshot  `json:"snapshots"`
	Receipts                map[string]Receipt   `json:"receipts"`
	LastClock               time.Time            `json:"last_clock"`
	ClockUncertain          bool                 `json:"clock_uncertain"`
	OwnerRecreatedAt        time.Time            `json:"owner_recreated_at,omitempty"`
	Retirement              *contract.Evidence   `json:"retirement,omitempty"`
	Report                  *Report              `json:"report,omitempty"`
	AssignmentReasons       map[string]string    `json:"assignment_reasons,omitempty"`
	SchedulingReason        string               `json:"scheduling_reason,omitempty"`
	InputReason             string               `json:"input_reason,omitempty"`
	RejectedOwnerHash       string               `json:"rejected_owner_hash,omitempty"`
	OwnerRetryAt            time.Time            `json:"owner_retry_at,omitempty"`
	OwnerReason             string               `json:"owner_reason,omitempty"`
	ReportObservedAt        time.Time            `json:"report_observed_at,omitempty"`
	ReportDeliveredAt       time.Time            `json:"report_delivered_at,omitempty"`
	ReportDeliveredSequence uint64               `json:"report_delivered_sequence,omitempty"`
}

func initialState() State {
	return State{Version: 1, Instances: map[string]*Instance{}, Heads: map[string]string{}, Snapshots: map[string]Snapshot{}, Receipts: map[string]Receipt{}}
}
func clone(s State) State {
	b, _ := json.Marshal(s)
	var out State
	if json.Unmarshal(b, &out) != nil {
		panic("invalid internal state")
	}
	return out
}

type record struct {
	Sequence uint64          `json:"sequence"`
	Previous string          `json:"previous"`
	State    json.RawMessage `json:"state"`
}
type fence struct {
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
}
type Journal struct {
	mu        sync.Mutex
	directory string
	lock      *os.File
	state     State
	head      fence
}

// OpenJournal recovers the exact full-state commit named by HEAD, never an older valid record.
func OpenJournal(directory string) (*Journal, error) {
	if err := os.MkdirAll(filepath.Join(directory, "commits"), 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(directory, "lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("owner_conflict")
	}
	j := &Journal{directory: directory, lock: lock, state: initialState()}
	fail := func() (*Journal, error) { j.Close(); return nil, ErrStateLost }
	head, err := os.ReadFile(filepath.Join(directory, "HEAD"))
	if os.IsNotExist(err) {
		entries, err := os.ReadDir(filepath.Join(directory, "commits"))
		if err != nil || len(entries) != 0 {
			return fail()
		}
		if _, err = os.Stat(filepath.Join(directory, "checkpoint")); !os.IsNotExist(err) {
			return fail()
		}
		b, _ := json.Marshal(fence{})
		if artifact.AtomicWrite(filepath.Join(directory, "HEAD"), b, 0600) != nil {
			return fail()
		}
		return j, nil
	}
	if err != nil || json.Unmarshal(head, &j.head) != nil {
		return fail()
	}
	if j.head.Sequence == 0 {
		if j.head.Digest != "" {
			return fail()
		}
		return j, nil
	}
	if !artifact.HashPattern.MatchString(j.head.Digest) {
		return fail()
	}
	read := func(name string) ([]byte, bool) {
		f, err := os.Open(name)
		if err != nil {
			return nil, false
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, 2*artifact.MaxContent+1))
		return b, err == nil && len(b) <= 2*artifact.MaxContent && artifact.Digest(b) == j.head.Digest
	}
	raw, ok := read(j.recordPath(j.head.Sequence))
	if !ok {
		raw, ok = read(filepath.Join(directory, "checkpoint"))
		if !ok {
			return fail()
		}
		if artifact.AtomicWrite(j.recordPath(j.head.Sequence), raw, 0600) != nil {
			return fail()
		}
	}
	var r record
	if json.Unmarshal(raw, &r) != nil || r.Sequence != j.head.Sequence || json.Unmarshal(r.State, &j.state) != nil || j.state.Version != 1 || j.state.Instances == nil || j.state.Heads == nil || j.state.Snapshots == nil || j.state.Receipts == nil {
		return fail()
	}
	return j, nil
}
func (j *Journal) recordPath(sequence uint64) string {
	return filepath.Join(j.directory, "commits", fmt.Sprintf("%020d.json", sequence))
}
func (j *Journal) Close() error {
	if j.lock != nil {
		_ = syscall.Flock(int(j.lock.Fd()), syscall.LOCK_UN)
		err := j.lock.Close()
		j.lock = nil
		return err
	}
	return nil
}
func (j *Journal) View() State { j.mu.Lock(); defer j.mu.Unlock(); return clone(j.state) }
func (j *Journal) Eligible(id, appID string) (string, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	i := j.state.Instances[id]
	if i == nil {
		return "", false
	}
	return i.PodUID, i.AppID != "" && i.AppID == appID && i.StopVerified && i.WithdrawalID == "" &&
		i.Phase != "removed" && i.Phase != "retired" && !j.state.ClockUncertain &&
		!j.state.Metadata.DrainRequested && !j.state.Metadata.Terminal &&
		j.state.Identity.Confirmed && !j.state.Identity.Retiring
}
func (j *Journal) Update(change func(*State) error) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	next := clone(j.state)
	if err := change(&next); err != nil {
		return err
	}
	state, err := json.Marshal(next)
	if err != nil {
		return err
	}
	before, _ := json.Marshal(j.state)
	if bytes.Equal(before, state) {
		return nil
	}
	raw, err := json.Marshal(record{Sequence: j.head.Sequence + 1, Previous: j.head.Digest, State: state})
	if err != nil {
		return err
	}
	if len(raw) > 2*artifact.MaxContent {
		return errors.New("state_size")
	}
	// Each immutable write-ahead record is a complete state, including sequence reservations.
	// HEAD is the authoritative commit fence; an orphan newer record has had no side effects.
	if err = artifact.AtomicWrite(j.recordPath(j.head.Sequence+1), raw, 0600); err != nil {
		return err
	}
	head := fence{Sequence: j.head.Sequence + 1, Digest: artifact.Digest(raw)}
	b, _ := json.Marshal(head)
	if err = artifact.AtomicWrite(filepath.Join(j.directory, "HEAD"), b, 0600); err != nil {
		return err
	}
	j.head = head
	j.state = next
	// The redundant checkpoint is useful only when it matches the latest fence exactly.
	if artifact.AtomicWrite(filepath.Join(j.directory, "checkpoint"), raw, 0600) == nil {
		entries, _ := os.ReadDir(filepath.Join(j.directory, "commits"))
		for _, entry := range entries {
			n, err := strconv.ParseUint(strings.TrimSuffix(entry.Name(), ".json"), 10, 64)
			if err == nil && n+1 < head.Sequence {
				_ = os.Remove(filepath.Join(j.directory, "commits", entry.Name()))
			}
		}
	}
	return nil
}
func (j *Journal) Reserve(expectedHash string) (uint64, error) {
	var sequence uint64
	err := j.Update(func(s *State) error {
		if s.OwnerHash != expectedHash || s.Identity.Retiring {
			return ErrSuperseded
		}
		if s.MutationSequence == ^uint64(0) {
			return errors.New("mutation_sequence_exhausted")
		}
		s.MutationSequence++
		sequence = s.MutationSequence
		return nil
	})
	return sequence, err
}

func receiptKey(r Receipt) string {
	return fmt.Sprintf("%s/%d/%s", r.RevisionID, r.Generation, r.Phase)
}
