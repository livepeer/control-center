package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/livepeer/control-center/runtime/artifact"
)

// Reports reserves order durably for replaceable non-runner observations.
// Runner reports already have their own journal/outbox and pass through unchanged.
type Reports struct {
	Client     Requester
	Directory  string
	mu         sync.Mutex
	pending    map[string]reportSample
	blocked    map[string]int64
	observerID string
	startedAt  time.Time
}

type reportSample struct {
	Input    []byte
	Body     []byte
	Sequence uint64
}

type reportCounter struct {
	NodeID            string `json:"node_id"`
	CredentialVersion int64  `json:"credential_version"`
	Sequence          uint64 `json:"sequence"`
	Blocked           bool   `json:"blocked,omitempty"`
}

func (r *Reports) Request(ctx context.Context, endpoint string, payload any, limit int64) ([]byte, http.Header, error) {
	if endpoint != "status" {
		return r.Client.Request(ctx, endpoint, payload, limit)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, errors.New("report_payload")
	}
	var identity struct {
		NodeID            string `json:"node_id"`
		CredentialVersion int64  `json:"credential_version"`
		Component         string `json:"component"`
	}
	if Decode(b, &identity) != nil {
		return nil, nil, errors.New("report_identity")
	}
	if identity.Component == "runner" {
		return r.Client.Request(ctx, endpoint, payload, limit)
	}
	if identity.Component != "runtime" && identity.Component != "connector" && identity.Component != "app-reconciler" {
		return nil, nil, errors.New("report_component")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if os.MkdirAll(r.Directory, 0700) != nil {
		return nil, nil, errors.New("report_state_unavailable")
	}
	name := reportCounterPath(r.Directory, identity.Component, identity.NodeID)
	lock, err := os.OpenFile(name+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, nil, errors.New("report_state_unavailable")
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, nil, errors.New("report_owner_conflict")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	var counter reportCounter
	if raw, readErr := os.ReadFile(name); readErr == nil {
		if len(raw) > 4096 || Decode(raw, &counter) != nil || counter.Sequence == 0 {
			return nil, nil, errors.New("report_state_corrupt")
		}
	} else if !os.IsNotExist(readErr) {
		return nil, nil, errors.New("report_state_unavailable")
	}
	if counter.NodeID == identity.NodeID && counter.CredentialVersion > identity.CredentialVersion {
		return nil, nil, errors.New("report_credential_regression")
	}
	if counter.NodeID != identity.NodeID || counter.CredentialVersion != identity.CredentialVersion {
		counter = reportCounter{NodeID: identity.NodeID, CredentialVersion: identity.CredentialVersion}
	}
	if counter.Blocked || counter.Sequence == ^uint64(0) {
		return nil, nil, errors.New("report_order_unavailable")
	}
	if version, ok := r.blocked[name]; ok && version >= identity.CredentialVersion {
		return nil, nil, errors.New("report_order_unavailable")
	}
	if sample, ok := r.pending[name]; ok && bytes.Equal(sample.Input, b) {
		if sample.Sequence != counter.Sequence {
			return nil, nil, errors.New("report_state_regression")
		}
		return r.send(ctx, sample.Body, limit, name, counter)
	}
	input := append([]byte(nil), b...)
	counter.Sequence++
	state, _ := json.Marshal(counter)
	if artifact.AtomicWrite(name, state, 0600) != nil {
		return nil, nil, errors.New("report_state_unavailable")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return nil, nil, errors.New("report_payload")
	}
	if r.observerID == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, nil, errors.New("report_identity_unavailable")
		}
		r.observerID = hex.EncodeToString(id[:])
		r.startedAt = time.Now().UTC()
	}
	// This identity is diagnostic only; it never resets the durable ordering scope.
	fields["observer_id"], _ = json.Marshal(r.observerID)
	fields["observer_started_at"], _ = json.Marshal(r.startedAt)
	fields["report_version"] = json.RawMessage("1")
	fields["sequence"], _ = json.Marshal(counter.Sequence)
	if _, exists := fields["observed_at"]; !exists {
		fields["observed_at"], _ = json.Marshal(time.Now().UTC())
	}
	b, _ = json.Marshal(fields)
	if r.pending == nil {
		r.pending = map[string]reportSample{}
	}
	r.pending[name] = reportSample{input, append([]byte(nil), b...), counter.Sequence}
	return r.send(ctx, b, limit, name, counter)
}

// The caller holds mu and the counter file lock, including for exact retries.
func (r *Reports) send(ctx context.Context, body []byte, limit int64, name string, counter reportCounter) ([]byte, http.Header, error) {
	result, headers, err := r.Client.Request(ctx, "status", json.RawMessage(body), limit)
	// A lost ordering file must not count upward until the server accepts it.
	// An authorized credential change starts a new scope; terminal recovery needs restored state.
	if IsStatus(err, http.StatusPreconditionFailed) {
		if r.blocked == nil {
			r.blocked = map[string]int64{}
		}
		r.blocked[name] = counter.CredentialVersion
		counter.Blocked = true
		state, _ := json.Marshal(counter)
		_ = artifact.AtomicWrite(name, state, 0600)
	}
	return result, headers, err
}

func reportCounterPath(directory, component, node string) string {
	return filepath.Join(directory, component+"-"+artifact.Digest([]byte(node))[7:]+".json")
}

// ReportErrorCode permits actionable local failures without remote error text.
func ReportErrorCode(err error) string {
	if IsStatus(err, http.StatusPreconditionFailed) {
		return "report_order_unavailable"
	}
	if err != nil {
		switch code := err.Error(); code {
		case "report_state_unavailable", "report_state_corrupt", "report_order_unavailable", "report_owner_conflict", "report_state_regression", "report_credential_regression", "report_identity_unavailable":
			return code
		}
	}
	return "report_unavailable"
}
