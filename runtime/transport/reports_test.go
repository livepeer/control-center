package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

type reportSink struct {
	Bodies [][]byte
	Err    error
	Before func()
}

func (s *reportSink) Request(_ context.Context, _ string, p any, _ int64) ([]byte, http.Header, error) {
	b, _ := json.Marshal(p)
	s.Bodies = append(s.Bodies, b)
	if s.Before != nil {
		s.Before()
	}
	return nil, nil, s.Err
}
func sample(at time.Time) map[string]any {
	return map[string]any{"node_id": "node_id", "credential_version": 1, "component": "runtime", "generation": 1, "observed_at": at, "ready": true}
}
func sequence(t *testing.T, b []byte) uint64 {
	t.Helper()
	var p struct {
		Sequence uint64 `json:"sequence"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return p.Sequence
}

func TestReportsReserveBeforeSendRetryExactlyAndRecover(t *testing.T) {
	directory := t.TempDir()
	sink := &reportSink{Err: errors.New("lost_response")}
	r := &Reports{Client: sink, Directory: directory}
	at := time.Now().UTC()
	value := sample(at)
	_, _, _ = r.Request(t.Context(), "status", value, 100)
	stored, err := os.ReadFile(reportCounterPath(directory, "runtime", "node_id"))
	if err != nil {
		t.Fatal(err)
	}
	if sequence(t, stored) != 1 || sequence(t, sink.Bodies[0]) != 1 {
		t.Fatal("transmitted without durable reservation")
	}
	_, _, _ = r.Request(t.Context(), "status", value, 100)
	if string(sink.Bodies[0]) != string(sink.Bodies[1]) {
		t.Fatal("retry renewed order or evidence time")
	}
	sink.Err = nil
	r = &Reports{Client: sink, Directory: directory}
	value = sample(at.Add(time.Second))
	if _, _, err = r.Request(t.Context(), "status", value, 100); err != nil {
		t.Fatal(err)
	}
	var initial, restarted struct {
		ObserverID string `json:"observer_id"`
	}
	_ = json.Unmarshal(sink.Bodies[0], &initial)
	_ = json.Unmarshal(sink.Bodies[2], &restarted)
	if initial.ObserverID == "" || initial.ObserverID == restarted.ObserverID {
		t.Fatal("reporter restart was not distinguishable")
	}
	if sequence(t, sink.Bodies[2]) != 2 {
		t.Fatal("restart rolled order back")
	}
	// A credential change is a new authenticated ordering scope.
	value["credential_version"] = 2
	if _, _, err = r.Request(t.Context(), "status", value, 100); err != nil {
		t.Fatal(err)
	}
	if sequence(t, sink.Bodies[3]) != 1 {
		t.Fatal("credential scope was not reset")
	}
	old := sample(at.Add(2 * time.Second))
	if _, _, err := r.Request(t.Context(), "status", old, 100); err == nil {
		t.Fatal("stale sample rewound a credential counter")
	}
	value["node_id"] = "replacement"
	value["credential_version"] = 1
	if _, _, err = r.Request(t.Context(), "status", value, 100); err != nil {
		t.Fatal(err)
	}
	if sequence(t, sink.Bodies[len(sink.Bodies)-1]) != 1 {
		t.Fatal("new node inherited old ordering")
	}
	old["credential_version"] = 2
	if _, _, err = r.Request(t.Context(), "status", old, 100); err != nil {
		t.Fatal(err)
	}
	value["observed_at"] = at.Add(3 * time.Second)
	if _, _, err = r.Request(t.Context(), "status", value, 100); err != nil {
		t.Fatal(err)
	}
	if sequence(t, sink.Bodies[len(sink.Bodies)-1]) != 2 {
		t.Fatal("retained node corrupted replacement ordering")
	}
}

func TestReportsFailClosedAfterOrderingLossOrCorruption(t *testing.T) {
	directory := t.TempDir()
	sink := &reportSink{Err: &HTTPError{Status: 412}}
	r := &Reports{Client: sink, Directory: directory}
	_, _, firstErr := r.Request(t.Context(), "status", sample(time.Now()), 100)
	if ReportErrorCode(firstErr) != "report_order_unavailable" {
		t.Fatal("initial rejection is not actionable", firstErr)
	}
	r = &Reports{Client: sink, Directory: directory}
	if _, _, err := r.Request(t.Context(), "status", sample(time.Now()), 100); ReportErrorCode(err) != "report_order_unavailable" || len(sink.Bodies) != 1 {
		t.Fatal("counted upward after server rejected ordering")
	}
	if err := os.WriteFile(reportCounterPath(directory, "runtime", "node_id"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Request(t.Context(), "status", sample(time.Now()), 100); ReportErrorCode(err) != "report_state_corrupt" || len(sink.Bodies) != 1 {
		t.Fatal("corruption manufactured an order reset")
	}
	if ReportErrorCode(errors.New("remote credential-sentinel")) != "report_unavailable" {
		t.Fatal("remote error exposed")
	}
}

type delayedReport struct{ entered, release chan struct{} }

func (s delayedReport) Request(ctx context.Context, _ string, payload any, _ int64) ([]byte, http.Header, error) {
	b, _ := json.Marshal(payload)
	var p struct {
		Component string `json:"component"`
	}
	_ = json.Unmarshal(b, &p)
	if p.Component == "runtime" {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	return nil, nil, nil
}

func TestIndependentComponentReportersDoNotBlockEachOther(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		directory := t.TempDir()
		sink := delayedReport{make(chan struct{}), make(chan struct{})}
		runtime := &Reports{Client: sink, Directory: directory}
		connector := &Reports{Client: sink, Directory: directory}
		done := make(chan struct{})
		go func() { defer close(done); _, _, _ = runtime.Request(t.Context(), "status", sample(time.Now()), 100) }()
		<-sink.entered
		defer func() { close(sink.release); <-done }()
		value := sample(time.Now())
		value["component"] = "connector"
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if _, _, err := connector.Request(ctx, "status", value, 100); err != nil {
			t.Fatal("runtime transmission blocked connector evidence", err)
		}
	})
}

func TestReportsRetryOrderingRejectionBlocksNewSamples(t *testing.T) {
	for _, persist := range []bool{true, false} {
		t.Run(map[bool]string{true: "durable", false: "write_failed"}[persist], func(t *testing.T) {
			directory := t.TempDir()
			sink := &reportSink{Err: errors.New("lost_response")}
			r := &Reports{Client: sink, Directory: directory}
			value := sample(time.Now().UTC())
			_, _, _ = r.Request(t.Context(), "status", value, 100)
			name := reportCounterPath(directory, "runtime", "node_id")
			stored, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if !persist {
				sink.Before = func() {
					if err := os.Remove(name); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(name, 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			sink.Err = &HTTPError{Status: 412}
			_, _, _ = r.Request(t.Context(), "status", value, 100)
			if string(sink.Bodies[0]) != string(sink.Bodies[1]) {
				t.Fatal("retry changed envelope")
			}
			if persist {
				r = &Reports{Client: sink, Directory: directory}
			} else {
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, stored, 0600); err != nil {
					t.Fatal(err)
				}
			}
			sink.Err, sink.Before = nil, nil
			if _, _, err := r.Request(t.Context(), "status", sample(time.Now()), 100); err == nil || len(sink.Bodies) != 2 {
				t.Fatal("ordering rejection on retry allowed counting upward")
			}
			value["credential_version"] = 2
			if _, _, err := r.Request(t.Context(), "status", value, 100); err != nil {
				t.Fatal(err)
			}
		})
	}
}
