package machineconfig

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestReconcileEachGivesEveryMachineItsOwnDeadline(t *testing.T) {
	machines := []Machine{{NodeID: "slow"}, {NodeID: "broken"}, {NodeID: "fenced"}, {NodeID: "last"}}
	var logs bytes.Buffer
	var visited []string
	err := reconcileEach(t.Context(), machines, 50*time.Millisecond, func(ctx context.Context, m Machine) error {
		visited = append(visited, m.NodeID)
		switch m.NodeID {
		case "slow":
			// Uses up its whole budget, as a machine stuck behind row locks does.
			<-ctx.Done()
			return ctx.Err()
		case "broken":
			return errors.New("database unavailable")
		case "fenced":
			return ErrFenced
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < 25*time.Millisecond {
			t.Error("a later machine inherited an earlier machine's spent deadline")
		}
		return nil
	}, slog.New(slog.NewTextHandler(&logs, nil)))
	if strings.Join(visited, ",") != "slow,broken,fenced,last" {
		t.Fatal("a failed machine stopped the pass", visited)
	}
	if err == nil || !strings.Contains(err.Error(), "2 of 4 machines failed") || !strings.Contains(err.Error(), "database unavailable") {
		t.Fatal("unexpected pass result", err)
	}
	for _, node := range []string{"node_id=slow", "node_id=broken"} {
		if !strings.Contains(logs.String(), node) {
			t.Fatal("failed machine was not logged", node, logs.String())
		}
	}
	if strings.Contains(logs.String(), "node_id=fenced") {
		t.Fatal("a fenced machine was logged as failed")
	}
}

func TestReconcileEachStopsWhenTheServiceStops(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var visited int
	err := reconcileEach(ctx, []Machine{{NodeID: "a"}, {NodeID: "b"}}, time.Minute, func(ctx context.Context, m Machine) error {
		visited++
		cancel()
		return ctx.Err()
	}, slog.New(slog.DiscardHandler))
	if !errors.Is(err, context.Canceled) || visited != 1 {
		t.Fatal("reconciliation continued after shutdown", err, visited)
	}
}
