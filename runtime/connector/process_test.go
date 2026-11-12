package connector

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type requestFunc func(context.Context, string, any, int64) ([]byte, http.Header, error)

func (f requestFunc) Request(ctx context.Context, endpoint string, value any, limit int64) ([]byte, http.Header, error) {
	return f(ctx, endpoint, value, limit)
}

func TestStartExecsWithFreshMemoryFileAndNeverFallsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "token")
	issued := 0
	client := requestFunc(func(_ context.Context, endpoint string, value any, _ int64) ([]byte, http.Header, error) {
		if endpoint != "tunnel/connector-token" {
			t.Fatal(endpoint)
		}
		issued++
		if issued == 3 {
			return nil, nil, errors.New("offline")
		}
		launch := value.(Launch)
		b, _ := json.Marshal(Grant{Association: Association{Launch: launch}, Token: strings.Repeat(string(rune('a'+issued)), 64)})
		return b, nil, nil
	})
	executed := 0
	exec := func(command string, args, env []string) error {
		executed++
		b, err := os.ReadFile(path)
		if err != nil || string(b) != strings.Repeat(string(rune('a'+executed)), 64) {
			t.Fatal("stale token file", err)
		}
		info, _ := os.Stat(path)
		parent, _ := os.Stat(filepath.Dir(path))
		if info.Mode().Perm() != 0600 || parent.Mode().Perm() != 0700 {
			t.Fatal("token permissions")
		}
		if command != "/usr/local/bin/cloudflared" || !strings.Contains(strings.Join(args, " "), "--token-file "+path) || strings.Contains(strings.Join(args, " "), string(b)) || strings.Contains(strings.Join(env, " "), string(b)) {
			t.Fatal("unsafe exec")
		}
		return errors.New("exec fixture")
	}
	for n := 0; n < 2; n++ {
		if start(t.Context(), client, path, "tunnel-pod", "pod-uid", strings.Repeat("e", 64), exec) == nil {
			t.Fatal("exec did not run")
		}
	}
	os.WriteFile(path, []byte("stale secret"), 0600)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if start(ctx, client, path, "tunnel-pod", "pod-uid", strings.Repeat("e", 64), exec) == nil {
		t.Fatal("offline start succeeded")
	}
	if executed != 2 || issued != 3 {
		t.Fatal("fallback or supervision changed process count")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed startup retained a credential")
	}
}

func TestProbeReadinessDoesNotDependOnConfigOrSocketDelivery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ready" {
			w.Write([]byte("ready"))
			return
		}
		w.Write([]byte("invalid config"))
	}))
	defer server.Close()
	marker := filepath.Join(t.TempDir(), "launch.json")
	b, _ := json.Marshal(Association{Launch: Launch{PodName: "tunnel-pod", PodUID: "pod-uid", LaunchID: strings.Repeat("a", 32), ProcessID: strings.Repeat("e", 64)}})
	os.WriteFile(marker, b, 0600)
	delivered := false
	client := requestFunc(func(ctx context.Context, endpoint string, value any, _ int64) ([]byte, http.Header, error) {
		delivered = true
		observation := value.(Observation)
		if endpoint != "tunnel/observation" || !observation.Ready || observation.ProviderVersion != 0 {
			t.Fatal("configuration failure overrode local readiness")
		}
		<-ctx.Done()
		return nil, nil, ctx.Err()
	})
	start := time.Now()
	if !probe(t.Context(), client, marker, server.URL, func() (string, error) { return strings.Repeat("e", 64), nil }) || !delivered {
		t.Fatal("report outage changed local readiness")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("reporting consumed readiness deadline")
	}
	delivered = false
	if !probe(t.Context(), client, marker, server.URL, func() (string, error) { return strings.Repeat("f", 64), nil }) || delivered {
		t.Fatal("replacement PID 1 reused its predecessor's marker or lost local readiness")
	}
	server.Close()
	client = requestFunc(func(_ context.Context, _ string, value any, _ int64) ([]byte, http.Header, error) {
		delivered = true
		if value.(Observation).Ready {
			t.Fatal("unavailable connector reported ready")
		}
		return nil, nil, nil
	})
	if probe(t.Context(), client, marker, server.URL, func() (string, error) { return strings.Repeat("e", 64), nil }) || !delivered {
		t.Fatal("connector readiness was not enforced and reported")
	}
}

func TestKernelIdentitySurvivesExecAndDistinguishesReplacement(t *testing.T) {
	stat := "1 (livepeer-runtime) S " + strings.Repeat("0 ", 18) + "12345 0\n"
	a, err := hashProcess("boot", "pid:[42]", stat)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hashProcess("boot", "pid:[42]", strings.Replace(stat, "livepeer-runtime", "cloudflared", 1))
	if err != nil || a != b {
		t.Fatal("exec changed the process identity")
	}
	for _, input := range []struct{ boot, ns, stat string }{{"new boot", "pid:[42]", stat}, {"boot", "pid:[43]", stat}, {"boot", "pid:[42]", strings.Replace(stat, "12345", "12346", 1)}} {
		if value, err := hashProcess(input.boot, input.ns, input.stat); err != nil || value == a {
			t.Fatal("replacement reused process identity", err)
		}
	}
	if _, err := hashProcess("boot", "pid:[42]", "truncated"); err == nil {
		t.Fatal("unreadable kernel identity accepted")
	}
}

func TestStartupRetriesTransientFailureBeforeExec(t *testing.T) {
	calls := 0
	client := requestFunc(func(_ context.Context, _ string, value any, _ int64) ([]byte, http.Header, error) {
		calls++
		if calls == 1 {
			return nil, nil, errors.New("Waiting")
		}
		b, _ := json.Marshal(Grant{Association: Association{Launch: value.(Launch)}, Token: strings.Repeat("x", 64)})
		return b, nil, nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	executed := false
	start(ctx, client, filepath.Join(t.TempDir(), "token"), "tunnel-pod", "pod-uid", strings.Repeat("e", 64), func(string, []string, []string) error { executed = true; return errors.New("exec fixture") })
	if !executed || calls != 2 {
		t.Fatal("transient startup failure caused a premature container exit")
	}
}
