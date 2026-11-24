package consumer

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
	"testing/synctest"
	"time"
)

type requestFunc func(context.Context, string, any, int64) ([]byte, http.Header, error)

func (f requestFunc) Request(ctx context.Context, endpoint string, value any, limit int64) ([]byte, http.Header, error) {
	return f(ctx, endpoint, value, limit)
}

func TestStartExecsWithFreshMemoryFileAndNeverFallsBack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
			if start(t.Context(), Connector, client, path, "tunnel-pod", "pod-uid", strings.Repeat("e", 64), nil, exec) == nil {
				t.Fatal("exec did not run")
			}
		}
		os.WriteFile(path, []byte("stale secret"), 0600)
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		if start(ctx, Connector, client, path, "tunnel-pod", "pod-uid", strings.Repeat("e", 64), nil, exec) == nil {
			t.Fatal("offline start succeeded")
		}
		if executed != 2 || issued != 3 {
			t.Fatal("fallback or supervision changed process count")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("failed startup retained a credential")
		}
	})
}

func TestProbeLocalReadinessAndProcessEvidence(t *testing.T) {
	previous := http.DefaultTransport
	http.DefaultTransport = &http.Transport{DisableKeepAlives: true}
	defer func() { http.DefaultTransport = previous }()
	for _, test := range []struct {
		name              string
		profile           Profile
		mismatch, healthy bool
		delay             time.Duration
		deliveryErr       error
		identityErr       error
		ready, delivered  bool
		reason            string
	}{
		{name: "connector-report-outage", profile: Connector, healthy: true, delay: 10 * time.Second, ready: true, delivered: true},
		{name: "connector-replaced-process", profile: Connector, mismatch: true, healthy: true, ready: true},
		{name: "connector-identity-denied", profile: Connector, healthy: true, identityErr: errors.New("connector_process_identity"), ready: true},
		{name: "connector-unavailable", profile: Connector, delivered: true, reason: "readiness_endpoint_failed"},
		{name: "node-delayed-proof", profile: Orchestrator, healthy: true, delay: 600 * time.Millisecond, ready: true, delivered: true},
		{name: "node-replaced-process", profile: Orchestrator, mismatch: true, healthy: true, reason: "launch_process_replaced"},
		{name: "node-identity-denied", profile: Orchestrator, healthy: true, identityErr: errors.New("connector_process_identity"), reason: "connector_process_identity"},
		{name: "node-report-outage", profile: Orchestrator, healthy: true, deliveryErr: errors.New("offline"), delivered: true, reason: "observation_undelivered"},
		{name: "node-unready-and-replaced", profile: Orchestrator, mismatch: true, reason: "readiness_endpoint_failed, launch_process_replaced"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case map[Profile]string{Connector: "/ready", Orchestrator: "/readyz"}[test.profile]:
					if !test.healthy {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					w.Write([]byte("ready"))
				case "/config":
					w.Write([]byte("invalid config"))
				default:
					t.Error("unexpected probe path", r.URL.Path)
				}
			}))
			defer server.Close()
			synctest.Test(t, func(t *testing.T) {
				marker := filepath.Join(t.TempDir(), "launch.json")
				process := strings.Repeat("e", 64)
				b, _ := json.Marshal(Association{Launch: Launch{PodName: "test-pod", PodUID: "uid", LaunchID: strings.Repeat("a", 32), ProcessID: process}})
				if err := os.WriteFile(marker, b, 0600); err != nil {
					t.Fatal(err)
				}
				delivered := false
				client := requestFunc(func(ctx context.Context, endpoint string, value any, _ int64) ([]byte, http.Header, error) {
					delivered = true
					observation := value.(Observation)
					if endpoint != map[Profile]string{Connector: "tunnel/observation", Orchestrator: "onchain/observation"}[test.profile] || observation.Ready != test.healthy || observation.ProviderVersion != 0 {
						t.Fatal("invalid process evidence", endpoint, observation)
					}
					select {
					case <-time.After(test.delay):
						return nil, nil, test.deliveryErr
					case <-ctx.Done():
						return nil, nil, ctx.Err()
					}
				})
				if test.mismatch {
					process = strings.Repeat("f", 64)
				}
				started := time.Now()
				err := probe(t.Context(), test.profile, client, marker, server.URL, func() (string, error) { return process, test.identityErr })
				if (err == nil) != test.ready || delivered != test.delivered {
					t.Fatal("unexpected readiness or evidence delivery", err, delivered)
				}
				if err != nil && err.Error() != test.reason {
					t.Fatal("unexpected not-ready reason", err)
				}
				if test.profile == Connector && time.Since(started) > 2*time.Second {
					t.Fatal("reporting consumed readiness deadline")
				}
			})
		})
	}
}

func TestRepairOnchainPermissionsOnlyUndoesGroupAccess(t *testing.T) {
	directory := t.TempDir()
	db := filepath.Join(directory, "onchain.sqlite")
	outside := filepath.Join(directory, "outside")
	for _, path := range []string{db, db + "-wal", outside} {
		if os.WriteFile(path, []byte("state"), 0600) != nil || os.Chmod(path, 0660) != nil {
			t.Fatal("fixture")
		}
	}
	if os.Symlink(outside, db+"-shm") != nil {
		t.Fatal("fixture")
	}
	repairOnchainPermissions(db)
	for path, want := range map[string]os.FileMode{db: 0600, db + "-wal": 0600, outside: 0660} {
		if info, err := os.Stat(path); err != nil || info.Mode() != want {
			t.Fatal("unexpected repair", path, info.Mode(), err)
		}
	}
	// Anything but the exact fsGroup result stays visible to Node's own check.
	for _, mode := range []os.FileMode{0640, 0664, 0666, 0620, 0660 | os.ModeSetgid} {
		if os.Chmod(db, mode) != nil {
			t.Fatal("fixture")
		}
		repairOnchainPermissions(db)
		if info, err := os.Stat(db); err != nil || info.Mode() != mode {
			t.Fatal("unexpected permissions repaired", mode, info.Mode(), err)
		}
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
	synctest.Test(t, func(t *testing.T) {
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
		start(ctx, Connector, client, filepath.Join(t.TempDir(), "token"), "tunnel-pod", "pod-uid", strings.Repeat("e", 64), nil, func(string, []string, []string) error { executed = true; return errors.New("exec fixture") })
		if !executed || calls != 2 {
			t.Fatal("transient startup failure caused a premature container exit")
		}
	})
}
