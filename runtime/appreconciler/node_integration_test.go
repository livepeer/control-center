package appreconciler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	runner "github.com/livepeer/golang-runner"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}
func realNode(t *testing.T, timeout string) string {
	t.Helper()
	binary := os.Getenv("LIVEPEER_NODE_TEST_BINARY")
	if binary == "" {
		t.Skip("set LIVEPEER_NODE_TEST_BINARY to the pinned merged livepeer-orchestrator binary")
	}
	addr, metrics := freeAddress(t), freeAddress(t)
	base := "http://" + addr
	secret := filepath.Join(t.TempDir(), "bootstrap")
	os.WriteFile(secret, []byte("bootstrap"), 0600)
	ctx, cancel := context.WithCancel(context.Background())
	log, err := os.Create(filepath.Join(t.TempDir(), "node.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "--config=", "--data-dir="+t.TempDir(), "--network=offchain", "--listen=unsafe@"+addr, "--metrics-listen=unsafe@"+metrics, "--service-url="+base, "--runner-service-url="+base, "--bootstrap-secret-file="+secret, "--runner-grants=127.0.0.0/8", "--heartbeat-interval=10ms", "--heartbeat-ttl=10s", "--drain-timeout="+timeout)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); cmd.Wait(); log.Close() })
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); {
		resp, err := http.Get(base + "/discovery")
		if err == nil {
			resp.Body.Close()
			return base
		}
		time.Sleep(10 * time.Millisecond)
	}
	data, _ := os.ReadFile(log.Name())
	t.Fatalf("real Node failed to start: %s", data)
	return ""
}
func nodePost(t *testing.T, endpoint string, out any) int {
	t.Helper()
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	} else {
		io.Copy(io.Discard, resp.Body)
	}
	return resp.StatusCode
}
func TestMergedNodeSDKDrain(t *testing.T) {
	for _, mode := range []string{"persistent", "single-shot"} {
		for _, completion := range []string{"natural", "timeout", "zero"} {
			t.Run(mode+"/"+completion, func(t *testing.T) {
				timeout := "500ms"
				if completion == "natural" {
					timeout = "10s"
				}
				if completion == "zero" {
					timeout = "0s"
				}
				base := realNode(t, timeout)
				started := make(chan struct{}, 8)
				app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if mode == "single-shot" {
						started <- struct{}{}
						<-r.Context().Done()
						return
					}
					fmt.Fprint(w, "running")
				}))
				defer app.Close()
				owner, _ := NewSDKOwner(base, "bootstrap", nil)
				defer owner.Close(context.Background())
				entries := []Registration{}
				for _, id := range []string{"first", "sibling"} {
					entries = append(entries, Registration{InstanceID: id, PodUID: "pod-" + id, Options: runner.AppOptions{ID: id, App: id, RunnerURL: app.URL + "/" + id, Mode: mode, Status: "not-ready", Capacity: 2}})
				}
				r := OwnerRequest{Epoch: "epoch", Identity: Identity{RunnerID: "owner"}, Entries: entries, Tracked: append([]Registration{}, entries...)}
				ch := make(chan Observation, 1024)
				hooks := OwnerHooks{Observe: func(o Observation) error { ch <- o; return nil }}
				if err := owner.Sync(t.Context(), r, hooks); err != nil {
					t.Fatal(err)
				}
				awaitObservation(t, ch, func(o Observation) bool { return o.Accepted })
				for n := range r.Entries {
					r.Entries[n].Options.Status = "ready"
				}
				if err := owner.Sync(t.Context(), r, hooks); err != nil {
					t.Fatal(err)
				}
				awaitObservation(t, ch, func(o Observation) bool { return o.Accepted && o.Apps[0].Status == "ready" })
				session := ""
				var workDone chan struct{}
				var cancelWork context.CancelFunc
				if mode == "persistent" {
					var result struct {
						ID string `json:"session_id"`
					}
					if status := nodePost(t, base+"/apps/first/session", &result); status != 200 {
						t.Fatal("session reservation failed", status)
					}
					session = result.ID
				} else {
					workDone = make(chan struct{})
					var workCtx context.Context
					workCtx, cancelWork = context.WithCancel(t.Context())
					defer cancelWork()
					go func() {
						request, _ := http.NewRequestWithContext(workCtx, http.MethodGet, base+"/apps/first/app", nil)
						resp, err := http.DefaultClient.Do(request)
						if err == nil {
							resp.Body.Close()
						}
						close(workDone)
					}()
					select {
					case <-started:
					case <-time.After(3 * time.Second):
						t.Fatal("single-shot did not reach app")
					}
				}
				first := r.Tracked[0]
				first.WithdrawalID = "withdrawal"
				first.WithdrawnAt = time.Now()
				r.Tracked[0] = first
				r.Entries = r.Entries[1:]
				if err := owner.Sync(t.Context(), r, hooks); err != nil {
					t.Fatal(err)
				}
				if completion != "zero" {
					awaitObservation(t, ch, func(o Observation) bool {
						for _, a := range o.Apps {
							if a.ID == "first" && a.Status == "draining" && len(a.SessionIDs) > 0 {
								return true
							}
						}
						return false
					})
				}
				if mode == "persistent" && completion == "natural" {
					// Restart only Runtime's owner loop against the surviving Node.
					r.Identity = owner.Accepted()
					owner.Close(t.Context())
					if err := owner.Sync(t.Context(), r, hooks); err != nil {
						t.Fatal(err)
					}
					resp, err := http.Get(base + "/apps/first/session/" + session + "/app")
					if err != nil {
						t.Fatal(err)
					}
					resp.Body.Close()
					if resp.StatusCode != 200 {
						t.Fatal("existing session lost across withdrawal/restart", resp.StatusCode)
					}
					if status := nodePost(t, base+"/apps/first/session/"+session+"/stop", nil); status != 200 {
						t.Fatal("natural stop failed", status)
					}
				}
				if mode == "single-shot" && completion == "natural" {
					cancelWork()
				}
				awaitObservation(t, ch, func(o Observation) bool {
					if !o.Accepted {
						return false
					}
					sibling := false
					for _, a := range o.Apps {
						if a.ID == "first" {
							return false
						}
						if a.ID == "sibling" {
							sibling = true
						}
					}
					return sibling
				})
				if workDone != nil {
					select {
					case <-workDone:
					case <-time.After(3 * time.Second):
						t.Fatal("Node expiry did not end in-flight call")
					}
				}
				// Withdraw the final app using an explicit empty array and retain heartbeats.
				r.Tracked[1].WithdrawalID = "final"
				r.Tracked[1].WithdrawnAt = time.Now()
				r.Entries = []Registration{}
				if err := owner.Sync(t.Context(), r, hooks); err != nil {
					t.Fatal(err)
				}
				awaitObservation(t, ch, func(o Observation) bool { return o.Accepted && len(o.Apps) == 0 })
				id := owner.Accepted()
				owner.Close(t.Context())
				if err := owner.Unregister(t.Context(), id); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// A restart must preserve existing work when the first restored heartbeat fails,
// including when the SDK catches up past an accepted request lost in the crash.
func TestMergedNodeSDKRestoredMembership(t *testing.T) {
	for _, failure := range []string{"sequence", "transport", "500", "503"} {
		t.Run(failure, func(t *testing.T) {
			base := realNode(t, "0s")
			app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "running") }))
			defer app.Close()
			owner, err := NewSDKOwner(base, "bootstrap", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close(context.Background())
			e := Registration{InstanceID: "instance", PodUID: "pod", Options: runner.AppOptions{ID: "app", App: "app", RunnerURL: app.URL, Mode: "persistent", Status: "not-ready", Capacity: 2}}
			r := OwnerRequest{Epoch: "epoch", Identity: Identity{RunnerID: "owner"}, Entries: []Registration{e}, Tracked: []Registration{e}}
			events := make(chan Observation, 1024)
			hooks := OwnerHooks{Observe: func(o Observation) error { events <- o; return nil }}
			if err := owner.Sync(t.Context(), r, hooks); err != nil {
				t.Fatal(err)
			}
			awaitObservation(t, events, func(o Observation) bool { return o.Accepted })
			r.Entries[0].Options.Status = "ready"
			if err := owner.Sync(t.Context(), r, hooks); err != nil {
				t.Fatal(err)
			}
			awaitObservation(t, events, func(o Observation) bool { return o.Accepted && o.Apps[0].Status == "ready" })
			var session struct {
				ID string `json:"session_id"`
			}
			if status := nodePost(t, base+"/apps/app/session", &session); status != http.StatusOK {
				t.Fatal("reserve", status)
			}
			if err := owner.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			saved := owner.Accepted()
			if saved.Sequence == nil {
				t.Fatal("missing saved sequence")
			}
			if failure == "sequence" {
				// Node accepts a final request that never reaches the persistence callback.
				payload := runner.HeartbeatRequest{RunnerID: saved.RunnerID, Seq: *saved.Sequence + 1, Apps: []runner.HeartbeatApp{{AppOptions: r.Entries[0].Options}}}
				data, _ := json.Marshal(payload)
				req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/runners/heartbeat", bytes.NewReader(data))
				req.Header.Set("Authorization", saved.Credential)
				req.Header.Set("Content-Type", "application/json")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatal("pre-crash request", resp.StatusCode)
				}
			}
			var failed atomic.Bool
			client := &http.Client{Transport: reviewRoundTripper(func(req *http.Request) (*http.Response, error) {
				if failure != "sequence" && req.URL.Path == "/runners/heartbeat" && failed.CompareAndSwap(false, true) {
					if failure == "transport" {
						return nil, errors.New("temporary connection failure")
					}
					w := httptest.NewRecorder()
					status := http.StatusInternalServerError
					if failure == "503" {
						status = http.StatusServiceUnavailable
					}
					w.WriteHeader(status)
					return w.Result(), nil
				}
				return http.DefaultTransport.RoundTrip(req)
			})}
			restored, err := NewSDKOwner(base, "bootstrap", client)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close(context.Background())
			r.Identity = saved
			r.Entries[0].Options.Status = "not-ready"
			recovered := make(chan Observation, 1024)
			restoredHooks := OwnerHooks{Observe: func(o Observation) error { recovered <- o; return nil }}
			if err := restored.Sync(t.Context(), r, restoredHooks); failure != "sequence" {
				if err == nil {
					t.Fatal("expected first restored request failure")
				}
				if err := restored.Sync(t.Context(), r, restoredHooks); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			obs := awaitObservation(t, recovered, func(o Observation) bool { return o.Accepted })
			resp, err := http.Get(base + "/apps/app/session/" + session.ID + "/app")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if len(obs.Request.Apps) != 1 || obs.Request.Apps[0].ID != "app" || resp.StatusCode != http.StatusOK {
				t.Fatalf("restoration withdrew active work: apps=%+v, session HTTP=%d", obs.Request.Apps, resp.StatusCode)
			}
		})
	}
}
