package management

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
)

type recorder struct{ calls int }

func (r *recorder) Request(_ context.Context, endpoint string, _ any, _ int64) ([]byte, http.Header, error) {
	r.calls++
	return []byte(`{}`), nil, nil
}

func TestScopedSocketsAndEnrollmentFencedAppReporting(t *testing.T) {
	// Short paths also fit Darwin's Unix socket address limit.
	root, err := os.MkdirTemp("/tmp", "lp-sockets-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	m := contract.Metadata{NodeID: "node_id", CredentialVersion: 1}
	control := &recorder{}
	apps := AppReports{Control: control, Desired: func() (contract.Metadata, bool) { return m, true }}
	connector := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tunnel/connector-token" {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		w.Write([]byte(`{}`))
	})
	sockets, err := Listen(root, connector, apps, http.NotFoundHandler(), http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	defer sockets.Close()
	go sockets.Run(ctx)
	if other, err := Listen(root, connector, apps, http.NotFoundHandler(), http.NotFoundHandler()); err == nil {
		other.Close()
		t.Fatal("two management publishers acquired the same root")
	}
	for _, consumer := range []string{"connector", "apps", "orchestrator", "telemetry"} {
		info, err := os.Stat(filepath.Join(root, consumer))
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("consumer directory exposed")
		}
		info, err = os.Stat(filepath.Join(root, consumer, "control.sock"))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("consumer socket exposed")
		}
	}
	client := transport.NewLocal(filepath.Join(root, "apps", "control.sock"))
	payload := map[string]any{"node_id": "node_id", "credential_version": 1, "component": "runner", "generation": 1}
	if _, _, err = client.Request(t.Context(), "status", payload, 1024); err != nil {
		t.Fatal(err)
	}
	if _, _, err = client.Request(t.Context(), "apps/11111111-1111-4111-8111-111111111111/status", payload, 1024); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"config", "removal-ack", "tunnel/connector-token"} {
		if _, _, err = client.Request(t.Context(), endpoint, payload, 1024); !transport.IsStatus(err, 403) {
			t.Fatal("app socket authorized", endpoint, err)
		}
	}
	payload["component"] = "connector"
	if _, _, err = client.Request(t.Context(), "status", payload, 1024); !transport.IsStatus(err, 403) {
		t.Fatal("app consumer impersonated connector")
	}
	payload["component"] = "runner"
	payload["node_id"] = "old"
	if _, _, err = client.Request(t.Context(), "status", payload, 1024); !transport.IsStatus(err, 403) {
		t.Fatal("cross-enrollment report passed")
	}
	payload["node_id"] = "node_id"
	payload["padding"] = strings.Repeat("x", contract.MaxStatusBytes)
	if _, _, err = client.Request(t.Context(), "status", payload, 1024); !transport.IsStatus(err, 403) {
		t.Fatal("oversized status crossed app socket", err)
	}
	if control.calls != 2 {
		t.Fatal("unauthorized operation reached Control Center")
	}
}

func TestSocketStartupRefusesSymlinkAndNonSocketPaths(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "lp-sockets-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	handler := http.NotFoundHandler()
	if err = os.Symlink(t.TempDir(), filepath.Join(root, "connector")); err != nil {
		t.Fatal(err)
	}
	if s, err := Listen(root, handler, handler, handler, handler); err == nil {
		s.Close()
		t.Fatal("followed consumer symlink")
	}
	os.Remove(filepath.Join(root, "connector"))
	os.Mkdir(filepath.Join(root, "connector"), 0700)
	os.WriteFile(filepath.Join(root, "connector", "control.sock"), []byte(strings.Repeat("x", 4)), 0600)
	if s, err := Listen(root, handler, handler, handler, handler); err == nil {
		s.Close()
		t.Fatal("replaced non-socket")
	}
}
