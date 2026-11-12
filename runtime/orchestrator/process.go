package orchestrator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/connector"
	"github.com/livepeer/control-center/runtime/transport"
)

func Start(ctx context.Context, args []string) error {
	if os.Getpid() != 1 {
		return errors.New("orchestrator_requires_private_pid_namespace")
	}
	process, e := connector.ProcessIdentity()
	if e != nil {
		return e
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return errors.New("orchestrator_launch_identity")
	}
	launch := Launch{PodName: os.Getenv("POD_NAME"), PodUID: os.Getenv("POD_UID"), LaunchID: hex.EncodeToString(nonce[:]), ProcessID: process}
	if !ValidLaunch(launch) {
		return errors.New("orchestrator_launch_identity")
	}
	dir := "/run/payment/private"
	if info, e := os.Lstat(dir); e == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
		return errors.New("payment_storage_unavailable")
	} else if e != nil && !os.IsNotExist(e) {
		return errors.New("payment_storage_unavailable")
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return errors.New("payment_storage_unavailable")
	}
	if os.Chmod(dir, 0700) != nil {
		return errors.New("payment_storage_unavailable")
	}
	for _, f := range []string{"rpc", "headers", "launch.json"} {
		if e = os.Remove(filepath.Join(dir, f)); e != nil && !os.IsNotExist(e) {
			return errors.New("stale_payment_material")
		}
	}
	client := transport.NewLocal("/management/control.sock")
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var g Grant
	for {
		b, _, err := client.Request(ctx, "payment/credentials", launch, 16384)
		if err == nil && transport.Decode(b, &g) == nil && g.Launch == launch && g.RPCURL != "" && g.Headers != "" {
			break
		}
		select {
		case <-ctx.Done():
			return errors.New("payment_credential_unavailable")
		case <-time.After(time.Second):
		}
	}
	if e := checkPaymentState("/data/payments.sqlite", g.RequireState); e != nil {
		return e
	}

	marker, _ := json.Marshal(g.Association)
	if artifact.AtomicWrite(filepath.Join(dir, "rpc"), []byte(g.RPCURL), 0600) != nil || artifact.AtomicWrite(filepath.Join(dir, "headers"), []byte(g.Headers), 0600) != nil || artifact.AtomicWrite(filepath.Join(dir, "launch.json"), marker, 0600) != nil {
		return errors.New("payment_credential_write")
	}
	_ = syscall.Exec("/usr/local/bin/livepeer", append([]string{"/usr/local/bin/livepeer"}, args...), []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent"})
	_ = os.Remove(filepath.Join(dir, "rpc"))
	_ = os.Remove(filepath.Join(dir, "headers"))
	_ = os.Remove(filepath.Join(dir, "launch.json"))
	return errors.New("orchestrator_exec_failed")
}

// Probe runs inside the Node container and proves the marker still names its
// current PID 1. Pod UID alone cannot distinguish container restarts.
func Probe(ctx context.Context) bool {
	b, e := os.ReadFile("/run/payment/private/launch.json")
	var a Association
	process, pe := connector.ProcessIdentity()
	if e != nil || pe != nil || len(b) > 16384 || transport.Decode(b, &a) != nil || !ValidLaunch(a.Launch) || a.ProcessID != process {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:8936/readyz", nil)
	client := *http.DefaultClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r, e := client.Do(req)
	if e != nil {
		return false
	}
	r.Body.Close()
	ready := r.StatusCode == 200
	_, _, e = transport.NewLocal("/management/control.sock").Request(ctx, "payment/observation", ProcessObservation{Association: a, ObservedAt: time.Now(), Ready: ready}, 1024)
	return e == nil && ready
}

func checkPaymentState(path string, required bool) error {
	if !required {
		return nil
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("payment_state_recovery_required")
	}
	return nil
}
