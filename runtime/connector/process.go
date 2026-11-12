package connector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/transport"
)

// Start discards old launch material and replaces itself with the pinned connector.
func Start(ctx context.Context, socket, tokenPath, podName, podUID string) error {
	if os.Getpid() != 1 {
		return errors.New("connector_requires_private_pid_namespace")
	}
	process, err := processIdentity()
	if err != nil {
		return err
	}
	return start(ctx, transport.NewLocal(socket), tokenPath, podName, podUID, process, syscall.Exec)
}

func start(ctx context.Context, client transport.Requester, tokenPath, name, uid, process string, exec func(string, []string, []string) error) error {
	directory := filepath.Dir(tokenPath)
	if info, err := os.Lstat(directory); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
		return errors.New("connector_token_directory")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return errors.New("connector_token_directory")
	}
	if os.Chmod(directory, 0700) != nil {
		return errors.New("connector_token_directory")
	}
	marker := filepath.Join(directory, "launch.json")
	for _, path := range []string{tokenPath, marker, tokenPath + ".tmp", marker + ".tmp"} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return errors.New("connector_stale_file")
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errors.New("connector_launch_identity")
	}
	launch := Launch{PodName: name, PodUID: uid, LaunchID: hex.EncodeToString(nonce[:]), ProcessID: process}
	if !validLaunch(launch) {
		return errors.New("connector_launch_identity")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var grant Grant
	delay := 500 * time.Millisecond
	for {
		attempt, stop := context.WithTimeout(ctx, 5*time.Second)
		b, _, err := client.Request(attempt, "tunnel/connector-token", launch, 16384)
		stop()
		var response Grant
		if err == nil && transport.Decode(b, &response) == nil && validToken(response.Token) && response.Launch == launch {
			grant = response
			break
		}
		select {
		case <-ctx.Done():
			return errors.New("connector_credential_unavailable")
		case <-time.After(delay):
		}
		delay = min(5*time.Second, delay*2)
	}
	if err := artifact.AtomicWrite(tokenPath, []byte(grant.Token), 0600); err != nil {
		return errors.New("connector_token_write")
	}
	b, _ := json.Marshal(grant.Association)
	if err := artifact.AtomicWrite(marker, b, 0600); err != nil {
		_ = os.Remove(tokenPath)
		return errors.New("connector_launch_write")
	}
	command := "/usr/local/bin/cloudflared"
	err := exec(command, []string{command, "tunnel", "--no-autoupdate", "--disable-path-normalization=false", "--metrics", "127.0.0.1:20241", "run", "--token-file", tokenPath}, []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent"})
	_ = os.Remove(tokenPath)
	_ = os.Remove(marker)
	return err
}

// Probe reports connector health without depending on management delivery.
func Probe(ctx context.Context, socket, marker string) bool {
	return probe(ctx, transport.NewLocal(socket), marker, "http://127.0.0.1:20241", processIdentity)
}

func probe(ctx context.Context, client transport.Requester, marker, base string, identity func() (string, error)) bool {
	read := func(path string, limit int64) ([]byte, bool) {
		requestCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		r, _ := http.NewRequestWithContext(requestCtx, http.MethodGet, base+path, nil)
		response, err := transport.HTTPClient().Do(r)
		if err != nil {
			return nil, false
		}
		defer response.Body.Close()
		b, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
		return b, err == nil && int64(len(b)) <= limit && response.StatusCode == http.StatusOK
	}
	_, ready := read("/ready", 1024)
	b, configOK := read("/config", 256<<10)
	var config struct {
		Version int64 `json:"version"`
	}
	if !configOK || transport.Decode(b, &config) != nil || config.Version < 1 {
		config.Version = 0
	}
	b, err := os.ReadFile(marker)
	var association Association
	process, processErr := identity()
	if err == nil && processErr == nil && len(b) <= 16384 && transport.Decode(b, &association) == nil && validLaunch(association.Launch) && association.ProcessID == process {
		deliveryCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_, _, _ = client.Request(deliveryCtx, "tunnel/observation", Observation{Association: association, Ready: ready, ProviderVersion: config.Version}, 1024)
		cancel()
	}
	return ready
}
