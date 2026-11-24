package consumer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/transport"
)

// Start discards old launch material and replaces itself with the pinned connector.
func Start(ctx context.Context, profile Profile, socket, tokenPath, podName, podUID string, args []string) error {
	if os.Getpid() != 1 {
		return errors.New("connector_requires_private_pid_namespace")
	}
	process, err := processIdentity()
	if err != nil {
		return err
	}
	if profile == Orchestrator {
		repairOnchainPermissions("/data/onchain.sqlite")
	}
	return start(ctx, profile, transport.NewLocal(socket), tokenPath, podName, podUID, process, args, syscall.Exec)
}

// Before Node's data volume became a hostPath, kubelet's fsGroup walk could add
// group read/write to its SQLite state. Undo exactly that change and leave any
// other permissions to Node's own owner-only check.
func repairOnchainPermissions(path string) {
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Lstat(name)
		if err != nil || info.Mode() != 0660 {
			continue
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(owner.Uid) != os.Geteuid() || int(owner.Gid) != os.Getegid() {
			continue
		}
		if err := os.Chmod(name, 0600); err != nil {
			slog.Error("Node SQLite permission repair failed", "path", name, "reason", repairFailure(err))
			continue
		}
		slog.Warn("Restored owner-only Node SQLite permissions", "path", name)
	}
}

func repairFailure(err error) string {
	switch {
	case errors.Is(err, syscall.EROFS):
		return "read_only_filesystem"
	case errors.Is(err, fs.ErrPermission):
		return "permission_denied"
	case errors.Is(err, fs.ErrNotExist):
		return "file_missing"
	}
	return "chmod_failed"
}

func start(ctx context.Context, profile Profile, client transport.Requester, tokenPath, name, uid, process string, args []string, exec func(string, []string, []string) error) error {
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
	paths := []string{tokenPath, marker}
	if profile == Orchestrator {
		paths = append(paths, filepath.Join(directory, "headers"))
	}
	for _, path := range append(append([]string{}, paths...), tokenPath+".tmp", marker+".tmp") {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return errors.New("connector_stale_file")
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errors.New("connector_launch_identity")
	}
	launch := Launch{PodName: name, PodUID: uid, LaunchID: hex.EncodeToString(nonce[:]), ProcessID: process}
	if !ValidLaunch(launch) {
		return errors.New("connector_launch_identity")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var grant Grant
	delay := 500 * time.Millisecond
	for {
		attempt, stop := context.WithTimeout(ctx, 5*time.Second)
		b, _, err := client.Request(attempt, profile.endpoint(), launch, 16384)
		stop()
		var response Grant
		if err == nil && transport.Decode(b, &response) == nil && ((profile == Connector && validToken(response.Token)) || (profile == Orchestrator && response.RPCURL != "" && response.Headers != "")) && response.Launch == launch {
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
	files := map[string][]byte{tokenPath: []byte(grant.Token)}
	if profile == Orchestrator {
		if err := checkOnchainState("/data/onchain.sqlite", grant.RequireState); err != nil {
			return err
		}
		files[tokenPath] = []byte(grant.RPCURL)
		files[filepath.Join(directory, "headers")] = []byte(grant.Headers)
	}
	b, _ := json.Marshal(grant.Association)
	files[marker] = b
	defer func() {
		for _, path := range paths {
			_ = os.Remove(path)
		}
	}()
	for path, data := range files {
		if artifact.AtomicWrite(path, data, 0600) != nil {
			return errors.New("consumer_credential_write")
		}
	}
	command := "/usr/local/bin/cloudflared"
	if profile == Connector {
		args = []string{"tunnel", "--no-autoupdate", "--disable-path-normalization=false", "--metrics", "127.0.0.1:20241", "run", "--token-file", tokenPath}
	} else {
		command = "/usr/local/bin/livepeer"
	}
	return exec(command, append([]string{command}, args...), []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent"})
}

// Probe reports local process health and scoped observations. Its error says
// why the Pod is not ready; kubelet shows exec probe output in Pod events.
func Probe(ctx context.Context, profile Profile, socket, marker string) error {
	base := "http://127.0.0.1:20241"
	if profile == Orchestrator {
		base = "http://127.0.0.1:8936"
	}
	return probe(ctx, profile, transport.NewLocal(socket), marker, base, processIdentity)
}

func probe(ctx context.Context, profile Profile, client transport.Requester, marker, base string, identity func() (string, error)) error {
	budget := time.Second
	if profile == Orchestrator {
		budget = 3 * time.Second
		bounded, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		ctx = bounded
	}
	read := func(path string, limit int64) ([]byte, bool) {
		requestCtx, cancel := context.WithTimeout(ctx, budget)
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
	readyPath := "/ready"
	if profile == Orchestrator {
		readyPath = "/readyz"
	}
	_, ready := read(readyPath, 1024)
	var b []byte
	configOK := false
	if profile == Connector {
		b, configOK = read("/config", 256<<10)
	}
	var config struct {
		Version int64 `json:"version"`
	}
	if !configOK || transport.Decode(b, &config) != nil || config.Version < 1 {
		config.Version = 0
	}
	b, err := os.ReadFile(marker)
	var association Association
	process, processErr := identity()
	unreported := ""
	switch {
	case err != nil || len(b) > 16384 || transport.Decode(b, &association) != nil || !ValidLaunch(association.Launch):
		unreported = "launch_marker_unavailable"
	case processErr != nil:
		unreported = processErr.Error()
	case association.ProcessID != process:
		unreported = "launch_process_replaced"
	default:
		deliveryBudget := 500 * time.Millisecond
		if profile == Orchestrator {
			deliveryBudget = budget
		}
		deliveryCtx, cancel := context.WithTimeout(ctx, deliveryBudget)
		_, _, err = client.Request(deliveryCtx, profile.observationPath()[1:], Observation{Association: association, Ready: ready, ProviderVersion: config.Version, ObservedAt: time.Now()}, 1024)
		if err != nil {
			unreported = "observation_undelivered"
		}
		cancel()
	}
	var failures []string
	if !ready {
		failures = append(failures, "readiness_endpoint_failed")
	}
	// Missing local evidence persists, and Control Center can only show the
	// connector as offline, so the pod reports it. Connector delivery keeps its
	// short budget: a slow agent does not make a working tunnel unready.
	if unreported != "" && (profile == Orchestrator || unreported != "observation_undelivered") {
		failures = append(failures, unreported)
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, ", "))
	}
	return nil
}

func checkOnchainState(path string, required bool) error {
	if !required {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("onchain_storage_missing")
	}
	return nil
}
