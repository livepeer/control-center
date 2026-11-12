package machineconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/onchain"
	"github.com/livepeer/control-center/runtime/transport"
	"go.yaml.in/yaml/v3"
)

func TestOnchainBundleDeterminismCredentialRotationAndHeldIdentity(t *testing.T) {
	c := onchain.Config{Version: 1, Generation: 1, CredentialRevision: 1, Mode: "onchain", Network: "custom", ChainID: 1, Controller: "0x" + strings.Repeat("1", 40), Recipient: "0x" + strings.Repeat("2", 40), RPCSecret: strings.Repeat("c", 64), RedeemerURL: "https://redeemer.example", RPCGrants: []string{"10.0.0.2:443"}, RedeemerGrants: []string{"10.0.0.3:443"}, WeiPerUSD: "100", TicketFaceValue: "100", TicketWinProb: "1", MaxPendingTickets: 100, MaxTicketsPerRecipient: 10}
	m := Desired{Machine: Machine{NodeID: "lp-aaaaaaaaaaaaaaaa", Epoch: "11111111-1111-4111-8111-111111111111", CredentialVersion: 1, InstallDir: "/srv/livepeer", K3sVersion: "v1.37.2+k3s1"}, Onchain: c, RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64), NodeImage: "registry.invalid/node@sha256:" + strings.Repeat("b", 64)}
	b, d, e := Build(m)
	if e != nil {
		t.Fatal(e)
	}
	again, dd, e := Build(m)
	if e != nil || d != dd || !bytes.Equal(b, again) {
		t.Fatal("unstable bundle", e)
	}
	files, e := artifact.Read(b)
	if e != nil {
		t.Fatal(e)
	}
	for name, body := range files {
		if !strings.HasSuffix(name, ".yaml") {
			continue
		}
		decoder := yaml.NewDecoder(bytes.NewReader(body))
		for {
			var document map[string]any
			if e := decoder.Decode(&document); e == io.EOF {
				break
			} else if e != nil {
				t.Fatal("invalid onchain manifest", name, e)
			}
		}
	}
	node := string(files["system/node/orchestrator.yaml"])
	if binary := os.Getenv("NODE_BINARY"); binary != "" {
		dir := t.TempDir()
		config := configurationFromManifest(node)
		for key, value := range map[string]string{"/run/onchain/private/rpc": "https://rpc.example", "/run/onchain/private/headers": "Authorization: Bearer test-only", "/credentials/secret": "bootstrap-test-only"} {
			file := filepath.Join(dir, filepath.Base(key))
			if e := os.WriteFile(file, []byte(value), 0600); e != nil {
				t.Fatal(e)
			}
			config = strings.ReplaceAll(config, key, file)
		}
		config = strings.ReplaceAll(config, `"/data`, `"`+filepath.Join(dir, "data"))
		path := filepath.Join(dir, "orchestrator.toml")
		os.WriteFile(path, []byte(config), 0600)
		if output, e := exec.Command(binary, "--config", path, "--print-config").CombinedOutput(); e != nil {
			t.Fatal("actual Node rejected onchain configuration", e, string(output))
		}
	}
	for _, want := range []string{"orchestrator-start", "orchestrator-probe", "publishNotReadyAddresses: true", "fsGroupChangePolicy: OnRootMismatch", "RPCURLFile", "RedeemerHeadersFile", "/data/onchain.sqlite", "medium: Memory"} {
		if !strings.Contains(node, want) {
			t.Fatal("missing", want)
		}
	}
	if strings.Contains(node, c.RPCSecret) || strings.Contains(node, "KeystorePassword") {
		t.Fatal("credential value/reference in Node config")
	}
	if !strings.Contains(string(files["management/app-reconciler.yaml"]), "10.0.0.3/32") {
		t.Fatal("missing private endpoint policy")
	}
	original := Digest(m)
	refreshed := m
	refreshed.CredentialVersion++
	if Digest(refreshed) == original {
		t.Fatal("management refresh did not schedule Node drain and replacement")
	}
	refreshed = m
	refreshed.Epoch = "22222222-2222-4222-8222-222222222222"
	if Digest(refreshed) == original {
		t.Fatal("re-enrollment reused a previous lifetime's Node workload")
	}
	m.Onchain.Generation++
	m.Onchain.CredentialRevision++
	if Digest(m) == original {
		t.Fatal("credential generation failed to restart Node")
	}
	m.State.HeldOrchestrator = node
	m.State.HeldOnchain = onchainJSON(c)
	meta := DesiredRuntime(m)
	if meta.Onchain.Generation != c.Generation || meta.ConfigDigest != original {
		t.Fatal("held workload borrowed desired onchain identity", meta)
	}
	var parsed Runtime
	if json.Unmarshal(files["runtime.json"], &parsed) != nil || parsed.Onchain.Recipient != c.Recipient {
		t.Fatal("onchain metadata absent")
	}
	// Fields omitted by a held offchain identity must not survive from the
	// desired onchain configuration while the existing workload drains.
	free := m
	free.State.HeldOrchestrator, free.State.HeldOnchain = "", ""
	free.Onchain = onchain.Offchain()
	freeBundle, _, e := Build(free)
	if e != nil {
		t.Fatal(e)
	}
	freeFiles, _ := artifact.Read(freeBundle)
	m.State.HeldOrchestrator = string(freeFiles["system/node/orchestrator.yaml"])
	m.State.HeldOnchain = onchainJSON(onchain.Offchain())
	b, _, e = Build(m)
	if e != nil {
		t.Fatal(e)
	}
	files, _ = artifact.Read(b)
	parsed, e = transport.ReadMetadata(files["runtime.json"])
	if e != nil || parsed.Onchain.Onchain() || parsed.Onchain.Recipient != "" || parsed.Onchain.RPCSecret != "" {
		t.Fatal("held offchain workload inherited desired onchain inputs", parsed.Onchain, e)
	}
}

func TestOnchainLookupFailureDoesNotBeginWithdrawal(t *testing.T) {
	manager := New(Config{}, Dependencies{})
	state := State{Lifecycle: "active", Generation: 4, ApprovedConfigDigest: strings.Repeat("a", 64)}
	before := state
	desired := Desired{OnchainError: fmt.Errorf("onchain lookup unavailable")}
	if _, e := manager.Gate(t.Context(), Machine{}, &state, desired); e == nil || state != before {
		t.Fatal("failed lookup changed rollout", e, state)
	}
	if _, e := manager.StageTarget(t.Context(), Machine{}, &state, desired, "endpoint"); e == nil || state != before {
		t.Fatal("failed lookup changed target", e, state)
	}
}
