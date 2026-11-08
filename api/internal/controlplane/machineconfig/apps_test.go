package machineconfig

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
)

func TestNodeImageOverrideBeforeBundleNegotiation(t *testing.T) {
	for _, format := range []int{1, 2} {
		m := Desired{Machine: Machine{NodeID: "lp-" + strings.Repeat("a", 16), Epoch: "22222222-2222-4222-8222-222222222222", CredentialVersion: 1, InstallDir: "/opt/livepeer", K3sVersion: "v1.37.2+k3s1"}, BundleFormat: format, RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64), NodeImage: "registry.invalid/node@sha256:" + strings.Repeat("b", 64)}
		data, _, err := Build(m)
		if err != nil {
			t.Fatal(format, err)
		}
		files, err := artifact.Read(data)
		if err != nil {
			t.Fatal(err)
		}
		path := "orchestrator.yaml"
		if format == 2 {
			path = "management/orchestrator.yaml"
		}
		if !strings.Contains(string(files[path]), "image: "+m.NodeImage) {
			t.Fatalf("format %d ignored the configured Node image", format)
		}
		before := Digest(m)
		m.NodeImage = "registry.invalid/node@sha256:" + strings.Repeat("c", 64)
		if Digest(m) == before {
			t.Fatalf("format %d did not fence an image change", format)
		}
		m.State.HeldOrchestrator = string(files[path])
		if Digest(m) != before {
			t.Fatalf("format %d changed a held image identity", format)
		}
		granted := strings.Contains(string(files[path]), `RunnerGrants = ["10.43.0.0/16"]`)
		if granted != (format >= 2) {
			t.Fatalf("format %d changed legacy runner grants", format)
		}
	}
}

func TestIndependentManagementAndFullWorkloadDigest(t *testing.T) {
	m := Desired{Machine: Machine{NodeID: "lp-" + strings.Repeat("a", 16), Epoch: "22222222-2222-4222-8222-222222222222", CredentialVersion: 1, InstallDir: "/opt/livepeer", K3sVersion: "v1.37.2+k3s1"}, BundleFormat: 2, RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64)}
	missing := m
	missing.RuntimeImage = ""
	if _, _, err := Build(missing); err == nil {
		t.Fatal("format 2 silently omitted its required consumer")
	}
	data, _, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	files, err := artifact.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(files["kustomization.yaml"]), "app-desired") || !strings.Contains(string(files["management/kustomization.yaml"]), "app-reconciler.yaml") {
		t.Fatal("two app apply paths")
	}
	var metadata contract.Metadata
	if json.Unmarshal(files["runtime.json"], &metadata) != nil {
		t.Fatal("invalid metadata")
	}
	p, err := appbundle.Read(files, metadata)
	if err != nil || p.Index.Available {
		t.Fatal("missing payload became empty intent", err)
	}
	first := Digest(m)
	m.NodeImage = "registry.invalid/node@sha256:" + strings.Repeat("b", 64)
	if Digest(m) == first {
		t.Fatal("Node image bypassed drain")
	}
	m.State.HeldOrchestrator = string(files["management/orchestrator.yaml"])
	m.State.HeldUpgradePlan = string(files["upgrade-plan/plan.yaml"])
	m.K3sVersion = "v1.37.3+k3s1"
	if Digest(m) != first {
		t.Fatal("held workload identity changed")
	}
	held, _, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := artifact.Read(held)
	if string(actual["management/orchestrator.yaml"]) != string(files["management/orchestrator.yaml"]) || string(actual["upgrade-plan/plan.yaml"]) != m.State.HeldUpgradePlan {
		t.Fatal("disruptive target released during repair")
	}
	m.State.HeldOrchestrator = ""
	m.State.HeldUpgradePlan = ""
	withUpgrade := Digest(m)
	m.K3sVersion = "v1.37.2+k3s1"
	if Digest(m) == withUpgrade {
		t.Fatal("K3s upgrade bypassed drain")
	}
	if !strings.Contains(string(files["management/orchestrator.yaml"]), `RunnerGrants = ["10.43.0.0/16"]`) {
		t.Fatal("missing private app grant")
	}
	m.Terminal = true
	m.RetainedFiles = files
	terminal, _, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	stages, _ := artifact.Read(terminal)
	if !strings.Contains(string(stages["management/orchestrator.yaml"]), "kind: Deployment") || strings.Contains(string(stages["terminal-cleanup/management/orchestrator.yaml"]), "kind: Deployment") {
		t.Fatal("terminal input removed Node before app cleanup")
	}
	var final contract.Metadata
	json.Unmarshal(stages["terminal-cleanup/runtime.json"], &final)
	if !final.TerminalCleanup {
		t.Fatal("terminal cleanup phase missing")
	}
}
func TestDrainProofDoesNotGainFreshnessFromDeliveryRetry(t *testing.T) {
	now := time.Now().UTC()
	m := Machine{NodeID: "node", Epoch: "epoch"}
	state := State{BundleFormat: 2, Generation: 7, DrainRequested: true, DrainStartedAt: now.Add(-time.Hour), PendingConfigDigest: "target"}
	r := Report{Generation: 7, Drained: true, Evidence: &contract.Evidence{Kind: "no_owner", Target: DrainTarget(m.NodeID, m.Epoch, state), WithdrawalID: "withdrawal", ObservedAt: now, ExpiresAt: now.Add(30 * time.Second)}}
	if !validDrainEvidence(m, state, r, now) {
		t.Fatal("late confirmed completion rejected")
	}
	if validDrainEvidence(m, state, r, now.Add(time.Minute)) {
		t.Fatal("old proof refreshed by retry")
	}
	r.Evidence.Target = "different"
	if validDrainEvidence(m, state, r, now) {
		t.Fatal("wrong target accepted")
	}
}
