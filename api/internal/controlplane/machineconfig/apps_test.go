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

func TestIndependentManagementAndFullWorkloadDigest(t *testing.T) {
	m := Desired{Machine: Machine{NodeID: "lp-" + strings.Repeat("a", 16), Epoch: "22222222-2222-4222-8222-222222222222", CredentialVersion: 1, InstallDir: "/opt/livepeer", K3sVersion: "v1.37.2+k3s1"}, RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64), NodeImage: "registry.invalid/node@sha256:" + strings.Repeat("b", 64)}
	missing := m
	missing.RuntimeImage = ""
	if _, _, err := Build(missing); err == nil {
		t.Fatal("missing required Runtime image")
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
	if !strings.Contains(string(files["system/node/orchestrator.yaml"]), "image: "+m.NodeImage) {
		t.Fatal("ignored the configured Node image")
	}
	first := Digest(m)
	m.NodeImage = "registry.invalid/node@sha256:" + strings.Repeat("c", 64)
	if Digest(m) == first {
		t.Fatal("Node image bypassed drain")
	}
	m.State.HeldOrchestrator = string(files["system/node/orchestrator.yaml"])
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
	if string(actual["system/node/orchestrator.yaml"]) != string(files["system/node/orchestrator.yaml"]) || string(actual["upgrade-plan/plan.yaml"]) != m.State.HeldUpgradePlan {
		t.Fatal("disruptive target released during repair")
	}
	m.State.HeldOrchestrator = ""
	m.State.HeldUpgradePlan = ""
	withUpgrade := Digest(m)
	m.K3sVersion = "v1.37.2+k3s1"
	if Digest(m) == withUpgrade {
		t.Fatal("K3s upgrade bypassed drain")
	}
	if !strings.Contains(string(files["system/node/orchestrator.yaml"]), `RunnerGrants = ["10.43.0.0/16"]`) {
		t.Fatal("missing private app grant")
	}

}
func TestDrainProofDoesNotGainFreshnessFromDeliveryRetry(t *testing.T) {
	now := time.Now().UTC()
	m := Machine{NodeID: "node", Epoch: "epoch"}
	state := State{Generation: 7, DrainRequested: true, DrainStartedAt: now.Add(-time.Hour), PendingConfigDigest: "target"}
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
