package machineconfig

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"go.yaml.in/yaml/v3"
)

func TestSystemPeersRetainTerminalCleanupAndScopedCredentials(t *testing.T) {
	m := Desired{IngressPublicKeys: []byte(`{"1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`), Machine: Machine{NodeID: "vkvkvkvkvkvkuaaaaaaaaaaaaa", CredentialVersion: 1, InstallDir: "/opt/livepeer", K3sVersion: "v1.37.2+k3s1"}, RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64), Connector: ConnectorConfig{Image: "registry.invalid/connector@sha256:" + strings.Repeat("b", 64)}, State: State{Lifecycle: "active"}, Exposure: &Exposure{IngressVersion: 1, ProxyURLTemplate: "https://{proxy}.node.example", DiscoveryURL: "https://discovery.node.example/discovery", TunnelID: "tunnel", ServiceURL: "https://machine.example", IngressDigest: "ingress", CredentialGeneration: 4, ProviderVersion: 8}}
	build := func(m Desired) map[string][]byte {
		data, _, err := Build(m)
		if err != nil {
			t.Fatal(err)
		}
		files, err := artifact.Read(data)
		if err != nil {
			t.Fatal(err)
		}
		return files
	}
	files := build(m)
	for _, field := range []string{"APIOriginURL", "RunnerServiceURL"} {
		if !strings.Contains(string(files["system/node/orchestrator.yaml"]), field+` = "`+PrivateOrchestrator+`"`) {
			t.Fatal("Node omitted private authority", field)
		}
	}
	if !strings.Contains(string(files["system/node/orchestrator.yaml"]), `ExcludedHeaders = ["CF-Access-*", "Livepeer-Session-*", "X-Forwarded-*"]`) {
		t.Fatal("Node omitted ingress header exclusion")
	}
	var deployment struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct{ Name, Image string }
				}
			}
		}
	}
	if err := yaml.Unmarshal(files["system/connector/tunnel.yaml"], &deployment); err != nil {
		t.Fatal(err)
	}
	containers := deployment.Spec.Template.Spec.Containers
	if len(containers) != 1 || containers[0].Name != "connector" || containers[0].Image != m.Connector.Image {
		t.Fatal("connector workload must contain only the pinned connector")
	}
	if strings.Contains(string(files["management/kustomization.yaml"]), "orchestrator.yaml") || files["system/node/orchestrator.yaml"] == nil {
		t.Fatal("system inventories were not partitioned")
	}
	for _, name := range []string{"livepeer-node", "livepeer-connector", "livepeer-app-reconciler", "livepeer-upgrade-controller", "livepeer-upgrade-plan"} {
		if !strings.Contains(string(files["management/system.yaml"]), "name: "+name+"\n") {
			t.Fatal("missing system reconciliation", name)
		}
	}
	tunnel := string(files["system/connector/tunnel.yaml"])
	if strings.Contains(tunnel, "python") || strings.Contains(tunnel, "name: broker") || strings.Contains(tunnel, "livepeer-service-auth") || !strings.Contains(tunnel, "timeoutSeconds: 5") {
		t.Fatal("connector retained broker credentials or supervision")
	}
	apps := string(files["system/app-reconciler/workload.yaml"])
	if strings.Contains(apps, "/credentials/token") || !strings.Contains(apps, "key: identity.json") || !strings.Contains(apps, "--management-socket") {
		t.Fatal("App Reconciler received the enrollment credential")
	}
	data, _, _ := Build(m)
	metadata, manifest, err := ReadApplied(data)
	if err != nil || metadata.ConfigDigest != Digest(m) || manifest != string(files["system/node/orchestrator.yaml"]) {
		t.Fatal("rollout reader lost Node identity", err)
	}
	m.Terminal = true
	m.RetainedFiles = files
	terminal := build(m)
	if !strings.Contains(string(files["management/system.yaml"]), "dependsOn: [{name: livepeer-upgrade-controller}]") {
		t.Fatal("active upgrade lost controller prerequisite")
	}
	for _, prefix := range []string{"", "terminal-cleanup/"} {
		if strings.Contains(string(terminal[prefix+"management/system.yaml"]), "dependsOn: [{name: livepeer-upgrade-controller}]") {
			t.Fatal("terminal Plan deletion depends on controller health")
		}
	}
	var retained, final contract.Metadata
	json.Unmarshal(terminal["runtime.json"], &retained)
	json.Unmarshal(terminal["terminal-cleanup/runtime.json"], &final)
	if strings.Contains(string(terminal["system/node/orchestrator.yaml"]), "kind: Deployment") || terminal["system/connector/tunnel.yaml"] == nil || retained.ConnectorTokenRef == "" || retained.TokenGeneration != 4 {
		t.Fatal("terminal pruning removed pending cleanup dependencies")
	}
	if strings.Contains(string(terminal["terminal-cleanup/system/node/orchestrator.yaml"]), "kind: Deployment") || terminal["terminal-cleanup/system/connector/tunnel.yaml"] != nil || !final.TerminalCleanup || final.ConnectorTokenRef != "" {
		t.Fatal("final cleanup did not fence the retained connector")
	}

}
