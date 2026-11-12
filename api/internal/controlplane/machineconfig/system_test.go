package machineconfig

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"go.yaml.in/yaml/v3"
)

func TestSystemPeersRetainTerminalCleanupAndScopedCredentials(t *testing.T) {
	m := Desired{Machine: Machine{NodeID: "vkvkvkvkvkvkuaaaaaaaaaaaaa", CredentialVersion: 1, InstallDir: "/opt/livepeer", K3sVersion: "v1.37.2+k3s1"}, RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64), Connector: ConnectorConfig{Image: "registry.invalid/connector@sha256:" + strings.Repeat("b", 64)}, State: State{Lifecycle: "active"}, Exposure: &Exposure{TunnelID: "tunnel", ServiceURL: "https://machine.example", IngressDigest: "ingress", CredentialGeneration: 4, ProviderVersion: 8}}
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
	for _, manifest := range [][]byte{files["system/connector/tunnel.yaml"]} {
		if len(manifest) == 0 {
			t.Fatal("missing connector manifest")
		}
		var deployment struct {
			Spec struct {
				Template struct {
					Spec struct {
						Containers []struct {
							Name, Image  string
							VolumeMounts []any `yaml:"volumeMounts"`
						}
					}
				}
			}
		}
		decoder := yaml.NewDecoder(bytes.NewReader(manifest))
		found := false
		for {
			if err := decoder.Decode(&deployment); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			for _, c := range deployment.Spec.Template.Spec.Containers {
				if c.Name == "node-proxy" {
					found = true
					if c.Image != m.RuntimeImage || len(c.VolumeMounts) != 0 {
						t.Fatal("Node proxy needs the Go helper without credential mounts")
					}
				}
			}
		}
		if !found {
			t.Fatal("missing Node proxy")
		}
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
	if !strings.Contains(string(terminal["system/node/orchestrator.yaml"]), "kind: Deployment") || terminal["system/connector/tunnel.yaml"] == nil || retained.ConnectorTokenRef == "" || retained.TokenGeneration != 4 {
		t.Fatal("terminal pruning removed pending cleanup dependencies")
	}
	if strings.Contains(string(terminal["terminal-cleanup/system/node/orchestrator.yaml"]), "kind: Deployment") || terminal["terminal-cleanup/system/connector/tunnel.yaml"] != nil || !final.TerminalCleanup || final.ConnectorTokenRef != "" {
		t.Fatal("final cleanup did not fence the retained connector")
	}

}

func TestProxyRoutingFollowsHeldNodeConfiguration(t *testing.T) {
	{
		m := Desired{Machine: Machine{NodeID: "vkvkvkvkvkvkuaaaaaaaaaaaaa", InstallDir: "/opt/livepeer"}, RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64), Connector: ConnectorConfig{Image: "registry.invalid/connector@sha256:" + strings.Repeat("b", 64)}, State: State{Lifecycle: "active"}}
		build := func() map[string][]byte {
			t.Helper()
			bundle, _, err := Build(m)
			if err != nil {
				t.Fatal(err)
			}
			files, err := artifact.Read(bundle)
			if err != nil {
				t.Fatal(err)
			}
			return files
		}
		prefix, nodeFile, proxyFile := "system/", "node/orchestrator.yaml", "connector/tunnel.yaml"
		private := build()
		m.Exposure = &Exposure{TunnelID: "tunnel", ServiceURL: "https://api-aaaaaaa.vkvkvkvkvkvkuaaaaaaaaaaaaa.a.invalid", ProxyURLTemplate: "https://{proxy}.vkvkvkvkvkvkuaaaaaaaaaaaaa.a.invalid", IngressDigest: "ingress"}
		a := build()
		if !strings.Contains(string(a[prefix+nodeFile]), `APIOriginURL = "`+PrivateOrchestrator+`"`) {
			t.Fatal("public Node routing omitted the private API origin")
		}
		m.State.HeldOrchestrator = string(a[prefix+nodeFile])
		m.Exposure.ServiceURL = "https://api-aaaaaaa.vkvkvkvkvkvkuaaaaaaaaaaaaa.b.invalid"
		m.Exposure.ProxyURLTemplate = "https://{proxy}.vkvkvkvkvkvkuaaaaaaaaaaaaa.b.invalid"
		for _, held := range []string{m.State.HeldOrchestrator, string(private[prefix+nodeFile])} {
			m.State.HeldOrchestrator = held
			files := build()
			manifest := string(files[prefix+proxyFile])
			_, manifest, _ = strings.Cut(manifest, "- name: node-proxy\n")
			if strings.Contains(manifest, "vkvkvkvkvkvkuaaaaaaaaaaaaa.b.invalid") || !strings.Contains(manifest, "--service-url") {
				t.Fatal("guard advanced beyond held Node configuration", manifest)
			}
			if strings.Contains(held, "vkvkvkvkvkvkuaaaaaaaaaaaaa.a.invalid") && !strings.Contains(manifest, "https://{proxy}.vkvkvkvkvkvkuaaaaaaaaaaaaa.a.invalid") {
				t.Fatal("guard lost held public proxy template")
			}
		}
	}
}
