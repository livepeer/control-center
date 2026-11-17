package machineconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"go.yaml.in/yaml/v3"
)

func telemetryDesired() Desired {
	return Desired{IngressPublicKeys: []byte(`{"1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`), Machine: Machine{NodeID: "vkvkvkvkvkvkuaaaaaaaaaaaaa", CredentialVersion: 1, InstallDir: "/opt/livepeer", K3sVersion: "v1.37.2+k3s1"},
		RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64), ControlAPIURL: "https://api.example", State: State{Lifecycle: "active"},
		TelemetryEnabled: true, TelemetryCapable: true, TelemetryAppLogs: true}
}

func bundleFiles(t *testing.T, m Desired) map[string][]byte {
	t.Helper()
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

func TestTelemetryCapabilityFromInstalledSoftware(t *testing.T) {
	for _, tc := range []struct {
		software []contract.SoftwareIdentity
		want     bool
	}{
		{nil, false},
		{[]contract.SoftwareIdentity{{Component: "gvisor", Scope: "installed", Version: "1"}}, false},
		{[]contract.SoftwareIdentity{{Component: TelemetryHostFeature, Scope: "running", Version: "1"}}, false},
		{[]contract.SoftwareIdentity{{Component: TelemetryHostFeature, Scope: "installed", Version: "0"}}, false},
		{[]contract.SoftwareIdentity{{Component: TelemetryHostFeature, Scope: "installed", Version: "x"}}, false},
		{[]contract.SoftwareIdentity{{Component: "runtime", Scope: "running"}, {Component: TelemetryHostFeature, Scope: "installed", Version: "1"}}, true},
		{[]contract.SoftwareIdentity{{Component: TelemetryHostFeature, Scope: "installed", Version: "2"}}, true},
	} {
		if got := TelemetryCapable(tc.software); got != tc.want {
			t.Fatalf("%+v: got %v", tc.software, got)
		}
	}
}

func TestTelemetryBundleIsGatedAndNeverDrainsNode(t *testing.T) {
	m := telemetryDesired()
	files := bundleFiles(t, m)
	system := string(files["management/system.yaml"])
	if !strings.Contains(system, "name: livepeer-telemetry\n") || !strings.Contains(system, "path: ./system/telemetry\n") {
		t.Fatal("telemetry Kustomization missing", system)
	}
	// Only telemetry removes its workloads when the Kustomization goes away.
	for _, doc := range strings.Split(system, "---\n") {
		want := "deletionPolicy: Orphan"
		if strings.Contains(doc, "name: livepeer-telemetry\n") {
			want = "deletionPolicy: Delete"
		}
		if !strings.Contains(doc, want) {
			t.Fatal("deletion policy", doc)
		}
	}
	if !strings.Contains(string(files["system/node/network.yaml"]), "kubernetes.io/metadata.name: livepeer-telemetry") {
		t.Fatal("telemetry agent cannot reach Node metrics")
	}
	agent := string(files["system/telemetry/agent.yaml"])
	for _, want := range []string{"image: 'registry.invalid/runtime@sha256:", "livepeer.io/node-id: 'vkvkvkvkvkvkuaaaaaaaaaaaaa'", "path: '/opt/livepeer/volumes/management-sockets/telemetry'",
		"path: '/opt/livepeer/volumes/telemetry'", "--transport, 'https'", "/opt/livepeer/(k3s|kubelet))"} {
		if !strings.Contains(agent, want) {
			t.Fatal("agent missing", want)
		}
	}
	var deployment struct {
		Spec struct {
			Template struct {
				Spec struct {
					HostNetwork bool `yaml:"hostNetwork"`
					HostPID     bool `yaml:"hostPID"`
					Containers  []struct {
						Name            string
						Image           string
						Args            []string
						Ports           []map[string]any
						SecurityContext struct {
							RunAsUser                *int  `yaml:"runAsUser"`
							AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
							ReadOnlyRootFilesystem   bool  `yaml:"readOnlyRootFilesystem"`
							Capabilities             struct{ Drop, Add []string }
						} `yaml:"securityContext"`
					}
				}
			}
		}
	}
	if err := yaml.Unmarshal(files["system/telemetry/agent.yaml"], &deployment); err != nil {
		t.Fatal(err)
	}
	spec := deployment.Spec.Template.Spec
	if spec.HostNetwork || spec.HostPID || len(spec.Containers) != 5 {
		t.Fatal("telemetry Pod must stay on the Pod network", spec.HostNetwork, spec.HostPID, len(spec.Containers))
	}
	for _, c := range spec.Containers {
		sc := c.SecurityContext
		if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || !sc.ReadOnlyRootFilesystem || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" || len(sc.Capabilities.Add) != 0 || len(c.Ports) != 0 {
			t.Fatal("container not restricted", c.Name)
		}
		// Only the log reader runs as UID 0, and it has no capabilities.
		if (sc.RunAsUser != nil && *sc.RunAsUser == 0) != (c.Name == "fluent-bit") {
			t.Fatal("unexpected root container", c.Name)
		}
		if c.Name != "relay" && !strings.Contains(c.Image, "@sha256:") {
			t.Fatal("unpinned image", c.Image)
		}
		// Agents listen only on the Pod loopback.
		for i, arg := range c.Args {
			value := ""
			if arg == "--listen" && i+1 < len(c.Args) {
				value = c.Args[i+1]
			} else if name, v, ok := strings.Cut(arg, "="); ok && (strings.Contains(strings.ToLower(name), "listen") || strings.HasSuffix(name, "host")) {
				value = v
			}
			if value != "" && value != "127.0.0.1" && !strings.HasPrefix(value, "127.0.0.1:") {
				t.Fatal("non-loopback listener", c.Name, arg, value)
			}
		}
	}
	if !strings.Contains(string(files["system/telemetry/network.yaml"]), "ingress: []") {
		t.Fatal("telemetry Pod accepts connections")
	}
	logs := string(files["system/telemetry/fluent-bit.conf"])
	if !strings.Contains(logs, "tag                 pod.app") || !strings.Contains(logs, "/opt/livepeer/logs/pods/livepeer-apps_*/*/*.log") || files["system/telemetry/app-logs.conf"] != nil {
		t.Fatal("app log input missing", logs)
	}
	quiet := telemetryDesired()
	quiet.TelemetryAppLogs = false
	logs = string(bundleFiles(t, quiet)["system/telemetry/fluent-bit.conf"])
	// System logs still exclude app output when app logs are disabled.
	if strings.Contains(logs, "pod.app\n    path") || strings.Count(logs, "livepeer-apps_") != 1 || !strings.Contains(logs, "exclude_path        /opt/livepeer/logs/pods/livepeer-apps_*/*/*.log") {
		t.Fatal("app logs collected while disabled", logs)
	}

	without := m
	without.TelemetryEnabled, without.TelemetryCapable = false, false
	if Digest(m) != Digest(without) {
		t.Fatal("telemetry changed the Node drain digest")
	}
	for name, change := range map[string]func(*Desired){
		"disabled":  func(d *Desired) { d.TelemetryEnabled = false },
		"incapable": func(d *Desired) { d.TelemetryCapable = false },
		"terminal":  func(d *Desired) { d.Terminal = true },
	} {
		d := telemetryDesired()
		change(&d)
		if telemetryActive(d) {
			t.Fatal("telemetry active when", name)
		}
		if d.Terminal {
			continue // Terminal bundles need retained cleanup inputs; activity alone gates them.
		}
		files := bundleFiles(t, d)
		for path := range files {
			if strings.Contains(path, "telemetry") {
				t.Fatal("telemetry delivered when", name, path)
			}
		}
		if strings.Contains(string(files["management/system.yaml"]), "livepeer-telemetry") || strings.Contains(string(files["system/node/network.yaml"]), "livepeer-telemetry") {
			t.Fatal("telemetry referenced when", name)
		}
	}
}

// kubectl's embedded Kustomize validates generator and resource structure.
func TestTelemetryKustomizationBuilds(t *testing.T) {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Skip("kubectl is unavailable")
	}
	dir := t.TempDir()
	for path, data := range bundleFiles(t, telemetryDesired()) {
		if !strings.HasPrefix(path, "system/telemetry/") {
			continue
		}
		target := filepath.Join(dir, strings.TrimPrefix(path, "system/telemetry/"))
		if err := os.WriteFile(target, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command(kubectl, "kustomize", dir).CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}
	rendered := string(out)
	for _, want := range []string{"name: livepeer-telemetry-config-", "kind: ClusterRole", "kind: NetworkPolicy", "kind: Deployment", "-remoteWrite.url=http://127.0.0.1:20244/metrics/write"} {
		if !strings.Contains(rendered, want) {
			t.Fatal("rendered telemetry missing", want)
		}
	}
}
