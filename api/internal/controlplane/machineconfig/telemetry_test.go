package machineconfig

import (
	"fmt"
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

type telemetryContainer struct {
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

type telemetryPod struct {
	HostNetwork                  bool  `yaml:"hostNetwork"`
	HostPID                      bool  `yaml:"hostPID"`
	AutomountServiceAccountToken *bool `yaml:"automountServiceAccountToken"`
	SecurityContext              struct {
		RunAsUser          *int  `yaml:"runAsUser"`
		FSGroup            *int  `yaml:"fsGroup"`
		SupplementalGroups []int `yaml:"supplementalGroups"`
	} `yaml:"securityContext"`
	Containers []telemetryContainer
	Volumes    []struct {
		Name     string
		HostPath *struct{ Path string } `yaml:"hostPath"`
	}
}

func telemetryPodSpec(t *testing.T, data []byte) telemetryPod {
	t.Helper()
	var deployment struct {
		Spec struct {
			Template struct{ Spec telemetryPod }
		}
	}
	if err := yaml.Unmarshal(data, &deployment); err != nil {
		t.Fatal(err)
	}
	return deployment.Spec.Template.Spec
}

func restricted(t *testing.T, c telemetryContainer) {
	t.Helper()
	sc := c.SecurityContext
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || !sc.ReadOnlyRootFilesystem || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" || len(sc.Capabilities.Add) != 0 {
		t.Fatal("container not restricted", c.Name)
	}
	if c.Name != "relay" && !strings.Contains(c.Image, "@sha256:") {
		t.Fatal("unpinned image", c.Image)
	}
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
		"path: '/opt/livepeer/volumes/telemetry'", "--transport, 'https'", "--node-id, 'vkvkvkvkvkvkuaaaaaaaaaaaaa'",
		"-remoteWrite.tmpDataPath=/buffer/vkvkvkvkvkvkuaaaaaaaaaaaaa\n", "-remoteWrite.maxDiskUsagePerURL=536871040\n"} {
		if !strings.Contains(agent, want) {
			t.Fatal("agent missing", want)
		}
	}
	spec := telemetryPodSpec(t, files["system/telemetry/agent.yaml"])
	if spec.HostNetwork || spec.HostPID || len(spec.Containers) != 4 {
		t.Fatal("telemetry Pod must stay on the Pod network", spec.HostNetwork, spec.HostPID, len(spec.Containers))
	}
	// The host's root, /proc and /sys are visible only to node_exporter.
	for _, v := range spec.Volumes {
		if v.HostPath != nil && (v.HostPath.Path == "/" || v.HostPath.Path == "/proc" || v.HostPath.Path == "/sys") {
			t.Fatal("agent Pod mounts host", v.HostPath.Path)
		}
	}
	for _, c := range spec.Containers {
		restricted(t, c)
		if len(c.Ports) != 0 {
			t.Fatal("agent container exposes a port", c.Name)
		}
		// Only the log reader runs as UID 0, and it has no capabilities.
		sc := c.SecurityContext
		if (sc.RunAsUser != nil && *sc.RunAsUser == 0) != (c.Name == "fluent-bit") {
			t.Fatal("unexpected root container", c.Name)
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
	exporter := telemetryPodSpec(t, files["system/telemetry/node-exporter.yaml"])
	// node_exporter shares no UID, group, token or loopback with management
	// workloads, so host paths owned by 65532 stay out of its reach.
	es := exporter.SecurityContext
	if exporter.HostNetwork || exporter.HostPID || exporter.AutomountServiceAccountToken == nil || *exporter.AutomountServiceAccountToken ||
		es.RunAsUser == nil || *es.RunAsUser != 65533 || es.FSGroup != nil || len(es.SupplementalGroups) != 0 || len(exporter.Containers) != 1 {
		t.Fatal("node_exporter Pod not isolated", exporter)
	}
	restricted(t, exporter.Containers[0])
	if c := exporter.Containers[0]; c.SecurityContext.RunAsUser != nil || !strings.Contains(strings.Join(c.Args, " "), "--web.listen-address=:9100 ") ||
		!strings.Contains(strings.Join(c.Args, " "), "/opt/livepeer/(k3s|kubelet))") {
		t.Fatal("node_exporter container", c.Args)
	}
	network := string(files["system/telemetry/network.yaml"])
	if !strings.Contains(network, "ingress: []") || !strings.Contains(network, "podSelector: {matchLabels: {app: livepeer-telemetry-node-exporter}}") ||
		!strings.Contains(network, "- podSelector: {matchLabels: {app: livepeer-telemetry-agent}}\n    ports: [{protocol: TCP, port: 9100}]") {
		t.Fatal("telemetry network policy", network)
	}
	if !strings.Contains(string(files["system/telemetry/vmagent.yaml"]), "label: app=livepeer-telemetry-node-exporter, field: 'spec.nodeName=%{NODE_NAME}'") {
		t.Fatal("vmagent does not scrape this node's node_exporter")
	}
	logs := string(files["system/telemetry/fluent-bit.conf"])
	// Log buffers and tail positions belong to this enrollment.
	if strings.Contains(logs, "/buffer/fluent-bit") || strings.Count(logs, "/buffer/vkvkvkvkvkvkuaaaaaaaaaaaaa") != 6 {
		t.Fatal("log buffers not scoped to the enrollment", logs)
	}
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
	for _, want := range []string{"name: livepeer-telemetry-config-", "kind: ClusterRole", "kind: NetworkPolicy", "kind: Deployment", "-remoteWrite.url=http://127.0.0.1:20244/metrics/write", "name: livepeer-telemetry-node-exporter\n  namespace: livepeer-telemetry"} {
		if !strings.Contains(rendered, want) {
			t.Fatal("rendered telemetry missing", want)
		}
	}
}

// Agents never send a body larger than Control Center accepts, so vmagent's
// single queue cannot stall on a 413.
func TestTelemetryWriteLimitsFollowIngestLimit(t *testing.T) {
	for _, tc := range []struct {
		max, body, block int64
	}{{0, 8 << 20, 4_000_000}, {8 << 20, 8 << 20, 4_000_000}, {64 << 20, 64 << 20, 4_000_000}, {1 << 20, 1 << 20, 1<<20 - 64<<10}, {4 << 20, 4 << 20, 4_000_000}} {
		body, block := telemetryWriteLimits(tc.max)
		if body != tc.body || block != tc.block || block > body-telemetryBlockMargin {
			t.Fatal(tc.max, body, block)
		}
		m := telemetryDesired()
		m.TelemetryMaxBody = tc.max
		agent := string(bundleFiles(t, m)["system/telemetry/agent.yaml"])
		if !strings.Contains(agent, fmt.Sprintf("--max-body-bytes, '%d'", tc.body)) || !strings.Contains(agent, fmt.Sprintf("-remoteWrite.maxBlockSize=%d\n", tc.block)) {
			t.Fatal("rendered limits", tc.max, agent)
		}
		without := m
		without.TelemetryEnabled = false
		if Digest(m) != Digest(without) {
			t.Fatal("ingest limit changed the Node drain digest")
		}
	}
}
