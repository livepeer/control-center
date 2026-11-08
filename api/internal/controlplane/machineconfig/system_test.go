package machineconfig

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"go.yaml.in/yaml/v3"
)

func TestSystemPeersRetainTerminalCleanupAndScopedCredentials(t *testing.T) {
	m := Desired{Machine: Machine{NodeID: "lp-aaaaaaaaaaaaaaaa", Epoch: "22222222-2222-4222-8222-222222222222", CredentialVersion: 1, InstallDir: "/opt/livepeer", K3sVersion: "v1.37.2+k3s1"}, BundleFormat: contract.SystemBundleFormat, RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64), Connector: ConnectorConfig{Image: "registry.invalid/connector@sha256:" + strings.Repeat("b", 64)}, State: State{Lifecycle: "active"}, Exposure: &Exposure{TunnelID: "tunnel", ServiceURL: "https://machine.example", IngressDigest: "ingress", CredentialGeneration: 4, ProviderVersion: 8}}
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
	assertSystemObservationRBAC(t, files)
	legacyDesired := m
	legacyDesired.BundleFormat = 2
	legacy := build(legacyDesired)
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
	// Export only synthetic manifests when running the real Flux inventory fixture.
	if root := os.Getenv("LIVEPEER_TEST_SYSTEM_OUTPUT"); root != "" {
		for stage, content := range map[string]map[string][]byte{"legacy": legacy, "active": files, "terminal": terminal} {
			for name, b := range content {
				path := filepath.Join(root, stage, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

// Exercise the actual rendered resource identities against the bootstrap grants,
// so adding a resource cannot silently make ownership migration wait forever.
func assertSystemObservationRBAC(t *testing.T, files map[string][]byte) {
	t.Helper()
	type rule struct {
		APIGroups     []string `yaml:"apiGroups"`
		Resources     []string `yaml:"resources"`
		ResourceNames []string `yaml:"resourceNames"`
		Verbs         []string `yaml:"verbs"`
	}
	type document struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string
		Metadata   struct{ Name, Namespace string }
		Rules      []rule
		Subjects   []struct{ Kind, Name, Namespace string }
		RoleRef    struct{ Kind, Name string } `yaml:"roleRef"`
	}
	decode := func(b []byte) []document {
		var result []document
		d := yaml.NewDecoder(bytes.NewReader(b))
		for {
			var o document
			if err := d.Decode(&o); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			if o.Kind != "" {
				result = append(result, o)
			}
		}
		return result
	}
	b, err := os.ReadFile("../../../../runtime/manifests/bootstrap/rbac.yaml")
	if err != nil {
		t.Fatal(err)
	}
	docs := decode(b)
	grants := map[string]bool{}
	for _, d := range docs {
		if d.Kind != "RoleBinding" && d.Kind != "ClusterRoleBinding" {
			continue
		}
		for _, subject := range d.Subjects {
			if subject.Kind == "ServiceAccount" && subject.Name == "livepeer-http-source" && subject.Namespace == "flux-system" {
				ns := d.Metadata.Namespace
				if d.RoleRef.Kind == "ClusterRole" {
					ns = ""
				}
				grants[ns+"/"+d.RoleRef.Kind+"/"+d.RoleRef.Name] = true
			}
		}
	}
	plurals := map[string]string{"Namespace": "namespaces", "PersistentVolume": "persistentvolumes", "PersistentVolumeClaim": "persistentvolumeclaims", "ConfigMap": "configmaps", "Deployment": "deployments", "Service": "services", "ServiceAccount": "serviceaccounts", "NetworkPolicy": "networkpolicies", "Role": "roles", "RoleBinding": "rolebindings", "ClusterRole": "clusterroles", "ClusterRoleBinding": "clusterrolebindings", "CustomResourceDefinition": "customresourcedefinitions"}
	contains := func(values []string, want string) bool {
		for _, v := range values {
			if v == want || v == "*" {
				return true
			}
		}
		return false
	}
	for name, b := range files {
		if !strings.HasPrefix(name, "system/") || strings.HasSuffix(name, "/kustomization.yaml") {
			continue
		}
		for _, o := range decode(b) {
			group, _, found := strings.Cut(o.APIVersion, "/")
			if !found {
				group = ""
			}
			allowed := false
			for _, role := range docs {
				if !grants[role.Metadata.Namespace+"/"+role.Kind+"/"+role.Metadata.Name] || (role.Kind == "Role" && role.Metadata.Namespace != o.Metadata.Namespace) {
					continue
				}
				for _, r := range role.Rules {
					if contains(r.APIGroups, group) && contains(r.Resources, plurals[o.Kind]) && contains(r.Verbs, "get") && (len(r.ResourceNames) == 0 || contains(r.ResourceNames, o.Metadata.Name)) {
						allowed = true
					}
				}
			}
			if !allowed {
				t.Errorf("management agent cannot observe %s %s/%s", o.Kind, o.Metadata.Namespace, o.Metadata.Name)
			}
		}
	}
}

func TestSystemAndLegacyImagesHaveIndependentMigrationPins(t *testing.T) {
	manager := New(Config{Connector: ConnectorConfig{Image: "legacy", ManagedImage: "managed"}}, Dependencies{})
	if manager.Desired(Machine{}, State{BundleFormat: 2}, nil).Connector.Image != "legacy" {
		t.Fatal("new image broke a legacy connector")
	}
	if manager.Desired(Machine{}, State{BundleFormat: 3}, nil).Connector.Image != "managed" {
		t.Fatal("managed connector selected the legacy image")
	}
	manager = New(Config{}, Dependencies{})
	if manager.Desired(Machine{}, State{BundleFormat: 3, SystemConnectorImage: "saved"}, nil).Connector.Image != "saved" {
		t.Fatal("lost persisted connector image during retirement or config recovery")
	}
}
