package httpsource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
	"go.yaml.in/yaml/v3"
)

var systemComponents = []string{"node", "connector", "app-reconciler", "upgrade-controller"}

type manifestObject struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name        string            `yaml:"name"`
		Namespace   string            `yaml:"namespace"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	data []byte
	file string
}

func (o manifestObject) id() string {
	group, _, found := strings.Cut(o.APIVersion, "/")
	if !found {
		group = ""
	}
	return o.Metadata.Namespace + "_" + o.Metadata.Name + "_" + group + "_" + o.Kind
}

// Only inspect the identities in centrally rendered local resource files. This
// does not render templates or interpret patches; those stay with Kustomize.
func manifestObjects(files map[string][]byte, directory string) ([]manifestObject, error) {
	var result []manifestObject
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		if depth > 8 {
			return errors.New("transfer_resource_depth")
		}
		var k struct {
			Resources []string `yaml:"resources"`
		}
		config, ok := files[path.Join(dir, "kustomization.yaml")]
		if !ok {
			return errors.New("transfer_kustomization_missing")
		}
		if err := yaml.Unmarshal(config, &k); err != nil {
			return err
		}
		for _, resource := range k.Resources {
			name := path.Join(dir, resource)
			if strings.Contains(resource, ":") || strings.HasPrefix(resource, "/") || strings.HasPrefix(name, "../") {
				return errors.New("transfer_resource_path")
			}
			if _, ok := files[path.Join(name, "kustomization.yaml")]; ok {
				if err := walk(name, depth+1); err != nil {
					return err
				}
				continue
			}
			b, ok := files[name]
			if !ok {
				return fmt.Errorf("transfer_resource_missing: %s", name)
			}
			d := yaml.NewDecoder(bytes.NewReader(b))
			for {
				var node yaml.Node
				if err := d.Decode(&node); err == io.EOF {
					break
				} else if err != nil {
					return err
				}
				var o manifestObject
				if err := node.Decode(&o); err != nil {
					return err
				}
				if o.Kind == "" {
					continue
				}
				if o.Metadata.Name == "" || o.APIVersion == "" {
					return errors.New("transfer_resource_identity")
				}
				o.data, _ = yaml.Marshal(&node)
				o.file = name
				result = append(result, o)
			}
		}
		return nil
	}
	if err := walk(directory, 0); err != nil {
		return nil, err
	}
	return result, nil
}

func kustomization(resources ...string) []byte {
	b, _ := yaml.Marshal(map[string]any{"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization", "resources": resources})
	return b
}

func copyFiles(files map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(files))
	for n, b := range files {
		out[n] = b
	}
	return out
}

func addRetained(files map[string][]byte, dir string, objects []manifestObject) error {
	if len(objects) == 0 {
		return nil
	}
	var k map[string]any
	if err := yaml.Unmarshal(files[path.Join(dir, "kustomization.yaml")], &k); err != nil {
		return err
	}
	var b []byte
	for _, o := range objects {
		b = append(b, []byte("---\n")...)
		b = append(b, o.data...)
	}
	files[path.Join(dir, "retained.yaml")] = b
	resources, _ := k["resources"].([]any)
	k["resources"] = append(resources, "retained.yaml")
	var err error
	files[path.Join(dir, "kustomization.yaml")], err = yaml.Marshal(k)
	return err
}

func legacyComponent(o manifestObject) string {
	if o.Kind == "ConfigMap" && o.Metadata.Namespace == "livepeer" && o.Metadata.Name == "livepeer-app-assignments" {
		return "node"
	}
	switch path.Base(o.file) {
	case "orchestrator.yaml":
		return "node"
	case "tunnel.yaml":
		return "connector"
	case "tunnel-network.yaml":
		if o.Metadata.Name == "orchestrator-private" {
			return "node"
		}
		return "connector"
	case "suc.yaml", "suc-crd.yaml":
		return "upgrade-controller"
	}
	return ""
}

// Capture both applied and in-flight legacy input before changing ownership.
// Omitted resources are retained until a child owns them and can prune them.
func (s *Source) freezeTransfer(ctx context.Context, files map[string][]byte, m contract.Metadata, root fluxState) (map[string][]byte, error) {
	frozen := map[string][]byte{"kustomization.yaml": kustomization()}
	known := map[string]string{}
	for _, component := range systemComponents {
		dir := "system/" + component
		objects, err := manifestObjects(files, dir)
		if err != nil {
			return nil, err
		}
		for _, o := range objects {
			known[o.id()] = component
		}
		for name, b := range files {
			if strings.HasPrefix(name, dir+"/") {
				frozen[".system-transfer/"+strings.TrimPrefix(name, "system/")] = b
			}
		}
	}
	current, err := manifestObjects(files, "")
	if err != nil {
		return nil, err
	}
	for _, o := range current {
		if _, ok := known[o.id()]; !ok {
			known[o.id()] = "parent"
		}
	}
	var source struct {
		Status struct {
			Artifact *transport.Artifact `json:"artifact"`
		} `json:"status"`
	}
	if err = s.Kube.Request(ctx, http.MethodGet, "/apis/source.toolkit.fluxcd.io/v1/namespaces/flux-system/externalartifacts/"+SourceName, nil, &source); err != nil {
		return nil, err
	}
	digests := []string{root.Status.LastAppliedRevision, root.Status.LastAttemptedRevision}
	if source.Status.Artifact != nil {
		digests = append(digests, source.Status.Artifact.Revision)
	}
	retained := map[string][]manifestObject{}
	covered := map[string]bool{}
	for _, digest := range digests {
		if digest == "" {
			continue
		}
		data, err := s.Store.Get(digest)
		if err != nil {
			return nil, errors.New("transfer_previous_archive_unavailable")
		}
		prior, err := artifact.Read(data)
		if err != nil {
			return nil, err
		}
		old, err := transport.ReadMetadata(prior["runtime.json"])
		if err != nil || old.NodeID != m.NodeID || old.Epoch != m.Epoch {
			return nil, errors.New("transfer_previous_enrollment")
		}
		objects, err := manifestObjects(prior, "")
		if err != nil {
			return nil, err
		}
		for _, o := range objects {
			covered[o.id()] = true
			if _, ok := known[o.id()]; ok {
				continue
			}
			component := legacyComponent(o)
			if component == "" {
				return nil, errors.New("transfer_unclassified_legacy_resource")
			}
			known[o.id()] = component
			retained[component] = append(retained[component], o)
		}
	}
	for _, entry := range root.Status.Inventory.Entries {
		if !covered[entry.ID] {
			return nil, errors.New("transfer_inventory_definition_missing")
		}
	}
	for _, component := range systemComponents {
		if err = addRetained(frozen, ".system-transfer/"+component, retained[component]); err != nil {
			return nil, err
		}
	}
	return frozen, nil
}

func inventoryContains(k fluxState, id string) bool {
	for _, e := range k.Status.Inventory.Entries {
		if e.ID == id {
			return true
		}
	}
	return false
}

func (o manifestObject) apiPath() (string, error) {
	resources := map[string]string{"Namespace": "namespaces", "PersistentVolume": "persistentvolumes", "PersistentVolumeClaim": "persistentvolumeclaims", "ConfigMap": "configmaps", "Deployment": "deployments", "Service": "services", "ServiceAccount": "serviceaccounts", "NetworkPolicy": "networkpolicies", "Role": "roles", "RoleBinding": "rolebindings", "ClusterRole": "clusterroles", "ClusterRoleBinding": "clusterrolebindings", "CustomResourceDefinition": "customresourcedefinitions"}
	resource := resources[o.Kind]
	if resource == "" {
		return "", errors.New("transfer_unknown_resource")
	}
	prefix := "/apis/" + o.APIVersion
	if o.APIVersion == "v1" {
		prefix = "/api/v1"
	}
	if o.Metadata.Namespace != "" {
		prefix += "/namespaces/" + o.Metadata.Namespace
	}
	return prefix + "/" + resource + "/" + o.Metadata.Name, nil
}

// Inventory membership alone cannot establish unique ownership: verify Flux's
// labels on the actual resource as well. Workload health is deliberately unused.
func (s *Source) transferred(ctx context.Context, root fluxState, frozen map[string][]byte) bool {
	for _, component := range systemComponents {
		objects, err := manifestObjects(frozen, ".system-transfer/"+component)
		if err != nil {
			return false
		}
		var child fluxState
		name := "livepeer-" + component
		if s.Kube.Request(ctx, http.MethodGet, fluxPath+name, nil, &child) != nil {
			return false
		}
		for _, o := range objects {
			if inventoryContains(root, o.id()) || !inventoryContains(child, o.id()) || !s.objectOwned(ctx, o, name) {
				return false
			}
		}
	}
	return true
}

func (s *Source) objectOwned(ctx context.Context, o manifestObject, name string) bool {
	p, err := o.apiPath()
	if err != nil {
		return false
	}
	var actual struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	return s.Kube.Request(ctx, http.MethodGet, p, nil, &actual) == nil && actual.Metadata.Labels["kustomize.toolkit.fluxcd.io/name"] == name && actual.Metadata.Labels["kustomize.toolkit.fluxcd.io/namespace"] == "flux-system"
}

func transferResources() []string {
	resources := []string{"management"}
	for _, c := range systemComponents {
		resources = append(resources, ".system-transfer/"+c)
	}
	return resources
}

// The definitions are centrally rendered; adoption changes only their input path
// and health wait. Upgrade-plan keeps its real CRD/controller prerequisite.
func adoptionDefinitions(b []byte) []byte {
	text := string(b)
	for _, c := range systemComponents {
		text = strings.ReplaceAll(text, "path: ./system/"+c+"\n", "path: ./.system-transfer/"+c+"\n")
	}
	return []byte(strings.ReplaceAll(text, "wait: true", "wait: false"))
}
