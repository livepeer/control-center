package machineconfig

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/schema"
	"io/fs"
	"strings"
)

//go:embed templates
var templates embed.FS

func Build(m Desired) ([]byte, string, error) {
	if m.NodeImage != "" && !ValidConnectorImage(m.NodeImage) {
		return nil, "", fmt.Errorf("Node image is not pinned")
	}
	files := map[string][]byte{}
	err := fs.WalkDir(templates, "templates", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := templates.ReadFile(path)
		if err != nil {
			return err
		}
		data = []byte(renderMachineTemplate(string(data), m))
		if bytes.Contains(data, []byte("@INSTALL_DIR@")) || bytes.Contains(data, []byte("@NODE_ID@")) {
			return fmt.Errorf("unresolved template value")
		}
		files[strings.TrimPrefix(path, "templates/")] = data
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	if err = addRoutingBundle(files, m); err != nil {
		return nil, "", err
	}
	if m.BundleFormat >= 2 {
		if err := addManagedApps(files, m); err != nil {
			return nil, "", err
		}
	} else if m.Apps != nil {
		manifest, appsDigest, err := schema.AssignmentConfigMap(*m.Apps)
		if err != nil {
			return nil, "", err
		}
		files[schema.AppAssignmentsFile] = manifest
		// Add to resources before the existing patches section.
		files["kustomization.yaml"] = []byte(strings.Replace(string(files["kustomization.yaml"]), "patches:", "- "+schema.AppAssignmentsFile+"\npatches:", 1))
		var runtime Runtime
		if err := json.Unmarshal(files["runtime.json"], &runtime); err != nil {
			return nil, "", err
		}
		runtime.AppsGeneration, runtime.AppsDigest = m.Apps.Generation, appsDigest
		files["runtime.json"], err = json.Marshal(runtime)
		if err != nil {
			return nil, "", err
		}
	}
	data, err := artifact.Pack(files)
	if err != nil {
		return nil, "", err
	}
	return data, strings.TrimPrefix(artifact.Digest(data), "sha256:"), nil
}
