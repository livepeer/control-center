package machineconfig

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/payment"
	"io/fs"
	"strings"
	"time"
)

//go:embed templates
var templates embed.FS

func Build(m Desired) ([]byte, string, error) {
	if m.NodeDrainTimeout != nil && (*m.NodeDrainTimeout < 0 || *m.NodeDrainTimeout > 12*time.Hour) {
		return nil, "", fmt.Errorf("Node drain timeout must be between zero and 12h")
	}
	if m.NodeImage != "" && !ValidConnectorImage(m.NodeImage) {
		return nil, "", fmt.Errorf("Node image is not pinned")
	}
	if m.PaymentError != nil {
		return nil, "", m.PaymentError
	}
	if m.Payment.Version == 0 {
		m.Payment = payment.Offchain()
	}
	if m.State.HeldOrchestrator != "" && m.State.HeldPayment != "" {
		var held payment.Config
		if json.Unmarshal([]byte(m.State.HeldPayment), &held) != nil {
			return nil, "", fmt.Errorf("invalid held payment identity")
		}
		if held.Version != 0 {
			if err := held.Validate(); err != nil {
				return nil, "", err
			}
		}
	}
	if err := m.Payment.Validate(); err != nil {
		return nil, "", err
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
	if err := addManagedApps(files, m); err != nil {
		return nil, "", err
	}
	if err = addSystemWorkloads(files, m); err != nil {
		return nil, "", err
	}
	data, err := artifact.Pack(files)
	if err != nil {
		return nil, "", err
	}
	return data, strings.TrimPrefix(artifact.Digest(data), "sha256:"), nil
}
