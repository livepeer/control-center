package machineconfig

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/livepeer/control-center/runtime/contract"
)

// Telemetry manifests are added only for capable machines, unlike templates.
//
//go:embed telemetry
var telemetryTemplates embed.FS

// TelemetryHostFeature is the installed-software entry that bootstrap records
// after applying the telemetry management socket and http-source RBAC.
const TelemetryHostFeature = "host-telemetry"

func telemetryActive(m Desired) bool {
	return m.TelemetryEnabled && m.TelemetryCapable && !m.Terminal
}

// TelemetryCapable reports whether a runtime report names the telemetry host
// feature. Older bootstraps lack the socket and RBAC the agent needs.
func TelemetryCapable(software []contract.SoftwareIdentity) bool {
	for _, s := range software {
		if s.Component == TelemetryHostFeature && s.Scope == "installed" {
			if version, err := strconv.Atoi(s.Version); err == nil && version >= 1 {
				return true
			}
		}
	}
	return false
}

func addTelemetry(files map[string][]byte, m Desired) error {
	if !telemetryActive(m) {
		return nil
	}
	appLogs := ""
	if m.TelemetryAppLogs {
		input, err := telemetryTemplates.ReadFile("telemetry/app-logs.conf")
		if err != nil {
			return err
		}
		appLogs = string(input)
	}
	return fs.WalkDir(telemetryTemplates, "telemetry", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || path == "telemetry/app-logs.conf" {
			return err
		}
		data, err := telemetryTemplates.ReadFile(path)
		if err != nil {
			return err
		}
		// App container output is collected only while TelemetryAppLogs allows it.
		data = []byte(templateValues(m).Replace(strings.ReplaceAll(string(data), "@APP_LOGS_INPUT@\n", appLogs)))
		if bytes.Contains(data, []byte("@INSTALL_DIR@")) || bytes.Contains(data, []byte("@NODE_ID@")) || bytes.Contains(data, []byte("@RUNTIME_IMAGE@")) || bytes.Contains(data, []byte("@APP_LOGS_INPUT@")) {
			return fmt.Errorf("unresolved telemetry template value")
		}
		files["system/"+path] = data
		return nil
	})
}

// telemetryNodeIngress admits the telemetry agent to Node's metrics port.
func telemetryNodeIngress() string {
	return `  - from:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: livepeer-telemetry}}
      podSelector: {matchLabels: {app: livepeer-telemetry-agent}}
    ports: [{protocol: TCP, port: 8936}]
`
}
