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
	body, block := telemetryWriteLimits(m.TelemetryMaxBody)
	limits := strings.NewReplacer("@TELEMETRY_MAX_BODY@", strconv.FormatInt(body, 10), "@TELEMETRY_BLOCK_BYTES@", strconv.FormatInt(block, 10))
	return fs.WalkDir(telemetryTemplates, "telemetry", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || path == "telemetry/app-logs.conf" {
			return err
		}
		data, err := telemetryTemplates.ReadFile(path)
		if err != nil {
			return err
		}
		// App container output is collected only while TelemetryAppLogs allows it.
		data = []byte(limits.Replace(templateValues(m).Replace(strings.ReplaceAll(string(data), "@APP_LOGS_INPUT@\n", appLogs))))
		for _, value := range []string{"@INSTALL_DIR@", "@NODE_ID@", "@RUNTIME_IMAGE@", "@CONTROL_TRANSPORT@", "@APP_LOGS_INPUT@", "@TELEMETRY_MAX_BODY@", "@TELEMETRY_BLOCK_BYTES@"} {
			if bytes.Contains(data, []byte(value)) {
				return fmt.Errorf("unresolved telemetry template value")
			}
		}
		files["system/"+path] = data
		return nil
	})
}

const (
	defaultTelemetryMaxBody = 8 << 20
	maxTelemetryBlock       = 4_000_000
	// Compression and framing can add a little to a full block.
	telemetryBlockMargin = 64 << 10
)

// telemetryWriteLimits returns the relay's body limit and vmagent's largest
// uncompressed block for Control Center's ingest limit. vmagent splits larger
// blocks, so a compressed write never exceeds the limit.
func telemetryWriteLimits(maxBody int64) (body, block int64) {
	if maxBody <= 0 {
		maxBody = defaultTelemetryMaxBody
	}
	return maxBody, min(maxTelemetryBlock, maxBody-telemetryBlockMargin)
}

// telemetryNodeIngress admits the telemetry agent to Node's metrics port.
func telemetryNodeIngress() string {
	return `  - from:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: livepeer-telemetry}}
      podSelector: {matchLabels: {app: livepeer-telemetry-agent}}
    ports: [{protocol: TCP, port: 8936}]
`
}
