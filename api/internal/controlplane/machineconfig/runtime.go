package machineconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/livepeer/control-center/runtime/contract"
	"regexp"
	"strings"
)

func routeEnabled(m Desired) bool {
	return !m.Terminal && m.Exposure != nil && m.Exposure.IngressDigest != "" && (m.State.Lifecycle == "active" || m.State.Lifecycle == "draining")
}
func templateValues(m Desired) *strings.Replacer {
	service, proxy := PrivateOrchestrator, ""
	if routeEnabled(m) {
		service = m.Exposure.ServiceURL
		proxy = m.Exposure.ProxyURLTemplate
	}
	return strings.NewReplacer("@NODE_ID@", m.NodeID, "@INSTALL_DIR@", m.InstallDir, "@K3S_VERSION@", m.K3sVersion, "@SERVICE_URL@", service, "@PROXY_URL_TEMPLATE@", proxy)
}
func orchestratorConfiguration(m Desired) string {
	if m.State.HeldOrchestrator != "" {
		return configurationFromManifest(m.State.HeldOrchestrator)
	}
	b, _ := templates.ReadFile("templates/orchestrator.yaml")
	s := specializeNode(templateValues(m).Replace(string(b)), m)
	return configurationFromManifest(s)
}
func configurationFromManifest(s string) string {
	_, body, _ := strings.Cut(s, "  orchestrator.toml: |\n")
	body, _, _ = strings.Cut(body, "\n---")
	lines := strings.Split(body, "\n")
	for i := range lines {
		lines[i] = strings.TrimPrefix(lines[i], "    ")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
}
func Digest(m Desired) string {
	if m.BundleFormat >= 2 || m.NodeImage != "" {
		b, _ := templates.ReadFile("templates/orchestrator.yaml")
		manifest := specializeNode(templateValues(m).Replace(string(b)), m)
		if m.State.HeldOrchestrator != "" {
			manifest = m.State.HeldOrchestrator
		}
		manifest = regexp.MustCompile(`livepeer.io/config-sha256: '[^']*'`).ReplaceAllString(manifest, "livepeer.io/config-sha256: '@ORCHESTRATOR_DIGEST@'")
		plan, _ := templates.ReadFile("templates/upgrade-plan/plan.yaml")
		upgrade := renderMachineTemplateWithoutDigest(string(plan), m)
		if m.State.HeldUpgradePlan != "" {
			upgrade = m.State.HeldUpgradePlan
		}
		h := sha256.Sum256([]byte(manifest + "\n" + upgrade))
		return hex.EncodeToString(h[:])
	}
	h := sha256.Sum256([]byte(orchestratorConfiguration(m)))
	return hex.EncodeToString(h[:])
}
func upgradeVersion(m Desired) string {
	b, _ := templates.ReadFile("templates/upgrade-plan/plan.yaml")
	plan := renderMachineTemplateWithoutDigest(string(b), m)
	if m.State.HeldUpgradePlan != "" {
		plan = m.State.HeldUpgradePlan
	}
	match := regexp.MustCompile(`(?m)^  version: '([^']+)'$`).FindStringSubmatch(plan)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}
func specializeNode(raw string, m Desired) string {
	if m.BundleFormat >= 2 {
		raw = strings.Replace(raw, "RunnerGrants = []", `RunnerGrants = ["10.43.0.0/16"]`, 1)
	}
	if m.NodeImage != "" {
		raw = regexp.MustCompile(`(?m)^        image: ghcr.io/livepeer/node:[^\n]+`).ReplaceAllString(raw, "        image: "+m.NodeImage)
	}
	return raw
}
func renderMachineTemplateWithoutDigest(raw string, m Desired) string {
	return specializeNode(templateValues(m).Replace(raw), m)
}
func renderMachineTemplate(raw string, m Desired) string {
	return strings.ReplaceAll(renderMachineTemplateWithoutDigest(raw, m), "@ORCHESTRATOR_DIGEST@", Digest(m))
}

type Runtime = contract.Metadata

func DesiredRuntime(m Desired) Runtime {
	d := Runtime{NodeID: m.NodeID, Epoch: m.Epoch, CredentialVersion: m.CredentialVersion, Generation: 1, Terminal: m.Terminal, ConfigDigest: Digest(m), ServiceURL: PrivateOrchestrator, APIURL: m.ControlAPIURL}
	d.RunnerServiceURL = PrivateOrchestrator
	d.Generation = max(m.State.Generation, 1)
	d.DrainRequested = m.State.DrainRequested
	d.BundleFormat = m.BundleFormat
	if m.BundleFormat >= 2 {
		d.UpgradeVersion = upgradeVersion(m)
	}
	d.AppsError = m.AppsError
	d.RequestedAppsGeneration = m.RequestedAppsGeneration
	d.DrainStartedAt = m.State.DrainStartedAt
	if d.DrainRequested {
		d.DrainTarget = DrainTarget(m.NodeID, m.Epoch, m.State)
		if m.DrainTimeout > 0 {
			d.DrainDeadline = m.State.DrainStartedAt.Add(m.DrainTimeout)
		}
	}
	if routeEnabled(m) {
		r := m.Exposure
		d.ServiceURL = r.ServiceURL
		d.TunnelID = r.TunnelID
		d.TokenGeneration = r.CredentialGeneration
		d.ProviderVersion = r.ProviderVersion
		d.ProxyURLTemplate = r.ProxyURLTemplate
		d.DiscoveryURL = r.DiscoveryURL
		d.IngressDigest = r.IngressDigest
		d.ConnectorTokenRef = "/v1/nodes/" + m.NodeID + "/tunnel/connector-token"
	}
	return d
}
func addRoutingBundle(files map[string][]byte, m Desired) error {
	if !m.Terminal && m.State.HeldOrchestrator != "" {
		files["orchestrator.yaml"] = []byte(m.State.HeldOrchestrator)
	}
	if !m.Terminal && m.State.HeldUpgradePlan != "" {
		files["upgrade-plan/plan.yaml"] = []byte(m.State.HeldUpgradePlan)
	}
	d := DesiredRuntime(m)
	b, e := json.Marshal(d)
	if e != nil {
		return e
	}
	files["runtime.json"] = b
	if m.Terminal {
		docs := strings.Split(string(files["orchestrator.yaml"]), "\n---\n")
		if len(docs) < 3 {
			return fmt.Errorf("missing retained orchestrator storage")
		}
		files["orchestrator.yaml"] = []byte(strings.Join(docs[:3], "\n---\n") + "\n")
		files["upgrade-plan/kustomization.yaml"] = []byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: []\n")
		delete(files, "upgrade-plan/plan.yaml")
		return nil
	}
	if !routeEnabled(m) {
		return nil
	}
	if !ValidConnectorImage(m.Connector.Image) {
		return fmt.Errorf("connector image is not pinned")
	}
	routingJSON, e := json.MarshalIndent(d, "", "  ")
	if e != nil {
		return e
	}
	files["tunnel.yaml"] = []byte(tunnelManifest(m, string(routingJSON)))
	files["tunnel-network.yaml"] = []byte(tunnelNetwork(m))
	files["kustomization.yaml"] = []byte(strings.Replace(string(files["kustomization.yaml"]), "- orchestrator.yaml", "- orchestrator.yaml\n- tunnel.yaml\n- tunnel-network.yaml", 1))
	return nil
}
