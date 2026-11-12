package machineconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/payment"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
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
	mode := "https"
	if strings.HasPrefix(m.ControlAPIURL, "http://") {
		mode = "development-http"
	}
	return strings.NewReplacer("@RUNTIME_IMAGE@", m.RuntimeImage, "@CONTROL_TRANSPORT@", mode, "@NODE_ID@", m.NodeID, "@ENROLLMENT_EPOCH@", m.Epoch, "@MANAGEMENT_CREDENTIAL_VERSION@", fmt.Sprint(m.CredentialVersion), "@INSTALL_DIR@", m.InstallDir, "@K3S_VERSION@", m.K3sVersion, "@SERVICE_URL@", service, "@PROXY_URL_TEMPLATE@", proxy)
}
func orchestratorConfiguration(m Desired) string {
	if m.State.HeldOrchestrator != "" {
		return configurationFromManifest(m.State.HeldOrchestrator)
	}
	b, _ := templates.ReadFile("templates/system/node/orchestrator.yaml")
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
	b, _ := templates.ReadFile("templates/system/node/orchestrator.yaml")
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
	timeout := 12 * time.Hour
	if m.NodeDrainTimeout != nil {
		timeout = *m.NodeDrainTimeout
	}
	raw = specializePayment(raw, m)
	raw = strings.ReplaceAll(raw, "@NODE_DRAIN_TIMEOUT@", timeout.String())
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
	d.Payment = effectivePayment(m)
	if d.Payment.Version == 0 {
		d.Payment = payment.Offchain()
	}
	d.PaymentActive = !m.State.DrainRequested && m.State.ApplyingConfigDigest == "" && (!d.Payment.Onchain() || (m.PaymentReady && m.State.ApprovedConfigDigest == d.ConfigDigest))
	if d.Payment.Onchain() {
		d.PaymentCredentialsRef = "/v1/nodes/" + m.NodeID + "/payment/credentials"
	}
	d.RunnerServiceURL = PrivateOrchestrator
	d.Generation = max(m.State.Generation, 1)
	d.DrainRequested = m.State.DrainRequested
	d.BundleFormat = contract.BundleFormat
	d.UpgradeVersion = upgradeVersion(m)
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
		files["system/node/orchestrator.yaml"] = []byte(m.State.HeldOrchestrator)
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
		docs := strings.Split(string(files["system/node/orchestrator.yaml"]), "\n---\n")
		if len(docs) < 3 {
			return fmt.Errorf("missing retained orchestrator storage")
		}
		files["system/node/orchestrator.yaml"] = []byte(strings.Join(docs[:3], "\n---\n") + "\n")
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
	if !ValidConnectorImage(m.RuntimeImage) {
		return fmt.Errorf("Node proxy Runtime image is not pinned")
	}
	var node struct{ ServiceURL, ProxyURLTemplate string }
	if _, err := toml.Decode(orchestratorConfiguration(m), &node); err != nil || node.ServiceURL == "" {
		return fmt.Errorf("invalid effective Node routing configuration")
	}
	files["system/connector/tunnel.yaml"] = []byte(managedTunnelManifest(m, nodeProxyContainer(m, node.ServiceURL, node.ProxyURLTemplate)))
	files["system/connector/network.yaml"] = []byte(tunnelNetwork(m))
	return nil
}
