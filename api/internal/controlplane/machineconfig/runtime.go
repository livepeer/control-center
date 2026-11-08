package machineconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	s := templateValues(m).Replace(string(b))
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
	h := sha256.Sum256([]byte(orchestratorConfiguration(m)))
	return hex.EncodeToString(h[:])
}
func renderMachineTemplate(raw string, m Desired) string {
	return strings.ReplaceAll(templateValues(m).Replace(raw), "@ORCHESTRATOR_DIGEST@", Digest(m))
}

type Runtime struct {
	NodeID            string `json:"node_id"`
	Epoch             string `json:"epoch"`
	CredentialVersion int64  `json:"credential_version"`
	Generation        int64  `json:"generation"`
	Terminal          bool   `json:"terminal"`
	DrainRequested    bool   `json:"drain_requested"`
	ConfigDigest      string `json:"config_digest"`
	ServiceURL        string `json:"service_url"`
	TunnelID          string `json:"tunnel_id"`
	TokenGeneration   int64  `json:"credential_generation"`
	ProviderVersion   int64  `json:"provider_version"`
	APIURL            string `json:"api_url"`
	RunnerServiceURL  string `json:"runner_service_url"`
	ProxyURLTemplate  string `json:"proxy_url_template"`
	DiscoveryURL      string `json:"discovery_url"`
	IngressDigest     string `json:"ingress_digest"`
	AppsGeneration    int64  `json:"apps_generation,omitempty"`
	AppsDigest        string `json:"apps_digest,omitempty"`
	ConnectorTokenRef string `json:"connector_token_ref"`
}

func DesiredRuntime(m Desired) Runtime {
	d := Runtime{NodeID: m.NodeID, Epoch: m.Epoch, CredentialVersion: m.CredentialVersion, Generation: 1, Terminal: m.Terminal, ConfigDigest: Digest(m), ServiceURL: PrivateOrchestrator, APIURL: m.ControlAPIURL}
	d.RunnerServiceURL = PrivateOrchestrator
	d.Generation = max(m.State.Generation, 1)
	d.DrainRequested = m.State.DrainRequested
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
