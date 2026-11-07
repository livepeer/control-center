package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

func routeEnabled(m Machine) bool {
	return !m.Terminal && m.Routing != nil && m.Routing.IngressDigest != "" && (m.Routing.Lifecycle == "active" || m.Routing.Lifecycle == "draining")
}
func templateValues(m Machine) *strings.Replacer {
	service, proxy := privateOrchestrator, ""
	if routeEnabled(m) {
		service = m.Routing.ServiceURL
		proxy = m.Routing.ProxyURLTemplate
	}
	return strings.NewReplacer("@NODE_ID@", m.NodeID, "@INSTALL_DIR@", m.InstallDir, "@K3S_VERSION@", m.K3sVersion, "@SERVICE_URL@", service, "@PROXY_URL_TEMPLATE@", proxy)
}
func orchestratorConfiguration(m Machine) string {
	if m.Routing != nil && m.Routing.HeldOrchestrator != "" {
		return configurationFromManifest(m.Routing.HeldOrchestrator)
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
func orchestratorDigest(m Machine) string {
	h := sha256.Sum256([]byte(orchestratorConfiguration(m)))
	return hex.EncodeToString(h[:])
}
func renderMachineTemplate(raw string, m Machine) string {
	return strings.ReplaceAll(templateValues(m).Replace(raw), "@ORCHESTRATOR_DIGEST@", orchestratorDigest(m))
}

type runtimeDesired struct {
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
	ConnectorTokenRef string `json:"connector_token_ref"`
}

func desiredRuntime(m Machine) runtimeDesired {
	d := runtimeDesired{NodeID: m.NodeID, Epoch: m.Epoch, CredentialVersion: m.CredentialVersion, Generation: 1, Terminal: m.Terminal, ConfigDigest: orchestratorDigest(m), ServiceURL: privateOrchestrator, APIURL: m.ControlAPIURL}
	d.RunnerServiceURL = privateOrchestrator
	if m.Routing != nil {
		d.Generation = m.Routing.Generation
		d.DrainRequested = m.Routing.DrainRequested
	}
	if routeEnabled(m) {
		r := m.Routing
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
func addRoutingBundle(files map[string][]byte, m Machine) error {
	if !m.Terminal && m.Routing != nil && m.Routing.HeldOrchestrator != "" {
		files["orchestrator.yaml"] = []byte(m.Routing.HeldOrchestrator)
	}
	d := desiredRuntime(m)
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
	if m.TunnelConfig == nil || !imageDigestPattern.MatchString(m.TunnelConfig.CloudflareConnectorImage) {
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
func tunnelManifest(m Machine, routing string) string {
	image := m.TunnelConfig.CloudflareConnectorImage
	return fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: livepeer-tunnel
  namespace: flux-system
data:
  routing.json: |
    %s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: livepeer-tunnel
  namespace: flux-system
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: livepeer-tunnel
  template:
    metadata:
      labels:
        app: livepeer-tunnel
      annotations:
        livepeer.io/token-generation: '%d'
        livepeer.io/process-image: '%s'
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: broker
        image: %s
        command: [python3, -B, /app/tunnel_broker.py]
        args: [--config, /config/routing.json, --token-file, /credentials/token, --socket, /broker/private/token.sock]
        resources:
          requests: {cpu: 25m, memory: 32Mi}
          limits: {memory: 128Mi}
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities: {drop: [ALL]}
        volumeMounts:
        - {name: config, mountPath: /config, readOnly: true}
        - {name: machine, mountPath: /credentials, readOnly: true}
        - {name: socket, mountPath: /broker}
      - name: connector
        image: %s
        command: [python3, -B, /app/tunnel_launcher.py]
        args: [--socket, /broker/private/token.sock, --token-path, /run/tunnel/private/token]
        resources:
          requests: {cpu: 50m, memory: 64Mi}
          limits: {memory: 256Mi}
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities: {drop: [ALL]}
        readinessProbe:
          exec:
            command: [python3, -c, "import urllib.request; urllib.request.urlopen('http://127.0.0.1:20241/ready',timeout=2)"]
        volumeMounts:
        - {name: socket, mountPath: /broker, readOnly: true}
        - {name: token, mountPath: /run/tunnel}
      volumes:
      - name: config
        configMap: {name: livepeer-tunnel}
      - name: machine
        secret: {secretName: livepeer-service-auth, defaultMode: 288}
      - name: socket
        emptyDir: {medium: Memory, sizeLimit: 1Mi}
      - name: token
        emptyDir: {medium: Memory, sizeLimit: 1Mi}
`, strings.ReplaceAll(routing, "\n", "\n    "), m.Routing.CredentialGeneration, image, image, image)
}
func tunnelNetwork(m Machine) string {
	v4 := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"}
	v6 := []string{"::/3", "4000::/2", "8000::/1", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"}
	for _, raw := range m.TunnelConfig.TunnelNodeAddresses {
		p, e := netip.ParsePrefix(raw)
		if e != nil {
			continue
		}
		if p.Addr().Is4() {
			v4 = append(v4, p.Masked().String())
		} else {
			v6 = append(v6, p.Masked().String())
		}
	}
	list := func(v []string) string { b, _ := json.Marshal(v); return string(b) }
	result := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: livepeer-tunnel, namespace: flux-system}
spec:
  podSelector: {matchLabels: {app: livepeer-tunnel}}
  policyTypes: [Ingress, Egress]
  ingress: []
  egress:
  - to:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}
      podSelector: {matchLabels: {k8s-app: kube-dns}}
    ports: [{protocol: UDP, port: 53}, {protocol: TCP, port: 53}]
  - to:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: livepeer}}
      podSelector: {matchLabels: {app: orchestrator}}
    ports: [{protocol: TCP, port: 8935}]
  - to:
    - ipBlock: {cidr: 0.0.0.0/0, except: %s}
    - ipBlock: {cidr: '::/0', except: %s}
    ports: [{protocol: TCP, port: 443}, {protocol: TCP, port: 7844}, {protocol: UDP, port: 7844}]
`, list(v4), list(v6))
	for _, cidr := range m.TunnelConfig.TunnelPrivateControlCIDRs {
		result += fmt.Sprintf("  - to:\n    - ipBlock: {cidr: %q}\n    ports: [{protocol: TCP, port: 443}]\n", cidr)
	}
	result += `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: orchestrator-private, namespace: livepeer}
spec:
  podSelector: {matchLabels: {app: orchestrator}}
  policyTypes: [Ingress]
  ingress:
  - from:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: flux-system}}
      podSelector: {matchLabels: {app: livepeer-tunnel}}
    ports: [{protocol: TCP, port: 8935}]
  - from:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: flux-system}}
      podSelector: {matchLabels: {app: livepeer-http-source}}
    ports: [{protocol: TCP, port: 8935}, {protocol: TCP, port: 8936}]
  - from:
    - podSelector: {matchLabels: {livepeer.io/runner-control: 'true'}}
    ports: [{protocol: TCP, port: 8935}]
  - from:
    - podSelector: {matchLabels: {app: livepeer-gvisor-smoke}}
    ports: [{protocol: TCP, port: 8935}, {protocol: TCP, port: 8936}]
`
	return result
}
