package machineconfig

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

func tunnelManifest(m Desired, routing string) string {
	image := m.Connector.Image
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
`, strings.ReplaceAll(routing, "\n", "\n    "), m.Exposure.CredentialGeneration, image, image, image)
}
func tunnelNetwork(m Desired) string {
	v4 := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"}
	v6 := []string{"::/3", "4000::/2", "8000::/1", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"}
	for _, raw := range m.Connector.NodeAddresses {
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
	for _, cidr := range m.Connector.PrivateControlCIDRs {
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
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: flux-system}}
      podSelector: {matchLabels: {app: livepeer-app-reconciler}}
    ports: [{protocol: TCP, port: 8935}]
  - from:
    - podSelector: {matchLabels: {livepeer.io/runner-control: 'true'}}
    ports: [{protocol: TCP, port: 8935}]
  - from:
    - podSelector: {matchLabels: {app: livepeer-gvisor-smoke}}
    ports: [{protocol: TCP, port: 8935}, {protocol: TCP, port: 8936}]
`
	return result
}
