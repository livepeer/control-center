package machineconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/livepeer/control-center/runtime/ingressauth"
)

const PrivateIngressAPI = "http://traefik.kube-system.svc.cluster.local:8080"
const PrivateIngressDiscovery = "http://traefik.kube-system.svc.cluster.local:8081"
const PrivateIngressApps = "http://traefik.kube-system.svc.cluster.local:8082"

// Ingress inputs deliberately do not participate in Digest, which owns Node's
// drain/replacement lifecycle. They have an independent Flux inventory.
func (m Desired) IngressConfigDigest() string {
	if m.Terminal || m.Exposure == nil || m.Exposure.IngressVersion != 1 || m.Exposure.DiscoveryURL == "" || len(m.IngressPublicKeys) == 0 {
		return ""
	}
	data, _ := json.Marshal([]any{"ingress-v1", m.NodeID, m.Exposure.ServiceURL, m.Exposure.ProxyURLTemplate, m.RuntimeImage, string(m.IngressPublicKeys)})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func addIngress(files map[string][]byte, m Desired) error {
	files["system/ingress/kustomization.yaml"] = kustomize()
	if m.Terminal || m.Exposure == nil || m.Exposure.TunnelID == "" {
		return nil
	}
	if m.Exposure.IngressVersion != 1 {
		return fmt.Errorf("existing machine requires the separate ingress migration")
	}
	keys, err := ingressauth.ParseKeys(m.IngressPublicKeys)
	if err != nil {
		return err
	}
	u, err := url.Parse(strings.Replace(m.Exposure.ProxyURLTemplate, "{proxy}", "marker", 1))
	if err != nil || !strings.HasPrefix(u.Hostname(), "marker.") {
		return fmt.Errorf("invalid ingress app hostname")
	}
	appHost := "^[^.]+\\." + strings.ReplaceAll(strings.TrimPrefix(u.Hostname(), "marker."), ".", "\\.") + "$"
	routes := `apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata: {name: discovery-auth, namespace: livepeer, annotations: {kubernetes.io/ingress.class: livepeer}}
spec:
  forwardAuth:
    address: http://ingress-auth.livepeer.svc.cluster.local:8080/authorize
    trustForwardHeader: false
    authRequestHeaders: [Authorization]
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata: {name: discovery-strip-auth, namespace: livepeer, annotations: {kubernetes.io/ingress.class: livepeer}}
spec:
  headers:
    customRequestHeaders:
      Authorization: ''
      CF-Access-Client-Id: ''
      CF-Access-Client-Secret: ''
`
	for _, route := range []struct{ name, entrypoint, match, middleware string }{
		{"api", "livepeer-api", "Host(`orchestrator.livepeer.svc.cluster.local`) && PathRegexp(`" + clientPath + "`)", ""},
		{"discovery", "livepeer-discovery", "Host(`orchestrator.livepeer.svc.cluster.local`) && Method(`GET`) && Path(`/discovery`)", "    middlewares: [{name: discovery-auth}, {name: discovery-strip-auth}]\n"},
		{"apps", "livepeer-apps", "HostRegexp(`" + appHost + "`) && !PathRegexp(`" + reservedPath + "`)", ""},
	} {
		routes += fmt.Sprintf(`---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata: {name: livepeer-%s, namespace: livepeer, annotations: {kubernetes.io/ingress.class: livepeer}}
spec:
  entryPoints: [%s]
  routes:
  - kind: Rule
    match: %q
%s    services: [{name: orchestrator, port: 8935, passHostHeader: true}]
`, route.name, route.entrypoint, route.match, route.middleware)
	}
	files["system/ingress/routes.yaml"] = []byte(routes)
	files["system/ingress/auth.yaml"] = []byte(fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata: {name: ingress-auth, namespace: livepeer}
data:
  public-keys.json: %q
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: ingress-auth, namespace: livepeer}
spec:
  replicas: 1
  selector: {matchLabels: {app: ingress-auth}}
  template:
    metadata:
      labels: {app: ingress-auth}
      annotations: {livepeer.io/ingress-config-sha256: '%s'}
    spec:
      automountServiceAccountToken: false
      nodeSelector: {livepeer.io/node-id: '%s'}
      securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
      - name: ingress-auth
        image: '%s'
        args: [ingress-auth, --listen, ':8080', --public-keys-file, /config/public-keys.json, --node-id, '%s']
        ports: [{name: http, containerPort: 8080}]
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
        resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {memory: 64Mi}}
        readinessProbe: {httpGet: {path: /readyz, port: http}}
        livenessProbe: {httpGet: {path: /readyz, port: http}}
        volumeMounts: [{name: config, mountPath: /config, readOnly: true}]
      volumes: [{name: config, configMap: {name: ingress-auth}}]
---
apiVersion: v1
kind: Service
metadata: {name: ingress-auth, namespace: livepeer}
spec:
  selector: {app: ingress-auth}
  ports: [{name: http, port: 8080, targetPort: http}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: ingress-auth, namespace: livepeer}
spec:
  podSelector: {matchLabels: {app: ingress-auth}}
  policyTypes: [Ingress, Egress]
  ingress:
  - from:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}
      podSelector: {matchLabels: {app.kubernetes.io/name: traefik}}
    ports: [{protocol: TCP, port: 8080}]
  egress: []
`, string(keys.JSON()), m.IngressConfigDigest(), m.NodeID, m.RuntimeImage, m.NodeID))
	files["system/ingress/kustomization.yaml"] = kustomize("routes.yaml", "auth.yaml")
	return nil
}

const reservedPath = `(?i)(?:^|/)(?:discovery|runners?|metrics|healthz|readyz)(?:/|;|$)|(?:^|/)ai/trickle(?:/|;|$)`
const clientPath = `^/(?:apps/[A-Za-z0-9_-]{1,128}/session(?:/[A-Za-z0-9_-]{1,128}/(?:stop|payment))?|refresh-payment)$`
