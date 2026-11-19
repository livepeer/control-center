package machineconfig

import (
	"fmt"
	"strings"
)

func managedTunnelManifest(m Desired) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata: {name: livepeer-tunnel, namespace: flux-system}
spec:
  replicas: 1
  strategy: {type: Recreate}
  selector: {matchLabels: {app: livepeer-tunnel}}
  template:
    metadata:
      labels: {app: livepeer-tunnel}
      annotations:
        livepeer.io/token-generation: '%d'
        livepeer.io/process-image: '%s'
    spec:
      automountServiceAccountToken: false
      hostPID: false
      shareProcessNamespace: false
      nodeSelector: {livepeer.io/node-id: '%s'}
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
      - name: connector
        image: '%s'
        command: [/usr/local/bin/livepeer-runtime, connector-start]
        args: [--socket, /management/control.sock, --token-path, /run/tunnel/private/token]
        env:
        - {name: POD_NAME, valueFrom: {fieldRef: {fieldPath: metadata.name}}}
        - {name: POD_UID, valueFrom: {fieldRef: {fieldPath: metadata.uid}}}
        resources:
          requests: {cpu: 50m, memory: 64Mi}
          limits: {memory: 256Mi}
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities: {drop: [ALL]}
        readinessProbe:
          exec:
            command: [/usr/local/bin/livepeer-runtime, connector-probe, --socket, /management/control.sock]
          timeoutSeconds: 5
          periodSeconds: 10
        volumeMounts:
        - {name: management, mountPath: /management, readOnly: true}
        - {name: token, mountPath: /run/tunnel}
      volumes:
      - name: management
        hostPath: {path: '%s/volumes/management-sockets/connector', type: Directory}
      - name: token
        emptyDir: {medium: Memory, sizeLimit: 1Mi}
`, m.Exposure.CredentialGeneration, m.Connector.Image, m.NodeID, m.Connector.Image, m.InstallDir)
}

func kustomize(resources ...string) []byte {
	text := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
	if len(resources) == 0 {
		return []byte(text + "resources: []\n")
	}
	text += "resources:\n"
	for _, name := range resources {
		text += "- " + name + "\n"
	}
	return []byte(text)
}

// addSystemWorkloads defines independent inventories for management workloads.
func addSystemWorkloads(files map[string][]byte, m Desired) error {
	for _, prefix := range []string{"", "terminal-cleanup/"} {
		if files[prefix+"runtime.json"] == nil {
			continue
		}
		if prefix != "" {
			files[prefix+"system/ingress/kustomization.yaml"] = kustomize()
		}
		// Telemetry runs only on the published configuration, never terminal cleanup.
		telemetry := prefix == "" && telemetryActive(m)
		network := nodeNetwork()
		if telemetry {
			network += telemetryNodeIngress()
		}
		files[prefix+"system/node/network.yaml"] = []byte(network)
		if effectiveOnchain(m).Onchain() {
			files[prefix+"management/app-reconciler.yaml"] = append(files[prefix+"management/app-reconciler.yaml"], []byte("\n---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: orchestrator-onchain-egress, namespace: livepeer}\nspec:\n  podSelector: {matchLabels: {app: orchestrator}}\n  policyTypes: [Egress]\n  egress:\n"+onchainNetwork(effectiveOnchain(m)))...)
		}
		files[prefix+"system/node/kustomization.yaml"] = kustomize("orchestrator.yaml", "network.yaml")
		connectorResources := []string{}
		if files[prefix+"system/connector/tunnel.yaml"] != nil {
			connectorResources = []string{"tunnel.yaml", "network.yaml"}
		}
		files[prefix+"system/connector/kustomization.yaml"] = kustomize(connectorResources...)
		upgradeDependency := "livepeer-upgrade-controller"
		if m.Terminal {
			upgradeDependency = "livepeer"
		}
		definitions := ""
		components := []struct {
			name, path, dependency, deletion string
			wait                             bool
		}{
			{"livepeer-ingress", "system/ingress", "livepeer", "Orphan", true},
			{"livepeer-node", "system/node", "livepeer", "Orphan", false},
			{"livepeer-connector", "system/connector", "livepeer", "Orphan", false},
			{"livepeer-app-reconciler", "system/app-reconciler", "livepeer", "Orphan", false},
			{"livepeer-upgrade-controller", "system/upgrade-controller", "livepeer", "Orphan", true},
			{"livepeer-upgrade-plan", "upgrade-plan", upgradeDependency, "Orphan", false},
		}
		if telemetry {
			// Disabling telemetry or losing the host feature removes the agents.
			components = append(components, struct {
				name, path, dependency, deletion string
				wait                             bool
			}{"livepeer-telemetry", "system/telemetry", "livepeer", "Delete", false})
		}
		for _, component := range components {
			definitions += fmt.Sprintf("---\napiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: %s\n  namespace: flux-system\n  labels: {livepeer.io/system-workload: 'true'}\nspec:\n  interval: 1m\n  retryInterval: 10s\n  timeout: 2m\n  path: ./%s\n  prune: true\n  deletionPolicy: %s\n  wait: %t\n  dependsOn: [{name: %s}]\n  sourceRef: {kind: ExternalArtifact, name: livepeer-service}\n", component.name, component.path, component.deletion, component.wait, component.dependency)
		}
		files[prefix+"management/system.yaml"] = []byte(strings.TrimPrefix(definitions, "---\n"))
		files[prefix+"management/kustomization.yaml"] = kustomize("app-reconciler.yaml", "system.yaml")
	}
	return nil
}
