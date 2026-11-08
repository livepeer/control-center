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

// addSystemWorkloads partitions centrally rendered resources into sibling inventories.
func addSystemWorkloads(files map[string][]byte, m Desired) error {
	if m.BundleFormat < 3 {
		return nil
	}
	for _, prefix := range []string{"", "terminal-cleanup/"} {
		if files[prefix+"runtime.json"] == nil {
			continue
		}
		root := string(files[prefix+"management/kustomization.yaml"])
		_, patches, _ := strings.Cut(root, "patches:\n")
		move := func(old, target string) {
			if b, ok := files[prefix+old]; ok {
				files[prefix+target] = b
				delete(files, prefix+old)
			}
		}
		move("management/orchestrator.yaml", "system/node/orchestrator.yaml")
		files[prefix+"system/node/network.yaml"] = []byte(nodeNetwork())
		files[prefix+"system/node/kustomization.yaml"] = kustomize("orchestrator.yaml", "network.yaml")
		move("management/suc-crd.yaml", "system/upgrade-controller/suc-crd.yaml")
		move("management/suc.yaml", "system/upgrade-controller/suc.yaml")
		files[prefix+"system/upgrade-controller/kustomization.yaml"] = append(kustomize("suc-crd.yaml", "suc.yaml"), []byte("patches:\n"+patches)...)
		connectorResources := []string{}
		if files[prefix+"management/tunnel.yaml"] != nil {
			move("management/tunnel.yaml", "system/connector/tunnel.yaml")
			network, _, _ := strings.Cut(string(files[prefix+"management/tunnel-network.yaml"]), "---\n")
			files[prefix+"system/connector/network.yaml"] = []byte(network)
			connectorResources = []string{"tunnel.yaml", "network.yaml"}
		}
		delete(files, prefix+"management/tunnel-network.yaml")
		files[prefix+"system/connector/kustomization.yaml"] = kustomize(connectorResources...)
		support, workload, found := strings.Cut(string(files[prefix+"management/app-reconciler.yaml"]), "---\napiVersion: apps/v1\nkind: Deployment\n")
		if !found {
			return fmt.Errorf("missing App Reconciler deployment")
		}
		workload = "apiVersion: apps/v1\nkind: Deployment\n" + workload
		workload = strings.Replace(workload, "        - --token-file\n        - /credentials/token", "        - --management-socket\n        - /management/control.sock", 1)
		workload = strings.Replace(workload, "        - {name: state, mountPath: /state}", "        - {name: state, mountPath: /state}\n        - {name: management, mountPath: /management, readOnly: true}", 1)
		workload = strings.Replace(workload, "      - name: credentials\n        secret: {secretName: livepeer-service-auth, defaultMode: 288}", "      - name: credentials\n        secret:\n          secretName: livepeer-service-auth\n          defaultMode: 288\n          items:\n          - {key: identity.json, path: identity.json}\n          - {key: config-url, path: config-url}\n      - name: management\n        hostPath: {path: '"+m.InstallDir+"/volumes/management-sockets/apps', type: Directory}", 1)
		files[prefix+"system/app-reconciler/workload.yaml"] = []byte(workload)
		files[prefix+"system/app-reconciler/kustomization.yaml"] = kustomize("workload.yaml")
		files[prefix+"management/app-reconciler.yaml"] = []byte(support)
		upgradeDependency := "livepeer-upgrade-controller"
		if m.Terminal {
			upgradeDependency = "livepeer"
		}
		definitions := ""
		for _, component := range []struct {
			name, path, dependency string
			wait                   bool
		}{
			{"livepeer-node", "system/node", "livepeer", false},
			{"livepeer-connector", "system/connector", "livepeer", false},
			{"livepeer-app-reconciler", "system/app-reconciler", "livepeer", false},
			{"livepeer-upgrade-controller", "system/upgrade-controller", "livepeer", true},
			{"livepeer-upgrade-plan", "upgrade-plan", upgradeDependency, false},
		} {
			definitions += fmt.Sprintf("---\napiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: %s\n  namespace: flux-system\n  labels: {livepeer.io/system-workload: 'true'}\nspec:\n  interval: 1m\n  retryInterval: 10s\n  timeout: 2m\n  path: ./%s\n  prune: true\n  deletionPolicy: Orphan\n  wait: %t\n  dependsOn: [{name: %s}]\n  sourceRef: {kind: ExternalArtifact, name: livepeer-service}\n", component.name, component.path, component.wait, component.dependency)
		}
		files[prefix+"management/system.yaml"] = []byte(strings.TrimPrefix(definitions, "---\n"))
		files[prefix+"management/kustomization.yaml"] = kustomize("app-reconciler.yaml", "system.yaml")
	}
	return nil
}
