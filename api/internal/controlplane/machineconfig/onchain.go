package machineconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/livepeer/control-center/runtime/onchain"
)

func effectiveOnchain(m Desired) onchain.Config {
	c := m.Onchain
	if m.State.HeldOrchestrator != "" && m.State.HeldOnchain != "" {
		c = onchain.Config{}
		_ = json.Unmarshal([]byte(m.State.HeldOnchain), &c)
	}
	if c.Version == 0 {
		c = onchain.Offchain()
	}
	return c
}
func specializeOnchain(raw string, m Desired) string {
	if !strings.Contains(raw, "  orchestrator.toml: |\n") {
		return raw
	}
	// The Service remains a private route to a live process during dependency loss.
	raw = strings.Replace(raw, "spec:\n  selector:\n    app: orchestrator", "spec:\n  publishNotReadyAddresses: true\n  selector:\n    app: orchestrator", 1)
	c := m.Onchain
	if !c.Onchain() {
		return raw
	}
	endpoint, _ := url.Parse(c.RedeemerURL)
	meta, _ := json.Marshal(c)
	hash := sha256.Sum256(meta)
	raw = strings.Replace(raw, "livepeer.io/config-sha256:", fmt.Sprintf("livepeer.io/onchain-sha256: '%x'\n        livepeer.io/config-sha256:", hash), 1)
	settings := map[string]any{"Network": c.Network, "ChainID": c.ChainID, "Controller": c.Controller, "OrchestratorAddress": c.Recipient, "RPCURLFile": "/run/onchain/private/rpc", "RedeemerGrants": c.RedeemerGrants, "RedeemerHeadersFile": "/run/onchain/private/headers", "RedeemerDB": "/data/onchain.sqlite", "TicketFaceValue": c.TicketFaceValue, "TicketWinProb": c.TicketWinProb, "MaxPendingTickets": c.MaxPendingTickets, "MaxTicketsPerRecipient": c.MaxTicketsPerRecipient}
	if c.WeiPerUSD != "" {
		settings["WeiPerUSD"] = c.WeiPerUSD
	} else {
		settings["ETHUSDFeed"] = c.ETHUSDFeed
		settings["PriceMaxAge"] = c.PriceMaxAge
	}
	var b bytes.Buffer
	if toml.NewEncoder(&b).Encode(settings) != nil {
		return raw
	}
	text := strings.TrimSuffix(b.String(), "\n")
	text = "    " + strings.ReplaceAll(text, "\n", "\n    ")
	raw = strings.Replace(raw, `    Network = "offchain"`, text, 1)
	// Node's URL field is a TOML table. Keep it last so subsequent global
	// settings are not accidentally decoded as URL fields.
	b.Reset()
	_ = toml.NewEncoder(&b).Encode(map[string]any{"RedeemerURL": map[string]string{"Scheme": endpoint.Scheme, "Host": endpoint.Host, "Path": endpoint.Path}})
	text = "    " + strings.ReplaceAll(strings.TrimSuffix(b.String(), "\n"), "\n", "\n    ")
	const marker = "  orchestrator.toml: |\n"
	head, config, _ := strings.Cut(raw, marker)
	body, tail, _ := strings.Cut(config, "\n---")
	raw = head + marker + body + "\n" + text + "\n---" + tail
	raw = strings.Replace(raw, "        args:\n", `        command: [/usr/local/bin/livepeer-runtime, orchestrator-start]
        env:
        - {name: POD_NAME, valueFrom: {fieldRef: {fieldPath: metadata.name}}}
        - {name: POD_UID, valueFrom: {fieldRef: {fieldPath: metadata.uid}}}
        args:
`, 1)
	// The wrapper executes /usr/local/bin/livepeer with these same Node arguments.
	raw = strings.Replace(raw, "        - name: config\n          mountPath:", "        - {name: onchain, mountPath: /run/onchain}\n        - {name: management, mountPath: /management, readOnly: true}\n        - name: config\n          mountPath:", 1)
	raw = strings.Replace(raw, "      volumes:\n", fmt.Sprintf("      volumes:\n      - name: onchain\n        emptyDir: {medium: Memory, sizeLimit: 1Mi}\n      - name: management\n        hostPath: {path: '%s/volumes/management-sockets/orchestrator', type: Directory}\n", m.InstallDir), 1)
	raw = strings.Replace(raw, "        readinessProbe:\n          httpGet:\n            path: /readyz\n            port: metrics", "        readinessProbe:\n          timeoutSeconds: 5\n          periodSeconds: 5\n          exec:\n            command: [/usr/local/bin/livepeer-runtime, orchestrator-probe]", 1)
	return raw
}

func onchainNetwork(c onchain.Config) string {
	var b strings.Builder
	for _, g := range append(append([]string{}, c.RPCGrants...), c.RedeemerGrants...) {
		a, p, e := onchain.Grant(g)
		if e != nil {
			continue
		}
		bits := 128
		if a.Is4() {
			bits = 32
		}
		fmt.Fprintf(&b, "  - to: [{ipBlock: {cidr: '%s/%d'}}]\n    ports: [{protocol: TCP, port: %d}]\n", a, bits, p)
	}
	return b.String()
}
