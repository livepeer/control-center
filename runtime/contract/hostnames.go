package contract

import "strings"

const PrivateOrchestrator = "http://orchestrator.livepeer.svc.cluster.local:8935"

// ReservedProxyID protects the machine's control hostname namespace. Generated
// Node IDs use app- or an unprefixed random label and do not occupy these names.
func ReservedProxyID(id string) bool {
	id = strings.ToLower(id)
	return id == "api" || id == "discovery" || strings.HasPrefix(id, "api-") || strings.HasPrefix(id, "discovery-")
}
