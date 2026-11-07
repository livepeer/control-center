package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type IngressRule struct {
	Hostname      string         `json:"hostname,omitempty"`
	Path          string         `json:"path,omitempty"`
	Service       string         `json:"service"`
	OriginRequest *OriginRequest `json:"originRequest,omitempty"`
}
type OriginRequest struct {
	Access *IngressAccess `json:"access,omitempty"`
}
type IngressAccess struct {
	Required bool     `json:"required"`
	TeamName string   `json:"teamName"`
	Audience []string `json:"audTag"`
}

const privateOrchestrator = "http://orchestrator.livepeer.svc.cluster.local:8935"

// Reserve these path segments even under generated app hosts. Go RE2 has no
// negative lookahead: ordered denial rules precede every forwarding rule.
const reservedPath = `(?i)(?:^|/)(?:discovery|runners?|metrics|healthz|readyz)(?:/|;|$)|(?:^|/)ai/trickle(?:/|;|$)`
const clientPath = `^/(?:apps/[A-Za-z0-9_-]{1,128}/(?:session(?:/[A-Za-z0-9_-]{1,128}/(?:stop|payment|app(?:/.*)?))?|app(?:/.*)?)|refresh-payment|(?:run|proxy)/[A-Za-z0-9_-]{1,128}(?:/.*)?)$`

func routingFor(node, domain string) RoutingState {
	return RoutingState{Lifecycle: "active", Generation: 1, EndpointGeneration: 1, CredentialGeneration: 1, SourceGeneration: 1, AccessVersion: 1,
		ServiceURL:       "https://api-" + node + "." + domain,
		ProxyURLTemplate: "https://{proxy}.apps-" + node + "." + domain, DiscoveryURL: "https://discovery-" + node + "." + domain + "/discovery", Resources: map[string]CFResource{}}
}
func ingressFor(node string, p TunnelParams, audience string) []IngressRule {
	api := "api-" + node + "." + p.CloudflareBaseDomain
	apps := "*.apps-" + node + "." + p.CloudflareBaseDomain
	discovery := "discovery-" + node + "." + p.CloudflareBaseDomain
	return []IngressRule{
		{Hostname: api, Path: reservedPath, Service: "http_status:404"},
		{Hostname: apps, Path: reservedPath, Service: "http_status:404"},
		{Hostname: discovery, Path: `^/discovery$`, Service: privateOrchestrator, OriginRequest: &OriginRequest{Access: &IngressAccess{Required: true, TeamName: p.CloudflareTeamName, Audience: []string{audience}}}},
		{Hostname: discovery, Service: "http_status:404"},
		{Hostname: api, Path: clientPath, Service: privateOrchestrator},
		{Hostname: apps, Service: privateOrchestrator},
		{Service: "http_status:404"},
	}
}
func ingressHash(r []IngressRule) string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func credentialRef(node, epoch string, version int64) string {
	return fmt.Sprintf("access/%s/%s/%d", node, epoch, version)
}
