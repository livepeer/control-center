package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/runtime/contract"
	"net/url"
	"strings"
)

type IngressRule struct {
	Hostname      string         `json:"hostname,omitempty"`
	Path          string         `json:"path,omitempty"`
	Service       string         `json:"service"`
	OriginRequest *OriginRequest `json:"originRequest,omitempty"`
}
type OriginRequest struct {
	Access         *IngressAccess `json:"access,omitempty"`
	HTTPHostHeader string         `json:"httpHostHeader,omitempty"`
}
type IngressAccess struct {
	Required bool     `json:"required"`
	TeamName string   `json:"teamName"`
	Audience []string `json:"audTag"`
}

const PrivateOrchestrator = machineconfig.PrivateOrchestrator
const ConnectorOrigin = contract.ConnectorOrigin

// Reserve these path segments even under generated app hosts. Go RE2 has no
// negative lookahead: ordered denial rules precede every forwarding rule.
const reservedPath = `(?i)(?:^|/)(?:discovery|runners?|metrics|healthz|readyz)(?:/|;|$)|(?:^|/)ai/trickle(?:/|;|$)`
const clientPath = `^/(?:apps/[A-Za-z0-9_-]{1,128}/(?:session(?:/[A-Za-z0-9_-]{1,128}/(?:stop|payment|app(?:/.*)?))?|app(?:/.*)?)|refresh-payment|(?:run|proxy)/[A-Za-z0-9_-]{1,128}(?:/.*)?)$`

func RoutingFor(node, domain, suffix string) Snapshot {
	return Snapshot{State: machineconfig.InitialState(false), RoutingState: RoutingState{EndpointGeneration: 1, CredentialGeneration: 1, SourceGeneration: 1, AccessVersion: 1,
		EndpointSuffix:   suffix,
		ServiceURL:       "https://api-" + suffix + "." + node + "." + domain,
		ProxyURLTemplate: "https://{proxy}." + node + "." + domain, DiscoveryURL: "https://discovery-" + suffix + "." + node + "." + domain + "/discovery", Resources: map[string]CFResource{}}}
}
func ingressFor(state RoutingState, p Config, audience string) []IngressRule {
	api := endpointHost(state.ServiceURL)
	discovery := endpointHost(state.DiscoveryURL)
	namespace := strings.TrimPrefix(endpointHost(state.ProxyURLTemplate), "{proxy}.")
	apps := "*." + namespace
	origin := protectedOrigin(p, audience)
	return []IngressRule{
		{Hostname: api, Path: reservedPath, Service: "http_status:404"},
		{Hostname: api, Path: clientPath, Service: ConnectorOrigin, OriginRequest: origin},
		{Hostname: api, Service: "http_status:404"},
		{Hostname: discovery, Path: `^/discovery$`, Service: ConnectorOrigin, OriginRequest: origin},
		{Hostname: discovery, Service: "http_status:404"},
		{Hostname: "api." + namespace, Service: "http_status:404"},
		{Hostname: "discovery." + namespace, Service: "http_status:404"},
		{Hostname: apps, Path: reservedPath, Service: "http_status:404"},
		{Hostname: apps, Service: ConnectorOrigin},
		{Service: "http_status:404"},
	}
}
func endpointHost(raw string) string {
	// url.Parse rejects braces in the template authority.
	u, err := url.Parse(strings.Replace(raw, "{proxy}", "lpcc-proxy-marker", 1))
	if err != nil {
		return ""
	}
	return strings.Replace(u.Host, "lpcc-proxy-marker", "{proxy}", 1)
}
func wildcardHost(template string) string {
	return strings.Replace(endpointHost(template), "{proxy}", "*", 1)
}
func protectedOrigin(p Config, audience string) *OriginRequest {
	return &OriginRequest{HTTPHostHeader: endpointHost(PrivateOrchestrator), Access: &IngressAccess{Required: true, TeamName: p.CloudflareTeamName, Audience: []string{audience}}}
}
func ingressHash(r []IngressRule) string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func credentialRef(node, epoch string, version int64) string {
	return fmt.Sprintf("access/%s/%s/%d", node, epoch, version)
}
