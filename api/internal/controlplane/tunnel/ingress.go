package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
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
	HTTPHostHeader string `json:"httpHostHeader,omitempty"`
}

const PrivateOrchestrator = machineconfig.PrivateOrchestrator

// Reserve these path segments even under generated app hosts. Go RE2 has no
// negative lookahead: ordered denial rules precede every forwarding rule.
const reservedPath = machineconfig.ReservedIngressPath

// Managed apps use Proxy=true, so app bytes go through generated proxy Hosts.
// The public API Host needs only reservation, stop and payment control.
const clientPath = machineconfig.ClientIngressPath

func RoutingFor(node, domain string) Snapshot {
	return Snapshot{State: machineconfig.InitialState(false), RoutingState: RoutingState{IngressVersion: 1, EndpointGeneration: 1, CredentialGeneration: 1, SourceGeneration: 1,
		ServiceURL:       "https://api." + node + "." + domain,
		ProxyURLTemplate: "https://{proxy}." + node + "." + domain, DiscoveryURL: "https://discovery." + node + "." + domain + "/discovery", Resources: map[string]CFResource{}}}
}
func ingressFor(state RoutingState) []IngressRule {
	api := endpointHost(state.ServiceURL)
	discovery := endpointHost(state.DiscoveryURL)
	namespace := strings.TrimPrefix(endpointHost(state.ProxyURLTemplate), "{proxy}.")
	apps := "*." + namespace
	return []IngressRule{
		{Hostname: api, Path: reservedPath, Service: "http_status:404"},
		{Hostname: api, Path: clientPath, Service: machineconfig.PrivateIngressAPI, OriginRequest: &OriginRequest{HTTPHostHeader: endpointHost(PrivateOrchestrator)}},
		{Hostname: api, Service: "http_status:404"},
		{Hostname: discovery, Path: `^/discovery$`, Service: machineconfig.PrivateIngressDiscovery, OriginRequest: &OriginRequest{HTTPHostHeader: endpointHost(PrivateOrchestrator)}},
		{Hostname: discovery, Service: "http_status:404"},
		{Hostname: apps, Path: reservedPath, Service: "http_status:404"},
		{Hostname: apps, Service: machineconfig.PrivateIngressApps},
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
func ingressHash(r []IngressRule) string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
