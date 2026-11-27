package controlplane

import (
	"net/http"
	"net/netip"
)

// Set from the API image's COMMIT build argument.
var buildRevision = "unknown"

// deploymentInfo is what this process loaded at startup: its baked revision
// and the Runtime image pins from its configuration. Deployment tooling
// compares it with the intended release. Every field must be safe to print in
// a deployment log; never add configuration values, credentials or keys.
type deploymentInfo struct {
	Revision              string `json:"revision"`
	RuntimeImage          string `json:"runtime_image"`
	RuntimeConnectorImage string `json:"runtime_connector_image"`
	RuntimeNodeImage      string `json:"runtime_node_image"`
}

func (s *Server) deploymentInfo() deploymentInfo {
	return deploymentInfo{
		Revision:              buildRevision,
		RuntimeImage:          s.params.RuntimeImage,
		RuntimeConnectorImage: s.params.RuntimeConnectorImage,
		RuntimeNodeImage:      s.params.RuntimeNodeImage,
	}
}

func (s *Server) deployment(w http.ResponseWriter, _ *http.Request, _ UserIdentity) {
	respond(w, http.StatusOK, s.deploymentInfo())
}

// localDeployment serves GET /internal/deployment without credentials, but
// only to processes in the API container's own network namespace, such as
// `docker exec <api> wget http://127.0.0.1:43812/internal/deployment`. Other
// Compose containers reach the private listener from their own addresses, and
// the host port and tunnel arrive through Docker from the bridge gateway, so
// all of them are refused. PublicHandler also never routes this path.
func (s *Server) localDeployment(w http.ResponseWriter, r *http.Request) {
	if !loopbackPeer(r) {
		fail(w, http.StatusForbidden, "loopback requests only")
		return
	}
	respond(w, http.StatusOK, s.deploymentInfo())
}

// A proxy in the API's network namespace would connect from loopback on behalf
// of someone else. These headers are never trusted to grant access; their
// presence means the request was relayed, so it is refused.
var forwardingHeaders = []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP"}

// loopbackPeer reports whether the TCP peer of r is a loopback address and r
// carries no forwarding headers.
func loopbackPeer(r *http.Request) bool {
	for _, name := range forwardingHeaders {
		if len(r.Header.Values(name)) > 0 {
			return false
		}
	}
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	return err == nil && peer.Addr().Unmap().IsLoopback()
}
