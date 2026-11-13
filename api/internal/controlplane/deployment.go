package controlplane

import "net/http"

// Set from the API image's COMMIT build argument.
var buildRevision = "unknown"

func (s *Server) deployment(w http.ResponseWriter, _ *http.Request, _ UserIdentity) {
	respond(w, http.StatusOK, map[string]string{
		"revision":           buildRevision,
		"runtime_node_image": s.params.RuntimeNodeImage,
	})
}
