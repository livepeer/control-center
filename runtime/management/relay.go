package management

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
)

// Desired returns only successfully published, enrollment-validated configuration.
type Desired func() (contract.Metadata, bool)

type AppReports struct {
	Control transport.Requester
	Desired Desired
}

var appStatus = regexp.MustCompile(`^apps/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/status$`)

func (a AppReports) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	endpoint := strings.TrimPrefix(r.URL.Path, "/")
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || (endpoint != "status" && !appStatus.MatchString(endpoint)) {
		http.Error(w, "operation refused", http.StatusForbidden)
		return
	}
	limit := int64(16 << 10)
	if endpoint == "status" {
		limit = 128 << 10
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	var identity struct {
		Epoch             string `json:"epoch"`
		CredentialVersion int64  `json:"credential_version"`
		Component         string `json:"component"`
	}
	m, ok := a.Desired()
	if err != nil || int64(len(b)) > limit || transport.Decode(b, &identity) != nil || !ok || identity.Epoch != m.Epoch || identity.CredentialVersion != m.CredentialVersion || (endpoint == "status" && identity.Component != "runner" && identity.Component != "app-reconciler") {
		http.Error(w, "report refused", http.StatusForbidden)
		return
	}
	result, _, err := a.Control.Request(r.Context(), endpoint, json.RawMessage(b), 16384)
	if err != nil {
		status := http.StatusServiceUnavailable
		var remote *transport.HTTPError
		if errors.As(err, &remote) {
			status = remote.Status
		}
		http.Error(w, "report unavailable", status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}
