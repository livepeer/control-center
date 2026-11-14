package secretservice

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	protocol "github.com/livepeer/control-center/secrets"
)

type operatorKey struct{}
type operatorIdentity struct{ UserID, Address string }

func operatorActor(r *http.Request) operatorIdentity {
	id, _ := r.Context().Value(operatorKey{}).(operatorIdentity)
	return id
}

func (s *Service) operator(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accepted := false
		defer func() {
			if !accepted && r.Method == http.MethodPost && r.URL.Path == "/v1/enrollment-grants" {
				s.issuanceRejected.Add(1)
			}
		}()

		user, err := s.user(r)
		if err != nil {
			failAuthorization(w, err, 401, "authentication_required")
			return
		}
		address, err := protocol.OrchestratorAddress(r.URL.Query().Get("orchestrator_address"))
		if err != nil {
			fail(w, 400, "invalid_orchestrator")
			return
		}
		if err = s.Metadata.Member(r.Context(), user, address); err != nil {
			failAuthorization(w, err, 403, "orchestrator_access_required")
			return
		}
		ctx := context.WithValue(r.Context(), operatorKey{}, operatorIdentity{user, address})
		accepted = true
		next(w, r.WithContext(ctx))
	}
}

func (c *controlMetadata) Member(ctx context.Context, user, address string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.s.Config.ControlURL, "/")+"/internal/users/"+url.PathEscape(user)+"/orchestrators/"+url.PathEscape(address), nil)
	if err != nil {
		return protocol.ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+c.s.Config.ControlToken)
	res, err := c.s.HTTP.Do(req)
	if err != nil {
		return protocol.ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode == 403 {
		var denied struct {
			Code string `json:"code"`
		}
		if json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&denied) == nil && denied.Code == "orchestrator_access_required" {
			return protocol.ErrDenied
		}
		return protocol.ErrUnavailable
	}
	var v struct {
		UserID  string `json:"user_id"`
		Address string `json:"orchestrator_address"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&v) != nil || v.UserID != user || v.Address != address {
		return protocol.ErrUnavailable
	}
	return nil
}
