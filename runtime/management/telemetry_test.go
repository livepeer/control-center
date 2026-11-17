package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
)

type tokenControl struct {
	body      string
	err       error
	endpoints []string
}

func (c *tokenControl) Request(_ context.Context, endpoint string, payload any, _ int64) ([]byte, http.Header, error) {
	c.endpoints = append(c.endpoints, endpoint)
	if payload != nil {
		return nil, nil, errors.New("telemetry token requests carry no relay input")
	}
	return []byte(c.body), nil, c.err
}

const telemetryJWT = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJub2RlIn0.c2lnbmF0dXJl"

func TestTelemetryTokensUseApprovedOriginAndEnrollment(t *testing.T) {
	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	m := contract.Metadata{NodeID: "abcdefghijklmnopqrstuvwxyz", CredentialVersion: 1}
	issued := func(node string, expires time.Time) string {
		b, _ := json.Marshal(map[string]any{"token": telemetryJWT, "expires_at": expires, "node_id": node})
		return string(b)
	}
	base := "https://cc.example/v1/nodes/" + m.NodeID
	call := func(control *tokenControl, desired contract.Metadata, ok bool, method, path string) *httptest.ResponseRecorder {
		h := TelemetryTokens{Control: control, Base: base, Desired: func() (contract.Metadata, bool) { return desired, ok }, Now: func() time.Time { return now }}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(`{"metrics_url":"https://attacker.example"}`)))
		return w
	}
	control := &tokenControl{body: issued(m.NodeID, now.Add(time.Hour))}
	w := call(control, m, true, http.MethodPost, "/telemetry/token")
	var grant TelemetryGrant
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &grant) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	if grant.Token != telemetryJWT || grant.MetricsURL != base+"/telemetry/metrics" || grant.LogsURL != base+"/telemetry/logs" || grant.NodeID != m.NodeID || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("telemetry grant", grant)
	}
	if len(control.endpoints) != 1 || control.endpoints[0] != "telemetry/token" {
		t.Fatal("unexpected control operations", control.endpoints)
	}
	for name, tc := range map[string]struct {
		control  *tokenControl
		desired  contract.Metadata
		ok       bool
		method   string
		path     string
		want     int
		upstream bool
	}{
		"other operation":  {&tokenControl{}, m, true, http.MethodPost, "/status", 403, false},
		"query":            {&tokenControl{}, m, true, http.MethodPost, "/telemetry/token?x=1", 403, false},
		"method":           {&tokenControl{}, m, true, http.MethodGet, "/telemetry/token", 403, false},
		"unpublished":      {&tokenControl{}, m, false, http.MethodPost, "/telemetry/token", 503, false},
		"retired":          {&tokenControl{}, contract.Metadata{NodeID: m.NodeID, Terminal: true}, true, http.MethodPost, "/telemetry/token", 503, false},
		"disabled":         {&tokenControl{err: &transport.HTTPError{Status: 403}}, m, true, http.MethodPost, "/telemetry/token", 403, true},
		"revoked":          {&tokenControl{err: &transport.HTTPError{Status: 401}}, m, true, http.MethodPost, "/telemetry/token", 401, true},
		"unreachable":      {&tokenControl{err: errors.New("control_unavailable")}, m, true, http.MethodPost, "/telemetry/token", 503, true},
		"other machine":    {&tokenControl{body: issued("zyxwvutsrqponmlkjihgfedcba", now.Add(time.Hour))}, m, true, http.MethodPost, "/telemetry/token", 502, true},
		"expired":          {&tokenControl{body: issued(m.NodeID, now)}, m, true, http.MethodPost, "/telemetry/token", 502, true},
		"excess lifetime":  {&tokenControl{body: issued(m.NodeID, now.Add(2*time.Hour))}, m, true, http.MethodPost, "/telemetry/token", 502, true},
		"malformed token":  {&tokenControl{body: `{"token":"a b","expires_at":"2026-11-17T10:30:00Z","node_id":"abcdefghijklmnopqrstuvwxyz"}`}, m, true, http.MethodPost, "/telemetry/token", 502, true},
		"malformed answer": {&tokenControl{body: `[]`}, m, true, http.MethodPost, "/telemetry/token", 502, true},
	} {
		w := call(tc.control, tc.desired, tc.ok, tc.method, tc.path)
		if w.Code != tc.want || (len(tc.control.endpoints) > 0) != tc.upstream || strings.Contains(w.Body.String(), telemetryJWT) {
			t.Fatal(name, w.Code, tc.control.endpoints, w.Body.String())
		}
	}
}
