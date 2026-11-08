package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

// Requester is the authenticated machine operation surface used by reporting.
type Requester interface {
	Request(context.Context, string, any, int64) ([]byte, http.Header, error)
}

// Local sends operations through a consumer's protected socket, without a machine credential.
type Local struct{ Client *http.Client }

func NewLocal(socket string) *Local {
	c := HTTPClient()
	c.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	return &Local{Client: c}
}

func (l *Local) Request(ctx context.Context, endpoint string, payload any, limit int64) ([]byte, http.Header, error) {
	if strings.ContainsAny(endpoint, "?#\\") || strings.HasPrefix(endpoint, "/") || strings.Contains(endpoint, "..") {
		return nil, nil, errors.New("local_operation")
	}
	if payload == nil {
		payload = struct{}{}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, errors.New("local_payload")
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://management/"+endpoint, bytes.NewReader(b))
	if err != nil {
		return nil, nil, errors.New("local_operation")
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := l.Client.Do(r)
	if err != nil {
		return nil, nil, errors.New("local_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, nil, &HTTPError{Status: response.StatusCode}
	}
	b, err = io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, nil, errors.New("local_response_size")
	}
	return b, response.Header, nil
}
