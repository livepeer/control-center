// Package transport supplies origin-bound Runtime clients. Errors never include remote bodies or credentials.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
)

var nodePath = regexp.MustCompile(`^(.*)/v1/nodes/(lp-[a-f0-9]{16})/config$`)
var tokenPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var appReportPath = regexp.MustCompile(`^apps/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/status$`)

type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("http_status_%d", e.Status) }
func IsStatus(err error, status int) bool {
	var e *HTTPError
	return errors.As(err, &e) && e.Status == status
}

func Decode(data []byte, value any) error {
	return jsonv2.Unmarshal(data, value, jsontext.AllowDuplicateNames(false))
}

func HTTPClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type Control struct {
	ConfigURL, NodeID, Base, TokenFile string
	AllowHTTP                          bool
	Client                             *http.Client
	approvedURL, approvedBase          string
}

func NewControl(configURL, tokenFile string, allowHTTP bool) (*Control, error) {
	u, err := url.Parse(configURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || path.Clean(u.Path) != u.Path || (u.Scheme != "https" && !(allowHTTP && u.Scheme == "http")) {
		return nil, errors.New("control_origin")
	}
	m := nodePath.FindStringSubmatch(u.Path)
	if m == nil {
		return nil, errors.New("control_path")
	}
	base := *u
	base.Path = m[1] + "/v1/nodes/" + m[2]
	return &Control{ConfigURL: configURL, NodeID: m[2], Base: base.String(), TokenFile: tokenFile, AllowHTTP: allowHTTP, Client: HTTPClient(), approvedURL: configURL, approvedBase: base.String()}, nil
}

func (c *Control) Request(ctx context.Context, endpoint string, payload any, limit int64) ([]byte, http.Header, error) {
	if c.ConfigURL != c.approvedURL || c.Base != c.approvedBase {
		return nil, nil, errors.New("control_origin_changed")
	}
	if endpoint != "config" && endpoint != "status" && endpoint != "removal-ack" && endpoint != "tunnel/connector-token" && !appReportPath.MatchString(endpoint) {
		return nil, nil, errors.New("control_endpoint")
	}
	token, err := os.ReadFile(c.TokenFile)
	if err != nil || !tokenPattern.Match(token) {
		return nil, nil, errors.New("control_credential")
	}
	var body []byte
	method := http.MethodPost
	if endpoint == "config" {
		method = http.MethodGet
	} else {
		if payload == nil {
			payload = struct{}{}
		}
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, nil, errors.New("control_payload")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+"/"+endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, errors.New("control_request")
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, nil, errors.New("control_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, &HTTPError{resp.StatusCode}
	}
	if c.AllowHTTP && resp.Header.Get("X-Livepeer-Tunnels-Enabled") == "true" {
		return nil, nil, errors.New("development_tunnel_refused")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, nil, errors.New("control_response_size")
	}
	return b, resp.Header, nil
}

type Identity struct {
	Epoch             string
	CredentialVersion int64
}

func ReadIdentity(name string) (Identity, error) {
	var i Identity
	b, err := os.ReadFile(name)
	if err != nil || len(b) > 16384 {
		return i, errors.New("identity_file")
	}
	var raw struct {
		Epoch   string          `json:"epoch"`
		Version json.RawMessage `json:"credential_version"`
	}
	if err = Decode(b, &raw); err != nil {
		return i, errors.New("identity_json")
	}
	version := strings.Trim(string(raw.Version), `"`)
	n, err := strconv.ParseInt(version, 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != version {
		return i, errors.New("identity_version")
	}
	return Identity{raw.Epoch, n}, nil
}

func ReadMetadata(b []byte) (contract.Metadata, error) {
	var m contract.Metadata
	if len(b) > 16384 || Decode(b, &m) != nil || !regexp.MustCompile(`^lp-[0-9a-f]{16}$`).MatchString(m.NodeID) || m.Generation < 1 || m.CredentialVersion < 0 {
		return m, errors.New("metadata_invalid")
	}
	return m, nil
}

type Kube struct {
	Base, TokenFile string
	Client          *http.Client
}

func InCluster() (*Kube, error) {
	dir := "/var/run/secrets/kubernetes.io/serviceaccount"
	ca, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, errors.New("kubernetes_ca")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("kubernetes_ca")
	}
	c := HTTPClient()
	c.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host == "" {
		host = "kubernetes.default.svc"
	}
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if port == "" {
		port = "443"
	}
	return &Kube{Base: "https://" + net.JoinHostPort(host, port), TokenFile: filepath.Join(dir, "token"), Client: c}, nil
}

func (k *Kube) Request(ctx context.Context, method, resource string, payload any, result any) error {
	return k.PatchType(ctx, method, resource, payload, result, "application/merge-patch+json")
}
func (k *Kube) PatchType(ctx context.Context, method, resource string, payload any, result any, contentType string) error {
	if !strings.HasPrefix(resource, "/") || strings.HasPrefix(resource, "//") {
		return errors.New("kubernetes_path")
	}
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return errors.New("kubernetes_payload")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, k.Base+resource, bytes.NewReader(body))
	if err != nil {
		return errors.New("kubernetes_request")
	}
	if k.TokenFile != "" {
		token, err := os.ReadFile(k.TokenFile)
		if err != nil {
			return errors.New("kubernetes_credential")
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	}
	if payload != nil {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := k.Client.Do(req)
	if err != nil {
		return errors.New("kubernetes_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil || len(b) > 4<<20 {
		return errors.New("kubernetes_response_size")
	}
	if result != nil && Decode(b, result) != nil {
		return errors.New("kubernetes_response")
	}
	return nil
}

type Artifact struct {
	Digest         string `json:"digest"`
	Revision       string `json:"revision"`
	Path           string `json:"path"`
	URL            string `json:"url"`
	Size           int    `json:"size"`
	LastUpdateTime string `json:"lastUpdateTime"`
}
type Condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
	ObservedGeneration int64  `json:"observedGeneration"`
	LastTransitionTime string `json:"lastTransitionTime"`
}
type External struct {
	Metadata struct {
		Generation int64 `json:"generation"`
	} `json:"metadata"`
	Status struct {
		Artifact   *Artifact   `json:"artifact"`
		Conditions []Condition `json:"conditions"`
	} `json:"status"`
}

func ExternalPath(name string) string {
	return "/apis/source.toolkit.fluxcd.io/v1/namespaces/flux-system/externalartifacts/" + name
}
func (k *Kube) Publish(ctx context.Context, name string, artifact *Artifact, ready bool, reason string) error {
	var current External
	p := ExternalPath(name)
	if err := k.Request(ctx, http.MethodGet, p, nil, &current); err != nil {
		return err
	}
	status := "False"
	if ready {
		status = "True"
	}
	transition := time.Now().UTC().Format(time.RFC3339)
	for _, c := range current.Status.Conditions {
		if c.Type == "Ready" && c.Status == status {
			transition = c.LastTransitionTime
		}
	}
	condition := Condition{Type: "Ready", Status: status, Reason: reason, Message: reason, ObservedGeneration: current.Metadata.Generation, LastTransitionTime: transition}
	if len(current.Status.Conditions) == 1 && current.Status.Conditions[0] == condition && (artifact == nil || (current.Status.Artifact != nil && *current.Status.Artifact == *artifact)) {
		return nil
	}
	state := map[string]any{"conditions": []Condition{condition}}
	if artifact != nil {
		state["artifact"] = artifact
	}
	return k.Request(ctx, http.MethodPatch, p+"/status", map[string]any{"status": state}, nil)
}
