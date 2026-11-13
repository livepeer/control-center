package secretservice

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/secretclient"
	protocol "github.com/livepeer/control-center/secrets"
)

func TestSignedRequestBindingAndDurableReplayProtection(t *testing.T) {
	s, key, m, _ := dbService(t)
	id := enrolled(t, s, key, m)
	now := time.Now().Truncate(time.Second)
	s.Now = func() time.Time { return now }
	body := []byte(`{"assignments":[]}`)
	original := httptest.NewRequest("POST", s.Config.PublicURL+"/v1/runtime/batch", bytes.NewReader(body))
	if e := protocol.SignRequest(original, body, id.Identity, key, now); e != nil {
		t.Fatal(e)
	}
	replay := func() *http.Request {
		r := original.Clone(t.Context())
		r.Body = io.NopCloser(bytes.NewReader(body))
		return r
	}
	serve := func(s *Service, r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.authenticated(s.batchVersions)(w, r)
		return w
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Method = "GET" },
		func(r *http.Request) { r.URL.Path = "/v1/runtime/resolve" },
		func(r *http.Request) { r.URL.RawQuery = "other=1" },
		func(r *http.Request) { r.Body = io.NopCloser(bytes.NewBufferString(`{}`)) },
		func(r *http.Request) { r.Header.Del("Authorization"); r.Header.Set("Client-Cert", "forged") },
		func(r *http.Request) {
			r.URL.Host = "another-service.example"
			_ = protocol.SignRequest(r, body, id.Identity, key, now)
		},
		func(r *http.Request) {
			_, wrong, _ := ed25519.GenerateKey(rand.Reader)
			_ = protocol.SignRequest(r, body, id.Identity, wrong, now)
		},
	} {
		r := replay()
		mutate(r)
		if w := serve(s, r); w.Code != 401 || !bytes.Contains(w.Body.Bytes(), []byte(`"code":"proof_refused"`)) {
			t.Fatal("invalid proof must be retryable", w.Code, w.Body.String())
		}
	}
	replica := New(s.DB, s.Config)
	replica.Metadata, replica.Now = s.Metadata, s.Now
	results := make(chan int, 8)
	for i := range 8 {
		go func() { results <- serve([]*Service{s, replica}[i%2], replay()).Code }()
	}
	accepted := 0
	for range 8 {
		switch code := <-results; code {
		case 200:
			accepted++
		case 401:
		default:
			t.Fatal("unexpected authentication result", code)
		}
	}
	if accepted != 1 {
		t.Fatal("replay accepted or invalid proof consumed the nonce", accepted)
	}
	if w := serve(New(s.DB, s.Config), replay()); w.Code != 401 {
		t.Fatal("restart revived a used proof", w.Code)
	}
	now = now.Add(2 * protocol.RequestLifetime)
	if e := s.Collect(t.Context()); e != nil {
		t.Fatal(e)
	}
	var retained int
	if e := s.DB.QueryRow(`SELECT count(*) FROM lpsecrets.request_nonces`).Scan(&retained); e != nil || retained != 0 {
		t.Fatal("expired nonce state retained", retained, e)
	}
	if w := serve(s, replay()); w.Code != 401 {
		t.Fatal("nonce cleanup revived an expired proof", w.Code)
	}
}

func TestRuntimeClientThroughTerminatingTLSProxy(t *testing.T) {
	s, key, m, _ := dbService(t)
	id := enrolled(t, s, key, m)
	var offset atomic.Int64
	var replay atomic.Bool
	s.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if replay.Load() {
			body, e := io.ReadAll(r.Body)
			if e != nil {
				t.Error(e)
			}
			first := r.Clone(r.Context())
			first.Body = io.NopCloser(bytes.NewReader(body))
			s.Handler().ServeHTTP(httptest.NewRecorder(), first)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		s.Handler().ServeHTTP(w, r)
	}))
	defer origin.Close()
	u, _ := url.Parse(origin.URL)
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = http.DefaultTransport
	edge := httptest.NewTLSServer(proxy)
	defer edge.Close()
	s.Config.PublicURL = edge.URL
	previous := http.DefaultTransport
	http.DefaultTransport = edge.Client().Transport
	defer func() { http.DefaultTransport = previous }()
	dir := t.TempDir()
	raw, _ := json.Marshal(id.Identity)
	for name, data := range map[string][]byte{"key.pem": protocol.PrivatePEM(key), "identity.json": raw, "url": []byte(edge.URL), "managed": []byte("1")} {
		if e := os.WriteFile(filepath.Join(dir, name), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	client := &secretclient.Client{Directory: dir}
	if e := client.Activate(t.Context()); e != nil {
		t.Fatal(e)
	}
	for _, fault := range []string{"expired", "future", "replay"} {
		switch fault {
		case "expired":
			offset.Store(int64(time.Minute))
		case "future":
			offset.Store(-int64(31 * time.Second))
		case "replay":
			replay.Store(true)
		}
		if _, _, e := client.VersionsAll(t.Context(), nil); !errors.Is(e, protocol.ErrUnavailable) {
			t.Fatal("proof rejection became permanent identity denial", fault, e)
		}
		offset.Store(0)
		replay.Store(false)
		if _, _, e := client.VersionsAll(t.Context(), nil); e != nil {
			t.Fatal("fresh proof could not recover", fault, e)
		}
	}
	for _, fault := range []string{"retired", "encryption", "revoked"} {
		m.machine.Active = fault != "retired"
		m.machine.EncryptionReady = fault != "encryption"
		if fault == "revoked" {
			if w := call(t, s, "/v1/machines/"+id.NodeID+"/revoke", "POST", "operator", nil, nil); w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
		}
		if _, _, e := client.VersionsAll(t.Context(), nil); !errors.Is(e, protocol.ErrDenied) {
			t.Fatal("ineligible identity authorized through proxy", fault, e)
		}
	}
}
