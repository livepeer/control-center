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
	"sync"
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
	request := func() *http.Request {
		r := httptest.NewRequest("POST", s.Config.PublicURL+"/v1/runtime/batch", bytes.NewReader(body))
		if e := protocol.SignRequest(r, body, id.Identity, key, now); e != nil {
			t.Fatal(e)
		}
		return r
	}
	original := request().Header.Get("Authorization")
	var accepted atomic.Int64
	handler := func(s *Service) http.HandlerFunc {
		return s.authenticated(func(w http.ResponseWriter, r *http.Request) {
			accepted.Add(1)
			w.WriteHeader(204)
		})
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Method = "GET" },
		func(r *http.Request) { r.URL.Path = "/v1/runtime/resolve" },
		func(r *http.Request) { r.URL.RawQuery = "other=1" },
		func(r *http.Request) { r.Body = io.NopCloser(bytes.NewBufferString(`{}`)) },
		func(r *http.Request) { r.Header.Del("Authorization"); r.Header.Set("Client-Cert", "forged") },
	} {
		r := request()
		r.Header.Set("Authorization", original)
		mutate(r)
		w := httptest.NewRecorder()
		handler(s)(w, r)
		if w.Code != 403 {
			t.Fatal("modified or unsigned request accepted", w.Code)
		}
	}
	for _, fault := range []string{"expired", "future", "audience", "key", "generation"} {
		r := request()
		signedAt, credential, signer := now, id.Identity, key
		switch fault {
		case "expired":
			signedAt = now.Add(-protocol.RequestLifetime)
		case "future":
			signedAt = now.Add(31 * time.Second)
		case "audience":
			r.URL.Host = "another-service.example"
		case "key":
			_, signer, _ = ed25519.GenerateKey(rand.Reader)
		case "generation":
			credential.Generation++
		}
		if e := protocol.SignRequest(r, body, credential, signer, signedAt); e != nil {
			t.Fatal(e)
		}
		w := httptest.NewRecorder()
		handler(s)(w, r)
		if w.Code != 403 {
			t.Fatal(fault, w.Code)
		}
	}
	// Independent service instances must share nonce consumption, including when
	// the first request is still executing. Invalid requests did not consume it.
	replica := New(s.DB, s.Config)
	replica.Now = s.Now
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			r := request()
			r.Header.Set("Authorization", original)
			w := httptest.NewRecorder()
			handler([]*Service{s, replica}[i%2])(w, r)
			if w.Code != 204 && w.Code != 403 {
				t.Error(w.Code, w.Body.String())
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("replay was accepted or invalid requests consumed the nonce", accepted.Load())
	}
	restarted := New(s.DB, s.Config)
	r := request()
	r.Header.Set("Authorization", original)
	w := httptest.NewRecorder()
	handler(restarted)(w, r)
	if w.Code != 403 {
		t.Fatal("restart revived a used credential", w.Code)
	}
	now = now.Add(2 * protocol.RequestLifetime)
	if e := s.Collect(t.Context()); e != nil {
		t.Fatal(e)
	}
	var retained int
	if e := s.DB.QueryRow(`SELECT count(*) FROM lpsecrets.request_nonces`).Scan(&retained); e != nil || retained != 0 {
		t.Fatal("expired nonce state retained", retained, e)
	}
	w = httptest.NewRecorder()
	r.Body = io.NopCloser(bytes.NewReader(body))
	handler(s)(w, r)
	if w.Code != 403 {
		t.Fatal("nonce cleanup revived an expired credential", w.Code)
	}
}

func TestRuntimeClientThroughTerminatingTLSProxy(t *testing.T) {
	s, key, m, _ := dbService(t)
	id := enrolled(t, s, key, m)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			t.Error("test origin must receive plain HTTP")
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
	if !client.IdentityReady() {
		t.Fatal("key and enrolled identity should be ready without a certificate")
	}
	if e := client.Activate(t.Context()); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if _, _, e := client.VersionsAll(t.Context(), nil); e != nil {
			t.Fatal("fresh signed request failed through proxy", e)
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
