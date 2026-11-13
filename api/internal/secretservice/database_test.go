package secretservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/livepeer/control-center/api/internal/testdb"
	"github.com/livepeer/control-center/schema"
	protocol "github.com/livepeer/control-center/secrets"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testOwner = "11111111-1111-4111-8111-111111111111"

type testMetadata struct {
	machine protocol.Machine
	after   func(*protocol.MachineBinding) error
}

func (m *testMetadata) Machine(_ context.Context, _ string, in *protocol.MachineBinding) (protocol.Machine, error) {
	if in != nil {
		if in.Owner != m.machine.Owner {
			return m.machine, protocol.ErrDenied
		}
		if in.ResetKey != "" {
			if m.machine.PublicKey == in.ResetKey {
				m.machine.PublicKey = ""
			}
		} else if in.Activate {
			if in.PublicKey != m.machine.PublicKey {
				return m.machine, protocol.ErrDenied
			}
			m.machine.Managed = true
		} else if m.machine.PublicKey == "" || in.PublicKey == m.machine.PublicKey {
			m.machine.PublicKey = in.PublicKey
		} else {
			return m.machine, protocol.ErrDenied
		}
	}
	if m.after != nil {
		if e := m.after(in); e != nil {
			return m.machine, e
		}
	}
	return m.machine, nil
}

type testTransit struct{ calls atomic.Int64 }

func (v *testTransit) Wrap(_ context.Context, _ string, key []byte) (string, error) {
	v.calls.Add(1)
	return "vault:v1:" + base64.StdEncoding.EncodeToString(key), nil
}
func (v *testTransit) Unwrap(_ context.Context, _ string, wrapped string) ([]byte, error) {
	v.calls.Add(1)
	return base64.StdEncoding.DecodeString(strings.TrimPrefix(wrapped, "vault:v1:"))
}
func dbService(t *testing.T) (*Service, ed25519.PrivateKey, *testMetadata, *testTransit) {
	t.Helper()
	db := testdb.Open(t)
	s := New(db, Config{SigningKey: strings.Repeat("s", 32), SigningKeyID: "current", SupabaseURL: "https://auth.example"})
	if e := s.Migrate(t.Context()); e != nil {
		t.Fatal(e)
	}
	s.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: ioBody(`{"id":"` + testOwner + `"}`)}, nil
	})
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caKey.Public(), caKey)
	if e != nil {
		t.Fatal(e)
	}
	s.Config.CA, _ = x509.ParseCertificate(der)
	s.Config.CAKey = caKey
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	m := &testMetadata{machine: protocol.Machine{NodeID: "test-node", Owner: testOwner, Active: true, PublicKey: base64.StdEncoding.EncodeToString(pub), EncryptionReady: true, PolicyGeneration: 1}}
	s.Metadata = m
	v := &testTransit{}
	s.Transit = v
	return s, key, m, v
}
func ioBody(s string) *bodyReader { return &bodyReader{strings.NewReader(s)} }

type bodyReader struct{ *strings.Reader }

func (*bodyReader) Close() error { return nil }
func call(t *testing.T, s *Service, path, method, token string, in any, cert *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(in)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert, s.Config.CA}}}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func enrolled(t *testing.T, s *Service, key ed25519.PrivateKey, m *testMetadata) *x509.Certificate {
	t.Helper()
	grant, _, _ := s.Grant(testOwner)
	public := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	in := protocol.EnrollRequest{NodeID: m.machine.NodeID, PublicKey: public, Signature: ed25519.Sign(key, protocol.Proof(m.machine.NodeID, public)), EncryptionReady: true}
	w := call(t, s, "/v1/machines/enroll", "POST", grant, in, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var id protocol.Identity
	_ = json.Unmarshal(w.Body.Bytes(), &id)
	block, _ := pem.Decode(id.Certificate)
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	if w := call(t, s, "/v1/machines/activate", "POST", "", map[string]bool{"admission_ready": true}, cert); w.Code != 200 {
		t.Fatal("activation failed", w.Code, w.Body.String())
	}
	return cert
}
func TestDatabaseStatelessGrantsRevocationAndIdentity(t *testing.T) {
	s, key, m, vault := dbService(t)
	for range 20 {
		w := call(t, s, "/v1/enrollment-grants", "POST", "operator", nil, nil)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	for _, table := range []string{"revoked_grants", "identities", "versions", "secrets", "audit", "challenges"} {
		var count int
		if e := s.DB.QueryRow("SELECT count(*) FROM lpsecrets." + table).Scan(&count); e != nil || count != 0 {
			t.Fatal(table, count, e)
		}
	}
	if vault.calls.Load() != 0 {
		t.Fatal("issuance called Vault")
	}
	grant, _, _ := s.Grant(testOwner)
	c, _ := s.grant(grant, false)
	for range 2 {
		w := call(t, s, "/v1/enrollment-grants/revoke", "POST", "operator", map[string]string{"token": grant}, nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	var n int
	_ = s.DB.QueryRow(`SELECT count(*) FROM lpsecrets.revoked_grants WHERE jti=$1`, c.ID).Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
	in := protocol.EnrollRequest{NodeID: m.machine.NodeID, PublicKey: m.machine.PublicKey, Signature: ed25519.Sign(key, protocol.Proof(m.machine.NodeID, m.machine.PublicKey)), EncryptionReady: true}
	if w := call(t, s, "/v1/machines/enroll", "POST", grant, in, nil); w.Code != 401 {
		t.Fatal(w.Code, w.Body.String())
	}
	cert := enrolled(t, s, key, m)
	if cert.Subject.CommonName != m.machine.NodeID {
		t.Fatal("identity")
	}
	_ = enrolled(t, s, key, m)
	_ = s.DB.QueryRow(`SELECT count(*) FROM lpsecrets.audit WHERE action='machine.enroll'`).Scan(&n)
	if n != 1 {
		t.Fatal("retry duplicated enrollment audit", n)
	}
	_ = s.DB.QueryRow(`SELECT count(*) FROM lpsecrets.audit WHERE action='grant.revoke'`).Scan(&n)
	if n != 1 {
		t.Fatal("retry duplicated revocation audit", n)
	}
	s.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if w := call(t, s, "/v1/enrollment-grants/revoke", "POST", "operator", map[string]string{"token": grant}, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if e := s.Collect(t.Context()); e != nil {
		t.Fatal(e)
	}
	if e := s.DB.QueryRow(`SELECT count(*) FROM lpsecrets.revoked_grants`).Scan(&n); e != nil || n != 0 {
		t.Fatal("expired revocations require no retained entry", n, e)
	}
}

func TestRevocationRechecksExpiryAfterWaitingForGrantLock(t *testing.T) {
	s, _, _, _ := dbService(t)
	var clock atomic.Int64
	clock.Store(time.Now().Unix())
	s.Now = func() time.Time { return time.Unix(clock.Load(), 0) }
	grant, _, _ := s.Grant(testOwner)
	c, _ := s.grant(grant, false)
	tx, e := s.DB.BeginTx(t.Context(), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = lockGrant(t.Context(), tx, c.ID); e != nil {
		t.Fatal(e)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- call(t, s, "/v1/enrollment-grants/revoke", "POST", "operator", map[string]string{"token": grant}, nil)
	}()
	// Wait until the request passed validation and is blocked behind acceptance.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting bool
		e = s.DB.QueryRow(`SELECT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))`).Scan(&waiting)
		if e != nil || time.Now().After(deadline) {
			_ = tx.Rollback()
			<-done
			t.Fatal("revocation did not reach the grant lock", e)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	clock.Add(3600)
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	w := <-done
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"changed":false`) {
		t.Fatal(w.Code, w.Body.String())
	}
	var count int
	if e = s.DB.QueryRow(`SELECT count(*) FROM lpsecrets.revoked_grants`).Scan(&count); e != nil || count != 0 {
		t.Fatal("expired revocation retained state", count, e)
	}
}

func TestConcurrentEnrollmentAndRevocation(t *testing.T) {
	s, key, m, _ := dbService(t)
	in := protocol.EnrollRequest{NodeID: m.machine.NodeID, PublicKey: m.machine.PublicKey, Signature: ed25519.Sign(key, protocol.Proof(m.machine.NodeID, m.machine.PublicKey)), EncryptionReady: true}
	for range 5 {
		grant, _, _ := s.Grant(testOwner)
		start := make(chan struct{})
		enrollment, revocation := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
		go func() {
			<-start
			enrollment <- call(t, s, "/v1/machines/enroll", "POST", grant, in, nil)
		}()
		go func() {
			<-start
			revocation <- call(t, s, "/v1/enrollment-grants/revoke", "POST", "operator", map[string]string{"token": grant}, nil)
		}()
		close(start)
		a, b := <-enrollment, <-revocation
		if (a.Code != 200 && a.Code != 401) || b.Code != 200 {
			t.Fatal(a.Code, a.Body.String(), b.Code, b.Body.String())
		}
		if w := call(t, s, "/v1/machines/enroll", "POST", grant, in, nil); w.Code != 401 {
			t.Fatal("enrollment after committed revocation", w.Code, w.Body.String())
		}
	}
}

func TestExpiredCertificateRecoveryIsSingleUseAndChecksEligibility(t *testing.T) {
	s, key, metadata, _ := dbService(t)
	cert := enrolled(t, s, key, metadata)
	now := cert.NotAfter.Add(time.Minute)
	s.Now = func() time.Time { return now }
	node := metadata.machine.NodeID
	challenge := func() (string, []byte) {
		t.Helper()
		w := call(t, s, "/v1/machines/recover", "POST", "", map[string]string{"node_id": node}, nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var v struct {
			ID    string `json:"challenge_id"`
			Nonce []byte `json:"nonce"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &v)
		return v.ID, ed25519.Sign(key, append([]byte("lpcc-recovery-v1\n"+v.ID+"\n"), v.Nonce...))
	}
	id, signature := challenge()
	if again, sig := challenge(); again != id || !bytes.Equal(sig, signature) {
		t.Fatal("challenge retry replaced an unexpired challenge")
	}
	in := map[string]any{"node_id": node, "challenge_id": id, "signature": signature}
	if w := call(t, s, "/v1/machines/recover", "POST", "", in, nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call(t, s, "/v1/machines/recover", "POST", "", in, nil); w.Code != 403 {
		t.Fatal("replayed recovery challenge", w.Code)
	}
	id, signature = challenge()
	now = now.Add(time.Minute)
	in = map[string]any{"node_id": node, "challenge_id": id, "signature": signature}
	if w := call(t, s, "/v1/machines/recover", "POST", "", in, nil); w.Code != 403 {
		t.Fatal("expired recovery challenge", w.Code)
	}
	if fresh, _ := challenge(); fresh == id {
		t.Fatal("expired challenge was reused")
	}
	for _, unavailable := range []string{"retired", "encryption"} {
		metadata.machine.Active = unavailable != "retired"
		metadata.machine.EncryptionReady = unavailable != "encryption"
		if w := call(t, s, "/v1/machines/recover", "POST", "", map[string]string{"node_id": node}, nil); w.Code != 403 {
			t.Fatal("ineligible identity recovered", unavailable, w.Code)
		}
	}
	metadata.machine.Active, metadata.machine.EncryptionReady = true, true
	if w := call(t, s, "/v1/machines/"+node+"/revoke", "POST", "operator", nil, nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call(t, s, "/v1/machines/recover", "POST", "", map[string]string{"node_id": node}, nil); w.Code != 403 {
		t.Fatal("revoked identity recovered", w.Code)
	}
	if w := call(t, s, "/v1/machines/renew", "POST", "", nil, cert); w.Code != 403 {
		t.Fatal("revoked identity renewed", w.Code)
	}
}

func TestHeadlessEncryptedUploadResolveDelete(t *testing.T) {
	s, key, m, vault := dbService(t)
	cert := enrolled(t, s, key, m)
	var def schema.DefinitionV1
	raw, e := osReadFixture()
	if e != nil {
		t.Fatal(e)
	}
	def, e = schema.DecodeCanonical(raw)
	if e != nil {
		t.Fatal(e)
	}
	def.Container.Secrets = []schema.SecretEnvironment{{Name: "API_TOKEN", Secret: "lp-app-provider", Key: "token"}}
	canonical, _ := schema.CanonicalBytes(def)
	ref := schema.RevisionRef{RevisionID: "22222222-2222-4222-8222-222222222222", Digest: schema.Digest(canonical)}
	a := schema.AppAssignment{RevisionRef: ref, Generation: 1, ActivationGeneration: 1, Desired: "present", StartAllowed: true, Replicas: 1, Revision: &schema.ResolvedRevision{Definition: def}}
	m.machine.Assignments = []schema.AppAssignment{a}
	request := protocol.ResolveRequest{RevisionID: a.RevisionID, Generation: 1, Activation: 1, Digest: a.Digest}
	checkFault := func(in protocol.ResolveRequest, want string) {
		t.Helper()
		w := call(t, s, "/v1/runtime/batch", "POST", "", map[string]any{"assignments": []protocol.ResolveRequest{in}}, cert)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"`+want+`"`) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	checkFault(request, "secret_unprovisioned")
	stale := request
	stale.Generation++
	checkFault(stale, "assignment_changed")
	m.machine.DeniedRevisions = []string{a.RevisionID}
	checkFault(request, "secrets_denied")
	m.machine.DeniedRevisions = nil
	w := call(t, s, "/v1/secrets/reserve", "POST", "operator", map[string]any{"name": "lp-app-provider", "key": "token", "expected_revision": 0}, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var binding protocol.Binding
	_ = json.Unmarshal(w.Body.Bytes(), &binding)
	encrypted, dek, e := protocol.Encrypt(binding, []byte("value-sentinel"))
	if e != nil {
		t.Fatal(e)
	}
	w = call(t, s, "/v1/secrets/"+binding.ID+"/wrap", "POST", "operator", map[string]any{"version_id": binding.Version, "data_key": dek}, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var wrapped struct {
		Key string `json:"wrapped_key"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &wrapped)
	encrypted.WrappedKey = wrapped.Key
	w = call(t, s, "/v1/secrets/"+binding.ID, "PUT", "operator", encrypted, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	in := protocol.ResolveRequest{RevisionID: a.RevisionID, Generation: 1, Activation: 1, Digest: a.Digest}
	before := vault.calls.Load()
	bad := in
	bad.RevisionID = "33333333-3333-4333-8333-333333333333"
	if w = call(t, s, "/v1/runtime/resolve", "POST", "", bad, cert); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if vault.calls.Load() != before {
		t.Fatal("unauthorized request reached Vault")
	}
	w = call(t, s, "/v1/runtime/resolve", "POST", "", in, cert)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var set protocol.VersionSet
	_ = json.Unmarshal(w.Body.Bytes(), &set)
	if len(set.Values) != 1 {
		t.Fatal("values")
	}
	plain, e := protocol.Decrypt(set.Values[0].Ciphertext, set.Values[0].DataKey)
	if e != nil || string(plain) != "value-sentinel" {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE lpsecrets.versions SET created_at=now()-interval '30 days' WHERE id=$1`, binding.Version); e != nil {
		t.Fatal(e)
	}
	oldVersion := binding.Version
	w = call(t, s, "/v1/secrets/reserve", "POST", "operator", map[string]any{"name": binding.Name, "key": binding.Key, "expected_revision": 2}, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	_ = json.Unmarshal(w.Body.Bytes(), &binding)
	encrypted, dek, e = protocol.Encrypt(binding, []byte("replacement-sentinel"))
	if e != nil {
		t.Fatal(e)
	}
	w = call(t, s, "/v1/secrets/"+binding.ID+"/wrap", "POST", "operator", map[string]any{"version_id": binding.Version, "data_key": dek}, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	_ = json.Unmarshal(w.Body.Bytes(), &wrapped)
	encrypted.WrappedKey = wrapped.Key
	w = call(t, s, "/v1/secrets/"+binding.ID, "PUT", "operator", encrypted, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	in.Expected = set.Digest
	before = vault.calls.Load()
	if w = call(t, s, "/v1/runtime/resolve", "POST", "", in, cert); w.Code != 409 || vault.calls.Load() != before {
		t.Fatal("superseded version authorized a new start", w.Code)
	}
	in.Expected = ""
	if e = s.Collect(t.Context()); e != nil {
		t.Fatal(e)
	}
	var retained int
	if e = s.DB.QueryRow(`SELECT count(*) FROM lpsecrets.versions WHERE id=$1`, oldVersion).Scan(&retained); e != nil || retained != 1 {
		t.Fatal("replacement retention started at original creation", retained, e)
	}
	now := time.Now().Add(7*24*time.Hour + time.Minute)
	s.Now = func() time.Time { return now }
	if e = s.Collect(t.Context()); e != nil {
		t.Fatal(e)
	}
	if e = s.DB.QueryRow(`SELECT count(*) FROM lpsecrets.versions WHERE id=$1`, oldVersion).Scan(&retained); e != nil || retained != 0 {
		t.Fatal("superseded payload survived retention", retained, e)
	}
	w = call(t, s, "/v1/secrets/"+binding.ID, "DELETE", "operator", map[string]int{"expected_revision": 3}, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = call(t, s, "/v1/runtime/resolve", "POST", "", in, cert)
	if w.Code != 409 {
		t.Fatal("deleted value resolved", w.Code)
	}
	m.machine.Consumers = []protocol.SecretConsumer{{RevisionID: "44444444-4444-4444-8444-444444444444", References: def.Container.Secrets}}
	before = vault.calls.Load()
	w = call(t, s, "/v1/runtime/batch", "POST", "", map[string]any{"assignments": []protocol.ResolveRequest{}}, cert)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"44444444-4444-4444-8444-444444444444":"secret_missing"`) || vault.calls.Load() != before {
		t.Fatal("cleanup observation missing or accessed Transit", w.Code, w.Body.String())
	}
	var n int
	_ = s.DB.QueryRow(`SELECT count(*) FROM lpsecrets.versions`).Scan(&n)
	if n != 0 {
		t.Fatal("deleted encrypted payload retained")
	}
}
func osReadFixture() ([]byte, error) {
	return os.ReadFile("../../../schema/testdata/minimal.canonical.json")
}

func TestResetFencesEveryPreviousKeyAndCertificate(t *testing.T) {
	s, key, metadata, _ := dbService(t)
	old := enrolled(t, s, key, metadata)
	initialKey := key
	server := httptest.NewUnstartedServer(s.Handler())
	server.TLS = s.TLSConfig()
	server.StartTLS()
	defer server.Close()
	renewTLS := func(cert *x509.Certificate, key ed25519.PrivateKey, want int) {
		t.Helper()
		pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), protocol.PrivatePEM(key))
		if e != nil {
			t.Fatal(e)
		}
		tr := server.Client().Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.Certificates = []tls.Certificate{pair}
		defer tr.CloseIdleConnections()
		res, e := (&http.Client{Transport: tr}).Post(server.URL+"/v1/machines/renew", "application/json", strings.NewReader(`{}`))
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != want {
			t.Fatal("real mTLS reset fencing", res.StatusCode, want)
		}
	}
	grant, _, _ := s.Grant(testOwner)
	for epoch := int64(2); epoch <= 3; epoch++ {
		node := metadata.machine.NodeID
		if w := call(t, s, "/v1/machines/"+node+"/reset", "POST", "operator", nil, nil); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		for _, retired := range []ed25519.PrivateKey{initialKey, key} {
			public := base64.StdEncoding.EncodeToString(retired.Public().(ed25519.PublicKey))
			in := protocol.EnrollRequest{NodeID: node, PublicKey: public, Signature: ed25519.Sign(retired, protocol.Proof(node, public)), EncryptionReady: true}
			if w := call(t, s, "/v1/machines/enroll", "POST", grant, in, nil); w.Code != 409 {
				t.Fatal("reset reused a retired key", w.Code, w.Body.String())
			}
		}
		previousKey := key
		_, key, _ = ed25519.GenerateKey(rand.Reader)
		current := enrolled(t, s, key, metadata)
		if current.URIs[0].Path != "/"+big.NewInt(epoch).String() {
			t.Fatal("reset epoch regressed", current.URIs[0].Path)
		}
		restarted := New(s.DB, s.Config)
		restarted.Metadata = metadata
		if _, _, e := restarted.machine(&http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{old}, VerifiedChains: [][]*x509.Certificate{{old, s.Config.CA}}}}); e != protocol.ErrDenied {
			t.Fatal("old certificate revived", e)
		}
		if w := call(t, s, "/v1/machines/renew", "POST", "", nil, current); w.Code != 200 {
			t.Fatal("replacement identity refused", w.Code, w.Body.String())
		}
		renewTLS(old, previousKey, 403)
		renewTLS(current, key, 200)
		old = current
	}
}

func TestRevokeCancelsPendingReset(t *testing.T) {
	s, key, metadata, _ := dbService(t)
	enrolled(t, s, key, metadata)
	node := metadata.machine.NodeID
	for _, action := range []string{"reset", "revoke"} {
		w := call(t, s, "/v1/machines/"+node+"/"+action, "POST", "operator", nil, nil)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", action, w.Code, w.Body.String())
		}
	}
	_, replacement, _ := ed25519.GenerateKey(rand.Reader)
	public := base64.StdEncoding.EncodeToString(replacement.Public().(ed25519.PublicKey))
	grant, _, _ := s.Grant(testOwner)
	in := protocol.EnrollRequest{NodeID: node, PublicKey: public, Signature: ed25519.Sign(replacement, protocol.Proof(node, public)), EncryptionReady: true}
	w := call(t, s, "/v1/machines/enroll", "POST", grant, in, nil)
	if w.Code != 409 {
		t.Fatal("revocation after reset did not close reset enrollment", w.Code, w.Body.String())
	}
	if w = call(t, s, "/v1/machines/"+node+"/reset", "POST", "operator", nil, nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = call(t, s, "/v1/machines/enroll", "POST", grant, in, nil); w.Code != 200 {
		t.Fatal("explicit reset after revoke did not reopen enrollment", w.Code, w.Body.String())
	}
}

func TestEnrollmentActivationRequiresInstalledIdentity(t *testing.T) {
	for _, failure := range []string{"certificate", "expiry", "encryption", "lost-response"} {
		t.Run(failure, func(t *testing.T) {
			s, key, metadata, _ := dbService(t)
			metadata.machine.PublicKey = ""
			grant, _, _ := s.Grant(testOwner)
			public := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
			in := protocol.EnrollRequest{NodeID: metadata.machine.NodeID, PublicKey: public, Signature: ed25519.Sign(key, protocol.Proof(metadata.machine.NodeID, public)), EncryptionReady: failure != "encryption"}
			if failure == "certificate" {
				s.Config.CA = nil
			}
			if failure == "expiry" {
				metadata.after = func(*protocol.MachineBinding) error {
					s.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
					return nil
				}
			}
			w := call(t, s, "/v1/machines/enroll", "POST", grant, in, nil)
			if metadata.machine.Managed {
				t.Fatal("failed or uninstalled enrollment became managed")
			}
			if failure != "lost-response" {
				if w.Code == 200 {
					t.Fatal("failure accepted", failure)
				}
				return
			}
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			var id protocol.Identity
			_ = json.Unmarshal(w.Body.Bytes(), &id)
			block, _ := pem.Decode(id.Certificate)
			cert, e := x509.ParseCertificate(block.Bytes)
			if e != nil {
				t.Fatal(e)
			}
			if w = call(t, s, "/v1/runtime/batch", "POST", "", map[string]any{"assignments": []any{}}, cert); w.Code != 503 {
				t.Fatal("pending identity authorized resolution", w.Code)
			}
			// A retry after a lost response preserves the binding and remains pending.
			w = call(t, s, "/v1/machines/enroll", "POST", grant, in, nil)
			if w.Code != 200 || metadata.machine.Managed {
				t.Fatal("pending retry", w.Code)
			}
			if w = call(t, s, "/v1/machines/activate", "POST", "", map[string]bool{"admission_ready": true}, cert); w.Code != 200 || !metadata.machine.Managed {
				t.Fatal("installed identity did not activate", w.Code)
			}
		})
	}
}

func TestResetSurvivesLostRemoteResponse(t *testing.T) {
	s, key, metadata, _ := dbService(t)
	old := enrolled(t, s, key, metadata)
	node := metadata.machine.NodeID
	metadata.after = func(in *protocol.MachineBinding) error {
		if in != nil && in.ResetKey != "" {
			return protocol.ErrUnavailable
		}
		return nil
	}
	if w := call(t, s, "/v1/machines/"+node+"/reset", "POST", "operator", nil, nil); w.Code != 503 {
		t.Fatal(w.Code)
	}
	var revoked, pending bool
	var generation int64
	if e := s.DB.QueryRow(`SELECT revoked,reset_pending,generation FROM lpsecrets.identities WHERE node_id=$1`, node).Scan(&revoked, &pending, &generation); e != nil || !revoked || !pending || generation != 2 {
		t.Fatal("reset not durable", revoked, pending, generation, e)
	}
	metadata.after = nil
	restarted := New(s.DB, s.Config)
	restarted.Metadata = metadata
	restarted.HTTP = s.HTTP
	if w := call(t, restarted, "/v1/machines/renew", "POST", "", nil, old); w.Code != 403 {
		t.Fatal("old cert revived", w.Code)
	}
	if w := call(t, restarted, "/v1/machines/"+node+"/reset", "POST", "operator", nil, nil); w.Code != 200 {
		t.Fatal("reset retry failed", w.Code, w.Body.String())
	}
	_, replacement, _ := ed25519.GenerateKey(rand.Reader)
	current := enrolled(t, restarted, replacement, metadata)
	if current.URIs[0].Path != "/2" {
		t.Fatal("reset retry changed epoch", current.URIs[0].Path)
	}
	// A delayed clear may only clear the retired binding, never its successor.
	_, e := metadata.Machine(t.Context(), node, &protocol.MachineBinding{EnrollRequest: protocol.EnrollRequest{NodeID: node}, Owner: testOwner, ResetKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))})
	if e != nil || metadata.machine.PublicKey == "" {
		t.Fatal("late reset erased successor", e)
	}
}

func TestOwnerCanResetPendingBindingWithoutCommittedIdentity(t *testing.T) {
	s, key, m, _ := dbService(t)
	oldKey := m.machine.PublicKey
	node := m.machine.NodeID
	if w := call(t, s, "/v1/machines/"+node+"/reset", "POST", "operator", nil, nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if m.machine.PublicKey != "" {
		t.Fatal("pending key not cleared")
	}
	grant, _, _ := s.Grant(testOwner)
	in := protocol.EnrollRequest{NodeID: node, PublicKey: oldKey, Signature: ed25519.Sign(key, protocol.Proof(node, oldKey)), EncryptionReady: true}
	if w := call(t, s, "/v1/machines/enroll", "POST", grant, in, nil); w.Code != 409 {
		t.Fatal("retired pending key accepted", w.Code)
	}
	_, replacement, _ := ed25519.GenerateKey(rand.Reader)
	enrolled(t, s, replacement, m)
}
