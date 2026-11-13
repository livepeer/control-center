package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/livepeer/control-center/runtime/artifact"
	protocol "github.com/livepeer/control-center/secrets"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/api/internal/testdb"
)

const ownerA = "11111111-1111-4111-8111-111111111111"
const ownerB = "22222222-2222-4222-8222-222222222222"
const ownerC = "33333333-3333-4333-8333-333333333333"

func testParams() Params {
	return Params{RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64), RuntimeNodeImage: "registry.invalid/node@sha256:" + strings.Repeat("b", 64), RuntimeConnectorImage: "registry.invalid/connector@sha256:" + strings.Repeat("c", 64), AppStopSignals: true, JWTSigningSecret: strings.Repeat("a", 32), MachineTokenSecret: strings.Repeat("b", 32), PublicAPIURL: "https://api.example", SupabasePublishableKey: "public-test", ConfigReconcileInterval: time.Minute}
}

func TestEnrollmentAuthorization(t *testing.T) {
	p := testParams()
	good, _, err := signEnrollment(p.JWTSigningSecret, ownerA, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if owner, err := verifyEnrollment(p.JWTSigningSecret, good); err != nil || owner != ownerA {
		t.Fatal(owner, err)
	}
	expired, _, _ := signEnrollment(p.JWTSigningSecret, ownerA, time.Now().Add(-2*time.Hour))
	for name, raw := range map[string]string{"expired": expired, "modified": good + "x", "malformed": "nope"} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifyEnrollment(p.JWTSigningSecret, raw); err == nil {
				t.Fatal("accepted invalid JWT")
			}
		})
	}
	for _, change := range []func(*enrollmentClaims){
		func(c *enrollmentClaims) { c.Issuer = "other" }, func(c *enrollmentClaims) { c.Audience = jwt.ClaimStrings{"other"} },
		func(c *enrollmentClaims) { c.Scope = "other" }, func(c *enrollmentClaims) { c.Subject = "not-a-user" },
		func(c *enrollmentClaims) { c.ExpiresAt = nil },
	} {
		claims := enrollmentClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: enrollmentIssuer, Subject: ownerA, Audience: jwt.ClaimStrings{enrollmentAudience}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}, Scope: "machines:register"}
		change(&claims)
		raw, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(p.JWTSigningSecret))
		if _, err := verifyEnrollment(p.JWTSigningSecret, raw); err == nil {
			t.Fatal("accepted wrong claims")
		}
	}
	claims := jwt.RegisteredClaims{Issuer: enrollmentIssuer, Subject: ownerA, Audience: jwt.ClaimStrings{enrollmentAudience}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}
	raw, _ := jwt.NewWithClaims(jwt.SigningMethodHS384, claims).SignedString([]byte(p.JWTSigningSecret))
	if _, err := verifyEnrollment(p.JWTSigningSecret, raw); err == nil {
		t.Fatal("accepted wrong signing algorithm")
	}
}

func archiveFiles(t *testing.T, data []byte) map[string]string {
	t.Helper()
	members, err := artifact.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]string, len(members))
	for name, contents := range members {
		files[name] = string(contents)
	}
	return files
}

func newTestServer(t *testing.T) *Server {
	db := testdb.Open(t)
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO auth.users(id,email,email_confirmed_at) VALUES($1,'a@example.invalid',now()),($2,'b@example.invalid',now())`, ownerA, ownerB); err != nil {
		t.Fatal(err)
	}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apikey") != "public-test" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/auth/v1/settings" {
			json.NewEncoder(w).Encode(map[string]bool{"mailer_autoconfirm": false})
			return
		}
		if r.URL.Path != "/auth/v1/user" {
			w.WriteHeader(404)
			return
		}
		owner := ""
		switch r.Header.Get("Authorization") {
		case "Bearer session-a":
			owner = ownerA
		case "Bearer session-b":
			owner = ownerB
		case "Bearer session-c":
			owner = ownerC
		default:
			w.WriteHeader(401)
			return
		}
		var email *string
		var confirmed *time.Time
		if err := db.QueryRow(`SELECT email,email_confirmed_at FROM auth.users WHERE id=$1 AND deleted_at IS NULL`, owner).Scan(&email, &confirmed); err != nil {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": owner, "email": email, "email_confirmed_at": confirmed, "user_metadata": map[string]any{"role": "admin"}})
	}))
	t.Cleanup(auth.Close)
	p := testParams()
	p.SupabaseURL = auth.URL
	return New(db, p, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func request(t *testing.T, s *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(data))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func currentReport(t *testing.T, s *Server, node string, report machineconfig.Report) machineconfig.Report {
	t.Helper()
	report.ReportVersion = 1
	report.ObservedAt = time.Now().UTC()
	var previous uint64
	err := s.db.QueryRow(`SELECT COALESCE((report->>'sequence')::numeric,0) FROM lpcc.machine_reports WHERE node_id=$1 AND component=$2`, node, report.Component).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	report.Sequence = previous + 1
	return report
}

func credentials(t *testing.T, data []byte) map[string]string {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	var resultValue string
	for _, key := range []string{"node_id", "token", "config_url"} {
		if err := json.Unmarshal(raw[key], &resultValue); err != nil {
			t.Fatal(err)
		}
		result[key] = resultValue
	}
	return result
}

func enroll(t *testing.T, s *Server, owner, fingerprint string) map[string]string {
	t.Helper()
	token, _, _ := s.params.signEnrollment(owner, s.currentTime())
	w := request(t, s, "POST", "/v1/nodes/register", token, registrationBody(owner, fingerprint, token))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	return credentials(t, w.Body.Bytes())
}
func registrationBody(owner, fingerprint, token string) map[string]any {
	seed := sha256.Sum256([]byte(owner + fingerprint))
	key := ed25519.NewKeyFromSeed(seed[:])
	pub := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	return map[string]any{"public_key": pub, "signature": ed25519.Sign(key, protocol.RegistrationProof(token, fingerprint, "worker-01", "/opt/livepeer", "v1.37.2+k3s1", pub, false)), "fingerprint": fingerprint, "hostname": "worker-01", "install_dir": "/opt/livepeer", "k3s_version": "v1.37.2+k3s1"}
}

func TestEnrollmentAndConfigFlow(t *testing.T) {
	s := newTestServer(t)
	if w := request(t, s, "POST", "/api/bootstrap-token", "invalid", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(t, s, "POST", "/api/bootstrap-token", "session-a", nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	first := enroll(t, s, ownerA, strings.Repeat("a", 64))
	repeat := enroll(t, s, ownerA, strings.Repeat("a", 64))
	if first["token"] != repeat["token"] || first["node_id"] != repeat["node_id"] {
		t.Fatal("registration retry changed identity")
	}
	second := enroll(t, s, ownerA, strings.Repeat("b", 64))
	enroll(t, s, ownerB, strings.Repeat("c", 64))
	foreign, _, _ := signEnrollment(s.params.JWTSigningSecret, ownerB, time.Now())
	conflict := request(t, s, "POST", "/v1/nodes/register", foreign, map[string]string{"fingerprint": strings.Repeat("a", 64), "hostname": "attacker", "install_dir": "/opt/livepeer", "k3s_version": "v1.37.2+k3s1"})
	if conflict.Code != 409 {
		t.Fatal(conflict.Code)
	}
	path := "/v1/nodes/" + first["node_id"] + "/config"
	for _, token := range []string{"", second["token"], foreign} {
		if w := request(t, s, "GET", path, token, nil); w.Code != 401 {
			t.Fatal("config credential isolation failed", w.Code)
		}
	}
	w := request(t, s, "GET", path, first["token"], nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/gzip" {
		t.Fatal(w.Code)
	}
	archiveFiles(t, w.Body.Bytes())
	if id, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(first["node_id"])); err != nil || len(id) != 16 {
		t.Fatal("node ID must encode 128 random bits as unpadded base32", err)
	}
	for session, count := range map[string]int{"session-a": 2, "session-b": 1} {
		w := request(t, s, "GET", "/api/machines", session, nil)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		var result struct {
			Machines []Machine `json:"machines"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result.Machines) != count {
			t.Fatal(err, w.Body.String())
		}
		if strings.Contains(w.Body.String(), first["token"]) {
			t.Fatal("listed machine credential")
		}
	}
	// Enrollment authorization expiry has no effect on durable machine credentials.
	expired, _, _ := signEnrollment(s.params.JWTSigningSecret, ownerA, time.Now().Add(-2*time.Hour))
	if w := request(t, s, "POST", "/v1/nodes/register", expired, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(t, s, "GET", path, first["token"], nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestReconciliationPreservesLastGoodBundle(t *testing.T) {
	s := newTestServer(t)
	credentials := enroll(t, s, ownerA, strings.Repeat("a", 64))
	id := credentials["node_id"]
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	var beforeDigest string
	var beforeTime time.Time
	if err := s.db.QueryRow(`SELECT sha256,generated_at FROM lpcc.machine_configs WHERE node_id=$1`, id).Scan(&beforeDigest, &beforeTime); err != nil {
		t.Fatal(err)
	}
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	var afterTime time.Time
	if err := s.db.QueryRow(`SELECT generated_at FROM lpcc.machine_configs WHERE node_id=$1`, id).Scan(&afterTime); err != nil || !beforeTime.Equal(afterTime) {
		t.Fatal("unchanged bundle rewritten", err)
	}
	// Upgrade-plan changes can publish while the Node workload is held for drain.
	s.build = func(m machineconfig.Desired) ([]byte, string, error) {
		m.K3sVersion = "v1.37.3+k3s1"
		return machineconfig.Build(m)
	}
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	var changed string
	if err := s.db.QueryRow(`SELECT sha256 FROM lpcc.machine_configs WHERE node_id=$1`, id).Scan(&changed); err != nil || changed == beforeDigest {
		t.Fatal("new backend config not persisted", err)
	}
	s.build = func(machineconfig.Desired) ([]byte, string, error) {
		return nil, "", errors.New("invalid desired config")
	}
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	var kept string
	if err := s.db.QueryRow(`SELECT sha256 FROM lpcc.machine_configs WHERE node_id=$1`, id).Scan(&kept); err != nil || kept != changed {
		t.Fatal("failed generation replaced last good bundle", err)
	}
}

func TestRegistrationFailureIsAtomic(t *testing.T) {
	s := newTestServer(t)
	token, _, _ := signEnrollment(s.params.JWTSigningSecret, ownerA, time.Now())
	body := map[string]string{"fingerprint": strings.Repeat("a", 64), "hostname": "worker", "install_dir": "/opt/livepeer", "k3s_version": "v1.37.2+k3s1"}
	s.build = func(machineconfig.Desired) ([]byte, string, error) { return nil, "", errors.New("generation failed") }
	if w := request(t, s, "POST", "/v1/nodes/register", token, body); w.Code != 503 {
		t.Fatal(w.Code)
	}
	// Simulate a persistence failure after inserting the machine: a bad digest
	// violates the bundle constraint, so both inserts must roll back.
	s.build = func(machineconfig.Desired) ([]byte, string, error) { return []byte("bundle"), "bad-digest", nil }
	if w := request(t, s, "POST", "/v1/nodes/register", token, body); w.Code != 503 {
		t.Fatal(w.Code)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM lpcc.machines`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed registration left a machine row", count, err)
	}
}
