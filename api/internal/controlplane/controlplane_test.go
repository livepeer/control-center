package controlplane

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/livepeer/control-center/api/internal/testdb"
)

const ownerA = "11111111-1111-4111-8111-111111111111"
const ownerB = "22222222-2222-4222-8222-222222222222"

func testParams() Params {
	return Params{JWTSigningSecret: strings.Repeat("a", 32), MachineTokenSecret: strings.Repeat("b", 32), PublicAPIURL: "https://api.example", SupabasePublishableKey: "public-test", ConfigReconcileInterval: time.Minute}
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

func TestConfigurationBundle(t *testing.T) {
	m := Machine{NodeID: "lp-" + strings.Repeat("a", 16), InstallDir: "/srv/livepeer", K3sVersion: "v1.37.2+k3s1"}
	first, digest, err := buildBundle(m)
	if err != nil {
		t.Fatal(err)
	}
	second, other, err := buildBundle(m)
	if err != nil || !bytes.Equal(first, second) || digest != other {
		t.Fatal("archive is not deterministic", err)
	}
	files := archiveFiles(t, first)
	for _, name := range []string{"kustomization.yaml", "orchestrator.yaml", "suc.yaml", "suc-crd.yaml", "upgrade-plan/kustomization.yaml", "upgrade-plan/plan.yaml"} {
		if _, ok := files[name]; !ok {
			t.Fatal("missing", name)
		}
	}
	for name, expected := range map[string]string{
		"suc-crd.yaml": "1393ba034e7691273fc519b721a7f72a0cdbef8c7b051c9e408be96090b8478d",
		"suc.yaml":     "81ef8c40f85b8822c87e0cf790612fc6d4dcf1eebb83f89e522bc929ef85e18c",
	} {
		hash := sha256.Sum256([]byte(files[name]))
		if hex.EncodeToString(hash[:]) != expected {
			t.Fatalf("rendering changed pinned asset %s", name)
		}
	}
	if strings.Contains(files["orchestrator.yaml"], "@INSTALL_DIR@") || strings.Contains(files["orchestrator.yaml"], "@NODE_ID@") || !strings.Contains(files["orchestrator.yaml"], "/srv/livepeer/volumes/orchestrator") {
		t.Fatal("incorrect machine rendering")
	}
	if !strings.Contains(files["upgrade-plan/plan.yaml"], m.K3sVersion) {
		t.Fatal("upgrade plan version missing")
	}
	hash := sha256.Sum256(first)
	if hex.EncodeToString(hash[:]) != digest {
		t.Fatal("wrong digest")
	}
}

func archiveFiles(t *testing.T, data []byte) map[string]string {
	t.Helper()
	z, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	tarReader := tar.NewReader(io.LimitReader(z, 64<<20))
	files := map[string]string{}
	for {
		h, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg || strings.HasPrefix(h.Name, "/") || strings.Contains(h.Name, "..") {
			t.Fatal("unsafe archive member")
		}
		if _, ok := files[h.Name]; ok {
			t.Fatal("duplicate archive member")
		}
		contents, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatal(err)
		}
		files[h.Name] = string(contents)
	}
	return files
}

func newTestServer(t *testing.T) *Server {
	db := testdb.Open(t)
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO auth.users(id) VALUES($1),($2)`, ownerA, ownerB); err != nil {
		t.Fatal(err)
	}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/v1/user" || r.Header.Get("apikey") != "public-test" {
			w.WriteHeader(401)
			return
		}
		owner := ""
		switch r.Header.Get("Authorization") {
		case "Bearer session-a":
			owner = ownerA
		case "Bearer session-b":
			owner = ownerB
		default:
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id": owner})
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

func enroll(t *testing.T, s *Server, owner, fingerprint string) map[string]string {
	t.Helper()
	token, _, _ := signEnrollment(s.params.JWTSigningSecret, owner, time.Now())
	w := request(t, s, "POST", "/v1/nodes/register", token, map[string]string{"fingerprint": fingerprint, "hostname": "worker-01", "install_dir": "/opt/livepeer", "k3s_version": "v1.37.2+k3s1"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
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
	s.build = func(m Machine) ([]byte, string, error) { m.InstallDir = "/srv/changed"; return buildBundle(m) }
	if err := s.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	var changed string
	if err := s.db.QueryRow(`SELECT sha256 FROM lpcc.machine_configs WHERE node_id=$1`, id).Scan(&changed); err != nil || changed == beforeDigest {
		t.Fatal("new backend config not persisted", err)
	}
	s.build = func(Machine) ([]byte, string, error) { return nil, "", errors.New("invalid desired config") }
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
	s.build = func(Machine) ([]byte, string, error) { return nil, "", errors.New("generation failed") }
	if w := request(t, s, "POST", "/v1/nodes/register", token, body); w.Code != 503 {
		t.Fatal(w.Code)
	}
	// Simulate a persistence failure after inserting the machine: a bad digest
	// violates the bundle constraint, so both inserts must roll back.
	s.build = func(Machine) ([]byte, string, error) { return []byte("bundle"), "bad-digest", nil }
	if w := request(t, s, "POST", "/v1/nodes/register", token, body); w.Code != 503 {
		t.Fatal(w.Code)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM lpcc.machines`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed registration left a machine row", count, err)
	}
}
