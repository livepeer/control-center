package secrets

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const RequestIssuer = "lpcc-secrets-runtime-v1"
const RequestLifetime = time.Minute

// RequestClaims bind a one-use credential to an enrolled identity and exact
// request. Audience is the public HTTPS origin, independent of proxy headers.
type RequestClaims struct {
	jwt.RegisteredClaims
	Generation int64  `json:"generation"`
	Digest     string `json:"request"`
}

// RequestDigest hashes compact JSON [method, request-target, hex(SHA256(body))].
// Proxies must preserve the method, escaped path, query and body bytes.
func RequestDigest(r *http.Request, body []byte) string {
	h := sha256.Sum256(body)
	b, _ := json.Marshal([]string{r.Method, r.URL.RequestURI(), hex.EncodeToString(h[:])})
	h = sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func SignRequest(r *http.Request, body []byte, id Identity, key ed25519.PrivateKey, now time.Time) error {
	if r.URL.Scheme != "https" || r.URL.Host == "" || id.NodeID == "" || id.Generation < 1 || len(key) != ed25519.PrivateKeySize {
		return ErrInvalid
	}
	now = now.Truncate(time.Second)
	c := RequestClaims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: RequestIssuer, Subject: id.NodeID, Audience: jwt.ClaimStrings{r.URL.Scheme + "://" + r.URL.Host},
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(RequestLifetime)), ID: rand.Text(),
	}, Generation: id.Generation, Digest: RequestDigest(r, body)}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	// Select an enrolled or retired key before checking identity revocation.
	t.Header["kid"] = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	token, e := t.SignedString(key)
	if e == nil {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return e
}
