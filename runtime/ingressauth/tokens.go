// Package ingressauth implements local discovery and telemetry token signing
// and verification. The two token kinds have distinct audiences and scopes and
// neither verifier accepts the other's tokens.
package ingressauth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const Issuer = "livepeer-control-center"
const Audience = "livepeer-discovery"
const Scope = "discovery:read"
const Lifetime = 5 * time.Minute
const ClockTolerance = 30 * time.Second

// Telemetry write tokens are minted for one enrollment credential and verified
// only by Control Center's ingest endpoints, never by machine ingress.
const TelemetryAudience = "livepeer-telemetry"
const TelemetryScope = "telemetry:write"
const MaxTelemetryLifetime = time.Hour

var machineID = regexp.MustCompile(`^[a-z2-7]{26}$`)
var orchestratorAddress = regexp.MustCompile(`^0x[0-9a-f]{40}$`)

type Keys map[string]ed25519.PublicKey

func ParseKeys(data []byte) (Keys, error) {
	var encoded map[string]string
	if json.Unmarshal(data, &encoded) != nil || len(encoded) == 0 || len(encoded) > 16 {
		return nil, errors.New("invalid Ed25519 public key map")
	}
	keys := Keys{}
	for id, value := range encoded {
		key, err := base64.StdEncoding.DecodeString(value)
		if id == "" || len(id) > 64 || err != nil || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 public verification key")
		}
		keys[id] = ed25519.PublicKey(key)
	}
	return keys, nil
}

func (keys Keys) JSON() []byte {
	encoded := map[string]string{}
	for id, key := range keys {
		encoded[id] = base64.StdEncoding.EncodeToString(key)
	}
	data, _ := json.Marshal(encoded)
	return data
}

func (keys Keys) Key(token *jwt.Token) (any, error) {
	id, ok := token.Header["kid"].(string)
	if !ok || token.Method != jwt.SigningMethodEdDSA || len(keys[id]) != ed25519.PublicKeySize {
		return nil, errors.New("unknown Ed25519 signing key")
	}
	return keys[id], nil
}

type Signer struct {
	Private ed25519.PrivateKey
	Keys    Keys
}

func Load(privateFile, publicFile, id string) (*Signer, error) {
	data, err := os.ReadFile(privateFile)
	if err != nil {
		return nil, errors.New("cannot read JWTSigningPrivateKeyFile")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("JWTSigningPrivateKeyFile requires an Ed25519 PKCS#8 PEM key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(key) != ed25519.PrivateKeySize || id == "" || len(id) > 64 {
		return nil, errors.New("invalid Ed25519 signing key or key ID")
	}
	keys := Keys{}
	if publicFile != "" {
		data, err := os.ReadFile(publicFile)
		if err != nil {
			return nil, errors.New("cannot read JWTVerificationPublicKeysFile")
		}
		keys, err = ParseKeys(data)
		if err != nil {
			return nil, err
		}
	}
	public := key.Public().(ed25519.PublicKey)
	if existing, ok := keys[id]; ok && !existing.Equal(public) {
		return nil, errors.New("current signing key ID conflicts with a public verification key")
	}
	keys[id] = public
	if len(keys) > 16 {
		return nil, errors.New("public verification key map exceeds 16 keys")
	}
	return &Signer{Private: key, Keys: keys}, nil
}

func (s *Signer) Sign(id string, claims jwt.Claims) (string, error) {
	if s == nil || len(s.Private) != ed25519.PrivateKeySize {
		return "", errors.New("JWT signing key is unavailable")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = id
	return token.SignedString(s.Private)
}

type Claims struct {
	jwt.RegisteredClaims
	Scope string `json:"scope"`
}

func (s *Signer) Discovery(id, node string, now time.Time) (string, error) {
	if !machineID.MatchString(node) {
		return "", errors.New("invalid discovery machine identity")
	}
	now = now.Truncate(time.Second)
	return s.Sign(id, Claims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: Issuer, Audience: jwt.ClaimStrings{Audience}, Subject: node,
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(Lifetime)),
	}, Scope: Scope})
}

func Verify(keys Keys, raw, node string, now time.Time) error {
	c := new(Claims)
	_, err := jwt.ParseWithClaims(raw, c, keys.Key, jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(Issuer), jwt.WithAudience(Audience), jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(), jwt.WithLeeway(ClockTolerance), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !machineID.MatchString(node) || c.Subject != node || c.Scope != Scope ||
		len(c.Audience) != 1 || c.Audience[0] != Audience || c.IssuedAt == nil || c.ExpiresAt == nil ||
		!c.ExpiresAt.After(c.IssuedAt.Time) || c.ExpiresAt.Sub(c.IssuedAt.Time) > Lifetime {
		return errors.New("invalid discovery bearer token")
	}
	return nil
}

// TelemetryClaims bind a write token to one machine credential version so that
// credential refresh and retirement can revoke it before expiry.
type TelemetryClaims struct {
	jwt.RegisteredClaims
	Scope             string `json:"scope"`
	Orchestrator      string `json:"orch"`
	CredentialVersion int64  `json:"cv"`
}

func (s *Signer) Telemetry(id, node, orchestrator string, credentialVersion int64, lifetime time.Duration, now time.Time) (string, time.Time, error) {
	if !machineID.MatchString(node) || !orchestratorAddress.MatchString(orchestrator) || credentialVersion < 1 {
		return "", time.Time{}, errors.New("invalid telemetry machine identity")
	}
	if lifetime < time.Second || lifetime > MaxTelemetryLifetime {
		return "", time.Time{}, errors.New("invalid telemetry token lifetime")
	}
	now = now.Truncate(time.Second)
	expires := now.Add(lifetime)
	raw, err := s.Sign(id, TelemetryClaims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: Issuer, Audience: jwt.ClaimStrings{TelemetryAudience}, Subject: node,
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(expires),
	}, Scope: TelemetryScope, Orchestrator: orchestrator, CredentialVersion: credentialVersion})
	return raw, expires, err
}

// VerifyTelemetry returns the authenticated machine identity of a write token.
// Callers must still confirm the identity matches a current enrollment.
func VerifyTelemetry(keys Keys, raw string, now time.Time) (TelemetryClaims, error) {
	c := new(TelemetryClaims)
	_, err := jwt.ParseWithClaims(raw, c, keys.Key, jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(Issuer), jwt.WithAudience(TelemetryAudience), jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(), jwt.WithLeeway(ClockTolerance), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !machineID.MatchString(c.Subject) || c.Scope != TelemetryScope ||
		!orchestratorAddress.MatchString(c.Orchestrator) || c.CredentialVersion < 1 ||
		len(c.Audience) != 1 || c.Audience[0] != TelemetryAudience || c.IssuedAt == nil || c.ExpiresAt == nil ||
		!c.ExpiresAt.After(c.IssuedAt.Time) || c.ExpiresAt.Sub(c.IssuedAt.Time) > MaxTelemetryLifetime {
		return TelemetryClaims{}, errors.New("invalid telemetry bearer token")
	}
	return *c, nil
}

// Handler is a persistent ForwardAuth endpoint. Authorization uses only the
// bearer and configured machine identity, never client-supplied forwarded data.
func Handler(keys Keys, node string) (http.Handler, error) {
	if !machineID.MatchString(node) || len(keys) == 0 {
		return nil, errors.New("ingress-auth requires verification keys and a machine identity")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Values("Authorization")
		if len(auth) == 1 && len(auth[0]) <= 8192 {
			scheme, raw, ok := strings.Cut(auth[0], " ")
			if ok && strings.EqualFold(scheme, "Bearer") && Verify(keys, raw, node, time.Now()) == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	return mux, nil
}
