// Package secrets defines the browser-independent operator secrets protocol.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/livepeer/control-center/schema"
)

const MaxValue = 64 << 10
const MaxInjected = 256 << 10
const EnvelopePrefix = "lpcc1."
const DefaultURL = "https://controlcenter-secrets.livepeer.live"

var ErrInvalid = errors.New("invalid_secret")
var ErrUnavailable = errors.New("secrets_unavailable")
var ErrDenied = errors.New("secrets_denied")

type Sensitive []byte

func (Sensitive) String() string   { return "[redacted]" }
func (Sensitive) GoString() string { return "[redacted]" }

type Enrollment struct {
	Version int    `json:"version"`
	Control string `json:"control"`
	Setup   string `json:"setup"`
}

func Join(control, setup string) (string, error) {
	if control == "" || setup == "" {
		return "", ErrInvalid
	}
	b, _ := json.Marshal(Enrollment{1, control, setup})
	return EnvelopePrefix + base64.RawURLEncoding.EncodeToString(b), nil
}
func Split(raw string) (Enrollment, error) {
	if !strings.HasPrefix(raw, EnvelopePrefix) {
		if len(strings.Split(raw, ".")) == 3 {
			return Enrollment{Control: raw}, nil
		}
		return Enrollment{}, ErrInvalid
	}
	b, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(raw, EnvelopePrefix))
	if e != nil || len(b) > 16384 {
		return Enrollment{}, ErrInvalid
	}
	var v Enrollment
	if json.Unmarshal(b, &v) != nil || v.Version != 1 || v.Control == "" || v.Setup == "" {
		return Enrollment{}, ErrInvalid
	}
	return v, nil
}

type Binding struct {
	Owner   string `json:"orchestrator_address"`
	ID      string `json:"secret_id"`
	Name    string `json:"name"`
	Key     string `json:"key"`
	Version string `json:"version_id"`
}

func (b Binding) AAD() []byte {
	v, _ := json.Marshal([]any{1, b.Owner, b.ID, b.Name, b.Key, b.Version})
	return v
}

var namePattern = regexp.MustCompile(`^lp-app-[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)

func ValidReference(name, key string) bool {
	return len(name) <= 63 && namePattern.MatchString(name) && keyPattern.MatchString(key)
}
func ValidValue(v []byte) bool {
	return len(v) <= MaxValue && utf8.Valid(v) && !strings.ContainsRune(string(v), 0)
}

type Ciphertext struct {
	Binding
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	WrappedKey string `json:"wrapped_key"`
}

func Encrypt(b Binding, value []byte) (Ciphertext, Sensitive, error) {
	if !ValidReference(b.Name, b.Key) || !ValidValue(value) {
		return Ciphertext{}, nil, ErrInvalid
	}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return Ciphertext{}, nil, e
	}
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	nonce := make([]byte, g.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return Ciphertext{}, nil, e
	}
	return Ciphertext{Binding: b, Nonce: nonce, Ciphertext: g.Seal(nil, nonce, value, b.AAD())}, key, nil
}
func Decrypt(v Ciphertext, key []byte) (Sensitive, error) {
	if len(key) != 32 || len(v.Nonce) != 12 || len(v.Ciphertext) > MaxValue+16 || !ValidReference(v.Name, v.Key) {
		return nil, ErrInvalid
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, ErrInvalid
	}
	g, _ := cipher.NewGCM(b)
	plain, e := g.Open(nil, v.Nonce, v.Ciphertext, v.AAD())
	if e != nil || !ValidValue(plain) {
		return nil, ErrInvalid
	}
	return plain, nil
}
func LocalKey(name, key string) string {
	s := sha256.Sum256([]byte(name + "\x00" + key))
	return "s-" + hex.EncodeToString(s[:])
}
func Fingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}
func PublicKey(raw string) (ed25519.PublicKey, error) {
	b, e := base64.StdEncoding.DecodeString(raw)
	if e != nil || len(b) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(b) != raw {
		return nil, ErrInvalid
	}
	return ed25519.PublicKey(b), nil
}
func PrivatePEM(key ed25519.PrivateKey) []byte {
	b, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
}
func ParsePrivate(raw []byte) (ed25519.PrivateKey, error) {
	p, _ := pem.Decode(raw)
	if p == nil {
		return nil, ErrInvalid
	}
	v, e := x509.ParsePKCS8PrivateKey(p.Bytes)
	if e != nil {
		return nil, ErrInvalid
	}
	k, ok := v.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalid
	}
	return k, nil
}
func Proof(node, public string) []byte {
	return []byte("lpcc-secrets-enroll-v1\n" + node + "\n" + public)
}

func RegistrationProof(grant, fingerprint, hostname, directory, version, public string, development bool) []byte {
	digest := sha256.Sum256([]byte(grant))
	b, _ := json.Marshal([]any{"lpcc-registration-v1", hex.EncodeToString(digest[:]), fingerprint, hostname, directory, version, development, public})
	return b
}

type Machine struct {
	DeniedRevisions  []string               `json:"denied_revisions,omitempty"`
	Consumers        []SecretConsumer       `json:"cleanup_consumers,omitempty"`
	NodeID           string                 `json:"node_id"`
	Owner            string                 `json:"orchestrator_address"`
	PublicKey        string                 `json:"public_key"`
	Active           bool                   `json:"active"`
	Managed          bool                   `json:"managed"`
	EncryptionReady  bool                   `json:"encryption_ready"`
	PolicyGeneration int64                  `json:"policy_generation"`
	Assignments      []schema.AppAssignment `json:"assignments"`
}

// SecretConsumer permits deletion observation for pinned cleanup work, never
// value resolution or authorization of another incarnation.
type SecretConsumer struct {
	RevisionID string                     `json:"revision_id"`
	References []schema.SecretEnvironment `json:"references"`
}
type EnrollRequest struct {
	Nonce           string `json:"nonce,omitempty"`
	NodeID          string `json:"node_id"`
	PublicKey       string `json:"public_key"`
	Signature       []byte `json:"signature"`
	Management      string `json:"management_token,omitempty"`
	EncryptionReady bool   `json:"encryption_ready"`
}

// MachineBinding is sent only by the independently authenticated secrets service.
// Owner comes from the verified grant or stored identity, never from enrollment input.
type MachineBinding struct {
	EnrollRequest
	Owner          string `json:"orchestrator_address"`
	Activate       bool   `json:"activate,omitempty"`
	AdmissionReady bool   `json:"admission_ready,omitempty"`
	ResetKey       string `json:"reset_key,omitempty"`
}
type Identity struct {
	NodeID     string        `json:"node_id"`
	Owner      string        `json:"orchestrator_address"`
	Generation int64         `json:"generation"`
	Service    *ServiceTrust `json:"service,omitempty"`
}

type ResolveRequest struct {
	RevisionID string `json:"revision_id"`
	Generation int64  `json:"generation"`
	Activation int64  `json:"activation_generation"`
	Digest     string `json:"digest"`
	Expected   string `json:"expected_version_set,omitempty"`
}

// DeliveryRequest binds a fresh recipient key to the signed resolve request.
type DeliveryRequest struct {
	ResolveRequest
	RecipientKey []byte `json:"recipient_key"`
}
type Resolved struct {
	Revision int64 `json:"revision"`
	Ciphertext
	DataKey   Sensitive `json:"-"` // Decrypted locally; never serialized.
	SealedKey Sensitive `json:"sealed_key,omitempty"`
}
type VersionSet struct {
	NodeID             string         `json:"node_id"`
	IdentityGeneration int64          `json:"identity_generation"`
	PolicyGeneration   int64          `json:"policy_generation"`
	Assignment         ResolveRequest `json:"assignment"`
	Digest             string         `json:"version_set"`
	Values             []Resolved     `json:"values"`
}

func VersionDigest(values []Resolved) string {
	b := make([]string, 0, len(values))
	for _, v := range values {
		b = append(b, v.Name+"/"+v.Key+"/"+v.ID+"/"+v.Version)
	}
	sort.Strings(b)
	raw, _ := json.Marshal(b)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
