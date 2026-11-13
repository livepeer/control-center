package secrets

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

const ServiceSignatureHeader = "X-Livepeer-Service-Signature"

// ServiceTrust is established during trusted enrollment. Later public API
// responses cannot replace the installed pin.
type ServiceTrust struct {
	Origin    string `json:"origin"`
	PublicKey string `json:"public_key"`
}

func serviceResponseProof(origin string, r *http.Request, request, response []byte, status int) []byte {
	credential := sha256.Sum256([]byte(r.Header.Get("Authorization")))
	digest := sha256.Sum256(response)
	proof, _ := json.Marshal([]any{"lpcc-secrets-response-v1", origin, RequestDigest(r, request), hex.EncodeToString(credential[:]), status, hex.EncodeToString(digest[:])})
	return proof
}

func SignServiceResponse(key ed25519.PrivateKey, origin string, r *http.Request, request, response []byte, status int) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, serviceResponseProof(origin, r, request, response, status)))
}

func (trust ServiceTrust) VerifyResponse(r *http.Request, request, body []byte, response *http.Response) error {
	key, e := PublicKey(trust.PublicKey)
	signature, err := base64.StdEncoding.DecodeString(response.Header.Get(ServiceSignatureHeader))
	if e != nil || err != nil || trust.Origin != r.URL.Scheme+"://"+r.URL.Host || !ed25519.Verify(key, serviceResponseProof(trust.Origin, r, request, body, response.StatusCode), signature) {
		return ErrUnavailable
	}
	return nil
}
