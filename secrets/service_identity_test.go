package secrets

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
)

func TestServiceResponsesRequireTheEnrolledKeyAndExactRequest(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	trust := ServiceTrust{Origin: "https://secrets.example", PublicKey: base64.StdEncoding.EncodeToString(pub)}
	req, _ := http.NewRequest("POST", trust.Origin+"/v1/runtime/resolve", nil)
	req.Header.Set("Authorization", "Bearer one-use-proof")
	body := []byte(`{"revision_id":"revision"}`)
	denial := []byte(`{"code":"identity_refused"}`)
	response := &http.Response{StatusCode: 403, Header: http.Header{}}
	response.Header.Set(ServiceSignatureHeader, SignServiceResponse(key, trust.Origin, req, body, denial, 403))
	if e := trust.VerifyResponse(req, body, denial, response); e != nil {
		t.Fatal("signed denial from pinned service refused", e)
	}
	for _, mutate := range []func(){
		func() { req.Header.Set("Authorization", "Bearer different-proof") },
		func() { req.URL.Path = "/v1/runtime/versions" },
		func() { body = []byte(`{}`) },
		func() { denial = []byte(`{"code":"secret_missing"}`) },
		func() { response.StatusCode = 200 },
		func() {
			_, wrong, _ := ed25519.GenerateKey(rand.Reader)
			trust.PublicKey = base64.StdEncoding.EncodeToString(wrong.Public().(ed25519.PublicKey))
		},
	} {
		originalRequest := req.Clone(t.Context())
		originalBody, originalDenial, originalStatus, originalTrust := body, denial, response.StatusCode, trust
		mutate()
		if e := trust.VerifyResponse(req, body, denial, response); e == nil {
			t.Fatal("modified or substituted service response accepted")
		}
		req, body, denial, response.StatusCode, trust = originalRequest, originalBody, originalDenial, originalStatus, originalTrust
	}
}

func TestEnrollmentReceiptBindsBothIdentitiesAndFreshNonce(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	trust := ServiceTrust{Origin: "https://secrets.example", PublicKey: base64.StdEncoding.EncodeToString(pub)}
	id := Identity{NodeID: "node", Owner: "owner", Generation: 1, PublicKey: "runtime-key", Nonce: rand.Text(), Service: &trust}
	id.ReceiptSignature = ed25519.Sign(key, id.EnrollmentProof())
	for _, field := range []string{"valid", "node", "owner", "generation", "key", "nonce", "service"} {
		copy := id
		switch field {
		case "node":
			copy.NodeID = "another-node"
		case "owner":
			copy.Owner = "another-owner"
		case "generation":
			copy.Generation++
		case "key":
			copy.PublicKey = "another-runtime-key"
		case "nonce":
			copy.Nonce = rand.Text()
		case "service":
			other := trust
			other.PublicKey = "substitute-service-key"
			copy.Service = &other
		}
		if e := trust.VerifyEnrollment(copy, id.NodeID, id.PublicKey, id.Nonce); (e == nil) != (field == "valid") {
			t.Fatal("enrollment receipt binding failed", field, e)
		}
	}
}
