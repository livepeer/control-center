package secrets

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestEncryptionAndBinding(t *testing.T) {
	b := Binding{"owner", "id", "lp-app-provider", "token", "v1"}
	c, k, e := Encrypt(b, []byte("value-sentinel"))
	if e != nil {
		t.Fatal(e)
	}
	p, e := Decrypt(c, k)
	if e != nil || string(p) != "value-sentinel" {
		t.Fatal(e)
	}
	c.Owner = "other"
	if _, e = Decrypt(c, k); e == nil {
		t.Fatal("cross-owner ciphertext accepted")
	}
	if bytes.Contains(c.Ciphertext, []byte("value-sentinel")) {
		t.Fatal("plaintext")
	}
}
func TestEnrollmentEnvelope(t *testing.T) {
	v, e := Join("a.b.c", "d.e.f")
	if e != nil {
		t.Fatal(e)
	}
	p, e := Split(v)
	if e != nil || p.Control != "a.b.c" || p.Setup != "d.e.f" {
		t.Fatal(p, e)
	}
	if _, e = Split("lpcc1.bad"); e == nil {
		t.Fatal("invalid envelope")
	}
}
func TestLocalKeysAndLimits(t *testing.T) {
	if LocalKey("lp-app-a", "token") == LocalKey("lp-app-b", "token") {
		t.Fatal("collision")
	}
	if ValidValue([]byte{0}) || ValidValue(bytes.Repeat([]byte("x"), MaxValue+1)) {
		t.Fatal("invalid value")
	}
}

func TestWebCryptoInteroperabilityVector(t *testing.T) {
	b, e := os.ReadFile("testdata/webcrypto.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Ciphertext
		DataKey Sensitive `json:"data_key"`
	}
	if json.Unmarshal(b, &v) != nil {
		t.Fatal("invalid vector")
	}
	p, e := Decrypt(v.Ciphertext, v.DataKey)
	if e != nil || string(p) != "public-interoperability-vector" {
		t.Fatal("WebCrypto/Go incompatibility", e)
	}
}

func TestEnrollmentProofVector(t *testing.T) {
	// Independently computed with Python hmac, using the ASCII bearer as key.
	proof := EnrollmentProof("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "test-node", "runtime-public", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if proof != "c6efccb8529b4c41094f271af3244753889894afbce03006eedec0c830536ad5" {
		t.Fatal("enrollment proof mismatch", proof)
	}
}
