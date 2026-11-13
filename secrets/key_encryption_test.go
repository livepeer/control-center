package secrets

import (
	"bytes"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
)

func TestHPKEBrowserInteroperabilityAndBinding(t *testing.T) {
	raw, e := os.ReadFile("testdata/hpke.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Private []byte  `json:"private_key"`
		Key     []byte  `json:"data_key"`
		Sealed  []byte  `json:"js_upload"`
		Origin  string  `json:"origin"`
		Binding Binding `json:"binding"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	private, e := EncryptionKEM().NewPrivateKey(v.Private)
	if e != nil {
		t.Fatal(e)
	}
	info := KeyInfo("upload", v.Origin, v.Binding)
	key, e := OpenDataKey(private, info, v.Sealed)
	if e != nil || !bytes.Equal(key, v.Key) {
		t.Fatal("hpke-js/Go incompatibility", e)
	}
	wrong, _ := EncryptionKEM().GenerateKey()
	if _, e = OpenDataKey(wrong, info, v.Sealed); e == nil {
		t.Fatal("wrong recipient accepted")
	}
	for _, mutate := range []func(*Binding){
		func(b *Binding) { b.Owner += "x" }, func(b *Binding) { b.ID += "x" },
		func(b *Binding) { b.Name += "x" }, func(b *Binding) { b.Key += "x" }, func(b *Binding) { b.Version += "x" },
	} {
		b := v.Binding
		mutate(&b)
		if _, e = OpenDataKey(private, KeyInfo("upload", v.Origin, b), v.Sealed); e == nil {
			t.Fatal("substituted binding accepted")
		}
	}
	for _, changed := range [][]byte{KeyInfo("delivery", v.Origin, v.Binding), KeyInfo("upload", "https://other.test", v.Binding)} {
		if _, e = OpenDataKey(private, changed, v.Sealed); e == nil {
			t.Fatal("wrong purpose/origin accepted")
		}
	}
	v.Sealed[40] ^= 1
	if _, e = OpenDataKey(private, info, v.Sealed); e == nil {
		t.Fatal("modified ciphertext accepted")
	}
}

func TestDataKeysCannotBeSerialized(t *testing.T) {
	raw, e := json.Marshal(Resolved{DataKey: Sensitive("usable-key-sentinel")})
	if e != nil || bytes.Contains(raw, []byte("data_key")) || bytes.Contains(raw, []byte("usable-key-sentinel")) {
		t.Fatal("local data key reached JSON", e)
	}
}

func TestServiceEncryptionPrivateKeyPEM(t *testing.T) {
	private, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	der, _ := x509.MarshalPKCS8PrivateKey(private)
	parsed, e := ParseEncryptionPrivate(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if e != nil || !bytes.Equal(parsed.PublicKey().Bytes(), private.PublicKey().Bytes()) {
		t.Fatal("OpenSSL PKCS8 format rejected", e)
	}
	if _, e = ParseEncryptionPrivate([]byte("not a key")); e == nil {
		t.Fatal("invalid key accepted")
	}
}
