package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type accessKeyring struct {
	current string
	keys    map[string]cipher.AEAD
}

func parseAccessKeyring(raw string) (*accessKeyring, error) {
	var v struct {
		Current string            `json:"current"`
		Keys    map[string]string `json:"keys"`
	}
	if json.Unmarshal([]byte(raw), &v) != nil || v.Current == "" || len(v.Keys) == 0 {
		return nil, errors.New("invalid Access encryption keyring")
	}
	k := &accessKeyring{current: v.Current, keys: map[string]cipher.AEAD{}}
	for id, encoded := range v.Keys {
		b, e := base64.StdEncoding.DecodeString(encoded)
		if e != nil || len(b) != 32 || id == "" {
			return nil, errors.New("access encryption keys must be 32 base64-encoded bytes")
		}
		block, _ := aes.NewCipher(b)
		a, _ := cipher.NewGCM(block)
		k.keys[id] = a
	}
	if k.keys[k.current] == nil {
		return nil, errors.New("current Access encryption key is missing")
	}
	return k, nil
}
func (k *accessKeyring) seal(ref string, c AccessCredential) (string, []byte, error) {
	a := k.keys[k.current]
	nonce := make([]byte, a.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return "", nil, e
	}
	b, e := json.Marshal(c)
	if e != nil {
		return "", nil, e
	}
	return k.current, a.Seal(nonce, nonce, b, []byte(ref)), nil
}
func (k *accessKeyring) open(id, ref string, b []byte) (AccessCredential, error) {
	var c AccessCredential
	a := k.keys[id]
	if a == nil || len(b) < a.NonceSize() {
		return c, errors.New("access credential cannot be decrypted")
	}
	plain, e := a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], []byte(ref))
	if e != nil || json.Unmarshal(plain, &c) != nil {
		return c, errors.New("access credential cannot be decrypted")
	}
	return c, nil
}

// Formatting must not expose encrypted-store plaintext credentials.
func (AccessCredential) String() string   { return "[redacted Access credential]" }
func (AccessCredential) GoString() string { return "[redacted Access credential]" }
