package secrets

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
)

// Data keys use RFC 9180 base mode with DHKEM(X25519, HKDF-SHA256),
// HKDF-SHA256 and AES-256-GCM. Wire encoding is enc || ciphertext.
func EncryptionKEM() hpke.KEM { return hpke.DHKEM(ecdh.X25519()) }

func KeyInfo(direction, origin string, b Binding) []byte {
	info, _ := json.Marshal([]string{"lpcc-data-key-v1", direction, origin, b.Owner, b.ID, b.Name, b.Key, b.Version})
	return info
}

func SealDataKey(public, info, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalid
	}
	recipient, e := EncryptionKEM().NewPublicKey(public)
	if e != nil {
		return nil, ErrInvalid
	}
	sealed, e := hpke.Seal(recipient, hpke.HKDFSHA256(), hpke.AES256GCM(), info, key)
	if e != nil {
		return nil, ErrInvalid
	}
	return sealed, nil
}

func OpenDataKey(private hpke.PrivateKey, info, sealed []byte) (Sensitive, error) {
	if private == nil || len(sealed) != 80 {
		return nil, ErrInvalid
	}
	key, e := hpke.Open(private, hpke.HKDFSHA256(), hpke.AES256GCM(), info, sealed)
	if e != nil || len(key) != 32 {
		clear(key)
		return nil, ErrInvalid
	}
	return key, nil
}

func ParseEncryptionPrivate(raw []byte) (hpke.PrivateKey, error) {
	p, _ := pem.Decode(raw)
	if p == nil {
		return nil, ErrInvalid
	}
	value, e := x509.ParsePKCS8PrivateKey(p.Bytes)
	if e != nil {
		return nil, ErrInvalid
	}
	key, ok := value.(*ecdh.PrivateKey)
	if !ok || key.Curve() != ecdh.X25519() {
		return nil, ErrInvalid
	}
	return hpke.NewDHKEMPrivateKey(key)
}
