package secretservice

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"

	protocol "github.com/livepeer/control-center/secrets"
)

func (s *Service) trust() *protocol.ServiceTrust {
	if len(s.Config.IdentityKey) != ed25519.PrivateKeySize {
		return nil
	}
	return &protocol.ServiceTrust{Origin: s.Config.PublicURL, PublicKey: base64.StdEncoding.EncodeToString(s.Config.IdentityKey.Public().(ed25519.PublicKey))}
}

type signedReply struct {
	http.ResponseWriter
	body   bytes.Buffer
	status int
}

func (w *signedReply) WriteHeader(status int)         { w.status = status }
func (w *signedReply) Write(body []byte) (int, error) { return w.body.Write(body) }

func (s *Service) signedResponses(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.trust() == nil {
			next.ServeHTTP(w, r)
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
		if e != nil || len(body) > 2<<20 {
			fail(w, 400, "invalid_request")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		reply := &signedReply{ResponseWriter: w, status: 200}
		next.ServeHTTP(reply, r)
		w.Header().Set(protocol.ServiceSignatureHeader, protocol.SignServiceResponse(s.Config.IdentityKey, s.Config.PublicURL, r, body, reply.body.Bytes(), reply.status))
		w.WriteHeader(reply.status)
		_, _ = w.Write(reply.body.Bytes())
	})
}

// The enrollment-pinned signing key authenticates this replaceable encryption
// key. A fresh nonce in the request prevents replay of an old signed key.
func (s *Service) encryptionKey(w http.ResponseWriter, r *http.Request) {
	if s.Config.EncryptionKey == nil || len(r.URL.Query().Get("nonce")) < 26 {
		fail(w, 400, "invalid_key_request")
		return
	}
	response(w, 200, map[string]string{"public_key": base64.StdEncoding.EncodeToString(s.Config.EncryptionKey.PublicKey().Bytes())})
}
