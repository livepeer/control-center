package consumer

import (
	"crypto/ed25519"
	"encoding/json"
	"time"
)

// Sign attests the launch checked by the runtime, independently of secrets service enrollment.
func (r *Request) Sign(key ed25519.PrivateKey, node string, version int64, endpoint string, now time.Time) {
	r.IssuedAt = now.Unix()
	r.Signature = ed25519.Sign(key, r.proof(node, version, endpoint))
}

func (r Request) Verify(key ed25519.PublicKey, node string, version int64, endpoint string, now time.Time) bool {
	issued := time.Unix(r.IssuedAt, 0)
	return len(key) == ed25519.PublicKeySize && !issued.After(now.Add(5*time.Second)) && now.Before(issued.Add(time.Minute)) &&
		ed25519.Verify(key, r.proof(node, version, endpoint), r.Signature)
}

func (r Request) proof(node string, version int64, endpoint string) []byte {
	// LaunchID is the nonce: exact replays reuse the grant's unique launch tuple;
	// changing any field requires a new signature, including after credential refresh.
	b, _ := json.Marshal([]any{"lpcc-onchain-launch-v1", node, version, endpoint, r.Launch, r.OnchainGeneration, r.ConfigDigest, r.IssuedAt})
	return b
}
