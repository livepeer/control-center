# Discovery authentication

Control Center signs enrollment grants, orchestrator claims, invitations and
machine discovery tokens with a local Ed25519 key. All API replicas need the
same signing configuration. Signing and ingress verification do not depend on
the secrets service.

## Signing configuration

Generate an Ed25519 PKCS#8 PEM key and retain it securely:

```sh
openssl genpkey -algorithm ED25519 -out jwt-signing-key.pem
chmod 0600 jwt-signing-key.pem
```

Mount the key read-only, readable by the API identity (UID 65532), and set
`JWTSigningPrivateKeyFile` to its path. `JWTSigningKeyID` defaults to `1`.
Optionally, `JWTVerificationPublicKeysFile` names a JSON object mapping key IDs
to standard-base64 encoded 32-byte Ed25519 public keys. The current signing
key's public key is included automatically. Keep private keys out of machine
artifacts, ConfigMaps, logs and command arguments.

## Discovery ingress

Control Center signs a token for each managed source request. The token has
issuer `livepeer-control-center`, audience `livepeer-discovery`, scope
`discovery:read`, the machine's node ID as subject, and issued-at and expiration
times. Its lifetime is five minutes with 30 seconds of clock tolerance. The
Collector sends credentials only to the exact configured HTTPS source and does
not follow redirects.

On each machine, the persistent `livepeer-runtime ingress-auth` HTTP service
verifies tokens with public keys and the machine's node ID. Traefik calls
`GET /authorize` using ForwardAuth: valid credentials return 204, missing or
invalid credentials return 401, and service failure denies access. `GET /readyz`
is private. The machine receives public verification keys, never the private
signing key.

## Key rotation

1. Add the next public key to `JWTVerificationPublicKeysFile` while continuing
   to sign with the current key. Verify that the new ingress configuration digest
   is applied and Runtime reports ingress ready.
2. Switch `JWTSigningPrivateKeyFile` and `JWTSigningKeyID` to the new key and ID.
3. Keep the previous public key for at least 24 hours after its last issuance,
   covering invitations as well as shorter-lived tokens. Then remove it in a
   separate public-key rollout.

Public-key distribution has its own inventory and ingress digest. Updating it
does not change Node's replacement digest or require a Node drain.
