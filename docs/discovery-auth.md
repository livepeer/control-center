# Discovery authentication

Control Center signs enrollment grants, orchestrator claims, invitations, discovery tokens, and telemetry write tokens using one local Ed25519 key shared by all API replicas. Signing and ingress verification run independently of the secrets service.

## Configure the signing key

Generate an Ed25519 PKCS#8 PEM key and restrict permissions.

```sh
openssl genpkey -algorithm ED25519 -out jwt-signing-key.pem
chmod 0600 jwt-signing-key.pem
```

Mount read-only for API UID `65532` and keep private keys out of machine artifacts, ConfigMaps, logs, and command args.

| Setting | Purpose |
| --- | --- |
| `JWTSigningPrivateKeyFile` | Read-only Ed25519 PKCS#8 PEM key path |
| `JWTSigningKeyID` | Signing key ID (default `"1"`) |
| `JWTVerificationPublicKeysFile` | Optional JSON map of key IDs to base64 32-byte Ed25519 public keys (active key auto-included) |

## Verify discovery ingress

Each poll mints a discovery token (`iss` `livepeer-control-center`, `aud` `livepeer-discovery`, `scope` `discovery:read`, `sub` `<node_id>`, `iat`/`exp`, `5m` lifetime, `30s` skew). The Collector sends credentials only to the exact HTTPS source without redirects.

Machine `livepeer-runtime ingress-auth` checks tokens against public keys and node ID. Traefik ForwardAuth calls `GET /authorize` (`204` valid, `401` invalid/missing, deny on error). `GET /readyz` stays private, and machines receive public keys only.

## Rotate signing keys

1. Add the next public key to `JWTVerificationPublicKeysFile` while signing with the current key. Confirm the new ingress digest applies and reports ready.
2. Switch `JWTSigningPrivateKeyFile` and `JWTSigningKeyID` to the new key.
3. Retain the old public key for `>= 24h` after last issuance (covering 24-hour invitations and shorter tokens), then remove it in a separate rollout.

Public-key rollouts use an independent inventory and ingress digest, leaving Node's replacement digest unchanged with zero Node drain.
