# Operator secrets

The secrets service stores application credentials and controls which runtimes
may receive them. Select an orchestrator to manage its secrets. Members share
secrets and app policies; the orchestrator address owns resources and user IDs
identify audit actors. Control Center manages assignments and sees names, but
not values or runtime private keys.

Each orchestrator can have at most 100 secrets. Deleted keys still count towards this limit.

The browser encrypts each value with a random data key. The service stores the
ciphertext and uses Vault Transit to encrypt, or **wrap**, that key for storage.
For an authorized runtime, the service asks Vault to unwrap the key and
encrypts it for that runtime. The runtime decrypts the key and value locally
for the application.

## Enrollment and trust

Generate an enrollment command in each browser profile that manages secrets.
This obtains a setup grant valid for one hour and saves the service's signing
public key as a **pin** in browser storage for that service origin. A changed
pin is refused. Run the command on the runtime machine; the installer creates
and saves a runtime signing key. Its private key stays on the machine.
The installer proves possession of its Control Center machine credential with
a purpose-bound HMAC over the node ID, runtime public key and fresh enrollment
nonce. The secrets service forwards the proof to Control Center for verification;
the reusable machine credential stays on the runtime.

```mermaid
sequenceDiagram
    actor O as Operator and browser
    participant C as Cloudflare
    participant S as Secrets service
    participant R as Installer / runtime
    O->>C: Request enrollment grant
    C->>S: Forward request
    S-->>C: Grant and service signing public key
    C-->>O: Forward grant and key
    O->>O: Pin service key for this origin
    O->>R: Run enrollment command with grant
    R->>R: Generate runtime signing key
    R->>C: Grant, runtime public key, proof and fresh nonce
    C->>S: Forward enrollment
    S->>S: Verify grant and proof; bind orchestrator, node and key
    S-->>C: Service public key and signed receipt
    C-->>R: Forward receipt
    R->>R: Verify receipt and save service-key pin
    R->>C: Activate binding with a signed request
    C->>S: Forward activation
```

The receipt binds the two identities and the fresh random challenge, or nonce,
so an old receipt cannot complete a new attempt. Retries preserve the runtime
key and service pin. Later requests are signed with the runtime key; service
replies are signed and bound to the exact request and authorization. Invalid
proofs and replayed replies are retried, while verified revocation is enforced.

Initial enrollment trusts Cloudflare and HTTPS to introduce both signing
identities. Without a prior pin, the installer cannot establish that the first
service key belongs to the intended service from its signature alone. The
browser similarly pins the key returned when it obtains the grant. Cloudflare
can observe the bearer credentials used for enrollment and member-authorized
resets, and those authorization paths remain trusted. After enrollment, a
modified service reply or replacement signing key fails verification against
the saved pin.

For uploads, the browser verifies a fresh signed service encryption key against
its pin, then encrypts the data key to the service using HPKE. The service
decrypts it inside its independent boundary before Vault wraps it. For delivery,
the runtime creates a fresh X25519 encryption key pair for each request. It
keeps the private key in memory and signs the request containing the public
key. The service checks authorization and encrypts the unwrapped data key to
that key. With trusted client code, Cloudflare sees metadata and operator
bearer tokens but no usable data keys on these encrypted paths. Browser
protection depends on the JavaScript it receives: altered code could bypass
encryption.

## Deployment

The secrets service and Vault are required services in the default
[Compose deployment](../deploy/compose.yaml). Existing installations using the
`livepeer-secrets` project should use the local deployment helper to retain the
running Vault and its network. For a fresh setup, work from `deploy/`. Set
`LIVEPEER_REDEEMER_IMAGE` in `compose.env` to a compatible digest-pinned Node
image before running Compose. This value is required even when starting only
Vault.

1. Copy `secrets-service.env.example` to `secrets-service.env`. Use the same
   Supabase settings as `config.toml`, and keep `SECRETS_PUBLIC_URL` equal to
   `SecretsURL`. Route that public hostname through the Cloudflare tunnel to
   `http://localhost:23812`. Set `SECRETS_CONTROL_URL=http://control-metadata:43812`
   for callbacks over the private API and secrets network. Callbacks require the
   shared metadata token. The API must listen on `0.0.0.0:43812`, as in
   `config.example.toml`; that private listener, not the public one, serves
   these callbacks. Set `SECRETS_ALLOWED_ORIGIN` to the exact UI origin
   (`https://controlcenter.livepeer.live`); browsers from any other origin are
   refused. Use HTTPS for callbacks across hosts or untrusted
   networks. Public origins and service identity pins use `SECRETS_PUBLIC_URL`.
2. Create `secrets-service-private/`, owned by `65532:65532`, mode `0700`.
   Give its files the same ownership and mode `0600`:

   | File | Contents |
   | --- | --- |
   | `database-url` | TLS PostgreSQL connection URI for the secrets service |
   | `signing-key` | Independent enrollment signing secret, at least 32 bytes |
   | `identity-key.pem` | Ed25519 service signing private key |
   | `encryption-key.pem` | X25519 service encryption private key |
   | `control-metadata-token` | Independent credential, at least 32 bytes, shared with the API's `SecretsMetadataTokenFile` |
   | `vault-token` | Vault Transit credential from the next step |
   | `ca-bundle.pem` | Public HTTPS root certificates plus the Vault CA |

   Generate the service keys once and retain them across upgrades:

   ```sh
   openssl genpkey -algorithm ED25519 -out secrets-service-private/identity-key.pem
   openssl genpkey -algorithm X25519 -out secrets-service-private/encryption-key.pem
   ```

3. Prepare `/opt/controlcenter-secrets/vault/{config,tls,data}` with data owned
   by UID 65532. Copy `vault.hcl` to `config/server.hcl`, and supply
   `tls/ca.pem`, `tls/server.pem`, and `tls/server-key.pem`, readable by UID 65532.
   The certificate must cover hostname `vault` and IP address `127.0.0.1`.
   Preserve existing Vault data when adopting these paths. Start Vault:

   ```sh
   docker compose --env-file compose.env up -d vault
   ```

   Initialize and unseal it, then enable Transit at `transit/`. Using an
   administrator credential, apply [the service policy](../deploy/vault-policy.hcl)
   as `operator-secrets` and issue a token with that policy. Save the token in
   `vault-token`. The policy allows wrapping and unwrapping for `orchestrator-*`,
   token renewal, and inspection of the token's own permissions.
   Do not grant key export or administration. Keep recovery keys privately and
   arrange unsealing after restarts and renewal of expiring tokens. Vault's HTTPS
   port binds only to `127.0.0.1:28200`. Disable raw Vault audit and ingress body
   logging.
4. Start the complete deployment:

   ```sh
   docker compose --env-file compose.env up -d --build --wait
   ```

The service applies PostgreSQL migrations on startup. See
[orchestrator provisioning](operations.md#orchestrators). To inspect migrations,
run `docker compose --env-file compose.env run --rm --no-deps secrets migrate status`.
Use `migrate up` to apply them separately. `migrate down` can delete data.

## Application behavior

Apps are provisioned only when their required secrets are available.
You can save values on the Secrets screen before an app is running.
Applications declare secret references in `container.secrets`; the runtime
provides values as environment variables. When a secret changes, affected app
instances are replaced one at a time, waiting for each replacement to become
ready. A single-instance app has downtime during this process.

Running instances continue during a service or Vault outage. Starting or
restarting an instance that needs secrets requires current authorization.
Deleting a secret or denying an app stops affected instances, although active
sessions and offline machines can delay removal. Revoke credentials at their
issuer too, to invalidate values already delivered to an app.

## Recovery

Back up the service database, Vault state, machine identity files, encrypted
Kubernetes state, runtime journal, signing keys and service encryption key. The
database alone cannot recover values without Vault's wrapping keys. Keep key
backups separate from database backups, and preserve revocations and deletions
when restoring old data.

Losing the service identity key breaks verification on enrolled runtimes.
Restore the original private key instead of silently replacing their pins. For
a compromised runtime key, use member-authorized
`POST /v1/machines/{node}/reset`, then enroll again. To revoke access without
resetting identity, use `POST /v1/machines/{node}/revoke`.

A member's departure and routine management credential refresh preserve the
runtime identity. Machine retirement and explicit identity revocation disable it.
