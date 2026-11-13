# Operator secrets

The secrets service stores application credentials and controls which runtimes
may receive them. Operators add or replace values on the Secrets screen. Control
Center manages assignments and sees names, but not values or runtime private
keys.

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
    S->>S: Verify grant and proof; bind owner, node and key
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
can observe the bearer credentials used for enrollment and owner resets, and
those authorization paths remain trusted. After enrollment, a modified service
reply or a replacement signing key fails verification against the saved pin.

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

1. Deploy separately from Control Center, with its own TLS PostgreSQL database,
   Vault instance and Cloudflare tunnel. Route the tunnel's public hostname to
   `http://secrets:8080`. Compose keeps that origin private and publishes no
   host port.
2. Create the files named in [Compose](../deploy/compose.secrets.yaml) under
   `deploy/secrets-service-private/`. Keep them owner-only, readable by UID
   65532, and out of Git. Generate the service signing and encryption keys:

   ```sh
   openssl genpkey -algorithm ED25519 \
     -out deploy/secrets-service-private/identity-key.pem
   openssl genpkey -algorithm X25519 \
     -out deploy/secrets-service-private/encryption-key.pem
   ```

   Compose mounts these as `SECRETS_IDENTITY_KEY_FILE` and
   `SECRETS_ENCRYPTION_KEY_FILE`. Preserve both across redeployments, separately
   from the enrollment-token signing secret.
3. Enable Vault Transit at `transit/`. Grant `create,update` on
   `transit/encrypt/operator-<owner UUID>` and `update` on its decrypt path.
   Do not grant key export or administration. Disable raw Vault audit and
   ingress body logging so credentials and data keys are not recorded.
4. Set `SECRETS_PUBLIC_URL` and Control Center's `SecretsURL` to the same public
   HTTPS origin. Set `SecretsMetadataTokenFile` to an independent credential
   of at least 32 bytes, and set `CONTROL_METADATA_TOKEN_FILE` to the mounted
   file containing that same credential. Supply the remaining Compose settings
   and start the separate project:

   ```sh
   docker compose -f deploy/compose.secrets.yaml up --build -d
   ```

The service applies PostgreSQL migrations on startup. The first migration
adopts databases from earlier service versions, preserving existing secrets
and identities. It refuses baseline rollback because it may contain data.

To inspect or apply migrations separately, run the service image with
`SECRETS_DATABASE_URL_FILE` configured. With the Compose deployment above:

```sh
docker compose -f deploy/compose.secrets.yaml \
  run --rm --no-deps secrets migrate status
docker compose -f deploy/compose.secrets.yaml \
  run --rm --no-deps secrets migrate up
```

Use `migrate down` to roll back reversible future migrations.

### Shared-host staging

Staging can use the existing Supabase project and Control Center tunnel, with
Vault and the secrets service in a separate Compose project on the same host.
This shares the host and database administration boundary with Control Center.
The application tables remain in the separate `lpsecrets` schema.

Add `deploy/compose.secrets-control.yaml` to the Control Center Compose command.
It mounts the shared metadata credential at
`/run/secrets/secrets-metadata-token` and moves tunnel metrics to port `23813`.
Set `SecretsMetadataTokenFile` to that path and `SecretsURL` to
`https://controlcenter-secrets.livepeer.live` in the private `config.toml`.
Caddy forwards only GET/POST requests to `/internal/secrets/nodes/*`; the API
requires the independent metadata token on these requests.

For the secrets project, combine `compose.secrets.yaml` with
`compose.secrets-staging.yaml`. The overlay binds the service to
`127.0.0.1:23812` for the existing host-networked tunnel and disables the
separate connector by default. Configure the tunnel's secrets hostname to
use `http://localhost:23812`.

Keep the environment settings from the deployment instructions in the ignored
`deploy/secrets-service.env`, using `VAULT_ADDR=https://vault:8200`. Place
Vault's TLS files in `deploy/vault-private/tls/` as `ca.pem`, `server.pem`, and
`server-key.pem`; the certificate must cover `vault` and `127.0.0.1`. Prepare
`deploy/vault-private/data/` for persistent Raft storage. The mounted Vault
configuration, TLS files and data directory must be readable by UID 65532,
and the data directory must be writable by that UID. To retain an existing
storage location, set `VAULT_STATE_DIR` in the private environment file.

Create `secrets-service-private/ca-bundle.pem` containing the normal upstream
CA roots plus Vault's CA, readable by UID 65532. Start Vault first, initialize
and unseal it, then configure Transit and the restricted service token as
described above. Preserve the recovery keys privately and arrange unsealing
after restarts and renewal of expiring service tokens.

```sh
cd deploy
docker compose --env-file secrets-service.env \
  -f compose.secrets.yaml -f compose.secrets-staging.yaml up -d vault
# Initialize/unseal Vault and provision secrets-service-private/vault-token.
docker compose --env-file secrets-service.env \
  -f compose.secrets.yaml -f compose.secrets-staging.yaml up --build -d
curl --fail https://controlcenter-secrets.livepeer.live/readyz
```

## Application behavior

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
a compromised runtime key, use owner-authorized
`POST /v1/machines/{node}/reset`, then enroll again. To revoke access without
resetting identity, use `POST /v1/machines/{node}/revoke`.

Upgrade the service, installer and runtime together, then rerun enrollment to
install the pin. Existing clusters must first complete
[K3s secrets encryption](https://docs.k3s.io/cli/secrets-encrypt).
