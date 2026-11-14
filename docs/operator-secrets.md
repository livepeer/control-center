# Operator secrets

The secrets service stores application credentials and controls which runtimes
may receive them. Select an orchestrator to manage its secrets. Members share
secrets and app policies; the orchestrator address owns resources and user IDs
identify audit actors. Control Center manages assignments and sees names, but
not values or runtime private keys.

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

1. Run the secrets service and Vault with [Compose](../deploy/compose.secrets.yaml).
   Route `controlcenter-secrets.livepeer.live` through the existing Cloudflare
   tunnel to `http://localhost:23812`. Only the secrets service binds a loopback
   host port. Vault uses HTTP on a private Docker network, with no published port.
   Prepare `deploy/vault-private/data/` owned by UID 65532 for persistent storage.
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
3. Start Vault with `docker compose -f deploy/compose.secrets.yaml up -d vault`,
   then initialize and unseal it. Enable Vault Transit at `transit/`. Grant
   `create,update` on `transit/encrypt/orchestrator-<lowercase address>` and
   `update` on its decrypt path.
   Do not grant key export or administration. Disable raw Vault audit and
   ingress body logging so credentials and data keys are not recorded. Preserve
   the recovery keys privately and arrange unsealing after restarts and renewal
   of expiring service tokens.
4. Set `SECRETS_PUBLIC_URL` and Control Center's `SecretsURL` to the same public
   HTTPS origin. Put an independent metadata credential of at least 32 bytes in
   `secrets-service-private/control-metadata-token`; Control Center's Compose
   file mounts it at `/run/secrets/secrets-metadata-token`. Set
   `SecretsMetadataTokenFile` to that path. Supply the remaining Compose settings
   and start the project:

   ```sh
   docker compose -f deploy/compose.secrets.yaml up --build -d
   ```

The service applies PostgreSQL migrations on startup.

To inspect or apply migrations separately, run the service image with
`SECRETS_DATABASE_URL_FILE` configured. With the Compose deployment above:

```sh
docker compose -f deploy/compose.secrets.yaml \
  run --rm --no-deps secrets migrate status
docker compose -f deploy/compose.secrets.yaml \
  run --rm --no-deps secrets migrate up
```

Use `migrate down` to roll back reversible future migrations.

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
a compromised runtime key, use member-authorized
`POST /v1/machines/{node}/reset`, then enroll again. To revoke access without
resetting identity, use `POST /v1/machines/{node}/revoke`.

Upgrade Control Center, the secrets service, installer and runtime together,
then rerun enrollment to install the pin. Existing clusters must first complete
[K3s secrets encryption](https://docs.k3s.io/cli/secrets-encrypt).
