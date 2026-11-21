# Operator secrets

The secrets service stores application credentials per orchestrator and controls runtime delivery. Members share secrets and app policies (orchestrator address owns resources, user IDs record audit actors). Control Center sees secret names only, keeping values and runtime private keys outside Control Center.

Each orchestrator supports up to `100` secrets, including deleted keys. The browser encrypts each value with a random data key, and Vault Transit **wraps** that key for storage. For authorized runtimes, the service unwraps the key via Vault and re-encrypts it for that runtime to decrypt locally.

## Enroll a runtime

1. In each managing browser profile, generate an enrollment command (issues a `1h` setup grant and saves the service signing public key as an origin **pin**, rejecting changed pins).
2. Run the command on the host. The installer creates a local runtime signing key and proves its Control Center machine credential via a purpose-bound HMAC over node ID, runtime public key, and fresh nonce while keeping the reusable machine credential on the host.

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

### Trust and encryption boundaries

Signed receipts bind identities and nonce against replay, and retries keep the runtime key and service pin. Later requests and replies are signed and bound to exact request and authorization (invalid proofs and replays retry, verified revocations apply).

Initial enrollment trusts Cloudflare and HTTPS to introduce signing keys, and Cloudflare can see enrollment and reset bearer tokens. Once pinned, altered replies or changed keys fail verification.

On upload, the browser verifies a signed service encryption key against its pin and seals the data key via HPKE (security relies on unmodified browser JS).

On delivery, the runtime generates a per-request ephemeral X25519 key pair in memory, signs the request carrying its public key, and receives the unwrapped data key encrypted to that key. With trusted client code, Cloudflare sees metadata and bearer tokens only.

## Use secrets in apps

Save values on the **Secrets** screen before or after assignment. Apps provision once required secrets exist, declaring `container.secrets` for Runtime to inject as env vars.

Secret updates replace affected instances one by one, waiting for readiness (single-instance apps incur downtime). Running instances survive service or Vault outages, while starting or restarting secret-dependent instances needs active authorization.

Deleting a secret or denying an app stops affected instances, and active sessions or offline machines delay removal. Revoke compromised credentials at their issuer too.

## Deploy the secrets service and Vault

Both services are required in [`deploy/compose.yaml`](../deploy/compose.yaml). Work from `deploy/` and set `LIVEPEER_REDEEMER_IMAGE` in `compose.env` to a compatible digest-pinned Node image before any Compose command, even for Vault alone.

### Configure the service

Copy `secrets-service.env.example` to `secrets-service.env` and match the Supabase settings in `config.toml`.

| Setting | Value |
| --- | --- |
| `SECRETS_PUBLIC_URL` | Match `SecretsURL`. Route its hostname through Cloudflare Tunnel to `http://localhost:23812`. This origin scopes service key pins. |
| `SECRETS_CONTROL_URL` | `http://control-metadata:43812` for callbacks using the shared metadata token. Set the private API `Listen` to `0.0.0.0:43812`. Use HTTPS across hosts or untrusted networks. |
| `SECRETS_ALLOWED_ORIGIN` | Exact UI origin, `https://controlcenter.livepeer.live` in the example. |

### Create private files

Create `secrets-service-private/` with mode `0700`. Set file modes to `0600` and own the directory and files as `65532:65532`.

| File | Contents |
| --- | --- |
| `database-url` | TLS PostgreSQL URI |
| `signing-key` | Independent enrollment signing secret (`>= 32` bytes) |
| `identity-key.pem` | Ed25519 service signing private key |
| `encryption-key.pem` | X25519 service encryption private key |
| `control-metadata-token` | Independent secret (`>= 32` bytes) matching `SecretsMetadataTokenFile` |
| `vault-token` | Vault Transit token created below |
| `ca-bundle.pem` | Public HTTPS roots plus Vault CA |

Generate service keys once and retain across upgrades.

```sh
openssl genpkey -algorithm ED25519 -out secrets-service-private/identity-key.pem
openssl genpkey -algorithm X25519 -out secrets-service-private/encryption-key.pem
```

### Start and configure Vault

1. Prepare `/opt/controlcenter-secrets/vault/{config,tls,data}`. Preserve existing data and assign UID `65532` to `data`. Copy `vault.hcl` to `config/server.hcl`. Supply `tls/ca.pem`, `tls/server.pem`, and `tls/server-key.pem` readable by UID `65532`. The certificate must cover `vault` and `127.0.0.1`.
2. Start Vault.

   ```sh
   docker compose --env-file compose.env up -d vault
   ```

3. Initialize and unseal Vault. Enable Transit at `transit/`. As a Vault administrator, apply [the policy](../deploy/vault-policy.hcl) as `operator-secrets` and save a token with that policy in `vault-token`. It permits `orchestrator-*` wrapping and unwrapping, self-renewal, and self-lookup. The service token needs no key export or administration privileges.

Keep recovery keys private and arrange unsealing and token renewal. Vault binds HTTPS to `127.0.0.1:28200`. Disable raw Vault audit and ingress body logging.

### Start the full deployment

```sh
docker compose --env-file compose.env up -d --build --wait
```

Migrations run on startup ([orchestrators](operations.md#manage-orchestrators-and-members)). Inspect or run manually with `docker compose --env-file compose.env run --rm --no-deps secrets migrate status` or `migrate up` (`migrate down` can delete data).

## Back up and recover

Back up secrets DB, Vault state, machine identity files, encrypted Kubernetes state, runtime journal, signing keys, and service encryption key. Restoring values needs both DB and Vault wrapping keys. Keep key backups separate from DB backups and preserve revocations and deletions on restore.

Losing `identity-key.pem` breaks enrolled runtime verification, so restore the original key to preserve pins. For a compromised runtime key, call member-authorized `POST /v1/machines/{node}/reset` and re-enroll. Call `POST /v1/machines/{node}/revoke` to revoke access while keeping identity.

Member departure and routine credential refresh preserve runtime identity. Machine retirement and explicit revocation disable it.
