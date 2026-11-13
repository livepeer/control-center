# Operator secrets

The Secrets screen stores write-only values. The client encrypts each value with AES-256-GCM before upload to
an independent secrets service. Vault Transit wraps the data key; authorized runtimes use signed requests over
HTTPS to receive it and decrypt locally. Control Center receives metadata, not values or private keys.

Apps are allowed by default. An owner's denial applies to a deployment name, all revisions and aliases,
including apps without secrets. Denial and secret deletion drain workloads; offline machines and active
sessions may delay cleanup. Delivered values cannot be recalled: revoke compromised credentials at their
issuer.

## Deploy the service

Deploy `deploy/compose.secrets.yaml` as a standalone Compose project on independent infrastructure with its
own TLS PostgreSQL database, Vault, administration and deployment credentials. Run
`docker compose -f deploy/compose.secrets.yaml up --build -d`; it does not join Control Center's network or
publish an origin port. Its own `cloudflared` connector provides public HTTPS and private origin connectivity.
Create and administer that tunnel within the secrets-service boundary, using separate tunnel credentials
from Control Center. Configure its public hostname to route to `http://secrets:8080`.

Supply the Compose environment variables and owner-only files in `deploy/secrets-service-private/`, readable
by UID 65532; never commit that directory. The files contain the database URL, a random enrollment-grant
signing key of at least 32 bytes, metadata credential, Vault token, and `tunnel-token`. Set `SECRETS_PUBLIC_URL`
to the public HTTPS origin, matching the clients' configured URL exactly. Preserve request methods, escaped
paths, query strings and body bytes through the proxy. Certificate forwarding is neither used nor trusted.
The service requires HTTPS upstreams; its HTTP listener is private to the connector. Outside Compose it
defaults to `127.0.0.1:8080` and can sit behind another HTTPS proxy.

Cloudflare terminates HTTPS and is trusted with API traffic, including operator bearer credentials and the
plaintext data keys sent for wrapping and runtime delivery. Client-side value encryption does not hide values
from an intermediary that receives those keys. Machine request signatures prevent request forgery and
modification, but do not authenticate responses end to end. Keeping keys confidential from Cloudflare would
require authenticated application-layer encryption for both upload and delivery, with independently trusted
endpoint keys; this API does not provide it.

Enable Vault Transit at `transit/`. Grant `create,update` on `transit/encrypt/operator-<owner UUID>` and
`update` on the corresponding `transit/decrypt/` path. Keys are created lazily as nonexportable AES-256-GCM
keys without derivation or convergent encryption. Do not grant the service key export, configuration, policy
administration or deletion privileges. Disable raw Vault audit and ingress request-body logging; log
identifiers, not values, data keys or bearer credentials.

Set backend `SecretsURL` to the service HTTPS origin and `SecretsMetadataTokenFile` to an independent
credential of at least 32 bytes. Mount the same credential as `CONTROL_METADATA_TOKEN_FILE` on the service.
It allows restricted metadata and binding access, not grant issuance or decryption. The UI requests each
service's grant directly; Control Center never receives the setup grant or combined envelope.

For signing-key rollover, mount old key-ID/key pairs as a JSON object in `SECRETS_VERIFY_KEYS_FILE` and select
the new `SECRETS_SIGNING_KEY_ID`. Control Center uses `JWTSigningKeyID` and `JWTVerificationKeysFile`
similarly. Retain old verification keys until outstanding one-hour grants expire. Tokens issued before key IDs
remain valid for their original hour; there is no expiry grace.

## Enrollment and identity

`POST /v1/enrollment-grants` authenticates an operator bearer session and issues a reusable one-hour setup
JWT without allocating storage or Vault resources. Earlier grants remain valid until expiry or explicit
revocation through `/v1/enrollment-grants/revoke`; revocation does not affect enrolled identities. Control
Center independently offers `/api/bootstrap-token/revoke`. Both accept the signed token in the JSON `token`
field and retain revoked grant IDs only until expiry. Successful enrollments and explicit revocations are
audited; issuance uses fixed-cardinality `/metrics` counters and finite logs, never permanent per-grant audits
or grant bodies. Neither backend receives the other's grant.

The reusable, one-hour `lpcc1.` envelope is base64url JSON with `version:1`, `control`, and `setup`. The
installer splits it locally, saves an Ed25519 key before registration, and proves possession with a proof
bound to the current grant and installation request. Retries retain the key; attaching an existing
installation also requires its saved management credential. An interrupted setup grant remains in a protected
host file until completion or expiry; a timer checks expiry every 30 seconds, including after restart.

Managed mode requires a committed service identity, installed host credentials, current runtime capability,
K3s encryption and admission readiness. The runtime activates its pending binding with a signed request after these checks;
interrupted activation resumes automatically. Managed mode remains sticky through same-enrollment outages and
credential refresh. Explicit re-enrollment starts a new identity without inheriting the old marker.

Each runtime request carries an Ed25519-signed JWT using its existing private key. The issuer is
`lpcc-secrets-runtime-v1`; the audience is the public HTTPS service origin. Claims bind the node ID, identity
generation, issue time, one-minute expiry, random nonce (`jti`), and `request` digest. That digest is SHA-256 of
compact JSON `[method,request_target,hex(SHA256(body))]`, encoded as lowercase hex. The service verifies against
its own enrolled public key and atomically records used nonces in PostgreSQL before executing a request.
Replays fail across replicas and restarts, even after failed operations. Retries sign a new request. Hosts
must synchronize their clocks: issue times may be at most 30 seconds ahead; expiry has no grace period.
Expired nonce records are collected every minute with an extra minute of retention for small clock differences
between service replicas.

No machine certificates are issued or renewed. For a lost or compromised key, use owner-authorized
`POST /v1/machines/{node}/reset`, then run a fresh enrollment command. Reset is resumable and permanently
fences old keys and identity generations, including after restart. Use `/revoke` to revoke without reset.
Routine management-token refresh preserves the secrets identity. Control Center cannot replace an enrolled
key, but the service still consults its live machine state and assignments before authorizing delivery.

The APIs use bearer credentials and JSON without cookies, redirects or an `Origin` requirement; CORS restricts
browsers, not authorization. Headless clients can use the same protocol. Enrollment does not encrypt
third-party values; encryption is needed when uploading or replacing them.

## Values and delivery

Declare `container.secrets` with `name` (environment variable), `secret` (logical `lp-app-*` name), and `key`.
Values must be UTF-8, at most 64 KiB, and contain no NUL. Total injected values may not exceed 256 KiB per
incarnation, including repeated injections. Before withdrawing a healthy source, the runtime also checks each
environment/argument string against 128 KiB and the combined size against a conservative 1 MiB, including
names, terminators and pointers.

The API reserves immutable secret and version IDs. For each value, the client uses a fresh 32-byte data key
and 12-byte nonce; the wrap endpoint accepts only that reserved version's key. AES-GCM AAD is compact UTF-8
JSON `[1,owner_id,secret_id,name,key,version_id]`. Ciphertext includes the 16-byte tag; JSON byte fields use
standard base64. Replacement and deletion use expected revisions. Resolution uses current pinned assignments
and exact versions; callers cannot select another owner, arbitrary wrapped keys, historical assignments or
Vault paths.

Deletion removes live encrypted payloads and retains a tombstone; recreation gets a new identity. Superseded
payloads cannot authorize new starts and are purged after seven days. A reserved secret without a value, or
stale assignment metadata, blocks new starts without draining healthy consumers. Actual deletion, policy
denial and removal take precedence and drain existing consumers.

The runtime creates one immutable Kubernetes Secret per incarnation; admission restricts managed Pods to
their own Secret. Flux artifacts, journals and reports contain references and version IDs, never values.
Rotation prepares a successor, drains one source, waits for cleanup, starts its successor, and requires fresh
readiness and Node registration before taking the next slot. One-replica apps incur downtime. Central
revision or scale changes take precedence over unstarted preparations.

Healthy workloads continue during outages, but each new secret-dependent incarnation, including crash
recovery, needs live authorization. Known denial, deletion and cleanup continue without Vault. Missing
credentials never restore manual-Secret fallback for an active managed enrollment.

## Migration and recovery

Upgrade the service, installer and runtime together when moving from machine certificates to signed requests.
Run a fresh enrollment command on existing installations to install `identity.json` alongside the saved key;
same-enrollment retries preserve that key. Earlier runtime clients and certificate renewal/recovery endpoints
are no longer supported.

New installations enable K3s secrets encryption. For existing clusters, follow the [K3s existing-cluster
procedure](https://docs.k3s.io/cli/secrets-encrypt#enable-secrets-encryption-on-an-existing-cluster): enable,
configure and restart, rotate keys, restart, then verify `Enabled` and `reencrypt_finished`. Use this
installation's K3s data directory and systemd unit, then rerun enrollment. Upload manual values before
treating them as managed; preserve legacy finalizer updates while old Pods drain.

Back up identity files, encrypted Kubernetes state, the runtime journal, service database, signing keys,
and Vault state. Keep key backups separate from database backups. Set finite backup retention,
preserve deletion and revocation records on restore, and test revoked grants and identities and deleted secret
identities before reopening traffic. Rewrap retained and restorable data before retiring Vault wrapping-key
versions. Deletion does not immediately erase backups.
