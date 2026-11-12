# Machine tunnels and protected discovery

Control Center provisions one Cloudflare Tunnel per machine enrollment. Runtime's
connector obtains a tunnel token and starts cloudflared; Kubernetes restarts it as
needed. The tunnel enables external access, and Node routes application traffic
to private workloads.
API and discovery use separate hostnames protected by one Cloudflare Access
application.

Public Trickle is unsupported and `/ai/trickle/*` is denied. Apps register
normally. A Trickle-dependent app can appear in discovery and fail for clients.

## Infrastructure and enablement

Supply account and zone IDs, a dedicated base domain, Zero Trust team, scoped
backend API credential, token lifetime/rotation window, observation TTL, drain
deadline, quotas with overlapping-token/hostname headroom, and all fleet node
and management address exclusions. Use the [required API token permissions](../api/internal/controlplane/tunnel/README.md#cloudflare-api-token-permissions)
when creating the backend credential. The generated network policy assumes
Runtime's fixed Pod/Service ranges. Verify actual
CNI/DNAT behavior; update exclusions before introducing any new network ranges
or node addresses.

Control Center orders an Advanced certificate for the zone apex and each machine's
wildcard; Cloudflare handles validation and renewal. Enable Advanced Certificate
Manager on an authoritative Cloudflare zone, allow certificate quota headroom, and
grant the provisioning token zone-scoped SSL and Certificates Write permission.

Configure `api/config.example.toml` using operator-selected values. Both feature
flags default false. `CloudflareEnabled` permits provisioning and external
probes; `CloudflareIngressApproved` permits a source to report ready after the
release evidence below is accepted. It is a readiness gate, not an edge kill
switch: provisioned client routes can be reachable before source advertisement.
Disabling the worker does not revoke resources. Use removal/compromise actions
when external access must stop.

From the repository root, build the supported amd64 connector image:

```sh
docker build --platform linux/amd64 -f runtime/services/Dockerfile.tunnel \
  --build-arg RUNTIME_IMAGE=<REGISTRY>/livepeer-runtime@sha256:<RUNTIME_DIGEST> \
  -t <REGISTRY>/livepeer-tunnel:<RELEASE> runtime/services
```

The separate image contains checksum-verified cloudflared 2026.10.7 and the
connector helper copied from the digest-pinned Runtime image. Push the image and
set backend `RUNTIME_CONNECTOR_IMAGE` (or `RuntimeConnectorImage` in configuration)
to its published digest before enabling managed ingress. Startup disables automatic
updates and enables path normalization. Changing the image replaces the connector
Deployment.

## Credential boundaries

| Class | Delivery / storage | Consumers |
| --- | --- | --- |
| Backend Cloudflare API token | Private, read-only operator-mounted file (`CloudflareAPITokenFile`), mode 0600; scoped account tunnel/Access and zone DNS/certificate write permissions | Control Center only |
| Machine Tunnel token | Provider API → authenticated Control Center endpoint → management agent's scoped Unix socket → private tmpfs file mode 0600 | cloudflared process only |
| API/discovery Access ID/secret | AES-GCM encrypted PostgreSQL row, immutable version reference; keyring in a separate private mounted file | Authorized backend API callers and discovery Collector |

Bootstrap stores the machine enrollment credential in owner-only host files and
the `flux-system/livepeer-service-auth` Secret. Only the management agent mounts
its token. The connector uses its own socket and has no Kubernetes API credential.
App Reconciler reports through a separate socket. Protect Kubernetes Secrets and
backups at deployment.

Use independently generated random 32-byte keys, base64 encoded:

```json
{"current":"<KEY_ID>","keys":{"<KEY_ID>":"<BASE64_32_BYTES>"}}
```

Back it up separately from database ciphertext. Add a new key, select it as
current, and restart Control Center; reconciliation re-encrypts existing rows.
Retain old keys until re-encryption and backup retention obligations are met.
Keep credentials out of bundles, ConfigMaps, command arguments, URLs, logs,
audit bodies and metric labels. Protect process memory and core dumps. Replace
backend credentials by controlled restart.

The connector fetches a fresh token before each start. Kubernetes restarts it
when needed; token rotation replaces it. Starting it requires Control Center and
Cloudflare. See
[Tunnel token behavior](https://developers.cloudflare.com/tunnel/reference/tunnel-tokens/).

## Enrollment, refresh and status

Identity is `(node_id, enrollment_epoch)`, with a separate credential version.
Idempotent active registration retains both; refresh increments only credential
version. Deletion and re-enrollment create a new epoch and tunnel UUID.
Cloudflare Tunnel must be the HTTPS front door, with the API origin reachable
only through the trusted connector. The API does not infer transport security
from arbitrary forwarded headers. HTTPS enrollment is eligible even when
provisioning is disabled; development credentials cannot enable live tunnels.
Use the Runtime commands in [its README](../runtime/README.md#protected-machine-ingress).

Refresh uses a durable operation ID so retries do not increment the credential
version twice. Interrupted transitions resume with the saved operation. HTTP
development mode cannot enable live provisioning.

Machine endpoints provide configuration, connector tokens, component status
and terminal removal acknowledgement. They are origin-bound, reject redirects
and return `Cache-Control: no-store`. Retired credentials can fetch their terminal
artifact, acknowledge its epoch and digest, and send scoped cleanup diagnostics.
See [machine and app status](machine-status.md) for evidence and recovery rules.

Reports retain their observation time and expiry across delivery retries. The
agent checks Node's applied revision, readiness, private discovery address and
installed K3s version, and probes cloudflared and the proxy. Source readiness
expires with `TunnelStatusTTL`.

## Reconciliation and recovery

Retirement is recorded even when machine deletion cascades from Supabase Auth.
Enrollment commits a private-only bundle without contacting Cloudflare. The
worker creates or recovers a tunnel, source token, an Access application covering
both hostnames and a Service Auth-only policy. It installs audience-validating
ingress before publishing routing. Managed Node configuration changes drain the
existing workload before replacement; an expired deadline requires intervention.
Token-generation changes replace the connector; remote-only ingress changes do
not unnecessarily restart it. Cancelling an endpoint change releases its drain;
retrying the same unfinished target preserves the original deadline.

After certificate and Runtime readiness, three proxied CNAMEs point at the tunnel UUID:
`api-<suffix>.<node>.<domain>`, `discovery-<suffix>.<node>.<domain>` and `*.<node>.<domain>`.
The shared random base32 suffix is persisted per enrollment. API and discovery
share Access service credentials. TLS, authenticated API/discovery,
unauthenticated rejection and authenticated isolation probes must succeed for each
endpoint generation. API/discovery forwarding sets Host to the private orchestrator;
wildcard application forwarding preserves the actual Host.
The loopback proxy rejects invalid app Hosts and strips Access credentials.
The API host allows reservation, stop/payment and payment refresh; discovery
allows `/discovery`. Other paths on those hosts return 404. App hosts deny
reserved paths and forward the rest; Node checks HTTP methods.
Services remain ClusterIP. Never add public Ingress, NodePort, LoadBalancer,
hostPort or hostNetwork to generated workloads.

On a lost create response, inventory scoped ownership before retrying. If no
result is found, retry with bounded backoff and the same durable operation
marker. Select a provider ID once and delete proven-owned duplicates; late
results cannot replace the selected tunnel or immutable credential version.
A found Access token without a stored secret is revoked and replaced. The
selected ID and encrypted Access secret are committed together. Continue watching
uncertain operations after observed absence and retirement to clean up late
results. Foreign ownership conflicts and externally deleted selected resources block
reconciliation. Resolve these conflicts through an operator inventory; never
adopt by a similar name or discard retirement records.

The last valid artifact and verified ingress survive transient provider failures.
Confirmed unsafe Access protection disables routes until verified protection is restored.
A rollback uses a new
generation and the prior restrictive settings; it never restores a revoked
credential. Account/zone/team changes require retiring the previous scope first.
Domain replacements drain and retain predecessor discovery protection until
the new source is acknowledged.

## Rotation and removal

Existing administrator authentication/auditing protects:

```text
POST /api/admin/machines/<NODE_ID>/tunnel/rotate
{"epoch":"<EPOCH>","kind":"connector|access","compromised":false}

POST /api/admin/machines/<NODE_ID>/drain/retry
{"epoch":"<EPOCH>","generation":<EXPIRED_GENERATION>}

DELETE /api/admin/machines/<NODE_ID>
{"epoch":"<EPOCH>","force":false}
```

The administrator fleet response supplies the epoch. Connector rotation keeps
the tunnel UUID, advances token generation and replaces the process. Compromise
rotation also disconnects existing connectors: rotation alone leaves established
connections active. Access rotation overlaps versions until successful Collector
acknowledgement; compromise revokes predecessors immediately. Expiry and
security rotations proceed even when Runtime is offline; `RotationReason`
reports rotation separately from observation expiry. See
[Access service tokens](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/).

Ordinary removal withdraws readiness and waits for draining. An expired drain
deadline remains blocked even if a late completion arrives. An administrator can
start a fresh drain with `drain/retry`, or deliberately remove with `force:true`.
Deletion denies token delivery, installs deny-only ingress, revokes connector
authentication before disconnecting, deletes DNS/tunnel resources before Access protection,
and revokes source tokens.
Cleanup proceeds even with the machine offline. A new epoch cannot reuse stable
hostnames until the predecessor's external cleanup is complete.

The terminal artifact prunes the connector and orchestrator and delivers app-removal
intents; Runtime cleans up assigned apps.
Bootstrap namespaces/Secrets, retained PV/PVC and shared upgrade controller/CRDs
remain, with no active upgrade Plan. Terminal delivery persists through local
acknowledgement; authentication/fetch errors never mean removal. Verify provider
absence separately from local cleanup.

## Integration agreements and release evidence

App assignments follow the [delivery and cleanup contract](app-registry.md#runtime-delivery-and-completion-contract).
Before production, test with compatible Node and SDK images and two machines:

1. Verify Cloudflare Access, DNS and TLS, including rejection of invalid or revoked
   credentials and attempts to bypass the tunnel directly.
2. Exercise Node routing to private gVisor apps, including session, payment and
   application paths. Test HTTP, SSE and WebSocket performance.
3. Test restart, reboot, provider and API outages, rotation, updates and offline
   removal. Check local and provider cleanup, and test actual CNI/DNAT, NodePort,
   host-port, direct Pod/Service and IPv6 access.

Cloudflared normalization affects matching and can differ from the forwarded
path; configuration inspection is not isolation evidence. Review Cloudflare
[origin parameters](https://developers.cloudflare.com/tunnel/reference/origin-parameters/),
[ingress matching](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/configuration-file/)
and [DNS lifecycle](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/dns/)
when upgrading the pinned image.
