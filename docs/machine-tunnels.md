# Machine tunnels and protected discovery

Control Center provisions one Cloudflare Tunnel per machine enrollment. Runtime's
connector starts cloudflared, which forwards to private Traefik ingress, then Node;
Node routes application traffic to private workloads. Client API and app hostnames
are public through the tunnel; discovery requires a machine-bound ingress bearer
token.

Public Trickle is unsupported and `/ai/trickle/*` is denied. Apps register
normally. A Trickle-dependent app can appear in discovery and fail for clients.

See [discovery authentication](discovery-auth.md) for signing configuration
and key rotation.

## Infrastructure and enablement

Supply account and zone IDs, a dedicated base domain, a scoped backend API
credential, observation TTL, drain deadline, hostname and certificate quota
headroom, and all fleet node and management address exclusions. Use the [required API token permissions](../api/internal/controlplane/tunnel/README.md#cloudflare-api-token-permissions)
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

## Credential boundaries

| Class | Delivery / storage | Consumers |
| --- | --- | --- |
| Backend Cloudflare API token | Private, read-only operator-mounted file (`CloudflareAPITokenFile`), mode 0600; scoped account tunnel and zone DNS/certificate write permissions | Control Center only |
| Machine Tunnel token | Provider API → authenticated Control Center endpoint → management agent's scoped Unix socket → private tmpfs file mode 0600 | cloudflared process only |
| Discovery signing private key | Local private read-only `JWTSigningPrivateKeyFile` mount | Control Center only |
| Discovery verification public keys | Generated ConfigMap, independently rolled out | Runtime ingress-auth |
| Telemetry write token | Minted locally by Control Center for the machine credential → management agent's scoped Unix socket → telemetry relay memory; one-hour lifetime | Telemetry relay only |

Bootstrap stores the machine enrollment credential in owner-only host files and
the `flux-system/livepeer-service-auth` Secret. Only the management agent mounts
its token. The connector uses its own socket and has no Kubernetes API credential.
App Reconciler reports through a separate socket. Protect Kubernetes Secrets and
backups at deployment.

Keep private signing material and provisioning credentials out of bundles,
ConfigMaps, command arguments, URLs, logs and metric labels. The public key map
is safe to distribute; private material stays with Control Center.

The connector fetches a fresh token before each start. Kubernetes restarts it
when needed; token rotation replaces it. Starting it requires Control Center and
Cloudflare. See
[Tunnel token behavior](https://developers.cloudflare.com/tunnel/reference/tunnel-tokens/).

## Enrollment, refresh and status

Active registration retries and credential refresh retain the node ID.
Re-enrollment creates a fresh node ID and tunnel UUID.
Cloudflare Tunnel must be the HTTPS front door, with the API origin reachable
only through the trusted connector. The API does not infer transport security
from arbitrary forwarded headers. HTTPS enrollment is eligible even when
provisioning is disabled; development credentials cannot enable live tunnels.
Use the Runtime commands in [its README](../runtime/README.md#protected-machine-ingress).

Machine endpoints are origin-bound and reject redirects. Retired credentials can
fetch terminal cleanup instructions and send scoped diagnostics. Reports expire
according to `TunnelStatusTTL`; see [machine status](machine-status.md) for
diagnosis and recovery.

## Reconciliation and recovery

The worker provisions the tunnel and private ingress routing. It waits for the
current ingress configuration digest, Runtime readiness and connector readiness
before publishing routes. Orchestrator updates and endpoint changes wait for
sessions to drain. Endpoint changes require a retry if the deadline expires.
Connector token changes replace its Deployment.

After certificate and Runtime readiness, three proxied CNAMEs point at the tunnel UUID:
`api.<node>.<domain>`, `discovery.<node>.<domain>` and `*.<node>.<domain>`.
TLS, public API routing, authenticated discovery, unauthenticated discovery
rejection and public route isolation probes must succeed for each endpoint
generation. API and discovery forwarding set Host to the private orchestrator;
app forwarding preserves the original Host and application Authorization header.
Traefik preserves the forwarded Host. The API host allows reservation,
stop/payment and payment refresh; discovery allows `/discovery`. Other paths on
those hosts return 404. App hosts deny discovery, runner, metrics, health and
Trickle paths and forward the rest; Node checks HTTP methods.
Services remain ClusterIP. Never add public Ingress, NodePort, LoadBalancer,
hostPort or hostNetwork to generated workloads.

If provisioning has an uncertain outcome or an ownership conflict, inventory
provider resources before retrying. Delete only proven-owned duplicates; do not
adopt resources by name or discard retirement records. Restore authenticated
ingress before publishing routes. The last valid artifact and verified ingress
survive transient provider failures. Account or zone changes
require retiring the previous scope first.

## Rotation and removal

Existing administrator authentication/auditing protects:

```text
POST /api/admin/machines/<NODE_ID>/tunnel/rotate
{"kind":"connector","compromised":false}

POST /api/admin/machines/<NODE_ID>/drain/retry
{"generation":<EXPIRED_GENERATION>}

POST /api/admin/machines/<NODE_ID>/drain/force
{"generation":<ROLLOUT_GENERATION>}

DELETE /api/admin/machines/<NODE_ID>
{"force":false}
```

The administrator fleet response supplies the node ID. Set `generation` to
`rollout_generation` from `GET /api/machines/<NODE_ID>/status` for drain commands.
Connector rotation keeps the tunnel UUID, advances token generation and replaces
the process. Compromise rotation also disconnects existing connectors. Rotation
alone leaves established connections active. Follow the
[signing-key rotation procedure](discovery-auth.md#key-rotation)
for public-key distribution and retention. Signing and ingress verification work
without the secrets service.

- **Orchestrator replacement.** `drain/force` skips the wait for a replacement
  at the same client addresses. Administrators can run it at any time while
  sessions drain. Control Center forces the replacement automatically after
  `DrainTimeout`. Forced updates end remaining sessions, and the replacement
  accepts sessions when Runtime reports it ready.
- **Endpoint changes and normal removal.** Control Center keeps the old client
  addresses until the runner confirms the drain. That rule also applies when an
  endpoint change includes an orchestrator replacement. Normal removal also
  waits for confirmation. Each attempt has up to `DrainTimeout` from the
  request (`12h10m` by default). At `0s`, the attempt expires immediately. If
  the drain times out, use `drain/retry` to start a fresh attempt. See
  [drain settings](app-registry.md#runtime-delivery-and-completion-contract).
- **Forced removal.** Send `force:true` with the machine DELETE request to
  start removal without waiting for a graceful drain.

Stop all older Control Center API replicas before an upgraded replica starts
writing rollout state. Let ongoing forced updates finish before rolling back to an
older API version.

Deletion denies token delivery, installs deny-only ingress, revokes connector
authentication before disconnecting, deletes owned DNS and tunnel resources.
Cleanup proceeds even with the machine offline. Retired-node cleanup cannot
delete a replacement node's routes or certificates.

Forced removal stops Node before app cleanup. Final cleanup removes the connector.
Retained volumes and bootstrap resources remain; verify provider absence separately
from local cleanup.
See [app removal](app-registry.md#runtime-delivery-and-completion-contract) for
normal and forced removal behavior.

## Integration checks

App assignments follow the [delivery and cleanup contract](app-registry.md#runtime-delivery-and-completion-contract).
Run the [end-to-end harness](development.md#end-to-end-tests) for routing and isolation checks.

When upgrading cloudflared, review its [origin parameters](https://developers.cloudflare.com/tunnel/reference/origin-parameters/),
[ingress matching](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/configuration-file/)
and [DNS lifecycle](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/dns/).
