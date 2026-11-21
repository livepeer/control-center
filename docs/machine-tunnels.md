# Machine tunnels and protected discovery

Control Center provisions one Cloudflare Tunnel per machine enrollment. The Runtime
connector forwards client API and app traffic through private Traefik ingress and
Node to workloads. Discovery requires a machine-bound ingress bearer token. Public
Trickle is unsupported: `/ai/trickle/*` is denied, so dependent apps can appear in
discovery but fail for clients. See [discovery authentication](discovery-auth.md).

## Production infrastructure

Production requires Cloudflare. Set the account, zone, base domain, provisioning
credential, status TTL, drain deadline, and node and management address exclusions
in the deployed `deploy/config.toml`. See the [API token permissions](../api/internal/controlplane/tunnel/README.md#cloudflare-api-token-permissions).

Enable Advanced Certificate Manager on the authoritative zone and allow
certificate and hostname quota headroom. Control Center orders certificates for the zone apex and each machine's
wildcard. Cloudflare validates and renews them. The generated network policy assumes
Runtime's fixed Pod/Service ranges. Verify CNI/DNAT behavior and update exclusions
before adding network ranges or node addresses. The bootstrap origin firewall is required.

Set `CloudflareIngressApproved = true` after verifying public routes and direct-origin
isolation. This permits verified sources to report ready. Provisioned routes can
serve traffic before readiness is advertised. Use removal or compromise actions to
revoke public access. The private API stays up during provider outages.

Build the supported amd64 connector image from the repository root:

```sh
docker build --platform linux/amd64 -f runtime/services/Dockerfile.tunnel \
  --build-arg RUNTIME_IMAGE=<REGISTRY>/livepeer-runtime@sha256:<RUNTIME_DIGEST> \
  -t <REGISTRY>/livepeer-tunnel:<RELEASE> runtime/services
```

## Retire legacy HTTP enrollment

1. Close HTTP registration and revoke outstanding grants, or wait one hour for them
   to expire. Keep the old release's private configuration and reporting endpoints
   reachable while retiring HTTP machines.
2. Before shutting those endpoints down, confirm that an authenticated GET to
   each retired machine’s saved configuration URL returns
   `X-Livepeer-Terminal: true` and `X-Livepeer-App-Cleanup-Ready: true`.
3. Remove `CloudflareEnabled` and `CLOUDFLARE_ENABLED`, verify the Cloudflare route
   to the private API origin, and deploy matching API, Runtime and bootstrap releases.
4. Export `LIVEPEER_API_URL` with the verified HTTPS API URL and run
   `--reenroll` with a fresh owner enrollment command to obtain a new node ID.
   Force retirement of any missed active HTTP enrollment. Keep a private path
   for the machine to fetch terminal instructions and report app cleanup before
   re-enrolling. See [rotation and removal](#rotation-and-removal).

## Credential boundaries

| Class | Delivery / storage | Consumers |
| --- | --- | --- |
| Backend Cloudflare API token | Private, read-only operator-mounted file (`CloudflareAPITokenFile`), mode 0600; scoped account tunnel and zone DNS/certificate write permissions | Control Center only |
| Machine Tunnel token | Provider API → authenticated Control Center endpoint → management agent's scoped Unix socket → private tmpfs file mode 0600 | cloudflared process only |
| Discovery signing private key | Local private read-only `JWTSigningPrivateKeyFile` mount | Control Center only |
| Discovery verification public keys | Generated ConfigMap, independently rolled out | Runtime ingress-auth |
| Telemetry write token | Minted locally by Control Center for the machine credential → management agent's scoped Unix socket → telemetry relay memory; one-hour lifetime | Telemetry relay only |

Bootstrap stores enrollment credentials in owner-only host files and the
`flux-system/livepeer-service-auth` Secret. Only the management agent mounts its
token. The connector uses its own socket and has no Kubernetes API credential.
App Reconciler uses a separate socket. Protect Kubernetes Secrets and backups.
Keep private keys and provisioning credentials out of bundles, ConfigMaps, command
arguments, URLs, logs and metrics. The public key map is safe to distribute.

The connector fetches a fresh token at startup, which requires Control Center and
Cloudflare. Kubernetes restarts it as needed and token rotation replaces it. See
[Cloudflare tunnel tokens](https://developers.cloudflare.com/tunnel/reference/tunnel-tokens/).

## Enrollment, refresh and status

Active registration retries and credential refresh retain the node ID. Re-enrollment
creates a fresh node ID and tunnel UUID. Production enrollment uses HTTPS through
Cloudflare Tunnel to the private API origin. Private development HTTP uses a fresh
separate database. See [development setup](development.md) and
[Runtime enrollment commands](../runtime/README.md#protected-machine-ingress).

Machine endpoints are origin-bound and reject redirects. Retired credentials can
fetch terminal cleanup instructions and send scoped diagnostics. Reports expire
according to `TunnelStatusTTL`; see [machine status](machine-status.md) for
diagnosis and recovery.

## Reconciliation and recovery

The worker provisions the tunnel and private ingress routing. It waits for the
current ingress configuration digest, Runtime readiness and connector readiness
before publishing routes. See [drain controls](#rotation-and-removal) for
orchestrator updates and endpoint changes. Connector token changes replace its
Deployment.

After certificate and Runtime readiness, three proxied CNAMEs point at the tunnel UUID:
`api.<node>.<domain>`, `discovery.<node>.<domain>` and `*.<node>.<domain>`.
TLS, public API routing, authenticated discovery, unauthenticated discovery
rejection and public route isolation probes must succeed for each endpoint
generation. See the [tunnel routing rules](../api/internal/controlplane/tunnel/README.md#machine-tunnels).
Services remain ClusterIP. Never add public Ingress, NodePort, LoadBalancer,
hostPort or hostNetwork to generated workloads.

After an uncertain provisioning outcome or ownership conflict, inventory provider
resources before retrying. Delete only proven-owned duplicates. Preserve retirement
records and restore authenticated ingress before publishing routes. The last valid
artifact and verified ingress survive transient provider failures. Retire the previous
scope before changing accounts or zones.

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

Get the node ID from the administrator fleet response and set drain command
`generation` to `rollout_generation` from `GET /api/machines/<NODE_ID>/status`.
Connector rotation retains the tunnel UUID, advances the token generation and
replaces the process. Compromise rotation also disconnects existing connections.
Signing and ingress verification work without the secrets service. Follow the
[signing-key rotation procedure](discovery-auth.md#key-rotation).

Client endpoints are the API base URL (`ServiceURL`) and session proxy URL
pattern (`ProxyURLTemplate`).

- **Deadline.** When `DrainTimeout` expires, Control Center stops waiting for
  sessions and proceeds with the pending Runtime replacement. Active sessions
  can be interrupted. See
  [drain settings](app-registry.md#runtime-delivery-and-completion-contract).
- **Force an update.** Use `drain/force` to skip the remaining drain wait for a
  pending runtime change.
- **Remove a machine.** Normal removal requires all sessions to drain before
  the deadline. After a timeout, use `drain/retry` to start a new drain or
  send a machine `DELETE` with `{"force":true}` to skip it.

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
