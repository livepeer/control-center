# Machine tunnels and protected discovery

Control Center provisions one Cloudflare Tunnel per machine enrollment. Runtime's connector forwards client API and app traffic via private Traefik ingress and Node to workloads, and discovery uses machine-bound bearer auth ([discovery auth](discovery-auth.md)). Public Trickle (`/ai/trickle/*`) is denied, so dependent apps can appear in discovery while failing client calls.

## Configure Cloudflare infrastructure

Production requires Cloudflare account, zone, base domain, provisioning token, status TTL, drain deadline, and node/management exclusions in `deploy/config.toml` ([API token permissions](../api/internal/controlplane/tunnel/README.md#cloudflare-api-token-permissions)).

Enable Advanced Certificate Manager (ACM) with cert/hostname quota headroom (Control Center orders zone-apex and per-machine wildcard certs, Cloudflare validates/renews). Generated network policies assume Runtime's fixed Pod/Service ranges, so check CNI/DNAT and update `TunnelNodeAddresses` before adding ranges or node addresses. The bootstrap origin firewall is required.

Set `CloudflareIngressApproved = true` after confirming public routes and direct-origin isolation so verified sources advertise ready. Provisioned routes can carry traffic prior to readiness, and removal or compromise rotation revokes public access. Private API access survives Cloudflare outages.

Build the `amd64` connector image from the repository root.

```sh
docker build --platform linux/amd64 -f runtime/services/Dockerfile.tunnel \
  --build-arg RUNTIME_IMAGE=<REGISTRY>/livepeer-runtime@sha256:<RUNTIME_DIGEST> \
  -t <REGISTRY>/livepeer-tunnel:<RELEASE> runtime/services
```

## Credential boundaries

| Class | Delivery and storage | Consumer |
| --- | --- | --- |
| Cloudflare API token | Read-only `CloudflareAPITokenFile` (`0600`), account tunnels + zone DNS/certs | Control Center |
| Machine Tunnel token | Provider API → Control Center → management agent socket → tmpfs (`0600`) | `cloudflared` |
| Discovery private key | Read-only `JWTSigningPrivateKeyFile` mount | Control Center |
| Discovery public keys | Generated ConfigMap, rolled out independently | Runtime `ingress-auth` |
| Telemetry write token | Local JWT → management agent socket → relay memory (`1h` max) | Telemetry relay |

Bootstrap saves enrollment credentials in owner-only host files and `flux-system/livepeer-service-auth`, mounted only by the management agent. Connector and App Reconciler use separate Unix sockets with zero Kubernetes API credentials.

Protect Kubernetes Secrets and backups, and exclude private keys and provisioning tokens from bundles, ConfigMaps, args, URLs, logs, and metrics (the public key map is safe to distribute). The connector fetches a fresh token at startup (requiring Control Center and Cloudflare), Kubernetes restarts it as needed, and rotation replaces it ([Cloudflare tunnel tokens](https://developers.cloudflare.com/tunnel/reference/tunnel-tokens/)).

## Enrollment, reconciliation, and recovery

Active registration retries and credential refresh preserve node ID, while re-enrollment assigns a new node ID and tunnel UUID. Production enrolls over HTTPS via Cloudflare Tunnel, and dev HTTP uses a fresh separate DB ([development](development.md), [Runtime enrollment](../runtime/README.md#protected-machine-ingress)).

Machine endpoints are origin-bound and reject redirects. Retired credentials fetch terminal bundles and post scoped diagnostics, expiring per `TunnelStatusTTL` ([machine status](machine-status.md)).

Reconciliation provisions the tunnel and private ingress, waits for ingress digest, Runtime/connector readiness, and certs, then publishes three proxied CNAMEs to the tunnel UUID (`api.<node>.<domain>`, `discovery.<node>.<domain>`, `*.<node>.<domain>`).

Each generation must pass TLS, public API routing, authenticated discovery, unauthenticated discovery rejection, and public route isolation probes ([routing rules](../api/internal/controlplane/tunnel/README.md#machine-tunnels)). Services stay ClusterIP (zero public Ingress, NodePort, LoadBalancer, hostPort, or hostNetwork), and connector token changes replace its Deployment.

After uncertain provisioning or ownership conflicts, inventory provider resources before retrying and delete only proven-owned duplicates. Keep retirement records and restore authenticated ingress before publishing routes. Last valid artifacts and verified ingress survive transient provider outages. Retire the prior scope before changing Cloudflare accounts or zones.

## Rotate connectors, drain, and remove machines

Administrator authentication and auditing protect these endpoints.

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

Get `<NODE_ID>` from admin fleet responses and `generation` from `rollout_generation` in `GET /api/machines/<NODE_ID>/status`. Client endpoints are `ServiceURL` (API base URL) and `ProxyURLTemplate` (session proxy pattern).

- **Connector rotation** — keeps tunnel UUID, bumps token generation, replaces process (`compromised: true` disconnects active connections). Signing keys follow [key rotation](discovery-auth.md#rotate-signing-keys).
- **Drains and forced updates** — `DrainTimeout` expiry runs pending Runtime replacement (active sessions can drop). `drain/force` skips remaining wait. After normal removal timeout, call `drain/retry` or `DELETE` with `{"force":true}`. Timeout defaults and app cleanup live in [drain and removal](app-registry.md#runtime-delivery-drain-and-removal).
- **API upgrade order** — stop older API replicas before an upgraded replica writes rollout state, and finish active forced updates before rollback.
- **Provider cleanup** — deletion denies tokens, installs deny-only ingress, revokes connector auth before disconnecting, and deletes owned DNS and tunnel resources even offline (preserving replacement routes/certs). Forced removal removes the connector last, keeping volumes and bootstrap files intact (verify provider absence separately from local cleanup).

## Retire legacy HTTP enrollment

1. Close HTTP registration and revoke active grants (or wait `1h`) while old private config and reporting endpoints stay reachable.
2. Confirm an authenticated GET to each retired machine's config URL returns `X-Livepeer-Terminal: true` and `X-Livepeer-App-Cleanup-Ready: true` before stopping old endpoints.
3. Remove `CloudflareEnabled` and `CLOUDFLARE_ENABLED`, verify the Cloudflare route to the private API origin, and deploy matching API, Runtime, and bootstrap releases.
4. Export verified HTTPS `LIVEPEER_API_URL` and run `--reenroll` with a fresh owner enrollment command for a new node ID. Force-retire missed active HTTP enrollments while keeping a private path for terminal bundles and cleanup reports.

## Verify and upgrade cloudflared

Run [end-to-end tests](development.md#end-to-end-tests) for routing and isolation checks. Before upgrading `cloudflared`, check [origin parameters](https://developers.cloudflare.com/tunnel/reference/origin-parameters/), [ingress matching](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/configuration-file/), and [DNS lifecycle](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/dns/).
