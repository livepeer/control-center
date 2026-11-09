# Machine tunnels and protected discovery (#112)

Control Center provisions one Cloudflare Tunnel per machine enrollment. Runtime
runs the connector; Node routes application traffic to private workloads.
API and discovery use separate hostnames protected by one Cloudflare Access
application.

Public Trickle is unsupported and `/ai/trickle/*` is denied. Apps register
normally. A Trickle-dependent app can appear in discovery and fail for clients.

## Infrastructure and enablement

Supply account and zone IDs, a dedicated base domain, Zero Trust team, scoped
backend API credential, token lifetime/rotation window, observation TTL, drain
deadline, quotas with overlapping-token/hostname headroom, and all fleet node
and management address exclusions. Use the [required API token permissions](../api/internal/controlplane/tunnel/README.md#cloudflare-api-token-permissions)
when creating the backend credential. Private Control Center exceptions are
individual private /32 or /128 addresses on HTTPS port 443. The generated
network policy assumes Runtime's fixed Pod/Service ranges. Verify actual
CNI/DNAT behavior; update exclusions before introducing any new network ranges
or node addresses. Management connectivity remains #95's responsibility.

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

Build the supported amd64 connector image, publish it, and configure its actual
immutable digest:

```sh
docker build --platform linux/amd64 -f runtime/services/Dockerfile.tunnel \
  --build-arg RUNTIME_IMAGE=<REGISTRY>/livepeer-runtime@sha256:<RUNTIME_DIGEST> \
  -t <REGISTRY>/livepeer-tunnel:<RELEASE> runtime/services
```

The image verifies the SHA256 of cloudflared 2026.10.7 and copies the helper from
the pinned Go Runtime image. Both connector formats use that Runtime image for
the credential-free loopback proxy sidecar. Set
`RuntimeConnectorImage` to its published digest before enabling managed ingress
on format 3. `CloudflareConnectorImage` remains the legacy format 1/2 image. Startup disables
automatic updates and enables path normalization. Changing the selected image
replaces the connector Deployment.

## Credential boundaries

| Class | Delivery / storage | Consumers |
| --- | --- | --- |
| Backend Cloudflare API token | Private, read-only operator-mounted file (`CloudflareAPITokenFile`), mode 0600; scoped account tunnel/Access and zone DNS/certificate write permissions | Control Center only |
| Machine Tunnel token | Provider API → authenticated Control Center endpoint → management agent's scoped Unix socket → private tmpfs file mode 0600 | cloudflared process only |
| API/discovery Access ID/secret | AES-GCM encrypted PostgreSQL row, immutable version reference; keyring in a separate private mounted file | Authorized backend API callers and discovery Collector |

Bootstrap stores the machine enrollment credential in owner-only host files and
the `flux-system/livepeer-service-auth` Secret. In format 3, only the management
agent mounts its token. The connector mounts its own socket directory and has no
Kubernetes API credential. App Reconciler mounts only nonsecret enrollment fields
and reports through a separate scoped socket. The agent has limited observation,
artifact-status and ownership-migration RBAC. Protect
Kubernetes Secrets and backups at deployment.

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

The Go helper deletes prior launch files, fetches a fresh token before every
start and execs cloudflared. Kubernetes owns exit and restart handling. An agent
restart leaves a healthy connector running; uncertain associations report no
positive readiness until a fresh probe revalidates the same Pod and private PID 1
grant. Rotation replaces the connector. New starts require Control Center and
Cloudflare. See
[Tunnel token behavior](https://developers.cloudflare.com/tunnel/reference/tunnel-tokens/).

## Enrollment, refresh and status

Identity is `(node_id, enrollment_epoch)`, with a separate credential version.
Idempotent active registration retains both; refresh increments only credential
version. Deletion and re-enrollment create a new epoch and tunnel UUID.
Cloudflare Tunnel must be the HTTPS front door, with the API origin reachable
only through the trusted connector. The API does not infer transport security
from arbitrary forwarded headers. Migration 004 makes existing credentials
legacy config-only. An HTTPS refresh with a fresh owner enrollment JWT is
required before enabling their tunnels.
Fresh HTTPS enrollment remains eligible when provisioning is disabled; later
enablement does not require another refresh. Development credentials stay ineligible.
Use the Runtime commands in [its README](../runtime/README.md#protected-machine-ingress).

Refresh uses a durable operation ID so retries do not increment the credential
version twice. Interrupted transitions resume with the saved operation. HTTP
development mode cannot enable live provisioning.

Machine endpoints provide configuration, connector tokens, component status
and terminal removal acknowledgement. They are origin-bound, reject redirects
and return `Cache-Control: no-store`. Retired credentials can fetch their terminal
artifact, acknowledge its epoch and digest, and send scoped cleanup diagnostics.
See [machine and app status](machine-status.md) for evidence and recovery rules.

Reports merge independently. Upgraded reports retain their original observation
time and expiry; delivery retries do not renew evidence. Legacy reports provide
limited evidence based on receipt time. The agent checks Node's
applied revision, completed rollout/config digest, metrics `/readyz`, private
discovery address and installed K3s version. Format 3 connector reports use a fresh
local probe of cloudflared and the proxy, the observed configuration version and
an incarnation-bound token grant.
Probe reporting is best effort within its five-second deadline; missing evidence
expires without restarting cloudflared. Source readiness expires with
`TunnelStatusTTL`; an offline source remains available
to #116's eviction policy. Bundle download or Pod readiness alone is insufficient.

## Reconciliation and recovery

Retirement is recorded even when machine deletion cascades from Supabase Auth.
Enrollment commits a private-only bundle without contacting Cloudflare. Existing
private Node workloads remain in place during additive upgrades until the
controlled routing rollout. The worker creates or recovers a tunnel, source
token, an Access application covering both hostnames and a Service Auth-only
policy. It installs audience-validating ingress before publishing routing. Managed Node configuration changes publish a drain
intent while retaining the previous workload. A fresh matching Runtime #113/#94 drain report
releases the replacement; an expired deadline blocks and requires intervention.
Token-generation changes replace the connector; remote-only ingress changes do
not unnecessarily restart it.
Private machines outside managed rollout retain their existing update behavior
while provisioning is disabled. Cancelling an endpoint change releases its drain;
retrying the same unfinished target preserves the original deadline.

After certificate and Runtime readiness, three proxied CNAMEs point at the tunnel UUID:
`api-<suffix>.<node>.<domain>`, `discovery-<suffix>.<node>.<domain>` and `*.<node>.<domain>`.
The shared random base32 suffix is persisted per enrollment. API and discovery
share Access service credentials. TLS, authenticated API/discovery,
unauthenticated rejection and authenticated isolation probes must succeed for each
endpoint generation. API/discovery forwarding sets Host to the private orchestrator;
wildcard application forwarding preserves the actual Host.
The loopback proxy rejects malformed, port-bearing, nested or reserved application
Hosts and removes Access headers and cookies before requests reach Node. Paths are matched
independently of HTTP method; Node enforces endpoint methods. The allowlist is
reservation, client session stop/payment, payment refresh, application paths,
`/run` and `/proxy`. Reserved discovery, runner/control, metrics, health and
Trickle paths precede forwarding rules. Unknown hosts/paths default to 404.
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
Retain migrations 004 and 008 and their enrollment/resource/certificate ledgers during software rollback;
never run their down migrations while owned resources or terminal delivery remain.
An older API that understands only legacy HMAC credentials cannot serve modern
enrollments; rollback to a compatible release rather than changing their verifier.
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

Ordinary removal stages drain and withdraws readiness. Runtime #113/#94 must
coordinate admission withdrawal and report drained for that generation. An expired drain deadline remains
blocked even if a late completion arrives. An administrator can start a fresh,
audited drain generation with `drain/retry`, or deliberately remove with
`force:true`. Legacy credentials require refresh or explicit force removal.
Deletion denies token delivery, installs deny-only ingress, revokes connector
authentication before disconnecting, deletes DNS/tunnel resources before Access protection,
and revokes source tokens.
Cleanup proceeds even with the machine offline. A new epoch cannot reuse stable
hostnames until the predecessor's external cleanup is complete.

The terminal artifact prunes the connector and orchestrator and delivers app-removal
intents; the Runtime lifecycle consumer (#113) cleans up assigned apps.
Bootstrap namespaces/Secrets, retained PV/PVC and shared upgrade controller/CRDs
remain, with no active upgrade Plan. Terminal delivery persists through local
acknowledgement; authentication/fetch errors never mean removal. Verify provider
absence separately from local cleanup.

## Integration agreements and release evidence

App assignments use the [delivery and cleanup contract](app-registry.md#runtime-delivery-and-completion-contract).
Normal removal and terminal removal acknowledgement require app cleanup by the
Runtime lifecycle consumer (#113). Runtime #113/#94 owns admission, destination
grants, drain policy, deadlines and workload pruning. #114 supplies collision-safe DNS-label
registration IDs (at most 63 lowercase characters), private `proxy=true`
RunnerURLs, literal IP/IP:port/CIDR RunnerGrants, registration observations and
compatible SDK/Node images.
Do not claim end-to-end private application readiness before that integration.

#115/#116 consume `DiscoverySources`, `ResolveAccessCredential` and
`AcknowledgeDiscovery` internally. A source includes stable ID, node/epoch,
complete URL, lifecycle/readiness, source generation and versioned credential
reference. `verified_generation` records the last approved source generation;
admit a new generation only when ready. Previously admitted offline generations
remain subject to #116's policy. Resolve an immutable snapshot only in authorized backend code. Send
both Access headers on every collection request. Install replacements with a
concurrency-safe wrapper or stop/join/recreate Collector, then acknowledge only
after successful collection with that snapshot. #116 owns deployment/offline
eviction. Add an authenticated resolution API only if deployment separation
requires one. No Node CLI authentication extension is required.

Simulated provider, database and local TLS/socket tests verify lifecycle,
encryption, fencing, lost-response recovery, references, rollout ordering and
protected delivery. They do not establish Cloudflare edge security. Before
advertising a production source, record in #112/#118:

1. Additive migrations/API with provisioning disabled; built connector digest;
   disposable Runtime upgrade and actual Flux pruning/retained-object evidence.
2. Pinned cloudflared + real Node/private app fixtures proving actual Host,
   reservation/payment/control/callback URLs and every client route/method.
3. Real edge **and direct-origin** bypass matrix: encoded/double-encoded
   separators, dot segments, repeated slashes, backslashes, mixed-case escapes,
   trailing slashes, prefixes, aliases, malformed wildcard hosts and redirects.
   Any bypass blocks rollout and requires an architecture decision.
4. Two machines with distinct stable tunnel UUIDs, isolated Access credentials,
   API/discovery/generated-host TLS before apps exist, and private gVisor targets.
   Missing/invalid/expired/revoked/wrong-source Access credentials must fail.
5. Restart/reboot, provider/API outages, partial creates, rotations/expiry,
   updates and offline removal; sanitized timelines, generations, inventories,
   external absence and no orphaned owned resources. Test actual CNI/DNAT,
   NodePort/host-port, direct Pod/Service and IPv6 attempts.
6. #96 HTTP/SSE/WebSocket performance criteria. Public Trickle remains denied.

Cloudflared normalization affects matching and can differ from the forwarded
path; configuration inspection is not isolation evidence. Review Cloudflare
[origin parameters](https://developers.cloudflare.com/tunnel/reference/origin-parameters/),
[ingress matching](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/configuration-file/)
and [DNS lifecycle](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/dns/)
when upgrading the pinned image.
