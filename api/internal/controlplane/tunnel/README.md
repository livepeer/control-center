# Machine tunnels

This package manages Cloudflare resources, credentials, ingress protection, and
external readiness for machine tunnels. On the machine, `cloudflared` opens an
outbound connection to Cloudflare and forwards to private Traefik ingress, then
Node. Node routes application traffic to private workloads.

Each tunnel belongs to a machine enrollment. Credential refresh preserves the
enrollment and tunnel; deletion and re-enrollment create a new enrollment.
Cleanup of an earlier enrollment must finish before a later one can reuse its
stable hostnames.

| Host | Purpose |
| --- | --- |
| `api.<node>.<domain>` | Public orchestrator client API controls |
| `*.<node>.<domain>` | Application traffic |
| `discovery.<node>.<domain>/discovery` | Bearer-protected discovery |

API and discovery forwarding use the private Node Host; application forwarding
preserves the original Host and Authorization header. The API host permits only
reservation, stop/payment and payment refresh controls. App hosts deny discovery,
runner, metrics, health and Trickle paths; unmatched API and discovery paths
return 404.

See the [operator guide](../../../../docs/machine-tunnels.md) for credential
boundaries, rotation and removal, and [discovery authentication](../../../../docs/discovery-auth.md)
for signing configuration and key rotation.

## Cloudflare API token permissions

Create a custom token scoped to the relevant account and zone:

| Scope | Permission | Access | Why |
| --- | --- | --- | --- |
| Account | Cloudflare One Connector: cloudflared | Edit | Manage tunnels, connector credentials and connections |
| Zone | DNS | Edit | Manage machine and wildcard CNAMEs and any validation records |
| Zone | SSL and Certificates | Edit | Manage Advanced Certificate packs for machine wildcard coverage |

SSL and Certificates is under Cache & Performance in the token builder. Enable
Advanced Certificate Manager (ACM) for the zone before ordering certificates.

## Reconciliation and readiness

PostgreSQL, Cloudflare, and the machine can fail independently. Reconciliation
records unfinished work and retries across restarts: for example, Cloudflare
may create a resource before its ID is saved, or a machine may be deleted while
offline. A resource ledger records creation intent, and ownership inventory
recovers lost responses and cleans up owned duplicates or late results.

Enrollment does not wait for external readiness. Once the enrollment is
eligible and a recent Runtime report confirms HTTPS, the manager prepares
Cloudflare resources, including an Advanced certificate for the zone apex and
machine wildcard. Certificate ownership and late-result cleanup follow the stable
namespace across enrollments. It then waits for recent Runtime and connector
reports, publishes DNS, and verifies HTTPS endpoints. Verification checks
public API routing, authenticated discovery access and public path isolation.
Ingress approval controls readiness advertisement; routes can already be reachable.
Readiness is tied to the current machine generation and expires when observations
become stale.

## Rollout and credentials

[Machine configuration](../machineconfig/README.md) owns general rollout and
shared concurrency. This package prepares certificate coverage and coordinates
endpoint replacement through its drain and configuration gates. The
[discovery package](../discovery/README.md) owns the collector.

The backend API token provisions resources; the enrollment credential
authenticates the machine; and the connector token joins its tunnel. A broker
delivers the connector token without mounting the enrollment credential in
`cloudflared`. Connector rotation preserves the tunnel UUID; compromise rotation
also disconnects existing connectors.

After normal removal drains the workload, cleanup installs deny-only ingress,
revokes connector authentication, disconnects connections, and deletes owned
DNS and tunnel resources. The machine separately receives a terminal bundle to
remove its local workloads.
