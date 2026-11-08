# Machine tunnels

This package manages the backend lifecycle of machine tunnels. On the machine,
`cloudflared` opens an outbound connection to Cloudflare, which routes requests
through it to the private orchestrator at
`orchestrator.livepeer.svc.cluster.local:8935`. Application workloads remain
behind Kubernetes services.

Each tunnel belongs to one machine enrollment, identified by `(node_id,
epoch)`. Refreshing an enrollment credential preserves the epoch and tunnel;
deleting and re-enrolling creates a new epoch. Cleanup of an earlier enrollment
must finish before a later one can reuse its stable hostnames.

| Host | Purpose |
| --- | --- |
| `api-<node>.<domain>` | Allowed orchestrator client API routes |
| `<proxy>.apps-<node>.<domain>` | Application traffic |
| `discovery-<node>.<domain>/discovery` | Discovery protected by Cloudflare Access |

Ingress rules deny discovery, runner, metrics, health, and Trickle paths on the
public API and application hosts. Unknown hosts and unmatched API paths return
404. Discovery requires the expected Access audience.

## Why reconciliation

PostgreSQL, Cloudflare, and the machine can fail independently. A machine may
be committed while Cloudflare is unavailable; Cloudflare may create a tunnel
before the API crashes without saving its ID; or a machine may be deleted while
offline. Reconciliation records unfinished work and retries it across
restarts, including external cleanup without the machine.

Creating a tunnel is also distinct from making it ready:

1. The machine enrolls and reports HTTPS. Once the enrollment is eligible and
   the Runtime report is recent, Cloudflare resources are created.
2. Machine configuration is published, applied, and connected.
3. The backend observes matching, recent Runtime and connector reports.
4. DNS is published and HTTPS endpoints are verified.
5. The discovery source is marked ready, subject to ingress approval.

This can take minutes, so enrollment does not wait for the whole sequence.
Verification checks authenticated discovery, rejection of unauthenticated
discovery, and isolation of sensitive public paths. Ingress approval controls
readiness advertisement; provisioned routes can already be reachable.

## Package boundary

`controlplane` imports `tunnel`. The manager owns provider resources,
credentials, ingress protection, readiness and drain transitions. The parent
owns HTTP and admin authorization, enrollment, bundles and templates, and
discovery wiring and its store adapter. The sibling
[discovery package](../discovery/README.md) owns the collector.

The parent's [rollout adapter](../tunnels.go) supplies desired and applied
configuration facts without exposing bundle formats to this package. The manager
can hold the applied workload and request a drain; a matching completion report
permits replacement.

## Credentials and recovery

The backend API token provisions Cloudflare resources; the enrollment credential
authenticates a machine to Control Center; the connector token joins its tunnel;
and the Access credential authorizes discovery. A broker delivers the connector
token to `cloudflared` without mounting the enrollment credential in that
container.

A durable resource ledger records creation intent before provider calls.
Ownership-based inventory recovers resources when a provider response is lost,
and removes owned duplicates or late results. An Access token whose secret was
not durably saved must be revoked and replaced. Database leases and revision
checks coordinate workers and prevent stale writes.

Connector and Access credentials rotate independently. Normal Access rotation
overlaps credentials until the collector acknowledges use of the replacement;
compromise rotation revokes predecessors immediately. Connector rotation
preserves the tunnel UUID; compromise rotation also disconnects existing
connectors. Credential maintenance can continue while Runtime is offline.

Normal removal first drains workloads. External cleanup then installs deny-only
ingress, revokes connector authentication, disconnects connections, and deletes
DNS, the tunnel, and Access resources. The machine separately receives a
terminal bundle to remove its local workloads.

See the [machine tunnel runbook](../../../../docs/machine-tunnels.md) for
operational setup and release requirements.
