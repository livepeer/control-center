# Fleet discovery

The Control Center API runs Node's public Collector and serves its cached fleet
inventory. The existing API proxy provides TLS; discovery needs no separate
service or Node release.

## Enable and secure

1. Complete the protected ingress and fleet acceptance checks below. Discovery
   is disabled by default.
2. Mount the existing `CloudflareKeyringFile` privately, with directory mode
   0700 and file mode 0600, readable by the API identity. All API replicas need
   the same keyring and credential database. A discovery reader does not need a
   Cloudflare provisioning token when provisioning is disabled.
3. Set `CloudflareIngressApproved = true` and `DiscoveryEnabled = true` in
   the existing API deployment. Expose public,
   read-only `GET /discovery` through its HTTPS proxy and restrict the API origin.
   Clients need no source credentials. Grant private destinations with
   `DiscoveryGrants` only when explicitly required.

Keep Access credentials, the keyring and provisioning tokens out of bundles,
ConfigMaps, application environments, browser responses, logs and command flags.
Every machine's raw `/discovery` must remain behind Cloudflare Access Service
Auth. Public app hosts and direct origins must deny discovery and management
access. See the [machine tunnel runbook](machine-tunnels.md) for credential
protection, rotation, removal and rollback.

The aggregate returns 503 when disabled. When enabled it returns cached
Node-compatible JSON, including `200 []` when no runners are advertised. An
empty response does not establish collection health. `/healthz` and `/readyz`
retain their API process/database meaning, independent of fleet freshness.

## Sources and credentials

The existing configuration worker derives sources from the managed tunnel
ledger at startup, after relevant committed changes and at
`ConfigReconcileInterval` (default one minute). There is no editable source
list. A failed database read retains the last selection; a confirmed removal
withdraws the source immediately. An empty selection is valid.

Unverified provisioning generations are excluded; previously approved offline
generations continue polling, including after restart. Draining sources remain
selected to observe withdrawals. Removed enrollments and blocked ingress are
excluded. Replacement resets the predecessor's cache even when the URL is
reused; an unverified replacement cannot retain that cache or admit its new
endpoint or credential. Follow the tunnel runbook's drain, acknowledgement and
provider cleanup order before retiring resources.

Credentials are immutable, AES-GCM encrypted PostgreSQL versions; only the
keyring is mounted as a protected file. Reconciliation loads a source-scoped
credential snapshot, while in-flight requests retain the version they started
with. Missing, expired, revoked or malformed credentials fail closed without
stopping healthy sources. Managed Cloudflare sources use authenticated HTTPS;
there is no plaintext credential export or unauthenticated fallback.

Requests use verified TLS, a three-second timeout, no environment proxy, cookies
or redirects, and Node's destination policy and 1 MiB source-body limit. The
Collector ignores advertised peer metadata and never collects its own origin.
Credential changes trigger a refresh, including a bounded follow-up when older
work was already in flight. HTTP reads never poll sources.

For ordinary Access rotation, publish the new credential with provider overlap
as described in the tunnel runbook. Confirm discovery acknowledgement and
subsequent provider retirement before finishing. Acknowledgement requires a new,
successfully decoded observation for the exact source incarnation and credential
version with the expected owning address. An old in-flight response, login HTML
or eviction cannot acknowledge it; an unsafe app URL alone does not block
retirement. Use the runbook's compromise path for immediate revocation and its
controlled restart/re-encryption procedure for keyring rotation.

## Inventory and diagnosis

`DiscoveryRefreshInterval` defaults to five minutes and
`DiscoveryMaxFailedRefreshes` to six; zero evicts on the first failure. Failures
retain the last records and original times until eviction, and polling continues
afterward. A valid empty inventory immediately clears that source. Cache is
in-memory and lost on restart. Each replica collects independently, so snapshots
can differ during a rolling restart.

The aggregate preserves whole runner records, extensions, exact JSON numbers and
original observation timestamps. Node's merge selects the newest record, with
deterministic source ordering for ties. Its decoder validates envelopes,
identities and timestamps, not every optional schema property. Protected source
hostnames and peer metadata are omitted. Entries with an unexpected owning
address are blocked; unsafe runner URLs are filtered individually so safe
siblings remain. Fix Node's `ServiceURL`, `ProxyURLTemplate` and proxy
registration when public routes are wrong; records are not rewritten.

Use administrator `GET /api/admin/discovery` to inspect selection freshness,
source lifecycle and generation, collection state (`uninitialized`, `healthy`,
`retained` or `evicted`), last success, failures, cached records, bounded
transport outcomes, credential availability, acknowledgement and blocked
publication. Collection is stale after two refresh intervals; selection is stale
after two reconciliation intervals. These thresholds do not evict inventory.
Response sizes over 1 MiB are logged, without truncating inventory; consumers may reject them.

Status supports #117's correlation with assignment, bundle and registration
reports. It cannot prove an applied deployment or external app reachability:
a recent collection does not make every record current. Status and logs exclude
credentials and source URLs; session and credential identities are not metric
labels.

If selection is stale or reconciliation fails, restore database access; do not
interpret a failed read as an empty fleet. For Access failures, check credential
availability, source state and rotation acknowledgement, then restore the correct
version through the tunnel workflow. After correcting public routes, wait for
collection.

## Release checks

Simulated source/TLS tests and isolated database tests do not establish live
Cloudflare or private-app behavior. Before production enablement, complete #118's
checks with two managed machines: Access, DNS, TLS and direct-origin bypass;
actual Node/SDK/private-gVisor routing; enrollment and app convergence; partial
outage and recovery; rotation, removal and cold restart. Verify the #111, #114
and #117 integrations, record sanitized source timelines and compatible aggregate
output within the consumer size limit. Evaluation remains under #44/#90/#91.
