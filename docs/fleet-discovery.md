# Fleet discovery

The Control Center API runs Node's public Collector and serves its cached fleet
inventory. The existing API proxy provides TLS; discovery needs no separate
service or Node release.

## Enable and secure

1. Run the [end-to-end harness](development.md#end-to-end-tests). Discovery
   is disabled by default.
2. Mount the existing `CloudflareKeyringFile` privately, with directory mode
   0700 and file mode 0600, readable by the API identity. All API replicas need
   the same keyring and credential database. A discovery reader does not need a
   Cloudflare provisioning token when provisioning is disabled.
3. Set `CloudflareIngressApproved = true` and `DiscoveryEnabled = true` in
   the existing API deployment. Expose public,
   read-only `GET /discovery` through its HTTPS proxy and restrict the API origin.
   Reading this aggregate requires no source credentials. Grant private
   destinations with `DiscoveryGrants` only when explicitly required.

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

Sources come from managed tunnels, not an editable list. Selection refreshes on
changes and at `ConfigReconcileInterval` (default one minute). Failed database
reads retain the last selection; confirmed removals withdraw sources. Unverified
or blocked ingress is excluded; approved offline and draining sources continue to
be polled. Replacement clears the predecessor's cache, even if its URL is reused.
Follow the [tunnel runbook](machine-tunnels.md#rotation-and-removal) for rotation
and removal, including discovery acknowledgement before retiring credentials.
Compromise requires immediate revocation.

Sources use authenticated HTTPS with verified TLS, a three-second timeout, no
proxy or redirects, and a 1 MiB response limit. Missing, expired, revoked or
malformed credentials fail closed without stopping healthy sources. Private
destinations require explicit `DiscoveryGrants`; HTTP reads use the cache and do
not poll sources.

## Inventory and diagnosis

`DiscoveryRefreshInterval` defaults to five minutes and
`DiscoveryMaxFailedRefreshes` to six; zero evicts on the first failure. Failed
polls retain records and their original timestamps until eviction; a valid empty
inventory clears that source immediately. The in-memory cache is lost on restart
and each replica collects independently.

Use administrator `GET /api/admin/discovery` to inspect selection freshness,
source lifecycle, collection state, failures, credential availability, rotation
acknowledgement and blocked publication. Collection is stale after two refresh
intervals and selection after two reconciliation intervals; neither threshold
evicts inventory. A successful empty snapshot is distinct from a failed or stale
collection, and retained inventory cannot acknowledge a new credential. Status
does not prove external app reachability. See [machine status](machine-status.md)
for correlating assignment and registration evidence.

If selection is stale or reconciliation fails, restore database access. For Access
failures, check credential availability and rotation acknowledgement, then use the
tunnel workflow. Entries with unexpected owning addresses and unsafe runner URLs
are filtered. If public routes are wrong, fix Node's `ServiceURL`,
`ProxyURLTemplate` and proxy registration, then wait for collection. Records are
not rewritten.
