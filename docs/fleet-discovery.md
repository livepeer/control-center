# Fleet discovery

The Control Center API runs Node's public Collector and serves its cached fleet
inventory. The existing API proxy provides TLS; discovery needs no separate
service or Node release.

## Enable and secure

1. Run the [end-to-end harness](development.md#end-to-end-tests). Discovery
   is disabled by default.
2. Mount Control Center's Ed25519 signing key using `JWTSigningPrivateKeyFile`.
   All API replicas share signing configuration and the source database. Ingress
   receives only public verification keys through its independent configuration
   inventory. A reader needs no Cloudflare provisioning token when provisioning
   is disabled.
3. Set `CloudflareIngressApproved = true` and `DiscoveryEnabled = true` in
   the existing API deployment. Expose the public, read-only `GET /discovery`
   through its HTTPS proxy and restrict the API origin.
   Reading this aggregate requires no source credentials. Grant private
   destinations with `DiscoveryGrants` only when explicitly required.

Keep the private signing key, bearer tokens and provisioning credentials out of
machine bundles, ConfigMaps, browser responses, logs and command flags. Each
machine's raw `/discovery` requires a machine-bound ingress bearer token. Public
app hosts and direct origins deny discovery and management access. See the
[authentication rollout](discovery-auth-rollout.md) for the two release stages
and separate existing-resource migrations.

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
excluded. Removing a source removes its cached inventory. Follow the tunnel
runbook's drain and provider cleanup order before retirement.

Control Center mints a five-minute Ed25519 token locally for each source request.
The token has a discovery-specific audience and scope and is bound to that
machine's identity. Ingress verifies it with mounted public keys, independently
of the secrets service. Signing failure denies the request without stopping
healthy sources; managed sources always use authenticated HTTPS.

Requests use verified TLS, a three-second timeout, no environment proxy, cookies
or redirects, and Node's destination policy and 1 MiB source-body limit. The
Collector ignores advertised peer metadata and never collects its own origin.
Credential changes apply to the next scheduled poll. HTTP reads never poll sources.

Rotate keys by distributing the next public key before switching signers, then
retain the previous verification key for at least 24 hours after last issuance.
See the rollout runbook for applied-digest checks.

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
transport outcomes, signer availability and blocked
publication. Collection is stale after two refresh intervals; selection is stale
after two reconciliation intervals. These thresholds do not evict inventory.
Response sizes over 1 MiB are logged without truncation; consumers may reject them.

Status supports correlation with assignment, bundle and registration
reports. It cannot prove an applied deployment or external app reachability:
a recent collection does not make every record current. Status and logs exclude
credentials and source URLs; session and credential identities are not metric
labels.

If selection is stale or reconciliation fails, restore database access; do not
interpret a failed read as an empty fleet. For authentication failures, check the
signing key ID, source machine identity, public verification keys and applied
ingress digest. After correcting public routes, wait for collection.
