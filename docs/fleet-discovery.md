# Fleet discovery

Control Center runs Node's public Collector and serves its cached Node-compatible inventory at public, read-only `GET /discovery` via Cloudflare Tunnel. Fleet discovery is disabled by default.

## Enable fleet discovery

1. Run [end-to-end tests](development.md#end-to-end-tests).
2. Share the [Ed25519 signing configuration](discovery-auth.md#configure-the-signing-key) and source database across API replicas.
3. Set `CloudflareIngressApproved = true` and `DiscoveryEnabled = true`, expose read-only `GET /discovery` via HTTPS proxy, and restrict the API origin. Add `DiscoveryGrants` only for explicit private destinations.

The aggregate is public. Each machine's `/discovery` requires a machine-bound bearer token. Public app hosts and direct origins deny discovery and management paths.

`GET /discovery` returns `503` when disabled and cached JSON when enabled. `200 []` means no advertised runners. Check collection separately. `/healthz` and `/readyz` report API and database health.

## Source selection and polling

The config worker derives sources from the tunnel ledger at startup, on committed changes, and every `ConfigReconcileInterval` (default `1m`), with no manual list. Failed DB reads keep the prior selection, confirmed removals drop the source and cache immediately, and empty selections are valid.

Selection excludes unverified provisioning generations, removed enrollments, and blocked ingress. Approved offline generations stay selected across restarts, and draining sources stay selected to observe withdrawals. Follow [tunnel cleanup order](machine-tunnels.md#rotate-connectors-drain-and-remove-machines) before retirement.

Each poll signs a local discovery token ([verify ingress](discovery-auth.md#verify-discovery-ingress)), and signing failures deny that poll while healthy sources continue. Polling enforces verified HTTPS, `3s` timeout, zero env proxies/cookies/redirects, Node's destination policy, and `1 MiB` body limit.

The Collector ignores peer metadata and skips its own origin. Credential updates apply on the next poll, and HTTP reads never trigger polls.

## Caching, merging, and diagnosis

`DiscoveryRefreshInterval` defaults to `5m` and `DiscoveryMaxFailedRefreshes` to `6` (`0` evicts on first failure). Failures keep prior records and timestamps until eviction while polling continues, and valid empty responses clear that source immediately. In-memory cache clears on restart, so replicas can temporarily serve different snapshots during rolling restarts.

Node decodes envelopes, identities, and timestamps, then merges complete runner records with extensions, exact JSON numbers, and original observation times. The newest record wins, with deterministic source ordering on ties. The aggregate omits protected hostnames and peer metadata, blocks records from unexpected owners, and filters unsafe runner URLs individually. Fix public routes in Node's `ServiceURL`, `ProxyURLTemplate`, or proxy registration. The aggregate leaves published records unchanged.

Admins inspect `GET /api/admin/discovery` for selection freshness, source lifecycle/generation, collection state (`uninitialized`, `healthy`, `retained`, `evicted`), last success, failures, cached records, bounded transport outcomes, signer availability, and blocked publication. Collection turns stale after `2 × DiscoveryRefreshInterval` and selection after `2 × ConfigReconcileInterval` without eviction. Responses over `1 MiB` log without truncation and consumers may reject them.

Status correlates with assignment, bundle, and registration reports, while applied deployments and external reachability need separate checks. Status and logs omit credentials and source URLs, and metric labels omit session and credential identities.

| Failure | Action |
| --- | --- |
| Stale selection or failed reconciliation | Restore DB access and treat failed reads as stale selection |
| Auth failure | Check signing key ID, node ID, public keys, and ingress digest ([key rotation](discovery-auth.md#rotate-signing-keys)) |
| Wrong public routes | Fix Node route config and wait for next poll |
