# Operations runbook

## Installation

Copy `api/config.example.toml` to `api/config.toml` and create its secret files.
Build and publish the Runtime image, then set `RuntimeImage` to its digest as
described in the [Runtime prerequisites](../runtime/README.md#prerequisites).
In the [Supabase authentication dashboard](https://supabase.com/dashboard),
enable the sign-in methods you plan to use and allow
`http://localhost:5173/auth/callback` as a redirect URL. Authentication and the
database must use the same trusted project. `make api` loads `api/config.toml`.

## Administrator access

Ensure email confirmation is enabled and administrator accounts have verified
email addresses. Administrators should initiate signup and never confirm
unsolicited emails.

Set `DefaultAdminEmail` (or `DEFAULT_ADMIN_EMAIL`) to create a pending grant
when none are active. This creates no login; the person must sign in with a
confirmed account. Use **Administration** to grant access by exact email or
revoke another administrator.

In the Supabase authentication dashboard, open **Authentication → Sign In /
Providers → Email** and enable **Confirm Email**. The app cannot grant new
access while this setting is disabled or unavailable. Existing access remains
in place.

Changing the default does not replace pending or deleted-account grants. A new
account cannot inherit a claimed grant. Recovering an account or linking another
identity can retain access, so revoke the grant before reassigning its mailbox.

## Recover administrator access

If the only administrator is inaccessible, deleted, or mistyped, inspect
`lpcc.administrator_grants` through a trusted database connection. Replace
the placeholders below; do not delete history or alter account associations.

```sql
BEGIN ISOLATION LEVEL READ COMMITTED;
SET LOCAL lock_timeout = '2s';
SELECT pg_advisory_xact_lock(1129073483, 2);
WITH revoked AS (
  UPDATE lpcc.administrator_grants
  SET revoked_at = now(), revision = revision + 1
  WHERE grant_id = '<STALE_GRANT_UUID>'::uuid AND revoked_at IS NULL
  RETURNING grant_id, revision
)
INSERT INTO lpcc.admin_audit_events
  (actor_kind, actor_id, action, target_kind, target_id, revision, outcome,
   reason)
SELECT 'system', 'operator:<YOUR_OPERATOR_ID>', 'administrator.revoke',
       'administrator_grant', grant_id::text, revision::text, 'success',
       'recovery'
FROM revoked;
COMMIT;
```

Verify that one row was inserted. Correct `DefaultAdminEmail` and restart; a new
grant is seeded only if no active grants remain.

## App catalog

Use **Administration → App catalog** to validate and publish TOML, inspect
revision history, and retire definitions. See the [app registry guide](app-registry.md)
for definition settings and pricing policy. Catalog changes alone do not assign
or deploy applications. In the fleet, use **Manage apps** for revision-pinned
assignments, replica edits and sequential replacement/removal. Runtime completion
is separate from current health; see the registry guide for the delivery and
cleanup contract.

## Onchain operation

Configure the redeemer and secret mounts using [deployment setup](../deploy/README.md#onchain-setup).
Edit [onchain.example.json](../deploy/onchain.example.json) and apply it from the
API deployment environment:

```sh
controlcenter onchain apply --config /etc/controlcenter/config.toml \
  --file /operator/onchain.json --expected-revision 0
```

Use the returned revision for the next apply. The file is a complete snapshot;
retain enabled machines or explicitly set `{"version":1,"mode":"offchain"}` to
disable one. Unconfigured machines default to offchain. App catalog prices remain
authoritative; every advertised onchain app needs a positive USD `hour` or `fixed` price.

Provision a new immutable `rpc_secret` file for RPC rotation; the configured
reference is the SHA-256 of its exact bytes, including a final newline. The API
rehashes the owner-only file on every read. Increment `credential_revision` to
rotate process-scoped submission grants; the successor replaces the prior grant.
Retain referenced RPC versions for held workloads and rollback. Reapply previous
settings at the current revision to roll back. Configuration changes use the
normal app and session drain flow. Inspect configuration, local admission and
handoff health separately in **Runtime status**. Redeemer owns confirmation.

Disabling onchain operation or removing a machine can leave pending tickets
unredeemed. Forced removal revokes submission grants and stops Node early. Keep
Node's durable data, including a consistent backup of `/data/onchain.sqlite`
and its sidecars, and back up the redeemer database and wallet separately. The
recipient, chain and controller remain immutable for a stable machine even after
re-enrollment. Private endpoints require exact IP:port `rpc_grants` and
`redeemer_grants`; these allow orchestrator access only. Apps receive no RPC or
redemption egress. If onchain readiness is lost, the private Node Service remains
reachable for management and cleanup.

## Machine ingress

Per-enrollment Cloudflare tunnels and protected Collector discovery are opt-in.
Follow [the machine tunnel runbook](machine-tunnels.md) for infrastructure
prerequisites, credential delivery, refresh, rotation, removal, integration
contracts and release evidence. Keep `CloudflareEnabled` and
`CloudflareIngressApproved` false until their respective gates are satisfied.

## Fleet discovery

Fleet discovery shares the API process and its TLS proxy. Enable it separately
after protected ingress approval, using the existing encrypted Access credential
store and protected keyring. See [fleet discovery](fleet-discovery.md) for
configuration, source lifecycle, rotation, freshness diagnosis and release gates.
