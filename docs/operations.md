# Operations runbook

## Installation

Copy `api/config.example.toml` to `api/config.toml` and create its secret files.
Build and publish the Runtime image, then set `RuntimeImage` to its digest as
described in the [Runtime prerequisites](../runtime/README.md#prerequisites).
In the [Supabase authentication dashboard](https://supabase.com/dashboard),
enable the sign-in methods you plan to use and allow
`http://localhost:5173/auth/callback` as a redirect URL. Authentication and the
database must use the same trusted project. `make api` loads `api/config.toml`.

## Orchestrators

Users select an orchestrator in the console. Its canonical owner is its lowercase
recipient address, independent of network and payment configuration. Members
share machines, secrets and app access policies. Administration remains global.

Provision access through a trusted database connection until the membership
verification flow is available. Confirm the recipient address and user identity
before inserting them; this SQL does not verify control of a wallet. Use the
Supabase user UUID, not an email address, for membership and audit identity:

```sql
BEGIN;
INSERT INTO lpcc.orchestrators(address, display_name)
VALUES(lower('<RECIPIENT_ADDRESS>'), '<DISPLAY_NAME>')
ON CONFLICT(address) DO UPDATE SET display_name=EXCLUDED.display_name;
INSERT INTO lpcc.orchestrator_memberships(user_id, orchestrator_address)
VALUES('<USER_UUID>'::uuid, lower('<RECIPIENT_ADDRESS>'))
ON CONFLICT DO NOTHING;
COMMIT;
```

Configure the [Vault policy](operator-secrets.md#deployment) for each address.

Remove access with:

```sql
DELETE FROM lpcc.orchestrator_memberships
WHERE user_id='<USER_UUID>'::uuid
AND orchestrator_address=lower('<RECIPIENT_ADDRESS>');
```

Removing a member or deleting their account preserves shared machines, secrets
and runtime identities, even when no members remain. Restore membership to
give another user access. A grant cannot be used while its issuer lacks
membership or has a deleted account; rejoining can restore an unexpired grant.
Only the issuing user can revoke a grant, and revocation lasts until expiry in
both services.

The orchestrator ownership migrations require fresh Control Center and secrets
service data. They refuse populated ownership-dependent tables. Existing
ciphertext cannot be reassigned by editing its owner field because ownership is
part of its authenticated encryption metadata.

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

## Apps

Use **Administration → App catalog** to publish definitions and **Manage apps**
in the fleet to assign them. See the [app registry guide](app-registry.md).

## Onchain operation

Configure the redeemer and secret mounts using [deployment setup](../deploy/README.md#onchain-setup).
Key [onchain.example.json](../deploy/onchain.example.json) with `credentials/fingerprint`.
Apply from the API deployment:

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
`redeemer_grants`; these allow orchestrator access only. Apps receive neither
these grants nor Node's RPC or redemption credentials. If onchain readiness is lost,
the private Node Service remains reachable for management and cleanup.

## Machine ingress and discovery

Machine tunnels and fleet discovery are opt-in. Follow the [tunnel runbook](machine-tunnels.md)
for setup and removal, then [fleet discovery](fleet-discovery.md) to expose the
aggregate inventory.
