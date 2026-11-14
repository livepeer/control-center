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

In an on-chain deployment, select **Add orchestrator**, enter its active
Arbitrum One address and wait for the activity check. Download the challenge
JWT, which has no trailing newline, then sign its exact bytes:

```sh
livepeer chain sign message --message-file ./orchestrator-claim.jwt \
  --keystore-file <file> --keystore-password-file <file> --output json
```

Paste the returned `signature` into the console. A successful claim creates
your membership, selects the orchestrator and displays its machine enrollment
command. One claim permits enrolling multiple machines. A later user cannot
claim the same address. In an off-chain deployment, **Add orchestrator** creates
the zero-address workspace by default; enter a distinct Ethereum address to
create another workspace.

Configure the [Vault policy](operator-secrets.md#deployment) for each address.

Open **Members** for the selected orchestrator to invite or remove members, or
leave. All members have equal permissions, including the original claimant.
Membership actions cannot remove the last live member; unaccepted invitations
do not count.

Share an invitation link directly with the recipient. They sign in or create an
account, review the orchestrator and signed-in account, and select **Accept
invitation**. Signed links expire after 24 hours and can be accepted only once,
even if the recipient later leaves. The inviter must still be a member at
acceptance. Creating a link stores no invitation state; acceptance records the
inviter and recipient and creates an audit event. There is no invitation list or
individual link cancellation.

Member removal and departure are audited. Removing a member or deleting their
account preserves shared machines, secrets and runtime identities. A grant
cannot be used while its issuer lacks membership or has a deleted account;
rejoining can restore an unexpired grant. Only the issuing user can revoke a
grant, and revocation lasts until expiry in both services. External Auth account
deletion and trusted database recovery remain outside the last-member guard.

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
Set `Mode = "onchain"` and `OnchainConfigFile` before first startup. Use
[onchain.example.json](../deploy/onchain.example.json) as the Control Center
template. Control Center fills in each claimed orchestrator address as the
recipient when a machine registers and automatically reconciles template
changes. App catalog prices remain authoritative; every advertised onchain
app needs a positive USD `hour` or `fixed` price.

Provision a new immutable `rpc_secret` file for RPC rotation; the configured
reference is the SHA-256 of its exact bytes, including a final newline. The API
rehashes the owner-only file on every read. Change the template's `rpc_secret`
to rotate the RPC endpoint and process-scoped grants. Retain referenced RPC
versions for held workloads and rollback. Configuration changes use the
normal app and session drain flow. Grant requests require a fresh signature
from the enrolled runtime key after the Pod is checked. The key is installed
with management credentials before secrets setup. Onchain grants do not
contact the secrets service; registrations without a runtime key are refused.
Inspect configuration, local admission and handoff health separately in
**Runtime status**. Redeemer owns confirmation.

Removing a machine can leave pending tickets unredeemed. Forced removal revokes
submission grants and stops Node early. Keep
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
