# Operations

For production Compose, registry, UI, and bootstrap releases, see [staging deployment](../deploy/README.md).

## Initial setup

1. Copy `api/config.example.toml` to `api/config.toml` and create its secret files.
2. Publish the Runtime image and set `RuntimeImage` to its digest ([Runtime prerequisites](../runtime/README.md#prerequisites)).
3. In [Supabase](https://supabase.com/dashboard), enable sign-in methods and allow redirect URL `http://localhost:5173/auth/callback`.

Authentication and the database must use the same trusted Supabase project. `make api` loads `api/config.toml`.

## Manage orchestrators and members

An orchestrator's canonical owner is its lowercase recipient Ethereum address, independent of network or payment settings. Members share machines, secrets, and app policies. Administration is global.

### Claim an orchestrator

1. In onchain mode, select **Add orchestrator**, enter an active Arbitrum One address, and wait for the activity check.
2. Download the challenge JWT (no trailing newline) and sign its exact bytes.

   ```sh
   livepeer chain sign message --message-file ./orchestrator-claim.jwt \
     --keystore-file <file> --keystore-password-file <file> --output json
   ```

   Any [EIP-191](https://eips.ethereum.org/EIPS/eip-191) `personal_sign` signer, like [`cast wallet sign`](https://www.getfoundry.sh/reference/cast/wallet/sign), also works.

3. Paste `signature` into the console.

Claiming adds membership, selects the orchestrator, and displays its enrollment command. One claim enrolls multiple machines, and each address is claimable once.

In offchain mode, **Add orchestrator** creates the zero-address workspace by default, or enter a distinct Ethereum address for another workspace. The shared [Vault policy](operator-secrets.md#deploy-the-secrets-service-and-vault) covers new orchestrators.

### Membership and migrations

Stateless invitations expire in `24h` and work once. Member removals and departures log to `lpcc.admin_audit_events`. Removing a member preserves orchestrators and machines, and the last member cannot leave.

Ownership migrations need fresh Control Center and secrets databases and refuse populated ownership tables. Ciphertext authenticates ownership metadata, so editing owner fields cannot reassign secrets.

## Manage administrator access

Enable **Confirm Email** in Supabase (**Authentication → Sign In / Providers → Email**) and verify admin emails. Admins initiate signup themselves and ignore unsolicited confirmations. Losing email confirmation blocks new grants while active admins remain.

`DefaultAdminEmail` (`DEFAULT_ADMIN_EMAIL`) seeds one pending grant only when zero active grants exist. Recipients claim grants by signing in with a confirmed account. Use **Administration** to grant by exact email or revoke another admin.

Changing `DefaultAdminEmail` keeps pending and deleted-account grants, and new accounts cannot inherit claimed grants. Revoke a grant before reassigning a mailbox because account recovery or linked identities can keep access.

### Recover administrator access

If the sole admin is inaccessible, deleted, or mistyped, inspect `lpcc.administrator_grants` over a trusted DB connection and run this transaction with real values. Keep history and account associations intact.

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

Confirm one row was inserted. Correct `DefaultAdminEmail` and restart. A fresh grant is seeded only if no active grants remain.

## Operate onchain payments

Onchain is the default ([deployment install](../deploy/README.md#install)). Control Center fills in each claimed address as recipient on registration and reconciles template updates automatically. Advertised onchain apps require a positive USD `hour` or `fixed` price ([app registry](app-registry.md#write-a-definition)).

### RPC rotation and runtime grants

To rotate RPC endpoints and process-scoped grants, add an immutable `rpc_secret` file named by the SHA-256 of its exact bytes (including trailing newline) and update template `rpc_secret`. The API rehashes the owner-only file on every read. Keep referenced RPC versions for held workloads and rollback, and let changes follow normal app and session drain.

Grant requests need a fresh signature from the enrolled runtime key after Pod checks. That key installs with management credentials before secrets setup. Onchain grants bypass the secrets service, and registrations without a runtime key fail.

### Monitoring, backups, and removal

Inspect config, local admission, and handoff health separately in **Runtime status** ([machine status](machine-status.md)). Redeemer confirms tickets.

Machine removal can leave pending tickets unredeemed, and forced removal revokes submission grants and stops Node early. Keep consistent backups of `/data/onchain.sqlite` with sidecars, plus separate redeemer DB and wallet backups. Recipient, chain, and controller stay immutable across re-enrollment.

Private endpoints need exact `IP:port` `rpc_grants` and `redeemer_grants` for the orchestrator only (apps receive zero RPC or redemption grants or credentials). Losing onchain readiness keeps the private Node Service reachable for management and cleanup.
