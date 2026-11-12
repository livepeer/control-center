# Managed onchain operation

This workflow targets fresh Control Center databases and fresh Runtime installations.
The app catalog's exact decimal prices are the registration inputs. Deployment
configuration owns Node payment infrastructure; the machine UI inspects its state.
Offchain Node advertises free service even if a catalog revision has a positive quote.
Onchain Node requires positive USD prices with `hour` or `fixed` units for every app.

## Fresh setup

Build Node with the redeemer authorization webhook and `RedeemerHeadersFile` support.
Build Runtime, then build `runtime/services/Dockerfile.node` with digest-pinned
`NODE_IMAGE` and `RUNTIME_IMAGE` arguments. Publish the resulting image and set its
actual digest as `RuntimeNodeImage`. Use that same compatible Node build for
`LIVEPEER_REDEEMER_IMAGE`. Record all component revisions and image digests in the
acceptance evidence. An arbitrary image digest is not evidence of compatibility.

```sh
docker build -f runtime/services/Dockerfile.node \
  --build-arg NODE_IMAGE=<registry/node@sha256:digest> \
  --build-arg RUNTIME_IMAGE=<registry/runtime@sha256:digest> \
  -t <registry/managed-node:build> runtime/services
docker push <registry/managed-node:build>
```

Use the digest returned by the push rather than the mutable build tag. The Pod's
volume policy preserves owner-only SQLite permissions on subsequent mounts;
retain that policy together with the database and its sidecars.

Copy `deploy/redeemer.example.toml` to `deploy/redeemer.toml`. Mount a dedicated
redemption wallet, its password, and its chain RPC file only in the redeemer.
Its wallet must satisfy Node's standalone redeemer policy; the ticket recipient
is the registered orchestrator, not the dedicated transaction-signing wallet.
Use a separate persistent redeemer database. The orchestrator keeps its own
payment database and SQLite sidecars under its retained `/data` volume.

Create owner-only files readable by container UID 65532:

- `deploy/secrets/payment-rpc/<versioned-reference>`: an HTTPS RPC URL.
- `deploy/secrets/payment-webhook-auth`: a random secret of at least 32 bytes.
- `deploy/secrets/redeemer/keystore.json`, `password`, and `rpc`.
- `deploy/secrets/redeemer/auth-url`: `http://api:43812/internal/redemption/authorize`.
- `deploy/secrets/redeemer/auth-headers`: `Authorization: Bearer <payment-webhook-auth>`.

Set `PaymentSecretsDir` and `PaymentWebhookSecretFile` in the API deployment
configuration as shown in `deploy/config.example.toml`. Start the fresh deployment
with `docker compose -f compose.yaml -f compose.onchain.yaml --profile onchain up -d`.
Only `POST /redemption/tickets` is exposed through the verified HTTPS API ingress.
Keep the redeemer's raw listener, metrics and webhook inaccessible externally.
The same-host deployment accepts host compromise as a trust-boundary limitation.

Copy and edit `deploy/payments.example.json`, using real machine IDs and recipient
addresses. The supplied ticket terms are illustrative, not an economic recommendation.
Select appropriate funded validation limits and ticket terms for your deployment.
Apply from the trusted API deployment environment:

```sh
controlcenter payments apply --config /etc/controlcenter/config.toml \
  --file /operator/payments.json --expected-revision 0
```

The command prints the current deployment revision. Use that revision on the next
apply. Imports are complete snapshots: retain all currently onchain machine entries,
or explicitly set one to `{"version":1,"mode":"offchain"}`. Do not supply generated
`generation` values. An identical retry is a no-op, including after a lost response. Stale changes conflict.
Settings, generations and audit records commit together. API processes consume
persisted desired settings rather than importing their own startup snapshot.

The first recipient and chain/controller binding remain pinned to the machine
identity across offchain operation, removal and re-enrollment. Ordinary apply
cannot change those bindings. No operator price override or pricing profile exists.
Private RPC/redemption access requires explicit IP:port grants; use exact addresses
and ports in `rpc_grants` / `redeemer_grants`. Loopback and broad CIDRs are unsupported.
The grants are rendered only for orchestrator egress; app policies remain isolated.

## Activation, changes and credentials

The existing maintenance workflow withdraws new work, drains active work and holds
the previous workload before replacing Node. Failed startup stays failed; it never
switches to free service. Node remains reachable through its protected private
Service when payment readiness fails, allowing management and recovery.

Runtime verifies the live Pod incarnation before fetching RPC and submission
credentials over its separate orchestrator socket. A private readiness probe also
matches the current PID 1 to the issued launch association before payment
observations can be current. Container restart cannot reuse an earlier process
observation. Files are owner-only and
memory-backed. The submission bearer authorizes only recipient-bound ticket
submission. It is distinct from machine management and the redeemer's webhook
service credential. Neither API nor app/Runtime pods receive the signing key.

For RPC rotation, provision a new immutable secret filename and change `rpc_secret`.
Never replace a referenced file's bytes. Increment `credential_revision` to rotate
submission credentials. Retain old RPC files while held workloads or rollback
settings reference them. An observed replacement grant retires earlier submission
grants. Management credential refresh fences management immediately while a held
Node's submission grant may remain usable until replacement. Restarted Node fetches
credentials for its exact published configuration.

Rollback to previous settings is an explicit new apply at the current revision;
generations never decrease. A previously retired submission bearer is not restored:
a new process obtains a new grant. Keep immutable RPC secret versions available.

## Failure, retirement and recovery

Configuration application, local onchain readiness and remote redemption handoff are
separate observations. A successful `/readyz`, download or empty worker pass does
not prove authorized handoff. `unverified` means no current successful handoff has
been observed; `degraded` reflects submission failures. Node's durable queue and
backpressure continue governing redemption outages.

Disable, destination change and ordinary removal wait for app drain and fresh
successful evidence of zero unsettled tickets. Missing, stale or incomplete queue
evidence blocks completion. Drain expiry requires the existing audited retry.
Normal removal retains the onchain workload and credentials while settling tickets.
An observed offchain replacement revokes the previous onchain workload's submission
grants after the required drain completes.

Forced removal or account deletion revokes submission grants immediately. Already
accepted tickets continue at the redeemer. Retained local tickets require explicit
recovery, reported as `recovery_required`; physical cleanup does not mean payments
drained. Preserve the orchestrator database and its sidecars. Re-enroll the same
machine identity and recover the retained database with its pinned recipient and
chain settings before resuming submission. Once the restored Node has reported a fresh successful
zero-unsettled observation, apply the same desired snapshot with
`--acknowledge-recovery <machine-id>` and the current expected revision. This
records an explicit recovery audit event and clears the recovery-required flag.
After a onchain Node has initialized successfully, credential delivery requires its
existing payment database; a missing database fails startup instead of silently
creating a replacement. Do not discard databases to clear an
error or reinterpret retained state on a different chain or recipient.

Back up SQLite through a consistent online backup or while the writer is stopped;
retain the matching database/WAL state. Back up the redeemer database separately
from the orchestrator's, and keep signing-key backups under operator control.
Retain the bound redemption origin and its private routing/trust inputs until
outstanding tickets are resolved. Restore those routes together with retained
state; changing destination still requires fresh zero-unsettled evidence.
Re-enrollment waits for authoritative cleanup of the preceding ingress resources
before publishing its new protected routes.

## Acceptance evidence

Use two freshly installed CPU machines with different infrastructure settings and
unchanged shared catalog revisions. Record component commits/digests, desired and
observed generations, bounded spending/runtime limits, and redacted outcomes.
Exercise onchain discovery/admission/execution/accounting, winning-ticket handoff,
lost acknowledgements, Node/redeemer restarts, webhook/redemption outages and
backpressure, rotation, ordinary/forced retirement and retained-state recovery.
Verify signing-key isolation, private endpoint reachability and blocked app access.
Keep application correctness, authorization, durable handoff and settlement results
separate. Local unit tests alone do not complete the funded #93/#118 gate.

## Configuration and implementation ownership

For #119, the deployment operator applies infrastructure settings through the
deployment CLI. Central administrator status, machine ownership and machine
credentials do not grant payment mutation authority. The browser exposes scoped
inspection only. PostgreSQL holds the authoritative desired settings.

Control Center owns immutable recipient bindings, versioned secret references,
submission grants, the private authorization callback and configuration/audit
transactions. Runtime owns machine delivery, live Pod/process checks, private
credential files, activation/drain coordination and bounded observations. Node
owns price conversion, ticket validation, durable admission, acknowledgements,
retry and settlement. Its standalone redeemer alone holds the signing key.

#93 owns funded challenge-app execution evidence using #90's responder/verifier;
#118 owns the broader fleet acceptance matrix. Record their remaining gates
separately from configuration integration and local verification.
