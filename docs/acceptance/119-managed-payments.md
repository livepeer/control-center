# Managed paid operation: fresh-install evidence

Date: 2026-11-12. Run: `cc-e2e-1112071043-bcbd`.

This records payment/configuration integration for #119. The broader #93/#118
acceptance gate remains open: #90's versioned responder, trusted verifier and
collection/report contract are still open work. The nonce-echo fixture used here
checks transport and execution correctness; it is not that benchmark verifier.

## Environment and provenance

Two fresh `e2-standard-4` CPU workers ran actual K3s, gVisor app workloads and
keyless Node. A third disposable GCP VM ran the isolated Control Center fixture,
registry, TLS routing and the actual hardened standalone redeemer. Worker A used
private RPC/redemption endpoints with exact IP/port grants; worker B used public
endpoints. Their shared immutable catalog revisions retained exact `0.001 USD`
prices, respectively `hour` and `fixed`, throughout infrastructure changes.

The redeemer used the actual Compose service and separate persistent database,
UID 65532, read-only root, dropped capabilities and no-new-privileges. This harness
used host networking for the redeemer's loopback connection to the native API;
it does not establish the full production Compose networking acceptance case.
The signing key was mounted only into the redeemer. No application received
payment, RPC, enrollment or origin-access credentials.

Node's outbound-header dependency landed in
[Node #85](https://github.com/livepeer/node/pull/85), commit
`3533951e66584531a54a771d21c1388873439099`. Its main-branch CI and both published
architectures passed. The committed wrapper Dockerfile was also built against
that landed Node image and the tested Runtime. The accompanying JSON separates
that built package from the earlier functional fixture image and records exact
source/binary hashes and image digests. These disposable-registry pins are test
artifacts, not a production release promotion. Their OCI images were archived
before registry teardown.

## Verified outcomes

- Full PostgreSQL-backed API/Runtime/schema race suite, `go vet`, 41 UI browser
  checks and the production UI build passed. All 45 Runtime Linux checks passed
  on each worker, including kubectl manifest validation. The later Cloudflare
  tombstone regression passed the tunnel race suite.
- Both workers applied payment generation 1 and registered the same catalog
  revisions. Actual Node parsed the rendered paid TOML. Failed paid configuration
  remained paid/failed and retained the last valid configuration.
- Paid persistent/hourly and single-shot/fixed calls executed ordinary sandboxed
  HTTP requests. A verifier-generated nonce was checked in the response. Origin
  access headers were absent from application requests.
- During private RPC loss, the same live Pod became unready while its funded
  retained session, protected diagnostics and session stop remained reachable.
  The public-RPC sibling remained ready. Recovery needed no Pod replacement.
- Both private endpoints were reachable only from the explicitly allowed
  orchestrator. All three apps on each worker and the other orchestrator were
  blocked. An unrelated neighboring port was reachable from the host and blocked
  from the orchestrator.
- RPC/submission rotation and explicit rollback produced new generations and
  grants and retained owner-only SQLite state. The disable/rollback cycle left
  the sibling unchanged. A real
  unsettled ticket blocked paid disable; the live paid workload/grant remained.
- A queue limit of two with two actual unsettled tickets closed local admission
  while preserving paid mode. Restoring capacity restored readiness.
- The redeemer durably accepted three ticket identities while six successful
  acknowledgements were deliberately lost. Retries produced nine HTTP
  acceptances, three unique stored tickets and degraded-then-healthy remote
  handoff observations. Empty worker passes did not establish healthy handoff.
- Forced removal with one unhanded winning ticket immediately revoked grants,
  retained payment storage and reported recovery required with drain incomplete.
  Re-enrollment preserved all tickets and the recipient pin. Ordinary management
  refresh drained/replaced Node and retired old grants after observing its
  replacement. Public discovery recovered under the new enrollment.
- Real Cloudflare deletion returned a tunnel tombstone without `config_src`.
  Matching its retained ID/name allowed predecessor cleanup; foreign/active
  ownership checks and late-resource inventory remained enforced.
- Ordinary removal with unsettled tickets retained Node/storage/grants and did
  not acknowledge completion. No forced-removal case was reported payment-drained.

## Funded bounds and remaining gates

The original campaign used a `0.003 USD` per-authorization ceiling and returned
three signed batches (five tickets). Two earlier unfunded signer requests returned
no signed batch. The five small winning tickets were durably handed off; their
face value did not cover the measured redemption gas ceiling, so settlement and
ordinary payment drain remained blocked by the existing economic guard.

The operator then approved a maximum `0.40 USD`: `0.20` ticket liability and `0.20`
redeemer gas. The bounded extension allowed at most nine authorizations, each at
most `0.02 USD`, with no fee replacements and a `45,000,000 wei` gas-price ceiling.
Seven authorizations, about `0.018 USD` maximum payout each, produced one additional
winning ticket. Signing stopped immediately. Catalog prices were unchanged.

Its transaction mined successfully and retained the same signed bytes/nonce
across redeemer restart, then reached finality. It used `189830` gas at
`20000000 wei`, totaling `0.0000037966 ETH`, with one durable transaction identity
and no fee replacement. Exact receipt and final cleanup evidence are recorded in
the accompanying JSON. The five small
unsettled tickets are preserved in separate owner-only Node/redeemer backups;
ordinary drain is not claimed complete for them.

## Cleanup and recovery retention

Cleanup was verified at `2026-11-12T10:09:25Z`. The saved post-cleanup inventory
contains no GCP or Cloudflare resources owned by this run; all four attempts
recorded verified cleanup and removed generated access credentials. A separate
active test run was excluded from this ownership scope and left untouched.

The broader baseline check did not pass unconditionally: an unrelated baseline
tunnel had been deleted at `08:13:03Z`, before this run's `10:03:43Z` teardown.
It was absent from this run's ownership intents. The scoped cleanup result keeps
that exception visible rather than claiming full baseline preservation.

Consistent Node/redeemer SQLite backups, a Control Center PostgreSQL dump, matching
private recovery inputs and the five pinned component images remain in an
owner-only operator archive. The OCI archive preserves the original pinned
manifests and has a recorded SHA-256. Cloud cleanup did not discard retained
financial state. Recover the five small tickets under their original bindings
and routing/trust inputs; removing infrastructure does not complete payment drain.

Still outside the completed evidence: #90/#44 verifier/report integration and the
full #93/#118 attribution, offline, cancellation and fleet acceptance matrix.
No case depends on changing an existing installation into this implementation.
