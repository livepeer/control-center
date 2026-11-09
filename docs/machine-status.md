# Machine and app status

Open **View status** on an owned machine or **Runtime status** in the administrator
fleet. Only the enrollment's owner or an administrator can read it; machine
credentials cannot. Owners cannot change assignments or inspect the catalog.
Retired enrollments remain visible until removal acknowledgement. A replacement
enrollment does not inherit access to the previous enrollment's diagnostics.

## Reading status

Compare the stages and their timestamps for the same enrollment and app:

| Stage | What it establishes |
| --- | --- |
| Requested | The desired app generation and pinned revisions |
| Delivered | The backend published the identified apps in a bundle |
| Downloaded | Runtime validated and cached the bundle; resources may not yet be applied |
| Staged, published, applied | The app artifact and its original generation and digest reached each stage |
| Applied receipt | Resource reconciliation completed; app health is separate |
| Configured health | The result and threshold of the configured local HTTP or TCP check, including its startup deadline |
| Registered | Node confirmed this runner and app while that observation remains valid |
| Discovery | The published fleet inventory contained the exact public app endpoint and version at the snapshot time |

Public app reachability remains **unverified**. Local checks, a verified tunnel
and successful discovery collection do not establish that an external client can
run the app. External probes and their freshness are separate observability work.

Report freshness uses `TunnelStatusTTL` (two minutes by default), but probes,
Node and connector observations, and Collector snapshots have their own times
and expiry. A new report or an exact retry does not renew older evidence. The
view continues to expire evidence if refresh fails. Clock uncertainty cannot
establish fresh readiness or drain completion.

A successful empty discovery snapshot is different from failed or stale
collection. After source or credential rotation, retained inventory cannot prove
membership or absence for the new version until it collects successfully. An
unrecoverable old artifact generation remains unknown.

Reports are limited to 128 KiB and 128 instances. Counts cover the full reported
state and omitted details are identified. A healthy subset cannot establish that
all instances are ready.

## Diagnose a failure

Start with the first unresolved stage and compare its generation, identity and
observation time:

- **Requested, delivered or downloaded differ:** inspect the delivery failure and
  Runtime adapter logs. Retained last-good app input keeps its original identity.
- **No instance exists:** inspect the assignment's resource refusal or cleanup
  prerequisite. Another assignment can still be healthy.
- **Image, startup, isolation or probe failure:** inspect the failure, Pod UID,
  configured check and startup deadline in the instance details.
- **`dependency_pending`:** install a compatible Node with the required
  registration capabilities; see the [Runtime guide](../runtime/README.md).
- **Node work is unknown:** missing or expired observations do not mean zero
  sessions. Registration loss or recreation does not prove earlier work survived;
  a Reconciler restart against a surviving Node is a separate case.
- **Cleanup is pending:** check withdrawal and deadline, cancellation attempt,
  removal publication, actual termination and registration cleanup separately.
  A cancellation attempt or published removal does not prove termination.
- **Access or collection failed:** check connector status, tunnel verification and
  the source transport outcome separately. See [machine tunnels](machine-tunnels.md)
  and [fleet discovery](fleet-discovery.md).

Use Runtime and Node logs and Flux/Kubernetes diagnostics, for example:

```sh
kubectl -n flux-system get kustomizations,externalartifacts
kubectl -n livepeer-apps get pods,services
kubectl -n livepeer-apps describe pod <instance-pod-name>
kubectl -n livepeer logs deployment/orchestrator
```

Correlate enrollment, app generation and revision, activation, instance, Pod UID,
runner and app IDs, artifact digest and observation time. Keep session IDs in
authorized logs or events. Do not paste credentials, bearer URLs, app environment
values or sensitive app output into issue evidence.

## Recovery and rollout

Deploy backend contract support before updated Runtime producers, then the UI.
Legacy reports provide limited evidence until upgraded. Preserve contract
support during rollback.

A status report HTTP 412 indicates lost or regressed ordering state. Restore
trustworthy state; do not delete counters or repeatedly increment them until the
server accepts a report. For active enrollments, the existing authorized
credential recovery can establish a new scope. Retired enrollments have no new
credential recovery protocol and remain unconfirmed if their ordering state is
lost. A process restart alone does not reset report ordering.

## Release verification

Run the Go race suite with `TEST_DATABASE_URL` pointing to disposable PostgreSQL,
the UI build and Playwright; skipped database tests do not establish acceptance.
For Runtime checks, follow [Runtime verification](../runtime/README.md#verification).
Record exact revisions and redacted evidence. Real Node/SDK/Flux/gVisor integration,
two-machine acceptance and production activation remain gated by
[#118](https://github.com/livepeer/naap-ops/issues/118); local tests do not establish
that acceptance or external reachability.
