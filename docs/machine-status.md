# Machine and app status

Open **View status** on your machine or **Runtime status** in **Administration → Machine fleet**. Only the enrollment owner and administrators can read status. Catalog access and assignment changes require an administrator. Retired enrollments stay visible until cleanup acknowledgement. Replacement enrollments have separate diagnostics.

## Read work readiness and stages

Machine lists and **Work readiness** share identical criteria. Fleet polls make one HTTP request, and detailed status fetches for the selected machine only.

| Badge | Criteria |
| --- | --- |
| **Green** — Ready to receive work | Node is ready, including onchain admission when configured. All active assignments have fresh health evidence and Node confirms that the requested replicas are ready. Managed tunnels need verified ingress and a ready connector. When enabled, discovery must show a current admitted replica. |
| **Amber** — Pending, partially ready, or unverified | Evidence is missing or expired, rollout is in progress, or only some replicas are ready. Older Runtime reports can show health or registration while admission remains pending. |
| **Red** — Not ready or not accepting work | Confirmed blocker, no active assignments, or enrollment draining or retired. |

Compare stages and timestamps for the same enrollment and app.

| Stage | Establishes |
| --- | --- |
| Requested | Desired generation and pinned revisions |
| Delivered | Control Center published apps in a bundle |
| Downloaded | Runtime validated and cached bundle before apply |
| Staged, published, applied | App artifact with original generation and digest reached stage |
| Applied receipt | Resource reconciliation done (app health separate) |
| Configured health | Local HTTP/TCP check result, threshold, and startup deadline |
| Registered | Node confirmed runner and app within observation window |
| Discovery | Fleet inventory held exact public endpoint and version at snapshot |

Work readiness reflects control-plane evidence only (verify client sessions separately). Reports expire after `TunnelStatusTTL` (default `2m`), while probes, Node/connector observations, and discovery snapshots track independent deadlines.

Only fresh discovery matching current source and credentials verifies membership. Reports list up to `128` instances and flag omissions.

## Diagnose failures

Start at the first unresolved stage and compare generation, identity, and observation time.

| Symptom | Check |
| --- | --- |
| Requested, delivered, or downloaded differ | Delivery errors and Runtime adapter logs (retained last-good input keeps original identity) |
| No instance exists | Resource refusal or cleanup prerequisites. Fresh reports for current input/generation/activation show startup blockers before retained diagnostics. Secret outages leave secret presence unconfirmed. Applied artifacts keep original identities and leave reconciliation failures intact. Other assignments can stay healthy. |
| Image, startup, isolation, or probe failure | Failure reason, Pod UID, configured check, and startup deadline in instance details |
| Node registration or protocol failure | Request error and Node/SDK revisions ([Runtime protocol](../runtime/README.md#system-workload-delivery)) |
| Node work unknown | Node connectivity and status (missing/expired observations leave active sessions unknown) |
| Cleanup pending | Drain deadline, workload config, Pod/Service deletion, and registration cleanup (maintenance deadlines trigger removal offline, and Flux/K8s outages delay deletion) |
| Auth or collection failed | Connector status, tunnel verification, and source transport separately ([tunnels](machine-tunnels.md), [discovery](fleet-discovery.md)) |

Inspect Flux, app workloads, and Node on the host.

```sh
kubectl -n flux-system get kustomizations,externalartifacts
kubectl -n livepeer-apps get pods,services
kubectl -n livepeer-apps describe pod <instance-pod-name>
kubectl -n livepeer logs deployment/orchestrator
```

Correlate enrollment, app generation/revision, activation, instance, Pod UID, runner/app IDs, artifact digest, and observation time. Keep session IDs in authorized logs/events and omit credentials, bearer URLs, env values, and sensitive app output from issue reports.

## Upgrade order and HTTP 412 recovery

Deploy an API accepting new status fields before upgrading Runtime. Roll back Runtime before reverting to an older API.

HTTP `412` signals lost or regressed report ordering state (process restarts preserve ordering). Restore trustworthy state and never delete counters or bump them repeatedly to force acceptance.

Active enrollments recover scope via authorized credential recovery. Retired enrollments have no recovery protocol and remain unconfirmed if ordering state is lost.

For test suites, see [checks](development.md#run-checks-and-ci) and [end-to-end tests](development.md#end-to-end-tests).
