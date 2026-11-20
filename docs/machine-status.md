# Machine and app status

Open **View status** on an owned machine or **Runtime status** in the administrator
fleet. Only the enrollment's owner or an administrator can read it; machine
credentials cannot. Owners cannot change assignments or inspect the catalog.
Retired enrollments remain visible until removal acknowledgement. A replacement
enrollment does not inherit access to the previous enrollment's diagnostics.

## Reading status

The machine list and **Work readiness** section use the same readiness criteria.
Each fleet poll makes one HTTP request. The browser fetches detailed status
only for the selected machine.

- **Green — Ready to receive work.** The current Node deployment is ready,
  onchain admission is ready when configured, and all active assignments have
  fresh health evidence and Node has accepted the requested replicas as ready.
  Managed tunnels require verified ingress and a ready connector. With
  discovery enabled, the fresh inventory must include a current admitted replica.
- **Amber — Pending, partially ready, or unverified.** Readiness evidence is
  missing or expired, startup or rollout is in progress, or only some
  requested app replicas are confirmed ready. Older Runtime reports can show
  healthy or registered replicas while admission evidence is still pending.
- **Red — Not ready or not accepting work.** A confirmed blocker prevents work,
  there are no active assignments, or the enrollment is draining or retired.

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

An external client completing a session requires separate verification. The
readiness badge uses the control plane's operational evidence.

Reports expire after `TunnelStatusTTL` (two minutes by default). Probes, Node
and connector observations, and discovery snapshots have their own deadlines.
Only fresh discovery for the current source and credentials verifies membership.
Reports show at most 128 instance details and indicate any omissions.

## Diagnose a failure

Start with the first unresolved stage and compare its generation, identity and
observation time:

- **Requested, delivered or downloaded differ:** inspect the delivery failure and
  Runtime adapter logs. Retained last-good app input keeps its original identity.
- **No instance exists:** inspect the assignment's resource refusal or cleanup
  prerequisite. Fresh reports for the current input, assignment generation and
  activation show the current startup blocker before any retained reconciliation
  diagnostic. Secret delivery being unavailable does not establish that a secret
  is missing. Artifact stages retain their original identities; an applied
  artifact alone does not clear a reported reconciliation failure. Another
  assignment can still be healthy.
- **Image, startup, isolation or probe failure:** inspect the failure, Pod UID,
  configured check and startup deadline in the instance details.
- **Node registration or protocol failure:** inspect the request failure and
  verify the deployed Node and SDK revisions meet the
  [Runtime protocol](../runtime/README.md#system-workload-delivery).
- **Node work is unknown:** check Node connectivity and status. Missing or expired
  observations do not establish whether sessions are still running.
- **Cleanup is pending:** check the drain deadline, published workload configuration,
  Pod and Service deletion, and registration cleanup. A maintenance deadline can
  initiate workload removal when Node is unavailable; Flux or Kubernetes outages
  can delay deletion.
- **Authentication or collection failed:** check connector status, tunnel verification and
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

Before upgrading Runtime, deploy a Control Center API version that accepts its
status report fields. When reverting to an API version that rejects those fields,
roll back Runtime first.

A status report HTTP 412 indicates lost or regressed ordering state. Restore
trustworthy state; do not delete counters or repeatedly increment them until the
server accepts a report. For active enrollments, the existing authorized
credential recovery can establish a new scope. Retired enrollments have no new
credential recovery protocol and remain unconfirmed if their ordering state is
lost. A process restart alone does not reset report ordering.

## Verification

See [development checks](development.md#development-checks) and the
[end-to-end harness](development.md#end-to-end-tests).
