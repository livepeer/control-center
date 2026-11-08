# Machine configuration

This package builds and publishes each machine's configuration bundle. It
renders the orchestrator workload, Runtime configuration, tunnel connector,
network policies, and k3s upgrade resources from installation and routing
inputs. Runtime and Flux apply the bundle and report the resulting state. The
parent control plane handles HTTP, authentication, administrator authorization,
auditing, and wiring.

## Rollout and removal

When draining is configured, a workload replacement holds the applied workload
and requests a drain. A recent runner report must match the requested generation
and current enrollment credential before the replacement is released. An expired
drain requires an authorized retry. Normal removal uses the same protocol, then
retires the enrollment and publishes a terminal bundle that retains storage;
this also works without a tunnel.

Without a drain deadline, private updates keep their existing behavior. When
managed ingress requires a controlled rollout, the applied workload is held if
no deadline is configured. With draining configured, a legacy version-zero
credential also holds the workload until the machine refreshes its HTTPS
credential. Removing the drain settings does not silently cancel a pending
rollout. The report freshness limit uses `TunnelStatusTTL`, defaulting to two
minutes when unset; `TunnelDrainTimeout` supplies the deadline.

The [tunnel manager](../tunnel/README.md) orders endpoint replacement. A completed
drain alone does not establish external readiness.

## State and concurrency

General rollout and provider routing state are stored separately but share an
enrollment lease and revision. State changes are rechecked under the lease;
rendering and publication do not hold the provider lease. Publication checks
the revision after locking the machine and artifact, so credential refresh,
removal, or a newer decision fences stale work. Credential refresh also fences
reports from the previous credential. Configuration passes do not reset
provider retry backoff.

See the [machine tunnel runbook](../../../../docs/machine-tunnels.md) for setup
and release operations.
