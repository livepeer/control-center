# Machine configuration

This package builds and publishes each machine's configuration bundle. It
renders the orchestrator workload, Runtime configuration, tunnel connector,
network policies, and k3s upgrade resources from installation and routing
inputs. Runtime and Flux apply the bundle and report the resulting state. The
parent control plane handles HTTP, authentication, administrator authorization,
auditing, and wiring.

## Rollout and removal

A workload replacement holds the applied workload while it drains. A fresh runner
report matching the requested generation and current enrollment credential allows
replacement. An administrator can force an orchestrator update while it waits for
sessions to drain. Control Center forces it on its next update check after the
deadline expires. Normal removal and endpoint migration require an authorized
retry if their drain expires. Normal removal retires the enrollment and publishes
a terminal bundle that retains storage, with or without a tunnel.

`RuntimeAppDrainTimeout` sets Node's per-app session grace after withdrawal. It
accepts `0s` through `12h` and defaults to `12h`. `DrainTimeout` starts when
Control Center requests a machine drain and must be at least the app timeout.
It defaults to the app timeout plus `10m` (`12h10m` by default). Confirmation
can allow the operation to proceed sooner. Setting both to `0s` makes the
machine deadline immediate, so normal removal and endpoint migration need a
positive `DrainTimeout` to receive confirmation.
`TunnelStatusTTL` sets report freshness and defaults to two minutes.

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
