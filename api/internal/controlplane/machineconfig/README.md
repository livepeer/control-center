# Machine configuration

This package builds and publishes each machine's configuration bundle. It
renders the orchestrator workload, Runtime configuration, tunnel connector,
network policies, and k3s upgrade resources from installation and routing
inputs. Runtime and Flux apply the bundle and report the resulting state. The
parent control plane handles HTTP, authentication, administrator authorization,
auditing, and wiring.

## Rollout and removal

A graceful replacement waits for a fresh runner report matching the drain
generation and current enrollment credential. Normal removal retires the
enrollment and preserves storage.

`TunnelStatusTTL` sets report freshness and defaults to two minutes.
See [drain settings](../../../../docs/app-registry.md#runtime-delivery-drain-and-removal)

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
