# Control Center documentation

## Orchestrator operators

- [Orchestrators and members](operations.md#manage-orchestrators-and-members) — claim orchestrators and manage members
- [Host bootstrap](../runtime/README.md) — install, enroll, upgrade, and recover hosts
- [Operator secrets](operator-secrets.md) — enroll runtimes and manage app secrets
- [Machine and app status](machine-status.md) — inspect readiness and diagnose failures

## App authors and administrators

- [Write an app definition](app-registry.md#write-a-definition) — author and validate TOML definitions
- [Publish and assign apps](app-registry.md#publish-and-retire-revisions) — manage revisions and machine assignments
- [Machine and app status](machine-status.md) — monitor fleet readiness and rollouts
- [Tunnel and machine actions](machine-tunnels.md#rotate-connectors-drain-and-remove-machines) — rotate connectors, drain, and remove machines

## Platform operators

- [Staging deployment](../deploy/README.md) — deploy Compose services, registry, UI, and bootstrap releases
- [Operations](operations.md) — setup, administrator access, and onchain payments
- [Discovery authentication](discovery-auth.md) — Ed25519 signing keys and discovery ingress auth
- [Machine tunnels](machine-tunnels.md) — Cloudflare tunnels, credentials, and HTTP cutover
- [Fleet discovery](fleet-discovery.md) — aggregate discovery setup and diagnosis
- [Secrets service deployment](operator-secrets.md#deploy-the-secrets-service-and-vault) — Vault and secrets service setup
- [Machine telemetry](telemetry.md) — metrics, logs, dashboards, and diagnosis

## Contributors

- [Development](development.md) — local setup, checks, CI, and Runtime tests
