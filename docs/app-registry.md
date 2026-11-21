# App registry

App authors use TOML to define HTTP apps. Administrators publish immutable catalog revisions and assign them to machines.

## Write a definition

Definitions are UTF-8 TOML up to `64 KiB` with case-sensitive keys. Unknown keys, duplicate keys, and wrong types fail validation. Values are literal without env expansion or file loading, and exclude secrets.

```toml
name = "my-app"
schema_version = 1

[container]
image = "traefik/whoami@sha256:c4717a8d1f0134a7444e24f881160e033991f23027c6c5a9a3f8fd22e70d1d44"
user = "10001:10001"

[container.environment]
WHOAMI_PORT_NUMBER = "8080"

[resources.limits]
memory = "1GiB"

[http]
port = 8080
```

Run images as a non-root user. If the image defaults to root, set `container.user` to a nonzero numeric `UID:GID`. Test pulls and startup during deployment. Onchain apps require a positive price. See [the full example](../runtime/tests/fixtures/whoami.toml).

### Definition settings

| Setting | Default and rules |
| --- | --- |
| `name` | **Required.** 1–128 ASCII letters, digits, `.`, `_`, `-`, starting with letter/digit |
| `schema_version` | **Required.** Integer `1` |
| `container.image` | **Required.** OCI/Docker ref pinned with `@sha256:` + 64 lowercase hex |
| `resources.limits.memory` | **Required.** Quoted limit, e.g. `"1GiB"` |
| `http.port` | **Required.** Integer `1`–`65535` |
| `app_version` | Empty, max `128` bytes, duplicates allowed |
| `container.platform` | Image default or `"linux/amd64"` |
| `container.entrypoint`, `container.command`, `container.working_dir`, `container.user` | Image defaults. Nonempty literal string arrays for entrypoint/command. Absolute path for working dir. |
| `container.environment` | Empty nonsecret string table |
| `container.secrets` | Up to `16` `{name, secret, key}` refs to `lp-app-*` Secrets |
| `resources.limits.cpu` | `1` CPU (integer cores or quoted `"0.5"`, `"500m"`) |
| `resources.limits.ephemeral_storage` | `"100MB"` |
| `resources.requests` | Defaults to limits (`<=` limits) |
| `health.readiness` | Omitted -> TCP on `http.port`. Table defaults to HTTP (`path` required) or `type = "tcp"`. Defaults `interval = "10s"`, `timeout = "2s"`, `failure_threshold = 3` (Runtime enforces `>= 10s` interval). |
| `filesystem.read_only_root` | `true` (required) |
| `filesystem.shm_size` | `"64MiB"` memory-backed |
| `filesystem.scratch` | None. Each `[[filesystem.scratch]]` needs `path`, defaults `size = "64MiB"`, memory-backed. |
| `network.egress` | `"deny"` or `"public-https"` (DNS + public TCP `443`) |
| `lifecycle.startup_timeout`, `lifecycle.stop_grace_period` | `"120s"`, `"30s"` |
| `lifecycle.stop_signal` | Image default or catchable Linux signal, e.g. `"SIGTERM"` |
| `instances.mode` | `"reusable"` (default) or `"single-session"` |
| `instances.replicas` | `1` (`1`–`100`) |
| `instances.capacity_per_instance` | `1` (`1`–`10,000`, `"single-session"` requires `1`) |
| `runner.mode` | `"persistent"` (default) or `"single-shot"` |
| `price.amount`, `price.currency`, `price.unit` | `"0"`, `"usd"`, `"hour"`. Nonnegative decimal string, `"usd"`, `"hour"` or `"fixed"`. |

### Value and path rules

Quote case-sensitive byte units (`"100MB"`, `"1GiB"`), whole-second durations (`"5s"`, `"12h"`), fractional CPUs, and prices (TOML floats rejected). Combined `shm_size` and scratch mounts must fit inside `resources.limits.memory`.

Working dir and scratch paths start with `/` without repeated/trailing slashes or `.`/`..` segments. Working dir allows `/`, and scratch forbids `/` and overlaps with other mounts or system/secret paths. HTTP readiness paths are local absolute paths without query, fragment, or traversal.

Shared deployments allow up to `256` public `[[apps]]` entries with `name`, private `path`, `capacity`, and `price` (unique, nonnested paths).

Catalog prices stay generic and immutable. Assignment and registration check compatibility against the machine's desired and observed Node onchain settings. Publishing a price leaves Node onchain activation unchanged ([onchain payments](operations.md#operate-onchain-payments)).

## Publish and retire revisions

1. Sign in as admin, open **Administration → App catalog**, and select **Create app**.
2. Paste TOML, select **Validate definition**, fix field errors, review normalized output, and select **Publish definition**.
3. For updates, select the app and choose **Publish new revision** (refresh base and revalidate on conflicts).

Open an app to inspect history, original TOML, normalized settings, and publication details. **Retire revision** permanently retires a revision while keeping history.

App `name` is case-sensitive and immutable, and new publications increment the revision number. Publishing a definition matching an existing revision (including formatting-only edits) returns that revision, even if retired, leaving revision numbers and latest unchanged. The latest revision can be retired.

### Catalog API

JSON routes require administrator authorization, and machine credentials are denied.

| Route | Purpose | Body |
| --- | --- | --- |
| `POST /api/admin/apps/validate` | Validate only | `source_toml` |
| `GET /api/admin/apps` | List apps | — |
| `GET /api/admin/apps/{name}` | View app and revisions | — |
| `GET /api/admin/apps/{name}/revisions/{id}` | View revision and TOML | — |
| `POST /api/admin/apps` | Publish new app | `source_toml` |
| `POST /api/admin/apps/{name}/revisions` | Publish revision | `source_toml`, `expected_head_revision_id` |
| `POST /api/admin/apps/{name}/revisions/{id}/retire` | Retire revision | `expected_state_version` |

List routes accept `limit` (default `50`, max `100`) and exclusive cursors `after_name` and `before_revision`. Mutations return the revision and `changed`, stale preconditions return `409`, and validation errors report fields.

## Assign revisions to machines

Open **Administration → Machine fleet**, choose **Manage apps**, pick an app, explicit revision, and replicas, and assign it.

Multiple revisions coexist with one assignment per revision and enrollment. New catalog revisions keep existing assignments unchanged, and scaling keeps the pinned definition and digest. New assignments reject retired revisions and policy-incompatible prices, while existing ones can scale or recover. Rollback assigns or replaces with an eligible prior revision.

**Replace revision** drains the source and stages the target.

- Matching replica limits above one roll within the shared limit. Each successor must be ready and registered before the next source is withdrawn. Target failure pauses replacement.
- A limit of one or differing limits requires source cleanup first.
- Rolling cleanup blocks replica edits and replacement chains. A blocked sequential target cannot be replaced. Removing the target continues source removal. Wait for cleanup acknowledgement before reassigning a removed revision.

- Equal replica limits `> 1` roll within that combined limit, waiting for each successor to become ready and registered before withdrawing another source and pausing on target failure.
- Limit `1` or differing limits complete source cleanup first.
- Replica edits and replacement chains are blocked during rolling cleanup, and blocked sequential targets cannot be replaced again.
- Removing a target keeps source removal active, and reassigning a removing revision waits for acknowledged cleanup.

**Applied — health unverified** confirms replica reconciliation and safe scale-down only. Health, registration, capacity, and discoverability are tracked separately, and bundle delivery alone leaves completion unconfirmed. Assignment details show pinned settings, actor, time, and paginated desired history.

### Assignment API

Server-verified administrator authority is required (machine owners, bootstrap JWTs, and machine credentials denied). Let `M = /api/admin/machines/{node_id}/apps`.

| Route | Body or query |
| --- | --- |
| `GET M` | `limit` (default `50`, max `100`), exclusive `after_revision_id` |
| `GET M/{revision_id}` | History `limit`, exclusive `before_generation` |
| `PUT M/{revision_id}` | `digest`, `expected_generation`, optional `replicas` |
| `DELETE M/{revision_id}` | `expected_generation` |
| `POST M/{revision_id}/replace` | `expected_generation`, `target: {revision_id, digest, expected_generation, replicas?}` |

Writes need an active enrollment (`expected_generation: 0` creates an assignment), and `replicas` accepts `1`–`100` (omitted uses definition default on create and keeps count on scale). Changes return `202`, identical completed retries return `200`, and conflicts return `409`. At most `100` assignments can be pending (including unacknowledged removals), and oversized changes keep the last valid bundle.

## Runtime delivery, drain, and removal

Runtime runs CPU `"reusable"` instances in `"persistent"` and `"single-shot"` modes (`"single-session"` unsupported). Each instance runs in a gVisor Pod with a private Service. Node advertises ready instances and checks capacity, and Control Center collects Node discovery responses.

| Setting | Default | Behavior |
| --- | --- | --- |
| `RuntimeAppDrainTimeout` | `12h` | `0s`–`12h` for sessions to finish after withdrawal (`0s` ends immediately) |
| `DrainTimeout` | `RuntimeAppDrainTimeout + 10m` (`12h10m`) | `>= RuntimeAppDrainTimeout` for machine drain confirmation (both `0s` expires immediately) |

After Node confirms registration removal, Runtime deletes the Pod and Service and reports cleanup. Node restarts or expired registrations can end sessions early.

Normal removal withdraws assignments and waits for app cleanup and machine drain. Forced removal stops Node early without graceful drain, keeping volumes, routes, and connector for app cleanup until the final phase unless credentials are compromised.

Registration cleanup requires Node Deployment absent and zero Node Pods remaining. Retired enrollments fetch terminal cleanup bundles and acknowledge cleanup, which re-enrollment requires. See [machine status](machine-status.md) and [tunnel removal](machine-tunnels.md#rotate-connectors-drain-and-remove-machines).
