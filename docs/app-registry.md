# App registry

The app registry is Control Center's catalog of HTTP applications. Each entry
describes a container image, its resources, health check, instance settings, and
price. The catalog keeps a history of immutable revisions for inspection and
retirement. It does not assign or deploy apps to machines.

## Publish an app

1. Sign in as an administrator, open **Administration → App catalog**, and
   select **Create app**.
2. Enter a TOML definition and select **Validate definition**. Correct any
   reported errors and validate again.
3. Review the normalized definition and select **Publish definition**.
4. To update an app, select it and choose **Publish new revision**. If the app
   changes while you edit, refresh the publication base and validate again.

Select an app to view its revision history, original TOML, normalized settings,
and publication details. Select a revision and choose **Retire revision** to
mark it retired. Retirement is permanent and does not delete the revision.

An app is identified by its case-sensitive name and cannot be renamed. A new
publication receives the next revision number. Publishing a definition identical
to an existing revision returns that revision, even if it is retired; it does
not create a revision or change the latest revision. Formatting changes alone
do not create a revision. The latest revision can be retired.

## Write a definition

Definitions use UTF-8 TOML, limited to 64 KiB. Keys are case-sensitive. Unknown
or duplicate keys and incorrect value types are rejected. Values are literal:
they do not expand environment variables or load files. Do not put secrets in
the definition.

This example uses a pinned image and configures it to listen on port 8080:

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

Replace the image, user, environment, and port with values for your app. The
image must run as a non-root user; if its metadata specifies root, set
`container.user` to a compatible nonzero numeric `UID:GID`. Validation checks
the definition, not whether the image can be pulled or run successfully. In
onchain mode, add a positive price to the example. See the
[complete example](../runtime/tests/fixtures/whoami.toml) for more settings.

### Required settings

| TOML setting | Description |
| --- | --- |
| `name` | 1–128 ASCII letters, digits, dots, underscores, or hyphens; starts with a letter or digit. |
| `schema_version` | Integer `1`. |
| `container.image` | OCI/Docker image reference pinned with `@sha256:` and 64 lowercase hexadecimal digits. |
| `resources.limits.memory` | Memory limit, such as `"1GiB"`. |
| `http.port` | Application HTTP port, from 1 to 65535. |

### Optional settings

| TOML setting | Default and accepted values |
| --- | --- |
| `app_version` | Empty; an optional string of up to 128 bytes. Versions need not be unique. |
| `container.platform` | Image default; `"linux/amd64"` if specified. |
| `container.entrypoint`, `container.command`, `container.working_dir`, `container.user` | Image defaults. Entrypoint and command are nonempty arrays of literal strings; working directory is an absolute path. |
| `container.environment` | No additions. A table of nonsecret string values. |
| `container.secrets` | Up to 16 `{name, secret, key}` references to `lp-app-*` Secrets. |
| `resources.limits.cpu` | 1 CPU. Use integer cores or quoted values such as `"0.5"` or `"500m"`. |
| `resources.limits.ephemeral_storage` | `"100MB"`. |
| `resources.requests` | Each omitted CPU, memory, or ephemeral storage request defaults to its corresponding limit. Requests cannot exceed limits. |
| `health.readiness` | With no table, TCP check on the HTTP port. A supplied table defaults to HTTP and requires `path`; set `type = "tcp"` for TCP. Defaults: `interval = "10s"`, `timeout = "2s"`, `failure_threshold = 3`. Runtime enforces a minimum interval of ten seconds. |
| `filesystem.read_only_root` | `true`; writable roots are unsupported. |
| `filesystem.shm_size` | `"64MiB"` of memory-backed shared memory. |
| `filesystem.scratch` | No mounts. Each `[[filesystem.scratch]]` table requires `path`; `size` defaults to `"64MiB"`. Mounts are memory-backed. |
| `network.egress` | `"deny"` or `"public-https"` for DNS and public TCP 443. |
| `lifecycle.startup_timeout`, `lifecycle.stop_grace_period` | `"120s"` and `"30s"`. |
| `lifecycle.stop_signal` | Image default; otherwise a supported catchable Linux signal name such as `"SIGTERM"`. |
| `instances.mode` | `"reusable"` or `"single-session"`. Default: `"reusable"`. |
| `instances.replicas` | `1`; range 1–100. |
| `instances.capacity_per_instance` | `1`; range 1–10,000. Single-session instances require 1. |
| `runner.mode` | `"persistent"` or `"single-shot"`. Default: `"persistent"`. |
| `price.amount`, `price.currency`, `price.unit` | `"0"`, `"usd"`, `"hour"`. Amount is a nonnegative decimal string; currency is USD; unit is `"hour"` or `"fixed"`. |

Byte quantities are quoted, with units such as `"100MB"` or `"1GiB"`; units
are case-sensitive. Durations are quoted, such as `"5s"` or `"12h"`, and must
resolve to whole seconds. Quote fractional CPU values and prices; TOML floats
are not accepted. Shared memory and scratch sizes together must fit within the
memory limit.

Working directories and scratch mount paths must start with `/` and cannot contain
repeated slashes, trailing slashes, or `.` or `..` directory segments. The working
directory may be `/`; scratch mounts cannot. Scratch mounts cannot overlap each
other or system and secret paths. HTTP readiness paths must be local absolute paths
without a query, fragment, or traversal. The validator reports the affected
field when a setting is invalid.

A shared deployment supports up to 256 public `[[apps]]`, each with a `name`,
private `path`, `capacity`, and `price`; paths must be unique and nonnested.

## Pricing policy

Catalog prices remain generic and immutable. Assignment and registration compatibility
is evaluated against the target machine's desired and observed Node onchain settings.
See [operations](operations.md#onchain-operation) for deployment configuration and
activation. Publishing a price does not activate onchain operation on a Node.

## Catalog API

Catalog routes require administrator authorization; machine credentials do not
grant access. Requests and responses use JSON.

| Method and route | Purpose | Request body |
| --- | --- | --- |
| `POST /api/admin/apps/validate` | Validate a definition without publishing it. | `source_toml` |
| `GET /api/admin/apps` | List apps. | — |
| `GET /api/admin/apps/{name}` | View an app and its revision history. | — |
| `GET /api/admin/apps/{name}/revisions/{id}` | View a revision, including its original TOML. | — |
| `POST /api/admin/apps` | Publish a new app. | `source_toml` |
| `POST /api/admin/apps/{name}/revisions` | Publish a revision. | `source_toml`, `expected_head_revision_id` |
| `POST /api/admin/apps/{name}/revisions/{id}/retire` | Retire a revision. | `expected_state_version` |

List routes accept `limit` (default 50, maximum 100); use `after_name` for the
app list and `before_revision` for revision history. Both cursors are
exclusive. Mutations return the revision and a `changed` boolean. A stale head
or state produces a conflict; refresh before retrying. Validation errors
include field-specific messages.

## Assign revisions to a machine

In **Administration → Machine fleet**, choose **Manage apps**, select an app
and explicit revision, set replicas, and assign it. Multiple revisions may coexist,
with one assignment per revision and enrollment. Publishing a catalog revision does
not change existing assignments; scaling does not change the definition or digest.
New assignments reject retired revisions and definitions incompatible with current
pricing policy, but existing assignments may scale or recover. Rollback requires an
explicit assignment or replacement with an eligible prior revision.

**Replace revision** drains the source and stages the target. Matching replica
limits above one allow rolling replacement within that combined limit. Each
successor must be ready and registered before another source is withdrawn; target
failure pauses progress. With a limit of one or differing limits, source cleanup
finishes first. Replica edits and replacement chains are refused during rolling
source cleanup; blocked sequential targets cannot be replaced again.
Removing a target leaves source removal in place. A revision being removed
cannot be reassigned until cleanup is acknowledged.

**Applied — health unverified** means the requested replicas were reconciled and
scale-down finished safely; it does not establish current health, registration,
capacity or discoverability. Bundle delivery alone does not establish app
completion. Inspect an assignment for pinned settings, actor, time and paginated
desired history.

### Assignment API

All routes require server-verified administrator authority; machine owners,
bootstrap JWTs and machine service credentials cannot mutate assignments. Let
`M = /api/admin/machines/{node_id}/apps`:

| Method and route | Body or query |
| --- | --- |
| `GET M` | `limit` (50 default, 100 maximum), exclusive `after_revision_id` |
| `GET M/{revision_id}` | History `limit`, exclusive `before_generation` |
| `PUT M/{revision_id}` | `digest`, `expected_generation`, optional `replicas` |
| `DELETE M/{revision_id}` | `expected_generation` |
| `POST M/{revision_id}/replace` | `expected_generation`, `target: {revision_id, digest, expected_generation, replicas?}` |

Writes require a current active enrollment. `expected_generation: 0` means never
assigned. Replicas range from 1 to 100; omitting them uses the definition default
on creation and preserves the count on scaling. Changed operations return 202;
identical completed retries return 200. Concurrent edits return 409; refresh before
retrying. At most 100 assignments may be pending, including unacknowledged
removals. Oversized changes leave the last valid bundle intact.

### Runtime delivery and completion contract

Runtime supports CPU reusable instances in persistent and single-shot protocol
modes. Single-session lifetimes are unsupported. Each instance runs in a gVisor
Pod with a private Service. Node advertises ready instances and checks capacity
before accepting work; Control Center collects Node's discovery responses.

Removal withdraws an instance from discovery and drains existing work. Set
`RuntimeNodeDrainTimeout` from 0 to 12 hours (default 12 hours); zero ends work
immediately. Normally Runtime waits for Node to confirm registration removal,
then removes the Pod and Service and reports cleanup. `TunnelDrainTimeout` is a
separate machine-maintenance deadline that defaults to 12 hours. After it expires
during an orchestrator update, Control Center forces replacement on its next
update check, possibly without Node confirmation. Ordinary machine removal and
endpoint migration require a retry after expiry. Node restart or owner expiry can
lose sessions.

Normal machine removal withdraws assignments and waits for app cleanup and
machine drain. Forced removal stops Node early without a graceful drain. It
retains volumes, routes and the connector for app cleanup until the final phase,
unless credentials are compromised. Registration cleanup requires the Node
Deployment to be absent and no Node Pods to remain. A retired enrollment can
receive terminal cleanup instructions and acknowledge cleanup; re-enrollment
requires that acknowledgement. See [machine status](machine-status.md) for
diagnosis and [machine tunnels](machine-tunnels.md#rotation-and-removal) for
removal commands.
