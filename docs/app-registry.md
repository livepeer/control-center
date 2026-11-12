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
| `health.readiness` | With no table, TCP check on the HTTP port. A supplied table defaults to HTTP and requires `path`; set `type = "tcp"` for TCP. Defaults: `interval = "5s"`, `timeout = "2s"`, `failure_threshold = 3`. |
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
is evaluated against the target machine's desired and observed Node payment settings.
See [managed paid operation](paid-operation.md) for deployment configuration and
activation. Publishing a price does not activate paid operation on a Node.

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
| `GET M/{revision_id}` | Optional retained `epoch`; history `limit`, exclusive `before_generation` |
| `PUT M/{revision_id}` | `epoch`, `digest`, `expected_generation`, optional `replicas` |
| `DELETE M/{revision_id}` | `epoch`, `expected_generation` |
| `POST M/{revision_id}/replace` | `epoch`, `expected_generation`, `target: {revision_id, digest, expected_generation, replicas?}` |

Writes require a current active enrollment with modern credentials.
`expected_generation: 0` means never assigned. Replicas range from 1 to 100;
omitting them uses the definition default on creation and preserves the count on
scaling. Changed operations return 202 and `{changed, epoch, assignments}`;
identical completed retries return 200 without advancing generations. Concurrent
edits return 409. A lost-response retry must match the immediately resulting
version and complete desired result; an intervening edit conflicts even if values
return to their earlier state. Audit and desired writes commit together.

At most 100 assignments may be pending, including present, queued and
unacknowledged removals. Admission reserves room for removal within the 900 KiB
ConfigMap limit; completed history does not count. Invalid or oversized changes
leave desired state and the last valid bundle intact.

### Runtime delivery and completion contract

Management resources and app workloads are delivered separately. If app
rendering fails, management can still update while Runtime retains the last valid
app configuration.

Each assignment identifies a pinned revision, desired `present`/`absent` state,
`generation`, stable `activation_generation` and cleanup policy. Present entries
include the definition, effective replicas and `start_allowed`; queued targets
also carry `start_after: {source_revision_id, source_removal_generation}`.
`replacement` identifies rolling targets without bypassing `start_after`.
Activation survives scaling and removal; reassignment after cleanup creates a
new activation. Absent entries retain identity and stop policy.
The desired configuration digest is independent of the rendered payload and
bundle digests. App-only edits preserve the Node and tunnel rollout generation.

Runtime supports CPU reusable instances in persistent and single-shot protocol
modes. Single-session lifetimes are unsupported. Each instance has a gVisor Pod
and private Service. Runtime reports each instance’s readiness to Node. Node
lists ready instances in its discovery response and checks readiness and capacity
before accepting new sessions or single-shot requests. Control Center collects
these responses into its cached fleet listing.

Unhealthy instances stop receiving new work but retain their registration.
Removal withdraws an instance from discovery while existing work drains.
`RuntimeNodeDrainTimeout` sets Node's drain deadline: it defaults to 12 hours,
accepts 0–12 hours, and zero ends work immediately.

Normally, the Pod and Service remain available until a fresh, accepted complete
Node snapshot confirms registration removal. Runtime then removes their workload
definitions so Flux and Kubernetes can delete them. Runtime reports completion
after registration and resource cleanup.

`TunnelDrainTimeout` is a separate machine-maintenance fallback. Expiry may force
physical removal without Node confirmation; ordinary replacement stays blocked
until an audited retry, even if Node completes later. Draining continues across
Runtime restart, but SDK sequencing cannot fence higher-sequence requests still
in flight at a crash. Node restart or owner expiry can lose sessions.

Runtime reports with the machine service credential to
`POST /v1/nodes/{node_id}/apps/{revision_id}/status`. The strict JSON body is limited
to 16 KiB:

```json
{"epoch":"<ENROLLMENT_UUID>","credential_version":1,"generation":2,
 "activation_generation":1,"apps_digest":"sha256:<HEX>",
 "phase":"removed","reason":""}
```

`applied` records reconciliation completion for a present, start-permitted version.
`removed` records cleanup of the entire activation, including owned instances,
private routes and registration. Completion reports require an empty reason.
`failed` records a diagnostic while incomplete and cannot undo completion. Its
reasons are `reconcile_failed`, `invalid_definition`, `image_pull_failed`,
`startup_failed`, `isolation_refused`, `resource_refused`,
`cleanup_failed`, or `registration_cleanup_failed`; do not send credentials,
payloads or arbitrary error text.

Reports must match published membership, desired state and start permission. An
older published digest remains valid while that assignment version is current.
Immutable completion receipts allow exact retries after removal-entry compaction
or reassignment without changing a newer activation. Unknown, future,
cross-enrollment and stale transitions are rejected. Completion is monotonic; no
report sequence is required, and changing health is separate.

Unacknowledged removals remain in snapshots while offline. Fetch or authentication
failure preserves the last valid artifact; on reconnection, Runtime receives the
latest snapshot without running every intermediate version. Cleanup acknowledgement
removes the tombstone from future active snapshots and releases prerequisites,
advancing `apps_generation` while preserving the Node/tunnel generation.

Normal machine removal withdraws all assignments, including queued targets, and
waits for app cleanup and machine drain completion. Force removal and owner
deletion retain terminal instructions and history. Terminal removal acknowledgement
also requires app cleanup. A retired enrollment can fetch its terminal bundle and
acknowledge exact terminal app cleanup, but cannot report active state or
administer apps. Terminal snapshots are write-once, and old-epoch cleanup cannot
affect reenrollment. Node, routes, the Reconciler and connector credentials
remain available until app cleanup receipts complete; credential compromise
overrides that hold.
