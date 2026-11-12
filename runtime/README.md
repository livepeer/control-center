# Livepeer host bootstrap

`bootstrap-livepeer.sh` is a Bash installer for a **single-node,
Debian/Ubuntu amd64, systemd** host. It installs K3s, gVisor, Flux, an API-backed
HTTP configuration adapter, system-upgrade-controller, and the standalone
[`livepeer/node`](https://github.com/livepeer/node) orchestrator in offchain mode.
Control Center assigns CPU reusable apps to isolated Pods; Node handles new
requests, sessions, capacity and private proxying. GPU setup and single-session lifetimes
remain separate work. Managed Cloudflare ingress is optional.

Runtime lives under `runtime/` in the Control Center repository. Run the
commands below from that directory.

Copy or clone the whole project onto the target machine. Host installation uses
Bash and standard Linux utilities. Runtime management, app reconciliation and
probes use one Go distribution. See [storage and host integration](#storage-and-host-integration)
for installed paths.

```bash
# On the machine that will receive the cluster:
sudo bash bootstrap-livepeer.sh --check-only
sudo bash bootstrap-livepeer.sh --status
export LIVEPEER_API_URL=https://your-control-center-api.example
export LIVEPEER_RUNTIME_IMAGE=your-registry/livepeer-runtime@sha256:<published-digest>
sudo --preserve-env=LIVEPEER_API_URL,LIVEPEER_RUNTIME_IMAGE bash bootstrap-livepeer.sh --token <TOKEN>

# Or contain the installation under another absolute directory:
sudo --preserve-env=LIVEPEER_API_URL,LIVEPEER_RUNTIME_IMAGE bash bootstrap-livepeer.sh --token <TOKEN> --install-dir /srv/livepeer
```

The default installation directory is `/opt/livepeer`. On a first run, choose a
new or empty directory. To rerun an existing Livepeer installation, use the same
`--install-dir`.

For directory names, use an absolute path such as `/srv/livepeer`, without
symlinks, spaces, repeated or trailing slashes, or `.` and `..` as directory
names. Allowed characters are letters, digits, `_`, `.`, `-` and `/`; `/` itself
is not allowed.

The installer stops if it detects a conflicting Kubernetes installation anywhere
on the host, including outside `--install-dir`.

## Prerequisites

Use a host with at least 2 CPUs, nominal 4 GiB RAM, 10 GiB free disk,
Linux 5.4+, enabled cgroups and namespaces, and no active swap. On a minimal
Debian 12+ or Ubuntu 22.04+ image, install prerequisites first:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl jq tar bzip2 gzip coreutils \
  gawk iproute2 kmod procps util-linux systemd nftables diffutils findutils
```

Eligibility checks run before authentication, downloads, directory creation, or
service changes. `--check-only` is read-only. Checks include available kernel
modules, reserved TCP ports 2379/2380/6443/6444/8935/8936/10010/10249/10250/10256/10257/10259/20241,
UDP 8472, and routes overlapping
the fixed `10.42.0.0/16` Pod, `10.43.0.0/16` Service and `10.44.0.0/16` gVisor
networks. Once K3s has been downloaded, its own `check-config` performs additional
kernel validation.
The installer requires nftables kernel support and `CAP_NET_ADMIN`, and reserves
its own `inet livepeer_bootstrap` table. It refuses to take over an existing
unowned table with that name. Existing host firewalls still apply; its allow
rules do not override a more restrictive policy in another firewall table.

gVisor uses a separate bridge. It can reply to incoming requests and initiate
public HTTPS and external DNS, but cannot initiate connections to the host,
other Pods, private networks or metadata services. System Pods retain local access.
Reload `livepeer-firewall.service` after changing host networks to refresh local routes.

The host and cluster need HTTPS access to GitHub releases and the configured
container registries. Downloads use fixed releases with checksum verification:

| Component | Pinned version |
| --- | --- |
| K3s | `v1.37.2+k3s1` |
| gVisor | `release-20261102.0` |
| Flux | `v2.10.0` |
| system-upgrade-controller | `v0.21.0` |

Runtime, tunnel, smoke-test BusyBox and Livepeer images must be pinned by digest.
The upgrade job's kubectl helper uses `rancher/kubectl:v1.36.2`, within one minor
of the installer's pinned Kubernetes version. Keep that helper within one minor
of the Kubernetes version. Published checksums provide download integrity;
the installer trusts the upstream HTTPS release endpoints.

Build the Go Runtime image from the repository root with
`docker build -f runtime/Dockerfile -t <registry>/livepeer-runtime:<tag> .`, push
it, and use its published digest for `LIVEPEER_RUNTIME_IMAGE` and backend
`RUNTIME_IMAGE`. The installer saves its selected image for reruns.

For managed external access, Runtime's connector obtains a Cloudflare Tunnel
token and starts cloudflared; Kubernetes restarts it when needed. Build and publish
the separate connector image, which combines cloudflared with the Runtime helper,
using the [tunnel build command](../docs/machine-tunnels.md#infrastructure-and-enablement).
Set backend `RUNTIME_CONNECTOR_IMAGE` to the published connector image digest
before enabling managed ingress.

## System workload delivery

Runtime delivers management and app workloads separately, so management can
continue to update when app reconciliation fails. Node reports its applied
revision and workload status. See the [tunnel runbook](../docs/machine-tunnels.md#credential-boundaries)
for connector credentials, startup and recovery.

Running production apps requires compatible Node and SDK releases. Set backend
`RUNTIME_NODE_IMAGE` to a compatible digest-pinned image and verify it with the
[Runtime release checks](#verification).

Explicit container stop signals require Kubernetes `ContainerStopSignals` on
both the API server and kubelet, plus backend `APP_STOP_SIGNALS=true`. Keep that
backend option disabled unless the cluster supports it; unsupported assignments
are diagnosed without suppressing management repairs.

## Enrollment and desired configuration

Get the enrollment command from the authenticated Livepeer Control Center
console. Set `LIVEPEER_API_URL` to the API base URL, reachable from the host and
its Kubernetes pods, and run the command as root. When using sudo, preserve the
environment variable as shown in Quick start. Backend `PUBLIC_API_URL` must use
the same reachable base URL. The installer rejects literal loopback configuration
URLs because pods cannot use host loopback.

The one-hour bootstrap JWT can enroll multiple machines. The installer saves
long-lived service credentials in owner-only files and reuses them on reruns,
even after the JWT expires. A fresh registration retry requires the original
owner, installation path and initial K3s version; otherwise it returns HTTP 409,
even with a new JWT. Normal recovery keeps the installation root and an already
upgraded K3s version. The runner-bootstrap credential stays local.

Control Center generates a configuration bundle for each machine. Runtime
polls for updates every minute and delivers valid configuration to Flux. If
generation or download fails, it retains the last valid configuration. Machine
owners do not upload or edit the bundle. Bootstrap resources and runner
credentials remain installer-managed. K3s upgrades require explicit opt-in using
the node label, and persistent volumes retain their data.

## Protected machine ingress

See [the machine tunnel runbook](../docs/machine-tunnels.md) for backend setup,
operator decisions and release gates. Live provisioning requires verified HTTPS
for enrollment, configuration, status and token delivery. Development HTTP is
available only with `LIVEPEER_ALLOW_DEVELOPMENT_HTTP=1` and cannot enable tunnels.

To refresh credentials, run the installer with a fresh owner enrollment JWT and
the same HTTPS origin and installation directory:

```bash
export LIVEPEER_API_URL=https://<CONTROL_CENTER_ORIGIN>
sudo --preserve-env=LIVEPEER_API_URL bash bootstrap-livepeer.sh \
  --refresh-credentials --token <FRESH_OWNER_JWT> --install-dir /opt/livepeer
```

If refresh is interrupted, rerun the command with a fresh JWT and the same HTTPS
origin. Refresh retains the enrollment, tunnel UUID, local runner credential and
installed K3s version.

After the backend removes an enrollment, use `--reenroll` with a fresh owner JWT
and the same installation root to create a new enrollment while retaining local
data. The installer requires confirmed app cleanup for the old enrollment.
Re-enrollment does not accelerate its external cleanup.

The connector fetches a fresh token before every start; running connectors can
reconnect during a Control Center outage. Runtime reports applied state, while
Control Center verifies external readiness. See the [tunnel runbook](../docs/machine-tunnels.md).

During enrollment removal, Node, routes and connector access remain available
while app cleanup is pending, unless credentials are compromised. Public Trickle
is unsupported.

## Storage and host integration

`bootstrap-livepeer.sh` uses the repository's `lib/` Bash helpers and renders
`config/` and `manifests/` templates for the selected installation root:

| Directory | Contents |
| --- | --- |
| `bin/`, `download/`, `runtimes/` | Verified binaries, versioned release caches, complete gVisor generations |
| `lib/` | Bash recovery helpers used before each K3s launch |
| `credentials/`, `state/` | Enrollment, runner secret, installation marker |
| `config/`, `systemd/` | K3s configuration, kubeconfig, runsc settings, service unit |
| `k3s/`, `kubelet/` | Explicit K3s data directory and kubelet root |
| `manifests/` | Bootstrap manifests |
| `volumes/` | Orchestrator data, source artifacts, scoped sockets, nonsecret connector associations, App Reconciler journal/artifacts, local-path storage |
| `logs/` | Bootstrap, K3s, Pod, and smoke-test logs |

K3s's data directory is explicitly `<root>/k3s`, never its default
`/var/lib/rancher/k3s`. The kubelet Pod log directory is configured with a drop-in
under that data directory. Arrange log rotation for `logs/k3s.log` and
`logs/bootstrap.log` on long-lived hosts.

Host integration still requires paths and state outside the root:

- `/etc/systemd/system/livepeer-k3s.service` and `livepeer-firewall.service` link to units beneath the root;
  systemd creates its usual enablement link and journal entries.
- `/run/lock/livepeer-bootstrap.lock`, K3s/containerd sockets under `/run/k3s`,
  Flannel runtime files under `/run/flannel`, and CNI state under `/var/lib/cni`.
- Kubelet creates its usual container-log links under `/var/log/containers`.
- The upstream upgrade controller mounts host certificate directories
  `/etc/ssl`, `/etc/pki`, and `/etc/ca-certificates`; Kubernetes may create missing
  certificate mount directories.
- Kubernetes creates mounts, network interfaces, firewall rules, and cgroups.
  The service loads kernel modules and enables forwarding and bridge filtering
  at startup, including after reboot, without adding `/etc/sysctl.d` files.

The orchestrator uses a local PV tied to this node. This is a single-host
installation, with no failover or durable sessions across process restarts.
It runs on `runc`, as do Flux, the helpers, and the upgrade controller.
gVisor is available through `runtimeClassName: gvisor` for workloads;
its systrap platform does not require KVM.

## Tunnel-only external access

K3s explicitly binds its main API listener to `0.0.0.0:6443`. Local Pods need a
reachable node endpoint behind `kubernetes.default.svc`; binding exclusively to
host loopback would break that path without additional networking.

`livepeer-firewall.service` loads `config/firewall.nft` before K3s starts:

- Loopback traffic is permitted, allowing a host-local tunnel to `127.0.0.1:6443`.
- The IPv4 Pod network on `cni0`/`flannel.1` may reach TCP 6443. Authentication and
  RBAC still apply; this permits the Pod CIDR, not individual namespaces.
- Non-loopback TCP access to the reserved management ports and UDP VXLAN 8472
  is dropped for both IPv4 and IPv6.
- External forwarded access to the IPv4 Pod and Service CIDRs is blocked,
  including ordinary NodePort DNAT. Replies to Pod-initiated connections work.
- SSH and host ports outside the reserved management set are unaffected.

The installer owns only its named table and never flushes the host ruleset.
Updates are atomic nftables transactions: a rejected update leaves old rules
intact. Firewall startup or reload failure stops K3s and fails installation.
The systemd dependency loads protection before K3s on reboot. Ordinary reruns
reload rules without restarting a healthy K3s service.

For example, establish a management tunnel with:

```bash
ssh -N -L 127.0.0.1:6443:127.0.0.1:6443 user@node
```

Keep kubeconfig credentials private. The firewall does not create a tunnel or
open SSH in another host/cloud firewall. Application services remain ClusterIP
and can be reached with `kubectl port-forward` over the tunnel. This policy
assumes this installer's fixed single-node Flannel networking. Multi-node,
IPv6 Pod networks, public ingress, and arbitrary host-network workloads require
a separate policy. After an administrator flushes the global nftables ruleset,
reload `livepeer-firewall.service`; it does not continuously monitor rule changes.

## Interrupted installation and recovery

Run the same installer command to resume. Steps are revalidated rather than
skipped based on progress flags. `--status` reports the last started phase, the
recorded release, and K3s/firewall service states without enrollment or writes.

- A new root is published with its marker already present. Interruption before
  publication leaves an unused sibling `<root>.initial.*` containing only an
  initialization marker; it can be inspected and removed. Existing operator
  files are never adopted as an installation.
- Credentials are published atomically and valid committed files are not rewritten.
  Empty or missing committed credentials require an operator backup.
- Release checksum manifests are refreshed on each run. Payloads and installed
  binaries are verified and repaired atomically; invalid upstream metadata or a
  checksum mismatch stops installation before binary or version changes. Partial
  gVisor installs are replaced by complete generations including shim and helpers;
  old generations remain available to running processes.
- K3s's selected release is recorded before binary replacement and before every
  service launch, including launches after upgrade-controller jobs. Repair uses
  that release or a newer healthy installed release. If cluster data exists but
  the version record is missing, restore a known `state/k3s-version` or full
  backup before repair.
  K3s restarts when generated host configuration changes or a binary repair needs activation.

These mechanisms handle interrupted installation steps. They do not reconstruct
lost credentials, repair a corrupted cluster database, or validate arbitrary
operator edits. Back up `credentials/`, K3s state, and persistent volumes
separately from disposable downloads and runtime generations.

Before a host upgrade or filesystem rollback, quiesce workloads and take a
consistent filesystem backup or snapshot of the root and persistent volumes. For rollback, stop/quiesce the
cluster and restore matching binaries, database, credentials, configuration,
and recorded version together. Replacing just a K3s binary can leave an
incompatible database; database rollback is not automated.

To uninstall:

1. Suspend reconciliation, delete/drain this cluster's workloads, and wait for
   storage to detach. Disable and stop `livepeer-k3s.service`.
2. Its `KillMode=process` preserves container tasks during normal restarts. Verify
   and terminate any remaining processes in this installation's containerd
   instance and unmount its kubelet mounts before removing files.
3. Remove only its systemd registration links and run `systemctl daemon-reload`.
   Keep the firewall loaded until all cluster listeners are gone. Then disable
   and stop `livepeer-firewall.service`, remove its registration, and explicitly
   delete only `table inet livepeer_bootstrap`. Never flush the host firewall.
4. Retain the root by default. Erase `credentials/`, `k3s/`, and `volumes/`
   only after an operator decision about retained data and backups.

There is no automatic destructive uninstall command. Collector/connectivity
components and an externally validated CPU support matrix are outside this
bootstrap's scope.

## Inspection and upgrades

```bash
# These examples use the default root; substitute your --install-dir if needed.
sudo /opt/livepeer/bin/k3s kubectl --kubeconfig /opt/livepeer/config/kubeconfig.yaml get pods -A
sudo /opt/livepeer/bin/k3s kubectl --kubeconfig /opt/livepeer/config/kubeconfig.yaml \
  -n flux-system get externalartifacts,kustomizations
sudo /opt/livepeer/bin/k3s kubectl --kubeconfig /opt/livepeer/config/kubeconfig.yaml \
  -n livepeer port-forward service/orchestrator 8935:8935 8936:8936
```

With the port-forward running:

```bash
curl -fsS http://127.0.0.1:8936/readyz
curl -fsS http://127.0.0.1:8935/discovery
```

See the [app delivery and lifecycle contract](../docs/app-registry.md#runtime-delivery-and-completion-contract)
for readiness and drain behavior. Public session URLs remain Node URLs.

Back up `volumes/app-reconciler/` together with cluster state and credentials.
Recovery requires the latest committed state; an older checkpoint alone is unsafe.
If state is missing or corrupt, `state_recovery_failed` stops app actions. Restore
a consistent backup; management can still repair the Runtime image.

Node restart or heartbeat expiry can lose sessions.
During maintenance, Node stops accepting new work until the Node or K3s operation
completes.

No node has `livepeer.io/allow-upgrade=true` initially. To enable a planned
upgrade, set `spec.version` to the target K3s version in the backend-owned
`api/internal/controlplane/machineconfig/templates/upgrade-plan/plan.yaml` template (relative to
the combined repository root) and redeploy
the backend. After the reconciler publishes the bundle and Flux applies it,
explicitly add that label to the intended node with
`kubectl label node <node-name> livepeer.io/allow-upgrade=true`. This permits a
privileged upgrade job to cordon/drain and restart this single node, interrupting
service. Follow the [K3s upgrade guidance](https://docs.k3s.io/upgrades/automated)
and Kubernetes version skew policy; no automatic channel is configured. The
standard K3s upgrade image discovers the running binary's custom path, while
systemd retains the explicit configuration and data directory.

On failure, the script prints cluster diagnostics and preserves state. Check
`logs/bootstrap.log`, `logs/k3s.log`, the helper Pod logs, and the Flux source and
Kustomization conditions, then follow the [recovery steps](#interrupted-installation-and-recovery).

## Verification

On Linux, with the tools listed in the
[remote-test guide](../docs/development.md#remote-runtime-tests), run from `runtime/`:

```bash
bash tests/run.sh
```

From the repository root, run `go test -race ./runtime/...` for archive,
transport, SDK, probes and lifecycle checks. The full backend suite uses a
disposable PostgreSQL database via `TEST_DATABASE_URL`.

The runner checks Bash syntax, runs ShellCheck and Python tests, then runs the
firewall traffic test in Docker. Python tests use temporary directories and
localhost servers without root or a cluster. Optional offline Kustomize checks
use `kubectl` and PyYAML and report skips if unavailable. From the repository
root, `make test-runtime REMOTE=<ssh-host>` runs the same tests remotely; the
[guide](../docs/development.md#remote-runtime-tests) covers running tests, results,
and cleanup.

The firewall test uses a disposable privileged Docker container and private
network namespaces; it does not apply rules to the host. The installer also
runs a gVisor smoke test and saves results in `logs/gvisor-smoke.log`.

See the [end-to-end harness](../docs/development.md#end-to-end-tests) for host and fleet checks.
