# Livepeer host bootstrap

`bootstrap-livepeer.sh` is a Bash installer for a **single-node,
Debian/Ubuntu amd64, systemd** host. It installs K3s, gVisor, Flux, an API-backed
HTTP configuration adapter, system-upgrade-controller, and the standalone
[`livepeer/node`](https://github.com/livepeer/node) orchestrator in offchain mode.
It does not deploy runners or configure GPUs or public ingress.

Runtime lives under `runtime/` in the combined Control Center repository.
Run the commands below from that directory. The combined repository is the
development source of truth; an older standalone checkout may be retained as
a reference, but is not automatically synchronized.

Copy or clone the whole project onto the target machine. Host installation uses
Bash and standard Linux utilities; Python runs only in the pinned HTTP service
containers. Repository templates and installed paths are described under
[Storage and host integration](#storage-and-host-integration).

```bash
# On the machine that will receive the cluster:
sudo bash bootstrap-livepeer.sh --check-only
sudo bash bootstrap-livepeer.sh --status
export LIVEPEER_API_URL=https://your-control-center-api.example
sudo --preserve-env=LIVEPEER_API_URL bash bootstrap-livepeer.sh --token <TOKEN>

# Or contain the installation under another absolute directory:
sudo --preserve-env=LIVEPEER_API_URL bash bootstrap-livepeer.sh --token <TOKEN> --install-dir /srv/livepeer
```

The default root is `/opt/livepeer`. Use the same `--install-dir` for subsequent
runs. Paths must be canonical, contain no symlinks or spaces, and use only the
characters described by `--help`. The installer refuses existing Kubernetes
installations and unmarked directories containing data. An interrupted older
installer's known empty directory layout can be claimed safely on a rerun.

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
modules, reserved TCP management ports 2379/2380/6443/6444/10010/10249/10250/10256/10257/10259,
UDP 8472, and routes overlapping
the fixed `10.42.0.0/16` Pod and `10.43.0.0/16` Service networks. Once K3s has been
downloaded, its own `check-config` performs additional kernel validation.
The installer requires nftables kernel support and `CAP_NET_ADMIN`, and reserves
its own `inet livepeer_bootstrap` table. It refuses to take over an existing
unowned table with that name. Existing host firewalls still apply; its allow
rules do not override a more restrictive policy in another firewall table.

The host and cluster need HTTPS access to GitHub releases and the configured
container registries. Downloads use fixed releases with checksum verification:

| Component | Pinned version |
| --- | --- |
| K3s | `v1.37.2+k3s1` |
| gVisor | `release-20261102.0` |
| Flux | `v2.10.0` |
| system-upgrade-controller | `v0.21.0` |
| Livepeer Node | `v1.0.6` |

The Python service, smoke-test BusyBox, and Livepeer images are pinned by digest.
The upgrade job's kubectl helper uses `rancher/kubectl:v1.36.2`, within one minor
of the initial Kubernetes version. Update that helper together with future
Kubernetes minor upgrades. Published checksums provide download integrity;
the installer trusts the upstream HTTPS release endpoints.

## Enrollment and desired configuration

Get the enrollment command from the authenticated Livepeer Control Center
console. Set `LIVEPEER_API_URL` to the API base URL, reachable from the host and
its Kubernetes pods, and run the command as root. When using sudo, preserve the
environment variable as shown in Quick start. Backend `PUBLIC_API_URL` must use
the same reachable base URL. The installer rejects literal loopback configuration
URLs because pods cannot use host loopback.

The one-hour bootstrap JWT can enroll multiple machines. The installer sends a
hash of `/etc/machine-id`, hostname, installation directory, and K3s version to
`POST /v1/nodes/register`. The API returns HTTP 200 with `node_id`, a 64-hex
long-lived service `token`, and `config_url` only after registration and initial
configuration are stored. The installer rejects redirects and invalid responses.
It saves credentials in owner-only files and reuses them on reruns; the service
credential remains valid after the bootstrap JWT expires. Fresh registration
retries require the original owner, install path, and initial K3s version; a
conflict returns HTTP 409 even with a new JWT. Normal recovery keeps the install
root and preserves an already upgraded K3s version. The separately generated
runner-bootstrap credential stays local.

Livepeer Control Center stores a bundle per machine and reconciles it every
minute by default. It updates changed digests only and retains the last valid
bundle if generation fails. Machine owners do not upload or edit configuration.
The service credential authorizes the existing HTTP adapter to fetch the bundle,
validate and cache artifacts, and publish them to Flux. There is no in-cluster
mock API or local editable desired directory.

The adapter polls every minute and preserves the last artifact on fetch failure.
It accepts relative, unique regular files with a root Kustomize configuration;
it rejects links, traversal, oversized archives, and redirects. Limits are
16 MiB compressed, 64 MiB expanded, and 2,048 files. Bootstrap resources and
runner credentials remain installer-managed. K3s upgrades require explicit
opt-in using the node label, and persistent volumes retain their data.

## Storage and host integration

`bootstrap-livepeer.sh` uses the repository's `lib/` Bash helpers and renders
`config/` and `manifests/` templates for the selected installation root:

| Directory | Contents |
| --- | --- |
| `bin/`, `download/`, `runtimes/` | Verified binaries, versioned release caches, complete gVisor generations |
| `lib/` | Bash recovery helpers used before each K3s launch |
| `services/` | Separate container-side HTTP service programs and ConfigMap packaging |
| `credentials/`, `state/` | Enrollment, runner secret, installation marker |
| `config/`, `systemd/` | K3s configuration, kubeconfig, runsc settings, service unit |
| `k3s/`, `kubelet/` | Explicit K3s data directory and kubelet root |
| `manifests/` | Bootstrap manifests |
| `volumes/` | Orchestrator data, source artifacts, local-path provisioner storage |
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
gVisor is available through `runtimeClassName: gvisor` for future workloads;
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
  Empty or missing committed credentials require an operator backup. Legacy JSON
  installation markers remain supported.
- Release checksum manifests are refreshed on each run. Payloads and installed
  binaries are verified and repaired atomically; invalid upstream metadata or a
  checksum mismatch stops installation before binary or version changes. Partial
  gVisor installs are replaced by complete generations including shim and helpers;
  old generations remain available to running processes.
- K3s's selected release is recorded before binary replacement and before every
  service launch, including launches after upgrade-controller jobs. Repair uses
  that release or a newer healthy installed release; older installations require
  an explicit upgrade. A damaged legacy install with cluster data but no version
  record needs a known `state/k3s-version` or full backup restored before repair.
  K3s restarts when generated host configuration changes or a binary repair needs activation.

These mechanisms handle interrupted installation steps. They do not reconstruct
lost credentials, repair a corrupted cluster database, or validate arbitrary
operator edits. Back up `credentials/`, K3s state, and persistent volumes
separately from disposable downloads and runtime generations.

Before an upgrade, quiesce workloads and take a consistent filesystem backup
or snapshot of the root and persistent volumes. For rollback, stop/quiesce the
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
bootstrap's scope; see [issue #86](https://github.com/livepeer/naap-ops/issues/86).

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

An empty runner inventory is expected. Runner registration can later use
`credentials/runner-bootstrap.secret`. The initial destination grants are empty;
before adding runners on private networks, configure the appropriate
[`RunnerGrants` and `HealthGrants`](https://github.com/livepeer/node/blob/v1.0.6/docs/orchestrator.md).

No node has `livepeer.io/allow-upgrade=true` initially. To enable a planned
upgrade, set `spec.version` to the target K3s version in the backend-owned
`api/internal/controlplane/templates/upgrade-plan/plan.yaml` template (relative to
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

On Linux, with the tools listed in the [remote-test guide](../README.md#remote-runtime-tests),
run from `runtime/`:

```bash
bash tests/run.sh
```

The runner checks Bash syntax, runs ShellCheck and Python tests, then runs the
firewall traffic test in Docker. Python tests use temporary directories and
localhost servers without root or a cluster. Optional offline Kustomize checks
use `kubectl` and PyYAML and report skips if unavailable. From the repository
root, `make test-runtime REMOTE=livepeer-t4` runs the same tests remotely; the
[guide](../README.md#remote-runtime-tests) covers source selection, results,
and cleanup.

The firewall test mounts Runtime source read-only in a disposable
`golang:1.27.2-bookworm` container, installs nftables, iproute2, curl, and Python
inside it, and uses NET_ADMIN/SYS_ADMIN, AppArmor unconfined, and IPv4
forwarding in private Docker namespaces. It checks simulated kube-proxy DNAT,
blocked external management and cluster access, SSH, Pod egress, and safe
reloads. Runtime firewall rules are never applied to the host.

The installer itself waits for node, controller, source, and workload readiness,
then runs a gVisor Pod checking its kernel banner, cluster DNS, and the
orchestrator readiness and discovery endpoints. Results are saved in
`logs/gvisor-smoke.log`.

For acceptance on a disposable supported VM, run the installer and verify the
backend bundle is delivered and workloads become ready. Rerun the installer and
confirm credentials and persistent data survive. Reboot and repeat readiness
checks. Repeat with `/srv/livepeer` on a fresh VM and inspect process arguments
and storage paths. Reboot and full K3s/gVisor integration require an actual
supported host; the unit/HTTP tests do not substitute for those checks.
