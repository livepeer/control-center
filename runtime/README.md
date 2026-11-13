# Livepeer host bootstrap

The installer prepares a single-node Debian or Ubuntu amd64 systemd host with
K3s, gVisor, Flux, Runtime and a Livepeer Node orchestrator in offchain mode.
Control Center assigns apps to isolated Pods; Node handles sessions, capacity
and proxying. Managed Cloudflare ingress provides external access.

## Prerequisites

Use Debian 12+ or Ubuntu 22.04+ with at least 2 CPUs, 4 GiB RAM, 10 GiB free,
Linux 5.4+, enabled cgroups and namespaces, and no active swap. The output of
`hostname` must be at most 63 bytes. The host and Pods need HTTPS access to the
Control Center API, GitHub releases and configured image registries.

Install the host packages first:

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates openssl curl jq tar bzip2 gzip coreutils \
  gawk iproute2 kmod procps util-linux systemd nftables diffutils findutils
```

The installer checks kernel modules, ports and routes, including the fixed
`10.42.0.0/16` Pod, `10.43.0.0/16` Service and `10.44.0.0/16` gVisor
networks. It requires nftables support and `CAP_NET_ADMIN`, and stops on a
conflicting Kubernetes installation. Existing host firewall policies still apply.

## Enrollment and desired configuration

Sign in to Control Center and copy the enrollment command. Run it as root after
preparing the host. The POSIX loader downloads and verifies a versioned bundle
before invoking the Bash installer:

```sh
set +x
curl -fsSL https://controlcenter.livepeer.live/bootstrap.sh | LIVEPEER_ENROLLMENT_TOKEN='<TOKEN>' sh -
```

For a non-root shell, pass the token on the sudo side of the pipe:

```sh
set +x
curl -fsSL https://controlcenter.livepeer.live/bootstrap.sh |
  LIVEPEER_ENROLLMENT_TOKEN='<TOKEN>' sudo --preserve-env=LIVEPEER_ENROLLMENT_TOKEN sh -s --
```

The one-hour enrollment command can enroll multiple machines. The installer saves
service credentials in owner-only files and uses them for reruns. See [operator
secrets](../docs/operator-secrets.md#enrollment-and-identity) for managed identity
setup and recovery. Runtime polls Control Center every minute and delivers the
last valid configuration to Flux.

The default installation root is `/opt/livepeer`. To choose another root on
first enrollment, add `--install-dir /srv/livepeer` after `sh -s --`. Use the
same root on reruns. It must be a new or empty absolute path containing letters,
digits, `_`, `.`, `-` and `/`, with no symlinks, spaces, repeated or trailing
slashes, or `.` and `..` path components.

`--check-only` runs read-only eligibility checks. `--status` reports the last
started phase, recorded release and service states. Neither requires a token:

```sh
# Run as root, or place sudo before sh.
curl -fsSL https://controlcenter.livepeer.live/bootstrap.sh | sh -s -- --check-only
curl -fsSL https://controlcenter.livepeer.live/bootstrap.sh | sh -s -- --status
```

### API and image overrides

The default API is `https://controlcenter-api.livepeer.live` and the bundle
provides a digest-pinned Runtime image. Set these variables for a custom API or
image before enrollment:

```sh
export LIVEPEER_API_URL='https://your-control-center-api.example'
export LIVEPEER_RUNTIME_IMAGE='your-registry/livepeer-runtime@sha256:<published-digest>'
```

The API URL must match the backend `PublicAPIURL` and be reachable from the
host and Pods. With sudo, add exported override names to `--preserve-env`, for
example `--preserve-env=LIVEPEER_ENROLLMENT_TOKEN,LIVEPEER_API_URL,LIVEPEER_RUNTIME_IMAGE`.
Image selection uses the explicit override, then the saved image, then the
bundle default. Reruns retain the saved selection; an invalid explicit or saved
image causes installation to fail.

The backend separately selects its system-services image with `RuntimeImage`
(or `RUNTIME_IMAGE` in its environment). The connector Docker build argument
`RUNTIME_IMAGE` selects a build input. See the
[deployment guide](../deploy/README.md) for image publication and bundle releases.

### Checked download for automation

A shell pipeline reports the last command's status, so automation should check
the initial loader download separately. The loader then checks its bundle and
returns the installer status:

```sh
(
  set +x
  set -eu
  umask 077
  loader_dir=$(mktemp -d)
  trap 'rm -rf -- "$loader_dir"' 0
  curl -fsSL https://controlcenter.livepeer.live/bootstrap.sh -o "$loader_dir/bootstrap.sh"
  LIVEPEER_ENROLLMENT_TOKEN='<TOKEN>' sh "$loader_dir/bootstrap.sh"
)
```

## System workload delivery

Runtime delivers management and app workloads separately, allowing management
updates during app reconciliation failures. Node reports its applied revision
and workload status. See the [app lifecycle contract](../docs/app-registry.md#runtime-delivery-and-completion-contract)
and [machine status guide](../docs/machine-status.md).

Production apps require compatible Node and SDK releases. Configure backend
`RUNTIME_NODE_IMAGE` with a compatible digest-pinned image. Explicit container
stop signals also require Kubernetes `ContainerStopSignals` on the API server
and kubelet and backend `APP_STOP_SIGNALS=true`.

## Protected machine ingress

The Runtime connector obtains a Cloudflare Tunnel token and starts cloudflared.
See the [machine tunnel runbook](../docs/machine-tunnels.md) for backend setup,
connector image publication, credentials and recovery.

To refresh credentials, use a fresh owner enrollment command with the original
HTTPS API origin and installation root. For a custom deployment, export the
original `LIVEPEER_API_URL` first:

```sh
set +x
curl -fsSL https://controlcenter.livepeer.live/bootstrap.sh |
  LIVEPEER_ENROLLMENT_TOKEN='<FRESH_TOKEN>' sh -s -- --refresh-credentials --install-dir /opt/livepeer
```

If interrupted, repeat with a fresh token. Refresh retains the enrollment, tunnel
UUID, local runner credential and installed K3s version. Management refresh immediately fences management access; the loaded submission grant remains valid until its replacement is observed.

After the backend removes an enrollment and confirms app cleanup, use
`--reenroll` with a fresh owner token, the original API override for custom
deployments, and the same root to create a new enrollment while retaining local
data:

```sh
set +x
curl -fsSL https://controlcenter.livepeer.live/bootstrap.sh |
  LIVEPEER_ENROLLMENT_TOKEN='<FRESH_TOKEN>' sh -s -- --reenroll --install-dir /opt/livepeer
```

Forced enrollment removal stops Node and preserves its database. Routes and
connector access remain available while app cleanup is pending, unless
credentials are compromised. Public Trickle is unsupported.

## Host operation and recovery

The installation root contains `credentials/`, `state/`, K3s data in `k3s/`,
persistent data in `volumes/`, configuration, binaries and logs. Host integration
also uses systemd units, runtime sockets, network interfaces and firewall rules.
Arrange rotation for `logs/bootstrap.log` and `logs/k3s.log`.

`livepeer-firewall.service` protects K3s management ports and Pod and Service
networks. Reload it after host network changes or a global nftables ruleset
flush. Keep kubeconfig credentials private. To reach the Kubernetes API through
SSH, establish a tunnel and use the installation kubeconfig:

```sh
ssh -N -L 127.0.0.1:6443:127.0.0.1:6443 user@node
```

To resume an interrupted installation, rerun with the same installation root
and API override. Saved credentials are reused; provide a fresh enrollment token
if registration has not completed. Inspect `--status`, `logs/bootstrap.log`, `logs/k3s.log`,
helper Pod logs and Flux conditions when diagnosing failures.

Back up `credentials/`, K3s state and persistent volumes, including
`volumes/app-reconciler/`. Before a host upgrade or rollback, quiesce workloads
and take a consistent snapshot. Restore matching binaries, database,
credentials, configuration and recorded version together. If cluster data
exists but `state/k3s-version` is missing, restore that record or a full backup
before repair. Missing or corrupt App Reconciler state requires a consistent
backup; `state_recovery_failed` stops app actions until recovery.
A stopped managed cluster can retain its Flannel UDP socket. Repair recognizes
it only when the saved release and generated host configuration still verify.

To uninstall, suspend reconciliation, drain workloads and detach storage; disable
and stop K3s, terminate this installation's remaining processes and unmount its
kubelet mounts. Remove its systemd links and reload systemd. Keep the firewall
until cluster listeners are gone, then disable and stop it and remove only
`table inet livepeer_bootstrap`.
Retain the installation root until deciding how to handle data and backups.

## Inspection and upgrades

These commands use the default root; substitute your `--install-dir`:

```sh
sudo /opt/livepeer/bin/k3s kubectl --kubeconfig /opt/livepeer/config/kubeconfig.yaml get pods -A
sudo /opt/livepeer/bin/k3s kubectl --kubeconfig /opt/livepeer/config/kubeconfig.yaml \
  -n flux-system get externalartifacts,kustomizations
sudo /opt/livepeer/bin/k3s kubectl --kubeconfig /opt/livepeer/config/kubeconfig.yaml \
  -n livepeer port-forward service/orchestrator 8935:8935 8936:8936
```

With the port-forward running, inspect `http://127.0.0.1:8936/readyz` and
`http://127.0.0.1:8935/discovery`.

For a planned K3s upgrade, set the target `spec.version` in the backend-owned
`api/internal/controlplane/machineconfig/templates/upgrade-plan/plan.yaml` and
redeploy the backend. After Flux applies the bundle, opt the node in with
`kubectl label node <node-name> livepeer.io/allow-upgrade=true`. The upgrade
cordons, drains and restarts this single node, interrupting service. Follow the
[K3s upgrade guidance](https://docs.k3s.io/upgrades/automated) and Kubernetes
version skew policy.

## Verification

On Linux, run `bash tests/run.sh` from `runtime/` and `go test -race ./runtime/...`
from the repository root. See the [remote-test guide](../docs/development.md#remote-runtime-tests)
for dependencies, remote execution and cleanup. The installer records its
gVisor smoke test in `logs/gvisor-smoke.log`.

See the [end-to-end harness](../docs/development.md#end-to-end-tests) for host and fleet checks.
