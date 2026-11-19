#!/usr/bin/env bash
# Bash host bootstrap; services and Kubernetes resources live alongside this file.
set +ax
# Clear inherited export attributes before retaining the short-lived JWT locally.
unset ENROLLMENT_TOKEN
ENROLLMENT_TOKEN=${LIVEPEER_ENROLLMENT_TOKEN:-}
unset LIVEPEER_ENROLLMENT_TOKEN
set -Eeuo pipefail

K3S_VERSION='v1.37.2+k3s1'
FLUX_VERSION='v2.10.0'
GVISOR_VERSION='release-20261102.0'
INSTALL_DIR='/opt/livepeer'
CHECK_ONLY=0
STATUS_ONLY=0
CREDENTIAL_TRANSITION=''
UPGRADE_RUNTIME=0
UNIT='livepeer-k3s.service'
case "${BASH_SOURCE[0]}" in */*) SCRIPT_DIR=${BASH_SOURCE[0]%/*} ;; *) SCRIPT_DIR=. ;; esac
SCRIPT_DIR=$(cd -- "$SCRIPT_DIR" && pwd -P)
# shellcheck source=lib/preflight.sh
source "$SCRIPT_DIR/lib/preflight.sh"
# shellcheck source=lib/recovery.sh
source "$SCRIPT_DIR/lib/recovery.sh"
# shellcheck source=lib/components.sh
source "$SCRIPT_DIR/lib/components.sh"
# shellcheck source=lib/credentials.sh
source "$SCRIPT_DIR/lib/credentials.sh"

log() { printf '%s\n' "$*" >&2; }
die() { log "error: $*"; exit 1; }

usage() {
  cat <<'EOF'
Usage: bootstrap-livepeer.sh [--install-dir /opt/livepeer] [--check-only]

Enroll with the configured Livepeer API and install K3s, gVisor, Flux,
system-upgrade-controller, and the offchain Livepeer Node orchestrator.
Set LIVEPEER_ENROLLMENT_TOKEN to the combined enrollment token from the console.
LIVEPEER_API_URL defaults to https://controlcenter-api.livepeer.live.
The API must be reachable from this host and its pods.

  --install-dir PATH  Absolute installation root (default /opt/livepeer).
                      Use letters, digits, underscores, hyphens, dots, slashes.
  --check-only        Read-only eligibility checks; no authentication or install.
  --status            Show local installation progress without changing anything.
  --refresh-credentials  Refresh via a fresh enrollment token and HTTPS, preserving identity.
  --reenroll           Enroll a removed installation as a new lifetime; retain data.
  --upgrade-runtime    Switch to this release's Runtime image instead of the saved one.
  -h, --help          Show this help without requiring root.

Requires Debian/Ubuntu amd64, systemd, 2 CPUs, 4 GiB RAM,
10 GiB free disk, and outbound HTTPS access. See README.md for dependencies.
EOF
}

parse_args() {
  while (( $# )); do
    case "$1" in
      --install-dir)
        (( $# >= 2 )) || die '--install-dir requires a path'
        INSTALL_DIR="$2"; shift 2 ;;
      --check-only) CHECK_ONLY=1; shift ;;
      --status) STATUS_ONLY=1; shift ;;
      --refresh-credentials) CREDENTIAL_TRANSITION=refresh; shift ;;
      --reenroll) CREDENTIAL_TRANSITION=reenroll; shift ;;
      --upgrade-runtime) UPGRADE_RUNTIME=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  [[ "$INSTALL_DIR" =~ ^/[a-zA-Z0-9_./-]+$ && "$INSTALL_DIR" != / ]] ||
    die 'installation directory must be an absolute path without spaces or shell metacharacters'
  command -v realpath >/dev/null || die 'missing command: realpath (coreutils)'
  [[ "$INSTALL_DIR" == "$(realpath -m -- "$INSTALL_DIR")" ]] ||
    die 'installation directory cannot contain repeated or trailing slashes, . or .. directory names, or symlinks'
}

read_machine_id() {
  [[ -s /etc/machine-id ]] && cat /etc/machine-id
}

# Enrollment credentials are separate from the short-lived bootstrap JWT.
# Reruns reuse the saved machine credential and never require another JWT.
authenticate_node() {
  local credentials="$INSTALL_DIR/credentials" key request response api status machine_id
  NODE_ID=''; SERVICE_TOKEN=''; CONFIG_URL=''; IDENTITY_NODE_ID=''; INSTALLATION_FINGERPRINT=''; CREDENTIAL_VERSION=0
  if [[ -f "$INSTALL_DIR/state/enrolled" ]] || { managed_installation && [[ -f "$credentials/node-id" && -f "$credentials/service-token" && -f "$credentials/config-url" && -f "$credentials/identity.json" ]]; }; then
    ENROLLMENT_TOKEN=''
    for key in node-id service-token config-url fingerprint; do
      [[ -f "$credentials/$key" && -s "$credentials/$key" ]] || die "saved credential is missing or invalid: $key; restore it from backup"
    done
    if [[ -f "$INSTALL_DIR/state/enrolled" || -e "$credentials/runner-bootstrap.secret" ]]; then
      [[ -f "$credentials/runner-bootstrap.secret" && -s "$credentials/runner-bootstrap.secret" ]] || die 'runner bootstrap credential is missing or invalid; restore it from backup'
    fi
    NODE_ID=$(cat "$credentials/node-id")
    INSTALLATION_FINGERPRINT=$(cat "$credentials/fingerprint")
    SERVICE_TOKEN=$(cat "$credentials/service-token")
    CONFIG_URL=$(cat "$credentials/config-url")
    if [[ ! -s "$credentials/identity.json" ]] || ! read_identity "$(cat "$credentials/identity.json")"; then
      die 'invalid saved enrollment identity; restore it from backup'
    fi
  else
    [[ -n "$ENROLLMENT_TOKEN" ]] || die 'a new installation requires LIVEPEER_ENROLLMENT_TOKEN'
    [[ "$ENROLLMENT_TOKEN" =~ ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$ ]] || die 'invalid enrollment token format'
    api=$(api_url)
    [[ "$api" == https://* || ${LIVEPEER_ALLOW_DEVELOPMENT_HTTP:-0} == 1 ]] || die 'enrollment requires HTTPS; development HTTP must be explicit'
    machine_id=$(read_machine_id) || die '/etc/machine-id must be initialized'
    INSTALLATION_FINGERPRINT=$(printf '%s' "$machine_id" | sha256sum)
    INSTALLATION_FINGERPRINT=${INSTALLATION_FINGERPRINT:0:64}
    request=$(jq -nc --arg fingerprint "$INSTALLATION_FINGERPRINT" --arg hostname "$(hostname)" \
      --arg install_dir "$INSTALL_DIR" --arg k3s_version "$K3S_VERSION" --argjson development_http "${LIVEPEER_ALLOW_DEVELOPMENT_HTTP:-0}" \
      '{fingerprint:$fingerprint,hostname:$hostname,install_dir:$install_dir,k3s_version:$k3s_version,development_http:($development_http==1)}')
    request=$(jq -c --arg public "$SECRET_PUBLIC" --rawfile signature <(registration_key_proof <<< "$request") '.+{public_key:$public,signature:$signature}' <<< "$request")
    log 'Registering machine with the Livepeer API.'
    # Pass the bearer header through a descriptor, rather than curl's argv.
    response=$(curl -q --silent --show-error --connect-timeout 10 --max-time 30 \
      --proto '=http,https' --write-out '\n%{http_code}' --request POST --header 'Content-Type: application/json' \
      --config <(printf 'header = "Authorization: Bearer %s"\n' "$ENROLLMENT_TOKEN") \
      --data-binary @<(printf '%s' "$request") "$api/v1/nodes/register") || die 'registration request failed; check LIVEPEER_API_URL and API availability'
    ENROLLMENT_TOKEN=''
    status=${response##*$'\n'}
    case "$status" in
      200) ;;
      401) die 'registration unauthorized; refresh the enrollment token' ;;
      409) die 'machine already registered to another account or installation; use the original installation settings' ;;
      *) die 'registration failed: API did not return HTTP 200' ;;
    esac
    response=${response%$'\n'*}
    NODE_ID=$(printf '%s' "$response" | jq -er '.node_id | select(type == "string")') || die 'invalid enrollment response: node_id'
    SERVICE_TOKEN=$(printf '%s' "$response" | jq -er '.token | select(type == "string")') || die 'invalid enrollment response: token'
    CONFIG_URL=$(printf '%s' "$response" | jq -er '.config_url | select(type == "string")') || die 'invalid enrollment response: config_url'
    read_identity "$response" || die 'invalid enrollment identity metadata'
    if [[ ${LIVEPEER_ALLOW_DEVELOPMENT_HTTP:-0} != 1 ]]; then
      [[ "$CONFIG_URL" == "$api/v1/nodes/$NODE_ID/config" ]] || die 'enrollment returned invalid HTTPS configuration URL'
    fi
  fi
  [[ "$INSTALLATION_FINGERPRINT" =~ ^[a-f0-9]{64}$ ]] || die 'invalid installation fingerprint'
  [[ "$IDENTITY_NODE_ID" == "$NODE_ID" ]] || die 'saved identity does not match the node'
  [[ "$NODE_ID" =~ ^[a-z2-7]{26}$ && "$SERVICE_TOKEN" =~ ^[a-f0-9]{64}$ ]] || die 'invalid enrollment credentials'
  [[ "$CONFIG_URL" =~ ^https?://[a-zA-Z0-9/_.:-]+$ ]] || die 'invalid configuration URL'
  [[ "$CONFIG_URL" == https://* || ${LIVEPEER_ALLOW_DEVELOPMENT_HTTP:-0} == 1 ]] || die 'saved HTTP credential requires --refresh-credentials over HTTPS'
  if (shopt -s nocasematch; [[ "$CONFIG_URL" =~ ^https?://(localhost\.?|127\.[0-9.]+)(:[0-9]+)?(/|$) ]]); then
    die 'configuration URL uses loopback; Kubernetes pods need a reachable API address'
  fi
  ENROLLMENT_TOKEN=''
}

random_token() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

# No credentials are interpolated into YAML; kubectl creates Secrets from files.
render_template() {
  local temporary
  temporary=$(mktemp "${2}.render.XXXXXX")
  sed -e "s|@INSTALL_DIR@|$INSTALL_DIR|g" -e "s|@NODE_ID@|$NODE_ID|g" \
    -e "s|@RUNTIME_IMAGE@|$RUNTIME_IMAGE|g" \
    -e "s|@CONFIG_URL@|$CONFIG_URL|g" \
    -e "s|@CONTROL_TRANSPORT@|$(control_transport)|g" \
    -e "s|@MODPROBE@|$(command -v modprobe)|g" -e "s|@SYSCTL@|$(command -v sysctl)|g" \
    -e "s|@NFT@|$(command -v nft)|g" "$1" > "$temporary"
  atomic_write "$2" 0644 < "$temporary"
  rm -- "$temporary"
}

copy_templates() {
  local file
  install -d -m 0755 "$2"
  for file in "$1"/*; do
    if [[ -d "$file" ]]; then copy_templates "$file" "$2/${file##*/}"
    else render_template "$file" "$2/${file##*/}"; chmod 0644 "$2/${file##*/}"; fi
  done
}

prepare_installation() {
  initialize_installation
  umask 022
  install -d -m 0755 "$INSTALL_DIR" "$INSTALL_DIR/bin" "$INSTALL_DIR/config" \
    "$INSTALL_DIR/manifests" "$INSTALL_DIR/systemd" "$INSTALL_DIR/logs" \
    "$INSTALL_DIR/lib" \
    "$INSTALL_DIR/volumes" "$INSTALL_DIR/kubelet" "$INSTALL_DIR/k3s/agent/etc/containerd" \
    "$INSTALL_DIR/k3s/agent/etc/kubelet.conf.d"
  install -d -m 0755 "$INSTALL_DIR/volumes/installed-software"
  install -d -m 0700 "$INSTALL_DIR/credentials" "$INSTALL_DIR/state" "$INSTALL_DIR/download" \
    "$INSTALL_DIR/volumes/http-source" "$INSTALL_DIR/volumes/orchestrator" "$INSTALL_DIR/volumes/app-reconciler"
  chown 65532:65532 "$INSTALL_DIR/volumes/http-source" "$INSTALL_DIR/volumes/orchestrator" "$INSTALL_DIR/volumes/app-reconciler"
  install -d -m 0700 "$INSTALL_DIR/volumes/management-sockets" \
    "$INSTALL_DIR/volumes/management-sockets/connector" "$INSTALL_DIR/volumes/management-sockets/apps" "$INSTALL_DIR/volumes/management-sockets/orchestrator" \
    "$INSTALL_DIR/volumes/management-sockets/telemetry"
  chown 65532:65532 "$INSTALL_DIR/volumes/management-sockets" \
    "$INSTALL_DIR/volumes/management-sockets/connector" "$INSTALL_DIR/volumes/management-sockets/apps" "$INSTALL_DIR/volumes/management-sockets/orchestrator" \
    "$INSTALL_DIR/volumes/management-sockets/telemetry"
  # Telemetry agents buffer here while Control Center is unreachable. The log
  # reader runs as UID 0 without capabilities, so its buffer is root-owned.
  install -d -m 0700 "$INSTALL_DIR/volumes/telemetry" "$INSTALL_DIR/volumes/telemetry-logs"
  chown 65532:65532 "$INSTALL_DIR/volumes/telemetry"
  printf '%s\n' "$RUNTIME_IMAGE" | atomic_write "$INSTALL_DIR/state/runtime-image"
  chmod 0700 "$INSTALL_DIR/k3s" "$INSTALL_DIR/kubelet"
  write_once "$INSTALL_DIR/credentials/fingerprint" "$INSTALLATION_FINGERPRINT"
  write_once "$INSTALL_DIR/credentials/node-id" "$NODE_ID"
  write_once "$INSTALL_DIR/credentials/service-token" "$SERVICE_TOKEN"
  write_once "$INSTALL_DIR/credentials/config-url" "$CONFIG_URL"
  save_identity
  if [[ ! -f "$INSTALL_DIR/credentials/runner-bootstrap.secret" ]]; then
    random_token | atomic_write "$INSTALL_DIR/credentials/runner-bootstrap.secret"
  fi
  find "$INSTALL_DIR/credentials" -maxdepth 1 -type f -exec chmod 0600 {} +
  printf '1\n' | atomic_write "$INSTALL_DIR/state/enrolled"
}

stage_manifests() {
  copy_templates "$SCRIPT_DIR/manifests/bootstrap" "$INSTALL_DIR/manifests/bootstrap"
  copy_templates "$SCRIPT_DIR/manifests/flux" "$INSTALL_DIR/manifests/flux"

}

version_at_least() {
  [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$ ]] || return 1
  [[ "$(printf '%s\n' "$1" "$2" | LC_ALL=C sort -V | head -n 1)" == "$2" ]]
}

write_host_configuration() {
  local changed=1
  local containerd_config="$INSTALL_DIR/k3s/agent/etc/containerd/config-v3.toml.tmpl"
  if [[ -f "$containerd_config" ]] && ! grep -Fq "cni_conf_dir = \"$INSTALL_DIR/config/gvisor-cni\"" "$containerd_config"; then
    die 'The previous gVisor network layout cannot be resumed; recreate this installation first'
  fi
  install -d -m 0755 "$INSTALL_DIR/config/gvisor-cni"
  render_template "$SCRIPT_DIR/config/gvisor.conflist" "$INSTALL_DIR/config/gvisor-cni/10-gvisor.conflist"
  render_template "$SCRIPT_DIR/config/runsc.toml" "$INSTALL_DIR/config/runsc.toml"
  render_template "$SCRIPT_DIR/config/containerd.tmpl" "$containerd_config"
  install -d -m 0755 "$INSTALL_DIR/k3s/server/manifests"
  render_template "$SCRIPT_DIR/config/traefik.yaml" "$INSTALL_DIR/k3s/server/manifests/livepeer-traefik-config.yaml"
  render_template "$SCRIPT_DIR/config/k3s.yaml" "$INSTALL_DIR/config/k3s.yaml"
  render_template "$SCRIPT_DIR/config/kubelet.conf" "$INSTALL_DIR/k3s/agent/etc/kubelet.conf.d/10-livepeer.conf"
  render_template "$SCRIPT_DIR/config/livepeer-k3s.service" "$INSTALL_DIR/systemd/$UNIT"
  render_template "$SCRIPT_DIR/config/firewall.nft" "$INSTALL_DIR/config/firewall.nft"
  render_template "$SCRIPT_DIR/config/livepeer-firewall.service" "$INSTALL_DIR/systemd/livepeer-firewall.service"
  atomic_binary "$SCRIPT_DIR/lib/firewall.sh" "$INSTALL_DIR/bin/livepeer-firewall"
  atomic_binary "$SCRIPT_DIR/lib/record-version.sh" "$INSTALL_DIR/bin/livepeer-record-version"
  atomic_write "$INSTALL_DIR/lib/recovery.sh" 0644 < "$SCRIPT_DIR/lib/recovery.sh"
  sha256sum "$INSTALL_DIR/config/k3s.yaml" "$INSTALL_DIR/config/runsc.toml" \
    "$INSTALL_DIR/config/gvisor-cni/10-gvisor.conflist" \
    "$INSTALL_DIR/k3s/agent/etc/containerd/config-v3.toml.tmpl" \
    "$INSTALL_DIR/k3s/agent/etc/kubelet.conf.d/10-livepeer.conf" \
    "$INSTALL_DIR/systemd/$UNIT" > "$INSTALL_DIR/state/host-config.new"
  if cmp -s "$INSTALL_DIR/state/host-config.new" "$INSTALL_DIR/state/host-config.sha256"; then changed=0; fi
  atomic_symlink "$INSTALL_DIR/systemd/$UNIT" "/etc/systemd/system/$UNIT"
  atomic_symlink "$INSTALL_DIR/systemd/livepeer-firewall.service" /etc/systemd/system/livepeer-firewall.service
  systemctl daemon-reload
  systemctl enable livepeer-firewall.service
  if ! systemctl start livepeer-firewall.service || ! systemctl reload livepeer-firewall.service; then
    systemctl stop "$UNIT" || true
    die 'firewall enforcement failed; K3s has been stopped'
  fi
  systemctl enable "$UNIT"
  if systemctl is-active --quiet "$UNIT" && { (( changed )) || [[ -f "$INSTALL_DIR/state/k3s-restart-required" ]]; }; then
    systemctl restart "$UNIT"
  else
    systemctl start "$UNIT"
  fi
  "$INSTALL_DIR/bin/livepeer-record-version" "$INSTALL_DIR/bin/k3s" "$INSTALL_DIR/state/k3s-version" "$INSTALL_DIR/lib/recovery.sh" "$INSTALL_DIR"
  mv "$INSTALL_DIR/state/host-config.new" "$INSTALL_DIR/state/host-config.sha256"
  rm -f -- "$INSTALL_DIR/state/k3s-restart-required"
}

# Host features name host-owned prerequisites that Control Center gates
# workloads on: telemetry needs its management socket and http-source RBAC.
# Record them only after the bootstrap that applied them has succeeded.
HOST_FEATURES='{"telemetry":1}'
record_host_features() {
  jq -nc --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson features "$HOST_FEATURES" \
    '{recorded_at:$at,features:$features}' |
    atomic_write "$INSTALL_DIR/volumes/installed-software/host-features.json" 0644
}

kube() { "$INSTALL_DIR/bin/k3s" kubectl --kubeconfig "$INSTALL_DIR/config/kubeconfig.yaml" --request-timeout=30s "$@"; }

bootstrap_cluster() {
  local _attempt ready=0
  for _attempt in {1..120}; do
    if kube get --raw=/readyz >/dev/null 2>&1 && [[ -n $(kube get nodes -o name) ]]; then ready=1; break; fi
    sleep 5
  done
  (( ready )) || die "K3s API did not become ready; inspect $INSTALL_DIR/logs/k3s.log"
  kube wait node --all --for=condition=Ready --timeout=300s
  kube apply -f "$SCRIPT_DIR/manifests/runtimeclass.yaml"
  "$INSTALL_DIR/bin/flux" install --version "$FLUX_VERSION" \
    --components source-controller,kustomize-controller --export > "$INSTALL_DIR/manifests/flux/flux.yaml"
  kube apply --server-side --field-manager=livepeer-bootstrap -k "$INSTALL_DIR/manifests/flux"
  kube wait --for=condition=Established crd/externalartifacts.source.toolkit.fluxcd.io --timeout=120s
  kube -n flux-system rollout status deployment/source-controller --timeout=300s
  kube -n flux-system rollout status deployment/kustomize-controller --timeout=300s
  kube apply -f "$INSTALL_DIR/manifests/bootstrap/namespaces.yaml"
  install_machine_secret
  kube -n livepeer create secret generic runner-bootstrap \
    --from-file="secret=$INSTALL_DIR/credentials/runner-bootstrap.secret" --dry-run=client -o yaml | kube apply -f -
  kube apply -k "$INSTALL_DIR/manifests/bootstrap"
  kube -n flux-system rollout status deployment/livepeer-http-source --timeout=300s
  kube -n flux-system wait externalartifact/livepeer-service --for=condition=Ready --timeout=300s
  kube -n flux-system wait kustomization/livepeer --for=condition=Ready --timeout=600s
  # Child reconciliation can recreate these after the parent is Ready.
  kube -n system-upgrade wait --for=create deployment/system-upgrade-controller --timeout=300s
  kube -n system-upgrade rollout status deployment/system-upgrade-controller --timeout=300s
  kube -n flux-system wait kustomization/livepeer-upgrade-plan --for=condition=Ready --timeout=300s
}

smoke_test() {
  # Secrets identity recovery must restore the signer before onchain readiness.
  kube -n livepeer wait --for=create deployment/orchestrator --timeout=300s
  kube -n livepeer rollout status deployment/orchestrator --timeout=300s
  kube -n livepeer delete pod/livepeer-gvisor-smoke --ignore-not-found --wait=true >/dev/null
  kube -n livepeer apply -f "$SCRIPT_DIR/manifests/gvisor-smoke.yaml"
  kube -n livepeer wait pod/livepeer-gvisor-smoke --for=jsonpath='{.status.phase}'=Succeeded --timeout=180s
  kube -n livepeer logs livepeer-gvisor-smoke > "$INSTALL_DIR/logs/gvisor-smoke.log"
  kube -n livepeer delete pod/livepeer-gvisor-smoke --wait=false >/dev/null
}

diagnostics() {
  log "Bootstrap failed. State is preserved under $INSTALL_DIR."
  if [[ -f "$INSTALL_DIR/config/kubeconfig.yaml" && -x "$INSTALL_DIR/bin/k3s" ]]; then
    kube get pods -A -o wide >&2 || true
    kube -n flux-system get externalartifact,kustomization >&2 || true
    kube get events -A --field-selector type=Warning --sort-by=.lastTimestamp >&2 || true
  fi
  log "K3s log: $INSTALL_DIR/logs/k3s.log"
}

lock_installation() {
  exec 9>/run/lock/livepeer-bootstrap.lock
  flock -n 9 || die 'another Livepeer bootstrap is running'
}

run_phase() {
  local phase="$1"; shift
  printf '%s\n' "$phase" | atomic_write "$INSTALL_DIR/state/phase"
  "$@"
}

show_status() {
  (( EUID == 0 )) || die 'run with sudo or as root to read local installation state'
  managed_installation || { log 'No initialized installation at this path.'; return 1; }
  printf 'Installation: %s\n' "$INSTALL_DIR"
  if [[ -f "$INSTALL_DIR/state/phase" ]]; then printf 'Last started phase: %s\n' "$(cat "$INSTALL_DIR/state/phase")"; fi
  if [[ -f "$INSTALL_DIR/state/k3s-version" ]]; then printf 'Verified K3s release: %s\n' "$(cat "$INSTALL_DIR/state/k3s-version")"; fi
  printf 'K3s service: '; systemctl is-active "$UNIT" || true
  printf 'Firewall service: '; systemctl is-active livepeer-firewall.service || true
}

main() {
  parse_args "$@"
  export K3S_DATA_DIR="$INSTALL_DIR/k3s"
  if (( STATUS_ONLY )); then show_status; return; fi
  preflight
  (( CHECK_ONLY == 0 )) || return 0
  runtime_image
  # Serialize enrollment reads as well as writes to prevent concurrent token changes.
  lock_installation
  check_existing_installation
  if [[ -n "$CREDENTIAL_TRANSITION" ]]; then
    managed_installation || die 'credential transition requires an initialized installation'
    [[ -s "$INSTALL_DIR/credentials/runner-bootstrap.secret" && -s "$INSTALL_DIR/credentials/identity.json" ]] || die 'restore the saved enrollment credentials before changing credentials'
    read_identity "$(cat "$INSTALL_DIR/credentials/identity.json")" || die 'invalid saved enrollment identity'
    [[ -n "$ENROLLMENT_TOKEN" ]] || die 'credential transition requires a fresh enrollment command'
    [[ $(api_url) == https://* ]] || die 'credential transition requires the verified HTTPS API'
    prepare_secrets_enrollment; transition_credentials; enroll_secrets; return
  fi
  [[ ! -f "$INSTALL_DIR/state/credential-transition.json" ]] || die 'resume the interrupted credential transition before normal installation'
  [[ -f "$INSTALL_DIR/credentials/node-id" || -n "$ENROLLMENT_TOKEN" ]] || die 'a new installation requires an enrollment command'
  local verified_api
  verified_api=$(api_url)
  [[ "$verified_api" == https://* || ${LIVEPEER_ALLOW_DEVELOPMENT_HTTP:-0} == 1 ]] || die 'enrollment requires HTTPS'
  prepare_secrets_enrollment
  authenticate_node
  trap diagnostics ERR
  prepare_installation
  exec > >(tee -a "$INSTALL_DIR/logs/bootstrap.log") 2>&1
  run_phase components install_components
  run_phase manifests stage_manifests
  run_phase host write_host_configuration
  run_phase cluster bootstrap_cluster
  run_phase secrets enroll_secrets
  run_phase smoke smoke_test
  run_phase features record_host_features
  run_phase complete true
  log "Ready. Kubeconfig: $INSTALL_DIR/config/kubeconfig.yaml"
  log "Configuration is managed by the Livepeer API; Flux polls every minute."
  log "Runner bootstrap credential: $INSTALL_DIR/credentials/runner-bootstrap.secret"
  log 'K3s upgrades require explicit opt-in with the livepeer.io/allow-upgrade=true node label.'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
