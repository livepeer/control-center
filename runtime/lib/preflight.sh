#!/usr/bin/env bash
# Read-only host checks. Sourced by bootstrap-livepeer.sh.

owned_pid() { [[ -r "/proc/$1/cgroup" ]] && grep -q '/livepeer-k3s.service' "/proc/$1/cgroup"; }

managed_installation() {
  [[ -f "$INSTALL_DIR/state/install-dir" && "$(cat "$INSTALL_DIR/state/install-dir")" == "$INSTALL_DIR" ]]
}

check_resources() {
  local parent="$INSTALL_DIR" memory free
  (( $(nproc --all) >= 2 )) || die 'at least 2 CPUs are required'
  memory=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
  (( memory >= 3800000 )) || die 'at least 4 GiB physical RAM is required'
  while [[ ! -e "$parent" ]]; do parent=${parent%/*}; [[ -n "$parent" ]] || parent=/; done
  free=$(df -Pk "$parent" | awk 'NR == 2 {print $4}')
  (( free >= 10485760 )) || die 'at least 10 GiB free disk is required'
}

check_kernel() {
  local major minor _patch controller module namespace config feature
  IFS=. read -r major minor _patch <<< "$(uname -r)"
  (( major > 5 || (major == 5 && minor >= 4) )) || die 'Linux kernel 5.4 or newer is required'
  for namespace in mnt uts ipc pid net user; do
    [[ -e "/proc/self/ns/$namespace" ]] || die "missing Linux $namespace namespace"
  done
  for controller in cpu cpuset memory pids; do
    if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
      grep -qw "$controller" /sys/fs/cgroup/cgroup.controllers || die "cgroup v2 $controller is required"
    else
      awk -v name="$controller" '$1 == name && $4 == 1 {ok=1} END {exit !ok}' /proc/cgroups ||
        die "cgroup v1 $controller must be enabled"
      grep -Eq " cgroup .*[, ]$controller([, ]|$)" /proc/mounts || die "cgroup v1 $controller must be mounted"
    fi
  done
  config="/boot/config-$(uname -r)"
  if [[ -r "$config" || -r /proc/config.gz ]]; then
    for feature in NAMESPACES CGROUPS MEMCG SECCOMP SECCOMP_FILTER NETFILTER; do
      if [[ -r "$config" ]]; then
        grep -Eq "^CONFIG_$feature=[ym]$" "$config" || die "kernel CONFIG_$feature is required"
      else
        # Consume the full stream to avoid a gzip SIGPIPE with pipefail enabled.
        gzip -dc /proc/config.gz | grep -E "^CONFIG_$feature=[ym]$" >/dev/null || die "kernel CONFIG_$feature is required"
      fi
    done
  else
    log 'warning: kernel configuration unavailable; K3s will perform additional checks after download'
  fi
  for module in overlay br_netfilter veth vxlan; do
    modprobe --dry-run "$module" >/dev/null 2>&1 || [[ -d "/sys/module/$module" ]] ||
      die "kernel module $module is unavailable"
  done
  (( $(wc -l < /proc/swaps) <= 1 )) || die 'swap is active; disable it before installing'
}

# K3s creates this compatibility link even with a custom kubeconfig path.
managed_kubeconfig_directory() {
  [[ -d "$1" && ! -L "$1" && "$(ls -A "$1")" == k3s.yaml &&
    -L "$1/k3s.yaml" && "$(readlink -f "$1/k3s.yaml")" == "$INSTALL_DIR/config/kubeconfig.yaml" ]]
}

# Multicall tools can leave only their extracted binaries at the default path.
managed_k3s_cache_directory() {
  [[ -d "$1" && ! -L "$1" && "$(ls -A "$1")" == data && -d "$1/data" && ! -L "$1/data" ]]
}

check_existing_installation() {
  local path service state proc comm
  MANAGED=0
  if managed_installation; then
    MANAGED=1
  elif [[ -e "$INSTALL_DIR/state/install-dir" ]]; then
    die 'incompatible installation marker'
  elif [[ -d "$INSTALL_DIR" && -n "$(ls -A "$INSTALL_DIR")" ]]; then
    die 'installation directory is nonempty and has no installation marker'
  fi
  for service in "$UNIT" livepeer-firewall.service; do
    path="/etc/systemd/system/$service"
    if [[ -e "$path" || -L "$path" ]]; then
      if (( ! MANAGED )) || [[ ! -L "$path" || "$(readlink -f "$path")" != "$INSTALL_DIR/systemd/$service" ]]; then
        die "$service belongs to another installation directory"
      fi
    fi
  done
  for path in /etc/rancher/k3s /var/lib/rancher/k3s /etc/kubernetes/manifests; do
    if (( MANAGED )) && [[ "$path" == /etc/rancher/k3s ]] && managed_kubeconfig_directory "$path"; then continue; fi
    if (( MANAGED )) && [[ "$path" == /var/lib/rancher/k3s ]] && managed_k3s_cache_directory "$path"; then continue; fi
    [[ ! -e "$path" ]] || die "conflicting Kubernetes state at $path; use a clean host"
  done
  for service in k3s k3s-agent kubelet rke2-server rke2-agent; do
    state=$(systemctl show "$service.service" --property=LoadState --value)
    [[ "$state" != loaded && "$state" != masked ]] || die "conflicting service: $service"
  done
  for proc in /proc/[0-9]*; do
    [[ -r "$proc/comm" ]] || continue
    read -r comm < "$proc/comm" || continue
    case "$comm" in
      k3s|kubelet|rke2)
        if (( ! MANAGED )) || ! owned_pid "${proc##*/}"; then die "conflicting process: $comm (${proc##*/})"; fi ;;
    esac
  done
}

managed_flannel_socket() {
  (( MANAGED )) && systemctl is-active --quiet "$UNIT" &&
    ip -d link show flannel.1 2>/dev/null | grep -Eq 'vxlan id 1 .*dstport 8472([[:space:]]|$)'
}

check_ports() {
  local protocol _state _recv _send address _peer rest port pid sockets
  sockets=$(ss -H -lntup) || die 'cannot inspect listening ports'
  while read -r protocol _state _recv _send address _peer rest; do
    port=${address##*:}
    case "$protocol:$port" in tcp:2379|tcp:2380|tcp:6443|tcp:6444|tcp:8935|tcp:8936|tcp:10010|tcp:10249|tcp:10250|tcp:10256|tcp:10257|tcp:10259|tcp:20241|udp:8472) ;; *) continue ;; esac
    if [[ "$protocol:$port" == udp:8472 && ! "$rest" =~ pid=([0-9]+) ]] && managed_flannel_socket; then continue; fi
    if (( ! MANAGED )) || [[ ! "$rest" =~ pid=([0-9]+) ]]; then die "required port in use: $protocol $port"; fi
    while [[ "$rest" =~ pid=([0-9]+) ]]; do
      pid=${BASH_REMATCH[1]}
      owned_pid "$pid" || die "required port in use: $protocol $port (PID $pid)"
      rest=${rest#*pid="$pid"}
    done
  done <<< "$sockets"
}

check_routes() {
  # Integer network comparisons handle broad routes (e.g. 10/8) as well as subnets.
  ip -o -4 route show table all | awk -v managed="$MANAGED" '
    function number(ip, a) {split(ip,a,"."); return a[1]*16777216+a[2]*65536+a[3]*256+a[4]}
    { dest=$1; if (dest ~ /^(local|broadcast|unreachable|blackhole|prohibit|throw)$/) dest=$2;
      if (dest == "default") next;
      dev=""; for(i=1;i<NF;i++) if($i=="dev") dev=$(i+1);
      if(managed && (dev ~ /^(cni|flannel|veth)/ || dev == "lp-gvisor0")) next;
      split(dest,parts,"/"); prefix=(parts[2]=="" ? 32 : parts[2]);
      if(parts[1] !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next;
      size=2^(32-prefix); first=int(number(parts[1])/size)*size; last=first+size-1;
      if(first <= number("10.44.255.255") && last >= number("10.42.0.0")) {
        print "error: host route " dest " overlaps Pod or Service networks" > "/dev/stderr"; bad=1
      }
    } END {exit bad}' || die 'resolve network overlap before installing'
}

preflight() {
  local tool
  (( EUID == 0 )) || die 'run with sudo or as root'
  [[ "$(uname -s)/$(uname -m)" == Linux/x86_64 ]] || die 'only Linux amd64 is supported'
  # The distribution-owned os-release uses shell assignment syntax.
  # shellcheck source=/dev/null
  source /etc/os-release
  [[ "$ID" == debian || "$ID" == ubuntu ]] || die 'only Debian and Ubuntu are supported'
  for tool in jq hostname curl tar bzip2 gzip sha256sum sha512sum install systemctl ip ss modprobe \
    flock realpath chown tee cmp ln readlink awk head chmod cat mv sleep sysctl sed \
    cp nproc df grep tr od sort wc ls dirname uname mktemp sync rm rmdir diff find nft; do
    command -v "$tool" >/dev/null || die "missing command: $tool; install the README prerequisites"
  done
  if [[ ! -d /run/systemd/system ]] || ! systemctl show-environment >/dev/null; then die 'systemd must be running on the host'; fi
  [[ ! -e "$INSTALL_DIR" || -d "$INSTALL_DIR" ]] || die 'installation root must be a directory'
  check_resources
  check_kernel
  check_existing_installation
  nft list tables >/dev/null || die 'nftables kernel support and CAP_NET_ADMIN are required'
  if (( ! MANAGED )) && nft list table inet livepeer_bootstrap >/dev/null 2>&1; then
    die 'nftables table livepeer_bootstrap already exists; refusing to replace an unowned table'
  fi
  check_ports
  check_routes
  log 'Host eligible: OS, resources, kernel, cgroups, existing installations, ports and routes checked.'
}
