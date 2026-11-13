#!/usr/bin/env bash
# Run before each K3s server launch, including launches after upgrade-controller jobs.
set -euo pipefail
# shellcheck source=lib/recovery.sh
source "$3"
version=$("$1" --version | awk 'NR == 1 {print $3}')
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$ ]] || {
  echo 'Cannot record K3s version; refusing to launch the server.' >&2
  exit 1
}
printf '%s\n' "$version" | atomic_write "$2"

# Installation facts are optional; their absence must not prevent K3s startup.
[[ -n ${4:-} ]] || exit 0
install_dir=$4
record="$install_dir/volumes/installed-software/software.json"
flux=$(timeout 2 "$install_dir/bin/flux" version --client 2>/dev/null) || flux=''
[[ $flux =~ ^flux:\ (v[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9._+-]*)$ ]] && flux=${BASH_REMATCH[1]} || flux=''
gvisor=$(timeout 2 "$install_dir/bin/runsc" --version 2>/dev/null) || gvisor=''
[[ $gvisor =~ ^runsc\ version\ ([A-Za-z0-9._+-]+) ]] && gvisor=${BASH_REMATCH[1]} || gvisor=''
jq -nc --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg flux "$flux" --arg gvisor "$gvisor" \
  '{recorded_at:$at,flux_cli:$flux,gvisor:$gvisor}' |
  atomic_write "$record" 0644 || { rm -f -- "$record" || true; }
