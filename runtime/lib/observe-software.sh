#!/usr/bin/env bash
# Publish only binary identities, never command lines, environment or credentials.
set -euo pipefail
install_dir=$1
# shellcheck source=lib/recovery.sh
source "$install_dir/lib/recovery.sh"
identity=$(cat "$install_dir/credentials/identity.json")
observed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

runsc_version() {
  local output
  output=$(timeout 2 "$1" --version 2>/dev/null) || return 1
  if [[ $output =~ ^runsc\ version\ ([A-Za-z0-9._+-]+) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  else
    return 1
  fi
}

flux=''
output=$(timeout 2 "$install_dir/bin/flux" version --client 2>/dev/null) || output=''
if [[ $output =~ ^flux:\ (v[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9._+-]*)$ ]]; then flux=${BASH_REMATCH[1]}; fi
installed=$(runsc_version "$install_dir/bin/runsc") || installed=''

# Old immutable generations can remain active after the installed link changes.
# Inspect executable links rather than trusting process names or configured pins.
running='[]'
seen='|'
count=0
for executable in /proc/[0-9]*/exe; do
  target=$(readlink "$executable" 2>/dev/null) || continue
  target=${target%" (deleted)"}
  case "$target" in "$install_dir"/runtimes/gvisor/*/runsc) ;; *) continue ;; esac
  # A container can spoof this pathname in its own mount namespace. Only the
  # trusted host generation may be executed, after matching the open inode.
  process_inode=$(stat -Lc '%d:%i' "$executable" 2>/dev/null) || {
    [[ -e "$executable" ]] || continue
    running=null; break
  }
  host_inode=$(stat -Lc '%d:%i' "$target" 2>/dev/null) || { running=null; break; }
  if [[ $process_inode != "$host_inode" ]]; then running=null; break; fi
  [[ $seen == *"|$target|"* ]] && continue
  seen+="$target|"
  count=$((count + 1))
  if (( count > 8 )); then running=null; break; fi
  if value=$(runsc_version "$target"); then
    running=$(jq -nc --argjson current "$running" --arg version "$value" '$current + [$version] | unique')
  else
    running=null
    break
  fi
done

jq -nc --argjson identity "$identity" --arg at "$observed_at" \
  --arg flux "$flux" --arg installed "$installed" --argjson running "$running" \
  '{node_id:$identity.node_id,credential_version:$identity.credential_version,observed_at:$at,
    flux_cli:$flux,gvisor_installed:$installed,gvisor_running:$running}' |
  atomic_write "$install_dir/volumes/host-software/software.json" 0644
