#!/usr/bin/env bash
set -euo pipefail

# Read the entire rules file before building a batch. Delete/create is one atomic
# nftables transaction, so a rejected update leaves the previous table in place.
rules=$(cat -- "$1")
nft_command="$2"
batch="$rules"
connected=$(ip -j -4 route show table all | jq -r '[.[] | select(.dst != null and .dst != "default" and (.scope == "link" or .scope == "host")) | .dst] | unique | join(", ")')
if "$nft_command" list table inet livepeer_bootstrap >/dev/null 2>&1; then
  batch=$'delete table inet livepeer_bootstrap\n'"$rules"
fi
if [[ -n "$connected" ]]; then
  batch+=$'\nadd element inet livepeer_bootstrap local_ipv4 { '"$connected"' }'
fi
printf '%s\n' "$batch" | "$nft_command" -f -
