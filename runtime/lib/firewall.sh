#!/usr/bin/env bash
set -euo pipefail

# Read the entire rules file before building a batch. Delete/create is one atomic
# nftables transaction, so a rejected update leaves the previous table in place.
rules=$(cat -- "$1")
nft_command="$2"
batch="$rules"
if "$nft_command" list table inet livepeer_bootstrap >/dev/null 2>&1; then
  batch=$'delete table inet livepeer_bootstrap\n'"$rules"
fi
printf '%s\n' "$batch" | "$nft_command" -f -
