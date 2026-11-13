#!/usr/bin/env bash
set -euo pipefail
# Share the installer lock so expiration cannot remove a newly replaced grant.
exec 9>/run/lock/livepeer-bootstrap.lock
flock -n 9 || exit 0
grant=$1
[[ -f "$grant" ]] || exit 0
payload=$(cut -d. -f2 "$grant")
payload=${payload//-/+}; payload=${payload//_/\/}
while (( ${#payload} % 4 )); do payload+='='; done
expiry=$(printf '%s' "$payload" | base64 --decode 2>/dev/null | jq -er '.exp | numbers') || expiry=0
if (( expiry <= $(date +%s) )); then rm -f -- "$grant"; fi
