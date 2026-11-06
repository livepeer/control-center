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
