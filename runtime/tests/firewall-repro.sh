#!/usr/bin/env bash
# Temporary diagnostic: repeatedly exercise only the pre-firewall topology.
set -euo pipefail
python3 - <<'PY'
from pathlib import Path
source = Path('/src/tests/firewall-network.sh').read_text()
prefix, separator, _ = source.partition('\nbash "$project/lib/firewall.sh"')
assert separator
Path('/tmp/firewall-baseline.sh').write_text(prefix + '\n')
PY
tcpdump -l -n -tt -i any 'ip6 or arp' >/tmp/firewall-packets.log 2>&1 &
capture=$!
trap 'kill "$capture" 2>/dev/null || true' EXIT
failures=0
for round in {1..30}; do
  echo "BASELINE ROUND $round $(date +%s.%N)"
  set +e
  bash /tmp/firewall-baseline.sh
  code=$?
  set -e
  echo "BASELINE RESULT $round $code $(date +%s.%N)"
  if (( code != 0 )); then
    failures=$((failures + 1))
    ip -6 neigh show
    ip -n external -6 neigh show
    ip -n pod -6 neigh show
    ip -6 addr show
    ip -n external -6 addr show
    ip -n pod -6 addr show
    tail -100 /tmp/firewall-packets.log
  fi
  for namespace in external pod gvisor2 gvisor3; do
    ip netns delete "$namespace"
  done
  for interface in wan cni0 lp-gvisor0; do
    ip link delete "$interface" 2>/dev/null || true
  done
  nft delete table ip service_test
  nft delete table inet operator_owned
done
echo "BASELINE FAILURES $failures / 30"
test "$failures" = 0
