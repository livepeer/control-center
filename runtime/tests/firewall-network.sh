#!/usr/bin/env bash
# Run ONLY inside a disposable Docker container, with its own network namespace.
set -euo pipefail
[[ -f /.dockerenv && "${LIVEPEER_FIREWALL_CONTAINER_TEST:-}" == 1 ]] || {
  echo 'Run this test in the disposable container documented in README.md.' >&2
  exit 2
}
project=$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)
pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT

ip netns add external
ip netns add pod
ip link add wan type veth peer name client
ip link set client netns external
ip addr add 192.0.2.1/24 dev wan
ip link set wan up
ip -n external addr add 192.0.2.2/24 dev client
ip -n external link set client up
ip -n external link set lo up
ip -n external route add default via 192.0.2.1
ip link add cni0 type veth peer name pod0
ip link set pod0 netns pod
ip addr add 10.42.0.1/16 dev cni0
ip link set cni0 up
ip -n pod addr add 10.42.0.2/16 dev pod0
ip -n pod link set pod0 up
ip -n pod link set lo up
ip -n pod route add default via 10.42.0.1

for port in 22 6443 10250; do
  python3 -m http.server "$port" --bind 0.0.0.0 --directory /tmp >"/tmp/http-$port.log" 2>&1 &
  pids+=("$!")
done
ip netns exec pod python3 -m http.server 8080 --bind 0.0.0.0 --directory /tmp >/tmp/pod-http.log 2>&1 &
pids+=("$!")
ip netns exec external python3 -m http.server 8080 --bind 0.0.0.0 --directory /tmp >/tmp/external-http.log 2>&1 &
pids+=("$!")
wait_http() {
  for _attempt in {1..50}; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep .1
  done
  echo "HTTP listener did not become ready: $*" >&2
  return 1
}
for port in 22 6443 10250; do
  wait_http curl --noproxy '*' -fsS --max-time 1 "http://127.0.0.1:$port"
done
for namespace in pod external; do
  wait_http ip netns exec "$namespace" curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:8080
done

# Simulate kube-proxy's Service DNAT before the firewall input hook.
nft -f - <<'NFT'
table ip service_test {
  chain prerouting {
    type nat hook prerouting priority dstnat;
    ip daddr 10.43.0.1 tcp dport 443 dnat to 192.0.2.1:6443
  }
}
table inet operator_owned {}
NFT

reachable() { ip netns exec "$1" curl --noproxy '*' -fsS --max-time 2 "$2" >/dev/null 2>&1; }
reachable external http://192.0.2.1:6443
reachable external http://10.42.0.2:8080
bash "$project/lib/firewall.sh" "$project/config/firewall.nft" "$(command -v nft)"
nft list table inet operator_owned >/dev/null
curl --noproxy '*' -fsS --max-time 2 http://127.0.0.1:6443 >/dev/null
reachable pod http://10.43.0.1:443
reachable pod http://192.0.2.1:6443
reachable external http://192.0.2.1:22
reachable pod http://192.0.2.2:8080
for url in http://192.0.2.1:6443 http://192.0.2.1:10250 http://10.42.0.2:8080 http://10.43.0.1:443; do
  if reachable external "$url"; then echo "Unexpected external access: $url" >&2; exit 1; fi
done
# Reapplying preserves operator rules, and malformed batches preserve old protection.
bash "$project/lib/firewall.sh" "$project/config/firewall.nft" "$(command -v nft)"
printf 'invalid nftables input\n' >/tmp/invalid.nft
if bash "$project/lib/firewall.sh" /tmp/invalid.nft "$(command -v nft)" 2>/dev/null; then exit 1; fi
nft list table inet operator_owned >/dev/null
nft list table inet livepeer_bootstrap >/dev/null
if reachable external http://192.0.2.1:6443; then exit 1; fi
reachable pod http://10.43.0.1:443
echo 'Firewall passed: local and Pod API access; external management/cluster denial; SSH and Pod egress; atomic reload.'
