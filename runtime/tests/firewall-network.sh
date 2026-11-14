#!/usr/bin/env bash
# Run ONLY inside a disposable Docker container, with its own network namespace.
set -Eeuo pipefail
trap 'printf "Firewall fixture failed at line %s: %s (args: %s)\n" "$LINENO" "$BASH_COMMAND" "$*" >&2' ERR
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
# Forwarding needs a usable link-local source for IPv6 neighbor discovery.
# Auto-generated addresses may still be tentative when the probes start.
ip -6 addr add fe80::1/64 dev wan nodad
ip -6 addr add 2001:db8:1::1/64 dev wan nodad
ip -n external -6 addr add 2001:db8:1::2/64 dev client nodad
ip -n external -6 route add default via 2001:db8:1::1
ip -6 addr add fe80::1/64 dev cni0 nodad
ip -6 addr add fd42::1/64 dev cni0 nodad
ip -n pod -6 addr add fd42::2/64 dev pod0 nodad
ip -n pod -6 route add default via fd42::1

ip link add lp-gvisor0 type bridge
ip addr add 10.44.0.1/16 dev lp-gvisor0
ip -6 addr add fe80::1/64 dev lp-gvisor0 nodad
ip -6 addr add fd44::1/64 dev lp-gvisor0 nodad
ip link set lp-gvisor0 up
for suffix in 2 3; do
  ip netns add "gvisor$suffix"
  ip link add "gv$suffix" type veth peer name eth0 netns "gvisor$suffix"
  ip link set "gv$suffix" master lp-gvisor0
  ip link set "gv$suffix" up
  bridge link set dev "gv$suffix" isolated on
  ip -n "gvisor$suffix" addr add "10.44.0.$suffix/16" dev eth0
  ip -n "gvisor$suffix" -6 addr add "fd44::$suffix/64" dev eth0 nodad
  ip -n "gvisor$suffix" link set eth0 up
  ip -n "gvisor$suffix" link set lo up
  ip -n "gvisor$suffix" route add default via 10.44.0.1
  ip -n "gvisor$suffix" -6 route add default via fd44::1
done
for address in 8.8.8.8 1.1.1.1 1.0.0.1 10.20.0.2 169.254.169.254; do
  ip -n external addr add "$address/32" dev client
  ip route add "$address/32" via 192.0.2.2
done
ip addr add 11.22.33.1/24 dev wan
ip -n external addr add 11.22.33.2/24 dev client
cat >/tmp/dns-echo.py <<'PY'
import socket, sys
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((sys.argv[1], 53))
while True:
    body, peer = server.recvfrom(512)
    server.sendto(body, peer)
PY
for address in 8.8.8.8 1.1.1.1 1.0.0.1 10.20.0.2 169.254.169.254; do
  ip netns exec external python3 /tmp/dns-echo.py "$address" >"/tmp/dns-$address.log" 2>&1 &
  pids+=("$!")
done

for port in 22 6443 8936 10250 20241; do
  python3 -m http.server "$port" --bind 0.0.0.0 --directory /tmp >"/tmp/http-$port.log" 2>&1 &
  pids+=("$!")
done
python3 -m http.server 8935 --bind :: --directory /tmp >/tmp/http-v6.log 2>&1 &
pids+=("$!")
ip netns exec pod python3 -m http.server 8080 --bind :: --directory /tmp >/tmp/pod-http-v6.log 2>&1 &
pids+=("$!")
ip netns exec external python3 -m http.server 8080 --bind 0.0.0.0 --directory /tmp >/tmp/external-http.log 2>&1 &
pids+=("$!")
for port in 53 443; do
  ip netns exec external python3 -m http.server "$port" --bind 0.0.0.0 --directory /tmp >"/tmp/external-$port.log" 2>&1 &
  pids+=("$!")
done
for namespace in gvisor2 gvisor3; do
  ip netns exec "$namespace" python3 -m http.server 8080 --bind :: --directory /tmp >"/tmp/$namespace-http.log" 2>&1 &
  pids+=("$!")
done
wait_http() {
  for _attempt in {1..50}; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep .1
  done
  echo "HTTP listener did not become ready: $*" >&2
  return 1
}
for port in 22 6443 8935 8936 10250 20241; do
  wait_http curl --noproxy '*' -fsS --max-time 1 "http://127.0.0.1:$port"
done
wait_http curl --noproxy '*' -gfsS --max-time 1 'http://[::1]:8935'
wait_http ip netns exec pod curl --noproxy '*' -gfsS --max-time 1 'http://[::1]:8080'
for namespace in pod external; do
  wait_http ip netns exec "$namespace" curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:8080
done
for namespace in gvisor2 gvisor3; do
  wait_http ip netns exec "$namespace" curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:8080
done
wait_http ip netns exec external curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:443
wait_http ip netns exec external curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:53

# Simulate kube-proxy's Service DNAT before the firewall input hook.
nft -f - <<'NFT'
table ip service_test {
  chain prerouting {
    type nat hook prerouting priority dstnat;
    ip daddr 10.43.0.1 tcp dport 443 dnat to 192.0.2.1:6443
    ip daddr 192.0.2.1 tcp dport { 30080, 18080 } dnat to 10.42.0.2:8080
  }
}
table inet operator_owned {}
NFT

reachable() { ip netns exec "$1" curl --noproxy '*' -fsS --max-time 2 "$2" >/dev/null 2>&1; }
dns_reachable() {
  ip netns exec "$1" python3 -c 'import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1); s.sendto(b"dns-test",(sys.argv[1],53)); assert s.recv(512)==b"dns-test"' "$2" 2>/dev/null
}
reachable external http://192.0.2.1:6443
reachable external http://192.0.2.1:10250
reachable external http://10.42.0.2:8080
reachable external 'http://[fd42::2]:8080'
reachable external 'http://[2001:db8:1::1]:8935'
reachable external http://192.0.2.1:30080
reachable gvisor2 http://192.0.2.1:6443
reachable gvisor2 http://192.0.2.1:10250
reachable gvisor2 http://10.42.0.2:8080
reachable gvisor2 http://10.20.0.2:443
reachable gvisor2 http://169.254.169.254:443
reachable gvisor2 http://11.22.33.2:443
dns_reachable gvisor2 10.20.0.2
bash "$project/lib/firewall.sh" "$project/config/firewall.nft" "$(command -v nft)"
nft list table inet operator_owned >/dev/null
curl --noproxy '*' -fsS --max-time 2 http://127.0.0.1:6443 >/dev/null
reachable pod http://10.43.0.1:443
reachable pod http://192.0.2.1:6443
reachable pod http://192.0.2.1:10250
reachable external http://192.0.2.1:22
reachable pod http://192.0.2.2:8080
reachable pod http://10.44.0.2:8080
reachable pod http://11.22.33.2:443
reachable gvisor2 http://8.8.8.8:443
reachable gvisor2 http://1.1.1.1:53
dns_reachable gvisor2 1.1.1.1
dns_reachable gvisor2 1.0.0.1
for address in 10.20.0.2 169.254.169.254 8.8.8.8; do
  if dns_reachable gvisor2 "$address"; then echo "Unexpected gVisor DNS access: $address" >&2; exit 1; fi
done
for url in http://192.0.2.1:6443 http://192.0.2.1:10250 http://10.43.0.1:443 http://192.0.2.1:22 http://10.44.0.1:8935 http://10.42.0.2:8080 http://10.44.0.3:8080 http://10.20.0.2:443 http://169.254.169.254:443 http://11.22.33.2:443 http://8.8.8.8:8080 'http://[fd44::1]:8935' 'http://[fd42::2]:8080'; do
  if reachable gvisor2 "$url"; then echo "Unexpected gVisor access: $url" >&2; exit 1; fi
done
for url in http://192.0.2.1:6443 http://192.0.2.1:10250 http://192.0.2.1:8935 http://192.0.2.1:8936 http://192.0.2.1:20241 http://10.42.0.2:8080 http://10.44.0.2:8080 http://10.43.0.1:443 http://192.0.2.1:30080 http://192.0.2.1:18080 'http://[fd42::2]:8080' 'http://[fd44::2]:8080' 'http://[2001:db8:1::1]:8935'; do
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
reachable pod http://192.0.2.1:10250
echo 'Firewall passed: gVisor local/Pod/metadata denial, public HTTPS/DNS, incoming replies; system Pod API/kubelet access; atomic reload.'
