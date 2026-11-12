#!/usr/bin/env bash
# Host-safe checks followed by the disposable firewall container. Never installs Runtime.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
project=$PWD
run_id=${LIVEPEER_TEST_RUN_ID:-local-$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM}
container=${LIVEPEER_TEST_CONTAINER_NAME:-livepeer-runtime-$run_id}
state=${LIVEPEER_TEST_STATE_DIR:-}
own_state=0
if [[ -z $state ]]; then
  state=$(mktemp -d /tmp/livepeer-runtime-local.XXXXXXXXXX)
  own_state=1
fi
cidfile=$state/container.cid
test_code=null
outcome=setup_failed
image=-

# Invoked indirectly by the EXIT trap.
# shellcheck disable=SC2317,SC2329
finish() {
  local code=$? cid present owner cleanup=0
  trap - EXIT
  if [[ -f $cidfile ]]; then
    cid=$(cat "$cidfile")
    if [[ $cid =~ ^[a-f0-9]{64}$ ]]; then
      if owner=$(docker inspect --format '{{index .Config.Labels "livepeer.runtime-test"}}' "$cid" 2>/dev/null); then
        if [[ $owner == "$run_id" ]]; then
          docker rm -f "$cid" >/dev/null 2>&1 || true
        else
          cleanup=1
        fi
      fi
      if ! present=$(docker container ls -aq --no-trunc --filter "id=$cid") || [[ -n $present ]]; then cleanup=1; fi
    else
      cleanup=1
    fi
  fi
  if (( cleanup )); then
    echo "Container cleanup incomplete: $container; state: $state" >&2
    if (( code == 0 )); then code=1; outcome=cleanup_failed; fi
  fi
  printf '%s %s %s\n' "$test_code" "$outcome" "$image" > "$state/runner.result"
  if (( own_state && ! cleanup )); then rm -rf -- "$state"; fi
  exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

[[ $(uname -s) == Linux ]] || { echo 'Runtime tests require Linux' >&2; exit 1; }
for tool in bash python3 shellcheck docker tar gzip bzip2 sha256sum curl jq awk sed grep stat diff find tee cat rm mktemp; do
  command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
done
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10+ is required")'
endpoint=${DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}')}
[[ $endpoint == unix://* ]] || { echo 'Use the developer host Docker daemon via a local Unix socket' >&2; exit 1; }
docker info >/dev/null
scripts=(bootstrap-livepeer.sh lib/*.sh tests/firewall-network.sh tests/run.sh)
outcome=test_failed
for script in "${scripts[@]}"; do
  if bash -n "$script"; then :; else test_code=$?; exit "$test_code"; fi
done
if shellcheck "${scripts[@]}"; then :; else test_code=$?; exit "$test_code"; fi
if python3 -m unittest discover -s tests -v; then :; else test_code=$?; exit "$test_code"; fi

outcome=setup_failed
image_tag=golang:1.27.4-bookworm
if ! image=$(docker image inspect --format '{{.Id}}' "$image_tag" 2>/dev/null); then
  image=-
  docker pull "$image_tag"
  image=$(docker image inspect --format '{{.Id}}' "$image_tag")
fi
echo "Firewall image: $image_tag ($image)"
printf 'REMOTE_TEST_IMAGE %s %s\n' "$run_id" "$image"
echo "Firewall container: $container"
# The marker differentiates in-container package setup failures from test failures.
set +e
docker run --rm --name "$container" --cidfile "$cidfile" \
  --label "livepeer.runtime-test=$run_id" \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  --sysctl net.ipv6.conf.default.forwarding=1 \
  -e LIVEPEER_FIREWALL_CONTAINER_TEST=1 -v "$project:/src:ro" \
  "$image" bash -ec '
    apt-get update -qq
    apt-get install -y -qq nftables iproute2 curl python3 jq tcpdump >/tmp/packages.log
    echo LIVEPEER_FIREWALL_TEST_STARTED
    bash /src/tests/firewall-repro.sh
  ' 2>&1 | tee "$state/firewall.log"
statuses=("${PIPESTATUS[@]}")
code=${statuses[0]}
set -e
if grep -qx LIVEPEER_FIREWALL_TEST_STARTED "$state/firewall.log"; then
  test_code=$code
  if (( code == 0 )); then outcome=passed; else outcome=test_failed; fi
fi
if (( statuses[1] != 0 )); then
  if (( code == 0 )); then code=1; fi
  outcome=setup_failed
fi
exit "$code"
