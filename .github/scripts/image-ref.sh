#!/usr/bin/env bash
# Usage: image-ref.sh NAME COMMIT
#
# Prints ghcr.io/livepeer/controlcenter-NAME@sha256:... for the tag
# sha-COMMIT, or nothing when the tag does not exist. Fails when the tagged
# image is not a linux/amd64 build of COMMIT.
set -euo pipefail

name=$1
commit=$2
[[ $name =~ ^[a-z]+$ && $commit =~ ^[0-9a-f]{40}$ ]] || {
  echo "::error::usage: image-ref.sh NAME COMMIT" >&2
  exit 2
}
repository=ghcr.io/livepeer/controlcenter-$name

if ! manifest=$(docker buildx imagetools inspect "$repository:sha-$commit" --format '{{json .Manifest}}' 2>/dev/null); then
  exit 0
fi
digest=$(jq -r .digest <<<"$manifest")
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "::error::$repository:sha-$commit has no manifest digest" >&2
  exit 1
}
config=$(docker buildx imagetools inspect "$repository@$digest" --format '{{json .Image}}')
jq -e --arg commit "$commit" '.os == "linux" and .architecture == "amd64"
  and .config.Labels["org.opencontainers.image.revision"] == $commit' <<<"$config" >/dev/null || {
  echo "::error::$repository:sha-$commit is not a linux/amd64 build of $commit" >&2
  exit 1
}
echo "$repository@$digest"
