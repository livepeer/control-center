#!/usr/bin/env bash
# Usage: image-ref.sh NAME COMMIT
#
# Prints ghcr.io/livepeer/controlcenter-NAME@sha256:... for the tag
# sha-COMMIT. It prints nothing only when GHCR answers that the tag or package
# does not exist. Any other answer, including an authorization failure, is an
# error, so a failed lookup is never mistaken for a missing tag and a publish
# never replaces an existing one. Fails unless the tag is a single linux/amd64
# image manifest built from COMMIT.
#
# Authenticates with GHCR_USER and GHCR_TOKEN when set, anonymously otherwise.
# GHCR_SCOPE is the access to request: pull (the default), or pull,push in a
# job that publishes the tag when it is missing, so the lookup is authorized
# like the push that may follow.
set -euo pipefail

usage() {
  echo "::error::usage: image-ref.sh NAME COMMIT" >&2
  exit 2
}
[[ $# -eq 2 ]] || usage
name=$1
commit=$2
scope=${GHCR_SCOPE:-pull}
[[ $name =~ ^[a-z]+$ && $commit =~ ^[0-9a-f]{40}$ && $scope =~ ^pull(,push)?$ ]] || usage

repository=livepeer/controlcenter-$name
reference=ghcr.io/$repository:sha-$commit
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() {
  echo "::error::$reference: $*" >&2
  exit 1
}

# Connection failures and 408, 429 and 5xx answers are retried; the last
# answer decides.
request() {
  curl --silent --show-error --retry 4 --retry-connrefused --max-time 60 "$@"
}

auth=()
if [[ -n ${GHCR_TOKEN:-} ]]; then
  # Credentials go in a private curl config file, not in argv.
  printf 'user = "%s:%s"\n' "${GHCR_USER:?GHCR_USER is required with GHCR_TOKEN}" "$GHCR_TOKEN" > "$work/credentials"
  auth=(--config "$work/credentials")
fi

status=$(request "${auth[@]}" --output "$work/token" --write-out '%{http_code}' \
  "https://ghcr.io/token?service=ghcr.io&scope=repository:$repository:$scope") ||
  fail "the token request failed"
[[ $status == 200 ]] || fail "GHCR refused a $scope token (HTTP $status)"
token=$(jq -er '.token' "$work/token") || fail "GHCR returned no token"
printf 'Authorization: Bearer %s\n' "$token" > "$work/bearer"

accept='application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
accept+=', application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'
status=$(request --header @"$work/bearer" --header "Accept: $accept" --output "$work/manifest" \
  --write-out '%{http_code}' "https://ghcr.io/v2/$repository/manifests/sha-$commit") ||
  fail "the manifest request failed"
case $status in
  200) ;;
  404)
    if jq -e 'any(.errors[]?; .code == "MANIFEST_UNKNOWN" or .code == "NAME_UNKNOWN")' \
      "$work/manifest" >/dev/null 2>&1; then
      exit 0
    fi
    fail "GHCR answered 404 without saying the manifest is unknown"
    ;;
  *) fail "GHCR answered HTTP $status" ;;
esac

media=$(jq -r '.mediaType // empty' "$work/manifest") || fail "the manifest is not JSON"
case $media in
  application/vnd.oci.image.manifest.v1+json | application/vnd.docker.distribution.manifest.v2+json) ;;
  *) fail "is ${media:-an untyped manifest}, not a single image manifest" ;;
esac
digest=sha256:$(sha256sum "$work/manifest" | cut -d' ' -f1)

config=$(jq -r '.config.digest // empty' "$work/manifest")
[[ $config =~ ^sha256:[0-9a-f]{64}$ ]] || fail "the manifest has no config digest"
# Blobs redirect to a CDN; curl sends the Authorization header only to ghcr.io.
status=$(request --location --header @"$work/bearer" --output "$work/config" --write-out '%{http_code}' \
  "https://ghcr.io/v2/$repository/blobs/$config") || fail "the config request failed"
[[ $status == 200 ]] || fail "the config blob answered HTTP $status"
[[ sha256:$(sha256sum "$work/config" | cut -d' ' -f1) == "$config" ]] ||
  fail "the config blob does not match its digest"
jq -e --arg commit "$commit" '.os == "linux" and .architecture == "amd64"
  and .config.Labels["org.opencontainers.image.revision"] == $commit' "$work/config" >/dev/null ||
  fail "is not a linux/amd64 build of $commit"
echo "ghcr.io/$repository@$digest"
