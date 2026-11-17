#!/bin/sh
# Grafana trusts only Cloudflare Access assertions issued for this team and
# application. Refuse to start rather than fall back to any other login.
set -eu
team=${CF_ACCESS_TEAM_DOMAIN:-}
aud=${CF_ACCESS_AUD:-}
root_url=${GRAFANA_ROOT_URL:-}
case $team in
  '' | *[!a-z0-9-]*)
    echo 'Set CF_ACCESS_TEAM_DOMAIN to the Cloudflare Access team name, the <team> in <team>.cloudflareaccess.com.' >&2
    exit 1
    ;;
esac
case $aud in
  '' | *[!a-f0-9]*)
    echo 'Set CF_ACCESS_AUD to the Access application audience (AUD) tag.' >&2
    exit 1
    ;;
esac
case $root_url in
  https://?*) ;;
  *)
    echo 'Set GRAFANA_ROOT_URL to the HTTPS Grafana hostname.' >&2
    exit 1
    ;;
esac
issuer="https://$team.cloudflareaccess.com"
export GF_AUTH_JWT_JWK_SET_URL="$issuer/cdn-cgi/access/certs"
export GF_AUTH_JWT_EXPECT_CLAIMS="{\"iss\":\"$issuer\",\"aud\":[\"$aud\"]}"
export GF_SERVER_ROOT_URL="$root_url"
exec /run.sh "$@"
