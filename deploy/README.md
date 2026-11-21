# Staging deployment

Docker Compose runs the Go API, persistent image registry and its read-only
proxy, payment redeemer, operator secrets service, Vault, machine telemetry
storage (VictoriaMetrics, VictoriaLogs and Grafana), and Cloudflare Tunnel
connector. The web UI and bootstrap files are served separately by Cloudflare
Workers; see [UI hosting](#ui-hosting).
PostgreSQL and authentication use the Supabase project selected in the private
`config.toml`.

| Hostname | Origin | Routes |
| --- | --- | --- |
| `controlcenter.livepeer.live` | Cloudflare Worker `controlcenter-ui-production` (route `controlcenter.livepeer.live/*`) | UI with SPA routes such as `/auth/callback` and `/invite`, `/bootstrap.sh`, versioned `/bootstrap/releases/*` from R2 |
| `controlcenter-api.livepeer.live` | `http://localhost:43811` | API public listener: `/api/*` (CORS for `AllowedOrigins`), `/v1/*`, `/discovery`, `POST /redemption/tickets` |
| `controlcenter-registry.livepeer.live` | `http://localhost:53812` | Read-only OCI registry `/v2/*` |
| `controlcenter-secrets.livepeer.live` | `http://localhost:23812` | Operator secrets API |
| `controlcenter-grafana.livepeer.live` | `http://localhost:13812` | Telemetry dashboards; Cloudflare Access required |

The application ports and the registry upload port `63812` bind only to
`127.0.0.1`. The cloudflared container uses host networking so the configured
`localhost` origins resolve to the host. Its token is mounted as a private file
and selected with `TUNNEL_TOKEN_FILE`.

The API listens twice. `Listen` (`43812`) serves every route, including the
`/internal/*` callbacks used by the redeemer and the secrets service, and is
reachable only on the Compose networks. `PublicListen` (`43811`) is the tunnel
origin: it omits `/metrics` and `/internal/*`, except the secrets-service
metadata and membership callbacks that a secrets service on another host
reaches over HTTPS with the shared metadata token. It forwards
`POST /redemption/tickets` to `RedeemerUpstreamURL` as `/tickets`. Keep the
redeemer URL in Node configurations (`redeemer_url` in `onchain.json`) on the
API hostname.

## Install

Place the source checkout in `/opt/controlcenter`, install Docker Engine with
Compose and Buildx, and enable `docker.service`. Copy `config.example.toml` to
`config.toml` in this directory and supply the real values. Place the secret
files named in `compose.yaml` in `secrets/`. Keep the directory mode `0700`,
secret file mode `0600`, and deployed secret ownership `65532:65532` so the
non-root API and cloudflared processes can read their respective mounts.
Keep the configuration readable by UID 65532 as well.

Create `compose.env` in this directory for Compose interpolation settings.
For an existing deployment, rename its current Compose interpolation file to
`compose.env` and update your Compose commands to pass `--env-file compose.env`.

Generate `secrets/jwt-signing-key.pem` as an Ed25519 PKCS#8 PEM key; see the
[discovery authentication guide](../docs/discovery-auth.md). Preserve this key
and machine credential secrets across upgrades. The registry uses the persistent
`controlcenter_registry-data` Docker volume.

Allow `https://controlcenter.livepeer.live/auth/callback` in the Supabase
authentication redirect URLs and keep the Site URL on the same origin. Keep
email confirmation enabled. The initial administrator signs in using the
verified address in `DefaultAdminEmail`. The UI origin must also appear in
`AllowedOrigins` in `config.toml` and in `SECRETS_ALLOWED_ORIGIN` in
`secrets-service.env`; browsers are refused any other origin.

The Compose network enables IPv6 because direct Supabase database endpoints can
be IPv6-only. The host needs working IPv6 egress for such an endpoint.

Prepare the required [operator secrets service and Vault](../docs/operator-secrets.md#deploy-the-secrets-service-and-vault)
before starting the complete deployment. They use the same Compose file.

Copy `redeemer.example.toml` to `redeemer.toml` and `onchain.example.json` to
`onchain.json`. Create these owner-only files, readable by UID 65532:

- `secrets/onchain-rpc/<sha256>`: HTTPS RPC URL. Name the file with the SHA-256
  of its exact bytes (`shasum -a 256 <rpc-file>`) and set `rpc_secret` in
  `onchain.json` to that hash.
- `secrets/onchain-webhook-auth`: random secret of at least 32 bytes.
- `secrets/redeemer/keystore.json`, `password`, and `rpc`: redeemer wallet inputs.
- `secrets/redeemer/auth-url`: `http://api:43812/internal/redemption/authorize`.
- `secrets/redeemer/auth-headers`: `Authorization: Bearer <onchain-webhook-auth>`.

Build and publish images from this directory. Set `NODE_IMAGE` to the compatible
upstream Node release digest; the first command starts only the registry:

```sh
LIVEPEER_REDEEMER_IMAGE="$NODE_IMAGE" docker compose --env-file compose.env up -d registry
docker build -f ../runtime/Dockerfile -t 127.0.0.1:63812/controlcenter/runtime:staging ..
docker push 127.0.0.1:63812/controlcenter/runtime:staging
docker build -f ../runtime/services/Dockerfile.tunnel \
  --build-arg RUNTIME_IMAGE=<registry/runtime@sha256:digest> \
  -t 127.0.0.1:63812/controlcenter/connector:staging ../runtime/services
docker push 127.0.0.1:63812/controlcenter/connector:staging
docker build -f ../runtime/services/Dockerfile.node \
  --build-arg NODE_IMAGE="$NODE_IMAGE" \
  --build-arg RUNTIME_IMAGE=<registry/runtime@sha256:digest> \
  -t 127.0.0.1:63812/controlcenter/node:staging ../runtime/services
docker push 127.0.0.1:63812/controlcenter/node:staging
```

Use the public registry hostname and returned digests for `RuntimeImage`,
`RuntimeConnectorImage`, and `RuntimeNodeImage` in `config.toml`. Set
`LIVEPEER_REDEEMER_IMAGE` in `compose.env` to the same managed Node digest as
`RuntimeNodeImage`. Start the complete deployment, then
[publish a bootstrap release](#bootstrap-releases):

```sh
docker compose --env-file compose.env up -d --build --wait
```

Onchain is the default; startup requires valid payment settings. Control Center
configures each machine automatically. The redeemer retains its wallet and
`redeemer-data` volume.

Production requires Cloudflare. Configure the account, zone, certificate permissions,
and every public and management address in `TunnelNodeAddresses` before enrollment.
Follow the [machine tunnel runbook](../docs/machine-tunnels.md) for setup and cutover.

## Telemetry storage

Machines push metrics and logs to the API, which checks each machine's
telemetry token and stamps its identity before writing to VictoriaMetrics and
VictoriaLogs. Both stores are on the internal `telemetry` network and are not
published. See [machine telemetry](../docs/telemetry.md).

Create the data directories, owned by UID 65532, before the first start:

```sh
sudo install -d -m 0700 -o 65532 -g 65532 /opt/controlcenter-telemetry \
  /opt/controlcenter-telemetry/victoriametrics \
  /opt/controlcenter-telemetry/victorialogs \
  /opt/controlcenter-telemetry/grafana
```

Retention defaults to 30 days for metrics and 14 days for logs, with logs also
capped at 50 GiB. Override them in `compose.env` with `TELEMETRY_METRICS_RETENTION`,
`TELEMETRY_LOGS_RETENTION` and `TELEMETRY_LOGS_MAX_DISK`. Plan about 6 MB of
metrics per machine per day; log volume depends mostly on app output. Back up
`/opt/controlcenter-telemetry/grafana` with the deployment; the stores can be
rebuilt from new data if lost.

Grafana accepts only Cloudflare Access logins:

1. Add the `controlcenter-grafana.livepeer.live` public hostname to the
   deployment tunnel with origin `http://localhost:13812`.
2. Create a self-hosted Cloudflare Access application for that hostname. Allow
   only the administrator emails; this list is separate from Control Center's
   administrator grants, so update both when administrators change.
3. Set `CF_ACCESS_TEAM_DOMAIN` (the `<team>` in `<team>.cloudflareaccess.com`),
   `CF_ACCESS_AUD` (the application's audience tag) and, for another hostname,
   `GRAFANA_ROOT_URL` in `compose.env`.

Grafana verifies each Access assertion against the team's signing keys and the
audience tag. Without these settings the container exits instead of starting.
Signed-in administrators get the Editor role. Dashboards come from
`deploy/grafana/dashboards` and cannot be changed in the UI. Set
`TelemetryEnabled = false` in `config.toml` to stop telemetry fleet-wide.

Deployment mode and chain identity are fixed at first startup. Local development
opts out with `Mode = "offchain"`; see [API configuration](../api/config.example.toml).

## UI hosting

The UI is a Workers Static Assets project configured in
[`ui/wrangler.jsonc`](../ui/wrangler.jsonc). Static files come from the Vite
build, with SPA fallback for unknown paths. `/bootstrap*` and `/api*` always run
[`ui/worker`](../ui/worker/index.ts) instead, so they never return the UI's
HTML. Response headers and caching for static files are in
[`ui/public/_headers`](../ui/public/_headers): fingerprinted `/assets/*` are
immutable and HTML revalidates on every load, so clients pick up a release on
their next navigation. Deploying or rolling back the UI never touches this host.

Cloudflare account prerequisites:

- An R2 bucket named `controlcenter-bootstrap` (no public access; the Worker
  reads it through its binding).
- A proxied DNS record for `controlcenter.livepeer.live` in the `livepeer.live`
  zone. With no other origin, use `AAAA 100::`; the Worker route serves every
  request.
- A GitHub `production` environment for the [deploy workflow](../.github/workflows/ui-deploy.yml),
  limited to `main` with required reviewers. It holds the secret
  `CLOUDFLARE_API_TOKEN`, scoped to account *Workers Scripts: Edit* and, on the
  `livepeer.live` zone only, *Workers Routes: Edit* and *Zone: Read* (wrangler
  looks up the route's `zone_name`). It also holds the variable
  `CLOUDFLARE_ACCOUNT_ID`. This token can publish the JavaScript that seals
  operator secrets; keep it there.

Run **Deploy UI** from `main` with `deploy` to build and release that commit.
The run summary lists recent Worker versions. To roll back, run it with
`rollback` and the version ID to restore; static assets roll back with the
Worker version. The build bakes in `VITE_CONTROLCENTER_API_URL` from
`ui/production.env` or the build environment. Set the GitHub environment
variable `CONTROLCENTER_API_URL` to override the default in the workflow.
Publish only browser-safe values there.

The same commands work from a workstation authenticated with
`npx wrangler login --env-file /dev/null`:

```sh
npm --prefix ui ci
npm --prefix ui run build
(cd ui && npx wrangler deploy --env-file /dev/null --env production)
(cd ui && npx wrangler deployments list --env-file /dev/null --env production)
(cd ui && npx wrangler rollback <version-id> --env-file /dev/null --env production)
```

`npx wrangler deploy --env-file /dev/null` publishes a smoke-test copy on
`workers.dev`. It reads the same bootstrap bucket but its origin is not in
`AllowedOrigins`, so sign-in there is expected to fail.

Before enforcing a CSP change in `_headers`, test it in report-only mode
through sign-in, machines, administration and secrets. Resolve any violations
reported in the browser console.

## Bootstrap releases

The UI Worker serves bootstrap files from the `controlcenter-bootstrap` R2
bucket. `/bootstrap.sh` is the object `bootstrap.sh` and is never cached;
`/bootstrap/releases/<id>/<file>` is `releases/<id>/<file>` and is immutable.
Missing files return a plain-text `404` with `no-store`. Every loader embeds its
release's bundle URL under `https://controlcenter.livepeer.live/bootstrap/releases/`,
so published releases must stay in the bucket.

From the repository root, package the checked-out commit under a new release
ID, then publish it. Use one release ID per commit:

```sh
NEW_RELEASE_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short=12 HEAD)"
python3 tools/package-bootstrap.py --release-id "$NEW_RELEASE_ID" --output deploy/bootstrap
python3 tools/publish-bootstrap.py --release-id "$NEW_RELEASE_ID"
python3 tools/publish-bootstrap.py --activate "$NEW_RELEASE_ID"
```

The build machine needs Python 3.10+, Git, Node.js 22.12+ with
`npm --prefix ui ci` (for wrangler), and Cloudflare credentials with R2 write
access (`npx wrangler login --env-file /dev/null`, or `CLOUDFLARE_API_TOKEN` and
`CLOUDFLARE_ACCOUNT_ID`). Target hosts need none of these. By default the
packager uses `RuntimeImage` in `staging-images.json` and the public
`https://controlcenter.livepeer.live` origin. Supply `--runtime-image` with
another compatible published digest and `--public-origin https://your-host` for
a custom deployment. Confirm anonymous Linux amd64 pulls and compatibility with
the deployed API, Node and connector before activation.

Each release retains the complete bundle, `SHA256SUMS`, its exact `bootstrap.sh`,
and `release.json` containing checksums, source revision/dirty-state evidence,
asset hashes and recorded image metadata when available. Only tracked
installer assets are packaged; add any newly required helpers/templates to Git
before packaging. The loader includes the bundle checksum. The packager stages
the complete local release and refuses reused IDs. The publisher checks that
the release's files agree, uploads the loader last, and reads every object
back. It skips identical objects and refuses to replace a published file with
different content. `--activate` switches `/bootstrap.sh` only after the whole
release reads back intact.

Activation only moves forward. The candidate's `source_commit` must be the
active release's commit or descend from it in the local Git history, so a slow
publish of an older commit cannot replace a newer loader. Packaging and
publishing runs that share `deploy/bootstrap` take the same lock, but the lock
is local: publish from one machine. Automation should activate only releases
built from the current tip of its deployment branch. Never put credentials in a
release. Keep
`deploy/bootstrap` and the activation and validation records with the
deployment artifacts.

To roll back or switch branches, set `RETAINED_RELEASE_ID` to the ID of the
retained release to restore.

```sh
python3 tools/publish-bootstrap.py --activate "$RETAINED_RELEASE_ID" --rollback
```

`--all` publishes every release under `deploy/bootstrap/releases`, which
restores a bucket from the retained directory.

Check the public script content type/body, its referenced bundle/checksum,
anonymous image pulls, and a prepared disposable Debian/Ubuntu host. Check both
the initial loader download and shell exit status in automated acceptance; a
plain POSIX pipeline can mask failure of an empty initial download. Reruns must
retain saved credentials and image selection. Record focused evidence with the
release; broader host lifecycle and application acceptance remain separate gates.

## Operate

```sh
cd /opt/controlcenter/deploy
docker compose --env-file compose.env ps
docker compose --env-file compose.env logs --tail=100 api registry-proxy cloudflared
curl --fail http://127.0.0.1:43811/readyz
curl --fail http://127.0.0.1:43811/api/config
curl --fail http://127.0.0.1:13812/api/health
curl --fail http://127.0.0.1:23813/ready
docker compose --env-file compose.env up -d --build --wait
curl --fail --head https://controlcenter.livepeer.live/bootstrap.sh
```

Docker restarts the services after host reboot. Public registry requests allow
only GET and HEAD; publish images through the loopback port on the SSH host.
Use digest-pinned image references for enrolled machines and retain referenced
images when updating staging. Only pass `--volumes` to
`docker compose --env-file compose.env down` if you intend to delete the stored
images.
