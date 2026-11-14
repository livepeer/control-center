# Staging deployment

Docker Compose runs the Go API, built web UI with Caddy, persistent image
registry, payment redeemer, operator secrets service, Vault, and Cloudflare
Tunnel connector.
PostgreSQL and authentication use the Supabase project selected in the private
`config.toml`.

| Hostname | Origin | Routes |
| --- | --- | --- |
| `controlcenter.livepeer.live` | `http://localhost:33812` | UI, `/auth/callback`, `/bootstrap.sh`, versioned `/bootstrap/releases/*`, same-origin `/api/*` proxy |
| `controlcenter-api.livepeer.live` | `http://localhost:43812` | API, `/v1/*`, `/discovery` |
| `controlcenter-registry.livepeer.live` | `http://localhost:53812` | Read-only OCI registry `/v2/*` |
| `controlcenter-secrets.livepeer.live` | `http://localhost:23812` | Operator secrets API |

The application ports and the registry upload port `63812` bind only to
`127.0.0.1`. The cloudflared container uses host networking so the configured
`localhost` origins resolve to the host. Its token is mounted as a private file
and selected with `TUNNEL_TOKEN_FILE`.

## Install

Place the source checkout in `/opt/controlcenter`, install Docker Engine with
Compose and Buildx, and enable `docker.service`. Copy `config.example.toml` to
`config.toml` in this directory and supply the real values. Place the secret
files named in `compose.yaml` in `secrets/`. Keep the directory mode `0700`,
secret file mode `0600`, and deployed secret ownership `65532:65532` so the
non-root API and cloudflared processes can read their respective mounts.
Keep the configuration readable by UID 65532 as well.

Preserve the signing secrets and Collector encryption keyring across upgrades.
For a fresh database, generate the keyring once with an independent random
32-byte base64 key, following [the tunnel runbook](../docs/machine-tunnels.md).
Back up the keyring separately from database backups. The registry uses the
persistent `controlcenter_registry-data` Docker volume.

Allow `https://controlcenter.livepeer.live/auth/callback` in the Supabase
authentication redirect URLs. Keep email confirmation enabled. The initial
administrator signs in using the verified address in `DefaultAdminEmail`.

The Compose network enables IPv6 because direct Supabase database endpoints can
be IPv6-only. The host needs working IPv6 egress for such an endpoint.

Prepare the required [operator secrets service and Vault](../docs/operator-secrets.md#deployment)
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
LIVEPEER_REDEEMER_IMAGE="$NODE_IMAGE" docker compose up -d registry
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
`LIVEPEER_REDEEMER_IMAGE` in `.env` to the same managed Node digest as
`RuntimeNodeImage`. Package a bootstrap release, then start the complete deployment:

```sh
python3 ../tools/package-bootstrap.py --release-id "$NEW_RELEASE_ID" --output bootstrap --activate
chmod 0755 bootstrap bootstrap/releases
docker compose up -d --build --wait
```

Onchain is the default; startup requires valid payment settings. Control Center
configures each machine automatically. The redeemer retains its wallet and
`redeemer-data` volume.

Enable managed tunnels and discovery after configuring the `livepeer.vip`
account/zone, Zero Trust team, certificate permissions, keyring, image digests,
and node address exclusions. Update `TunnelNodeAddresses` with the public and
management addresses of every machine before enrollment; the bootstrap
installer's origin firewall remains required.

Deployment mode and chain identity are fixed at first startup. Local development
opts out with `Mode = "offchain"`; see [API configuration](../api/config.example.toml).

## Bootstrap releases

The web service mounts `deploy/bootstrap` read-only at `/srv/bootstrap`. The
current `/bootstrap.sh` resolves to `bootstrap/bootstrap.sh`; a versioned URL
`/bootstrap/releases/<id>/runtime-bootstrap.tar.gz` resolves to
`bootstrap/releases/<id>/runtime-bootstrap.tar.gz`. These routes return 404 for
missing files and never fall back to the UI. The current loader is not cached;
versioned files are immutable. Keep this directory across web builds/deployments.

From the repository root, choose a previously unused release ID:

```sh
python3 tools/package-bootstrap.py --release-id "$NEW_RELEASE_ID" \
  --output deploy/bootstrap --activate
chmod 0755 deploy/bootstrap deploy/bootstrap/releases
```

The build machine needs Python 3.10+ and Git; target hosts need neither. By
default the packager uses `RuntimeImage` in `staging-images.json` and
the public `https://controlcenter.livepeer.live` origin. Supply `--runtime-image`
with another compatible published digest and `--public-origin https://your-host`
for a custom deployment. Confirm anonymous Linux amd64 pulls and compatibility
with the deployed API, Node and connector before activation.

Each release retains the complete bundle, `SHA256SUMS`, its exact `bootstrap.sh`,
and `release.json` containing checksums, source revision/dirty-state evidence,
asset hashes and recorded image build provenance when available. Only tracked
installer assets are packaged; add any newly required helpers/templates to Git
before packaging. The loader includes the bundle checksum. Publication stages
the complete release directory, refuses reused IDs, then `--activate` atomically
switches the current loader last. Omit `--activate` to stage a release for checks.
All published assets must be readable by web UID 65532; files are mode 0644 and
release directories mode 0755. Never put credentials in this directory.
Retain activation and validation records with the deployment artifacts.

For a remote deployment, transfer into a staging directory outside the served
bootstrap tree, on the same filesystem. After the transfer and checksum checks,
rename the complete directory into `bootstrap/releases/<id>`, then switch the
current loader. Do not upload directly into the final release directory or replace
or delete prior releases. Missing artifacts return `404` with `no-store`; existing
release files use immutable caching.

To activate a staged release or roll back, run on the deployment host from
`deploy/`, substituting the retained release ID:

```sh
cp bootstrap/releases/bootstrap-20261112.1/bootstrap.sh bootstrap/.loader-next
chmod 0644 bootstrap/.loader-next
mv -f bootstrap/.loader-next bootstrap/bootstrap.sh
```

Check the public script content type/body, its referenced bundle/checksum,
anonymous image pulls, and a prepared disposable Debian/Ubuntu host. Check both
the initial loader download and shell exit status in automated acceptance; a
plain POSIX pipeline can mask failure of an empty initial download. Reruns must
retain saved credentials and image selection. Record focused evidence with the
release; broader host lifecycle and application acceptance remain separate gates.

## Operate

```sh
cd /opt/controlcenter/deploy
docker compose ps
docker compose logs --tail=100 api web cloudflared
curl --fail http://127.0.0.1:43812/readyz
curl --fail http://127.0.0.1:33812/api/config
curl --fail http://127.0.0.1:23813/ready
docker compose up -d --build --wait
```

Docker restarts the services after host reboot. Public registry requests allow
only GET and HEAD; publish images through the loopback port on the SSH host.
Use digest-pinned image references for enrolled machines and retain referenced
images when updating staging. Do not use `docker compose down --volumes` unless
you intend to delete the stored images.
