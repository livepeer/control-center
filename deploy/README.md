# Staging deployment

Docker Compose runs the Go API, built web UI with Caddy, persistent image
registry, and Cloudflare Tunnel connector. PostgreSQL and authentication use the
Supabase project selected in the private `config.toml`.

| Hostname | Origin | Routes |
| --- | --- | --- |
| `controlcenter.livepeer.live` | `http://localhost:33812` | UI, `/auth/callback`, same-origin `/api/*` proxy |
| `controlcenter-api.livepeer.live` | `http://localhost:43812` | API, `/v1/*`, `/discovery` |
| `controlcenter-registry.livepeer.live` | `http://localhost:53812` | Read-only OCI registry `/v2/*` |

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

From this directory:

```sh
docker compose up -d registry
docker build -f ../runtime/Dockerfile -t 127.0.0.1:63812/controlcenter/runtime:staging ..
docker push 127.0.0.1:63812/controlcenter/runtime:staging
# Use the returned Runtime digest below.
docker build -f ../runtime/services/Dockerfile.tunnel \
  --build-arg RUNTIME_IMAGE=127.0.0.1:63812/controlcenter/runtime@sha256:<RUNTIME_DIGEST> \
  -t 127.0.0.1:63812/controlcenter/connector:staging ../runtime/services
docker push 127.0.0.1:63812/controlcenter/connector:staging
# Set RuntimeImage, RuntimeConnectorImage, and RuntimeNodeImage in config.toml
# using the public registry hostname and the digests returned by the pushes.
docker compose config --quiet
docker compose up -d --build --wait
```

Enable managed tunnels and discovery after configuring the `livepeer.vip`
account/zone, Zero Trust team, certificate permissions, keyring, image digests,
and node address exclusions. Update `TunnelNodeAddresses` with the public and
management addresses of every machine before enrollment; the bootstrap
installer's origin firewall remains required.

## Onchain setup

Package the Node image with Runtime's startup wrapper and set `RuntimeNodeImage`
to the pushed digest. Use the same Node build for `LIVEPEER_REDEEMER_IMAGE`.
The Node build must support `RPCURLFile`, `RedeemerHeadersFile` and unregister
acknowledgements that wait for durable redeemer handoff.

```sh
docker build -f ../runtime/services/Dockerfile.node \
  --build-arg NODE_IMAGE=<registry/node@sha256:digest> \
  --build-arg RUNTIME_IMAGE=<registry/runtime@sha256:digest> \
  -t <registry/managed-node:build> ../runtime/services
docker push <registry/managed-node:build>
```

Copy `redeemer.example.toml` to `redeemer.toml`. Create owner-only files readable
by UID 65532:

- `secrets/onchain-rpc/<version>`: HTTPS RPC URL.
- `secrets/onchain-webhook-auth`: random secret of at least 32 bytes.
- `secrets/redeemer/keystore.json`, `password`, and `rpc`: redeemer wallet inputs.
- `secrets/redeemer/auth-url`: `http://api:43812/internal/redemption/authorize`.
- `secrets/redeemer/auth-headers`: `Authorization: Bearer <onchain-webhook-auth>`.

Set `OnchainSecretsDir` and `OnchainWebhookSecretFile` in `config.toml`, then start:

```sh
docker compose -f compose.yaml -f compose.onchain.yaml --profile onchain up -d
```

The wallet is mounted only into the redeemer, which uses the separate
`redeemer-data` volume. Only HTTPS ticket submission is exposed through ingress.
Apply machine settings using the [operations runbook](../docs/operations.md#onchain-operation).

## Operate

```sh
cd /opt/controlcenter/deploy
docker compose ps
docker compose logs --tail=100 api web cloudflared
curl --fail http://127.0.0.1:43812/readyz
curl --fail http://127.0.0.1:33812/api/config
curl --fail http://127.0.0.1:23812/ready
docker compose up -d --build --wait
```

Docker restarts the services after host reboot. Public registry requests allow
only GET and HEAD; publish images through the loopback port on the SSH host.
Use digest-pinned image references for enrolled machines and retain referenced
images when updating staging. Do not use `docker compose down --volumes` unless
you intend to delete the stored images.
