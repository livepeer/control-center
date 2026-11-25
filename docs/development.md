# Development

Run commands from the repository root. The Go API, web UI, and host bootstrap live in `api/`, `ui/`, and `runtime/`.

## Run locally

Use Go 1.27.4+, Node.js 22.12+, and TLS-enabled PostgreSQL 15+. Configure Supabase using [the API config example](../api/config.example.toml) and [initial setup](operations.md#initial-setup).

```sh
go mod download
npm --prefix ui ci
make api
# Second terminal
make ui
```

Open [http://localhost:5173](http://localhost:5173). Migrations run on startup.

The local example sets `DevelopmentHTTP = true` with a separate DB and fresh enrollments. For local enrollment tests, bind the API on the private dev network, set `PublicAPIURL` to the HTTP URL reachable by hosts and Pods, and run bootstrap with matching `LIVEPEER_API_URL` and `LIVEPEER_ALLOW_DEVELOPMENT_HTTP=1`.

Vite proxies `/api` to the local API. Production builds use `VITE_CONTROLCENTER_API_URL` from [`ui/production.env`](../ui/production.env) by default. Add the **UI origin** to the API's `AllowedOrigins`.

To test the deployed SPA fallback, `_headers`, and bootstrap routes with local R2, build the UI and run `npx wrangler dev --env-file /dev/null` in `ui/`.

## Run checks and CI

```sh
make test
make build
npm --prefix ui run test:browser
npm --prefix ui run test:worker
```

- **Database tests** — need `TEST_DATABASE_URL` for a disposable PostgreSQL with DB and test-role creation privileges (skipped when unset).
- **Browser tests** — run Chrome with mocks.
- **Real-process tests** — set `NODE_BINARY` and `LIVEPEER_NODE_TEST_BINARY` to the compatible Node binary (Flux/gVisor cluster tests are opt-in).

[CI](../.github/workflows/ci.yml) runs on PRs, `main` pushes, and manual dispatch. Hidden-file checks allow `.github/`, `.gitignore`, and `.dockerignore` and reject other dot-prefixed tracked paths, including inside `.github/`.

CI runs `gofmt`, race tests (PostgreSQL, Node, cloudflared, Traefik, VictoriaMetrics, VictoriaLogs, vmagent fixtures), `go vet`, Staticcheck, Govulncheck, UI build/browser/Worker tests, Wrangler production dry-run, and bootstrap/remote-runner/Runtime tests.

[Build](../.github/workflows/build.yml) validates API, secrets, Runtime, and Grafana images on Linux `amd64`/`arm64` for PRs, `main`, and manual runs. After checks pass on a `main` push, [Publish images](../.github/workflows/publish.yml) builds each deployable `linux/amd64` image once and pushes it to GHCR as `ghcr.io/livepeer/controlcenter-<name>:sha-<commit>` (`api`, `secrets`, `grafana`, `runtime`, `connector`, `node`). The managed Node image uses the Node release in `go.mod`; CI checks that its binary reports that release and carries the runtime image's wrapper before pushing it. The run summary and `release` artifact list the digests. Machines pull runtime, connector, and node anonymously; the other packages are private. Published tags are never replaced, so reruns reuse existing images.

After a green `main` build, [Request deploy](../.github/workflows/deploy-dispatch.yml) asks the deployer (livepeer/deploy-control-center) to deploy the commit when the deployer GitHub App is configured: to staging automatically, then, once staging succeeds, to prod after approval. Bootstrap activation follows [production deployment](../deploy/README.md). [Deploy UI](../.github/workflows/ui-deploy.yml) deploys the UI ([UI hosting](../deploy/README.md#ui-hosting)).

## Run Runtime and end-to-end tests

### Unit and host tests

```sh
python3 -m unittest discover -s runtime/tests
```

macOS runs host-safe tests with system Bash, GNU fixtures, Python 3, `jq`, and Ed25519 `openssl` (Secrets signature tests). Run Linux host checks and the firewall container via `make test-runtime`.

### Remote Runtime tests

```sh
make test-runtime REMOTE=<ssh-host>
make test-runtime REMOTE=<ssh-host> REF=<commit>
```

The first command tests current `runtime/` files (including uncommitted changes). `REF` selects a commit. Only `runtime/` is transferred.

- **Local** — Git, Python `3.10+`, OpenSSH configured for `<ssh-host>`.
- **Remote Linux** — Bash, Python `3.10+`, ShellCheck, `jq`, `bzip2`, standard shell/archive/checksum utilities, sudo-less Docker socket access, network access for images/packages (`kubectl`/PyYAML skip if absent).

Find logs and `result.json` in `.remote-test-results/<run-id>/`. The command exits nonzero on test, transport, or cleanup failure. After interruption, inspect the printed IDs for leftover remote containers or directories before cleanup or retry.

### End-to-end tests

Use the separate `e2e-clankery` harness per its `README.txt`.
