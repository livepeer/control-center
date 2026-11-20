# Development

The repository contains the Go API (`api/`), web UI (`ui/`), and host bootstrap
and tests (`runtime/`), with one Go module at the repository root. Run the
commands below from the repository root.

## Run locally

Requires Go 1.27.4+, Node.js 22.12+, TLS-enabled PostgreSQL 15+, and authentication.
Configure credentials and sign-in using
[api/config.example.toml](../api/config.example.toml) and the
[operations runbook](operations.md). Then run:

```sh
go mod download
npm --prefix ui ci
make api
# In another terminal:
make ui
```

Open [http://localhost:5173](http://localhost:5173). Migrations run on startup.
The Vite dev server proxies `/api` to the local API on the same origin. Deployed
builds call the API origin from `VITE_CONTROLCENTER_API_URL`, which defaults to
the value in [`ui/production.env`](../ui/production.env). Add the UI origin to
the deployed API's `AllowedOrigins`.

To try the deployed edge behaviour locally (SPA fallback, `_headers`, and
bootstrap routes against a local R2 bucket), build the UI and run
`npx wrangler dev --env-file /dev/null` in `ui/`.

## Development checks

```sh
make test
make build
npm --prefix ui run test:browser
npm --prefix ui run test:worker
```

Database tests skip without `TEST_DATABASE_URL` for a disposable PostgreSQL
instance with database and test-role creation privileges. Browser tests use
Chrome and mocks.

[GitHub Actions CI](../.github/workflows/ci.yml) runs on pull requests and can
be run manually. The hidden file check requires an exact allowlist entry for
each tracked path with a dot-prefixed file or directory name. CI checks Go
formatting and runs race tests, Vet, Staticcheck and Govulncheck. It builds and
browser-tests the UI, tests its edge Worker, dry-runs the production UI
deployment and runs the bootstrap, remote runner and Runtime tests. CI
supplies PostgreSQL, Livepeer Node and cloudflared for integration tests.
Pushes to `main` also run these checks.

For local real-process tests, set `NODE_BINARY` and `LIVEPEER_NODE_TEST_BINARY`
to the compatible Node binary. CI sets both. Isolated Flux/gVisor cluster tests
remain opt-in.

[Build](../.github/workflows/build.yml) validates the API, secrets and Runtime
Docker images on native Linux amd64 and arm64 runners for pull requests and
`main` pushes, and can be run manually. Image publication and bootstrap
activation follow the [deployment process](../deploy/README.md). The UI is
released separately with the [Deploy UI](../.github/workflows/ui-deploy.yml)
workflow; see [UI hosting](../deploy/README.md#ui-hosting).

## Runtime unit tests

```sh
python3 -m unittest discover -s runtime/tests
```

On macOS, the host-safe tests use the system Bash and test fixtures for GNU
commands. They use Python 3 and jq, and the Secrets signature test requires
an `openssl` that supports Ed25519. Run the Linux host checks and firewall
container with `make test-runtime`.

## Remote Runtime tests

```sh
make test-runtime REMOTE=<ssh-host>
make test-runtime REMOTE=<ssh-host> REF=<commit>
```

The first command tests current `runtime/` files, including uncommitted changes;
`REF` selects a repository commit. Only `runtime/` is transferred.

The local machine needs Git, Python 3.10+, and OpenSSH configured for the remote
host. The Linux remote user needs Bash, Python 3.10+, ShellCheck, jq, bzip2,
standard shell, archive and checksum utilities, and access without sudo to a
Docker daemon over a Unix socket. Image retrieval and container package
installation need network access. Optional kubectl/PyYAML checks report skips
when unavailable.


Logs and results are written to `.remote-test-results/<run-id>/`; `result.json`
records test and cleanup outcomes. The command returns nonzero for test,
transport, or cleanup failures. Interrupted runs may retain a remote container
or temporary directory; inspect the resource identifiers printed by the helper
before removing those resources or rerunning. Delete the local run directory
when its results are no longer needed.

## End-to-end tests

Use the separate `e2e-clankery` harness; commands are in its `README.txt`.
