# Livepeer Control Center

Control Center manages onboarding and configuration for Livepeer orchestrators.
The repository contains the Go API (`api/`), web UI (`ui/`), and host bootstrap
and tests (`runtime/`), with one Go module at the repository root.

## Run locally

Requires Go 1.27.3+, Node.js 22.12+, TLS-enabled PostgreSQL, and authentication.
Configure credentials and sign-in using
[api/config.example.toml](api/config.example.toml) and the
[operations runbook](docs/operations.md). Then run:

```sh
go mod download
npm --prefix ui ci
make api
# In another terminal:
make ui
```

Open [http://localhost:5173](http://localhost:5173). Migrations run on startup.

See the [app registry guide](docs/app-registry.md) for publishing app
definitions, revision history, and pricing policy.

The API can also serve [fleet discovery](docs/fleet-discovery.md) from managed,
Access-protected orchestrators using Node's Collector library.

## Connect a node

On a Debian or Ubuntu amd64 systemd host with 2 CPUs, 4 GiB RAM, and 10 GiB
free, sign in and run the bootstrap command from the combined checkout:

```sh
cd runtime
export LIVEPEER_API_URL=https://your-control-center-api.example
sudo --preserve-env=LIVEPEER_API_URL ./bootstrap-livepeer.sh --token <TOKEN>
```

Set `PublicAPIURL` to the same address, reachable by the host and its Kubernetes
pods.

## Development checks

```sh
make test
make build
npm --prefix ui run test:browser
```

Database tests skip without `TEST_DATABASE_URL` for a disposable PostgreSQL
instance with database and test-role creation privileges. Browser tests use
Chrome and mocks.

## Remote Runtime tests

From the combined repository root:

```sh
make test-runtime REMOTE=livepeer-t4
make test-runtime REMOTE=livepeer-t4 REF=<commit>
```

The first command tests current `runtime/` files, including uncommitted changes;
`REF` selects a repository commit containing `runtime/tests/run.sh`. Only
`runtime/` is transferred; no push or remote checkout update is needed.

Locally, install Git, Python 3.10+, and OpenSSH configured with your usual SSH
settings and host keys. `REMOTE` is required; local Docker is not. The Linux
remote user needs Bash, Python 3.10+, ShellCheck, jq, bzip2, standard shell,
archive and checksum utilities, and access without sudo to a Docker daemon over
a Unix socket. Image retrieval and container package installation need network
access. The helper installs no host packages and changes no Docker permissions.
Optional kubectl/PyYAML checks report skips when unavailable.

The runner checks Bash syntax, runs ShellCheck and Python tests, then exercises
firewall traffic in a disposable Docker container. It uses a cached image when
available and records and runs its resolved image ID. Image tags and apt
repositories mean builds are not fully reproducible. See
[Runtime verification](runtime/README.md#verification).

### Source capture

Working-tree capture includes tracked files and non-ignored untracked files,
honoring deletions; commit capture reads Git objects. Both preserve executable
modes and reject symlinks, submodules, conflicts, and selected nonregular files.
Within `runtime/`, these paths are excluded:

- Any `.git`, `secrets`, `.venv`, `venv`, `node_modules`, `__pycache__`,
  `.pytest_cache`, `.mypy_cache`, or `.ruff_cache` path component.
- `.env` and `.env.*` components (including `.env.example`), `*.pyc`, `*.pyo`,
  and `.coverage` files.
- Top-level `bin/`, `download/`, `runtimes/`, `credentials/`, `state/`,
  `systemd/`, `k3s/`, `kubelet/`, `volumes/`, `logs/`, `build/`, `dist/`,
  `test-results/`, and `htmlcov/`, plus `config/kubeconfig.yaml`.

Excluded untracked files are omitted; a tracked path matching the policy causes
an error. Source templates under `config/`, `lib/`, `services/`, and `manifests/`
remain included. This path policy is not generic secret detection.

Do not edit during capture: it is not an atomic snapshot. After `Capture
complete`, later edits cannot affect the archive. For working-tree capture,
`source.revision` is HEAD at capture, while SHA-256 identifies the submitted
archive bytes.

### Results and cleanup

Each run writes ignored `.remote-test-results/<run-id>/` with `source.tar.gz`
when captured, streamed `test.log`, and `result.json`. The JSON records source,
resources, image identity when available, timestamps, known test status,
outcome, cleanup result, and helper exit status. `make` returns nonzero on
failure; consult `result.json` for the exact test status. The Python helper
preserves known test failures and returns 130 for handled Ctrl-C; setup or
transport failures and incomplete cleanup after passing tests also return
nonzero. Delete a run directory or `.remote-test-results/` to remove local results.

The remote source is in a private `/tmp/livepeer-runtime-<run-id>.*` directory.
The test uses normal Docker networking and image caching; firewall rules apply
only inside its container. Unrelated checkouts, installed Runtime, services,
and containers are left untouched.

Ctrl-C or disconnect may leave the runner active. The helper attempts cleanup
once, targeting only this run's recorded container ID with its matching
ownership label. It removes source only if execution never began, or the runner
finished and its container stopped; otherwise it retains source and prints the
resource identifiers. Inspect the run before rerunning.

For manual cleanup on the remote host, use the printed identifiers. If the
exact allocation output was lost, list candidates with
`ls -d /tmp/livepeer-runtime-<run-id>.*` and inspect each candidate to identify
this run; do not delete by prefix. Obtain the container ID from
`docker inspect <container-name>` or `<remote-directory>/container.cid`, and
verify its `livepeer.runtime-test` label matches the run ID before removing it:

```sh
docker inspect <container-name>  # Check ID and ownership label.
cat <remote-directory>/container.cid  # Alternative source of the ID.
docker rm -f <container-id>  # Only after verifying its label.
cat <remote-directory>/runner.finished  # Written when the runner finishes.
# If completion is unknown, inspect and wait for this run's processes.
# Once no process uses the source, remove only the identified directory.
rm -rf -- <remote-directory>
```

Do not use global Docker pruning or remove another run's resources. Run full
installer, reboot, and gVisor acceptance on a disposable supported host; see
[Runtime verification](runtime/README.md#verification).
