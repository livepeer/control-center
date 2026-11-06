# Livepeer Control Center

Control Center manages onboarding and configuration for Livepeer orchestrators.

## Run locally

Requires Go 1.27.3+, Node.js 22.12+, TLS-enabled PostgreSQL, and authentication.
Configure credentials and sign-in using
[api/config.example.toml](api/config.example.toml) and the
[operations runbook](docs/operations.md). Then run:

```sh
cd api && go mod download && cd ..
npm --prefix ui ci
make api
# In another terminal:
make ui
```

Open [http://localhost:5173](http://localhost:5173). Migrations run on startup.

Administrators manage access and inspect fleet metadata; ordinary accounts
retain their inventory and enrollment access. Note that administrator status
grants no machine-token, host, Kubernetes, SSH, payment, or operator-secret
access. Runtime configuration still requires the machine's credential.

## Connect a node

On a Debian or Ubuntu amd64 systemd host with 2 CPUs, 4 GiB RAM, and 10 GiB
free, sign in and run the bootstrap command from the runtime checkout:

```sh
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
