# Livepeer Control Center

Control Center is an orchestrator control plane for the Livepeer network. It
brings node onboarding and configuration together to manage network capacity.

## Run locally

Requires Go 1.27.3+, Node.js 22.12+, a TLS-enabled PostgreSQL database, and a
Supabase project for authentication.

1. Copy `api/config.example.toml` to `api/config.toml` and follow its setup
   instructions for Supabase and private credential files.
2. Enable email/password and Google sign-in in Supabase Auth. Allow
   `http://localhost:5173/auth/callback` and set the Supabase callback URL in Google.
3. Start the API and UI:

   ```sh
   cd api && go mod download && cd ..
   npm --prefix ui ci
   make api
   # In another terminal:
   make ui
   ```

Open [http://localhost:5173](http://localhost:5173). Migrations run on startup.

## Configuration

Boa loads an optional `config.toml` from the working directory; `make api` runs
in `api`. Use `--config PATH` or `CONTROL_CENTER_CONFIG` to select another file,
or `--config=` to disable file loading. Missing nondefault paths and malformed
files fail. Boa does not search parent directories or load dotenv files.

Ordinary settings use flags > environment > TOML > defaults. Existing environment
names remain supported; run `serve --help` for options. Secrets come from direct
environment variables or files, not flags or inline TOML. A secret and its file
cannot both be set: override the corresponding `_FILE` environment variable to
select another file, or use `--config=` for environment-only configuration.
TOML file paths are relative to the config file; flag and environment paths are
relative to the working directory. `api/config.toml` and `api/secrets/` are ignored
by Git. Migration commands use the same configuration but load only database
settings; for example, `cd api && go run ./cmd/controlcenter migrate status`.

## Connect a node

Sign in and run the bootstrap command from the runtime checkout on a Debian or
Ubuntu amd64 systemd host with 2 CPUs, 4 GiB RAM, and 10 GiB free:

```sh
export LIVEPEER_API_URL=https://your-control-center-api.example
sudo --preserve-env=LIVEPEER_API_URL ./bootstrap-livepeer.sh --token <TOKEN>
```

Set the backend's `PublicAPIURL` to the same address, reachable by the host
and its Kubernetes pods. The console shows nodes and configuration requests.

## Development checks

```sh
make test
make build
```

Database tests skip unless `TEST_DATABASE_URL` points to a disposable PostgreSQL
instance. They never use the application configuration.
