-- UP
REVOKE ALL ON SCHEMA lpcc FROM PUBLIC;
CREATE TABLE lpcc.machines (
 node_id TEXT PRIMARY KEY CHECK(node_id ~ '^lp-[0-9a-f]{16}$'),
 fingerprint TEXT NOT NULL UNIQUE CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
 owner_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
 hostname TEXT NOT NULL,
 install_dir TEXT NOT NULL,
 k3s_version TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_config_fetch_at TIMESTAMPTZ
);
CREATE INDEX machines_owner ON lpcc.machines(owner_id, created_at DESC);
CREATE TABLE lpcc.machine_configs (
 node_id TEXT PRIMARY KEY REFERENCES lpcc.machines(node_id) ON DELETE CASCADE,
 bundle BYTEA NOT NULL CHECK(octet_length(bundle) BETWEEN 1 AND 16777216),
 sha256 TEXT NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 generated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- DOWN
DROP TABLE lpcc.machine_configs;
DROP TABLE lpcc.machines;
