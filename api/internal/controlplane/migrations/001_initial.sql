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
-- Payment infrastructure is part of the fresh-install schema. These records
-- deliberately survive enrollment and Auth account deletion.
CREATE TABLE lpcc.payment_revision (id BOOLEAN PRIMARY KEY DEFAULT true CHECK(id), revision BIGINT NOT NULL DEFAULT 0);
INSERT INTO lpcc.payment_revision DEFAULT VALUES;
CREATE TABLE lpcc.payment_machines (
 node_id TEXT PRIMARY KEY CHECK(node_id ~ '^lp-[0-9a-f]{16}$'),
 recipient TEXT NOT NULL DEFAULT '', chain_id BIGINT NOT NULL DEFAULT 0, controller TEXT NOT NULL DEFAULT '',
 generation BIGINT NOT NULL CHECK(generation>0), config JSONB NOT NULL,
 initialized BOOLEAN NOT NULL DEFAULT false, drained BOOLEAN NOT NULL DEFAULT false, recovery_required BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE lpcc.payment_versions (
 node_id TEXT NOT NULL, generation BIGINT NOT NULL, config JSONB NOT NULL,
 PRIMARY KEY(node_id,generation)
);
CREATE TABLE lpcc.payment_secrets (reference TEXT PRIMARY KEY, fingerprint TEXT NOT NULL);
CREATE TABLE lpcc.payment_grants (
 grant_id UUID PRIMARY KEY, issued_sequence BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE, node_id TEXT NOT NULL, epoch UUID NOT NULL,
 payment_generation BIGINT NOT NULL, config_digest TEXT NOT NULL,
 pod_uid TEXT NOT NULL, launch_id TEXT NOT NULL, process_id TEXT NOT NULL,
 observed_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
 UNIQUE(node_id,epoch,payment_generation,pod_uid,launch_id,process_id)
);
CREATE INDEX payment_grants_machine ON lpcc.payment_grants(node_id,epoch);
-- DOWN
DROP TABLE lpcc.payment_grants,lpcc.payment_secrets,lpcc.payment_versions,lpcc.payment_machines,lpcc.payment_revision;
DROP TABLE lpcc.machine_configs;
DROP TABLE lpcc.machines;
