-- UP
-- Retain storage identity and recovery state after the active machine is removed.
CREATE TABLE lpcc.onchain_revision (id BOOLEAN PRIMARY KEY DEFAULT true CHECK(id), revision BIGINT NOT NULL DEFAULT 0);
INSERT INTO lpcc.onchain_revision DEFAULT VALUES;
CREATE TABLE lpcc.onchain_configs (
 node_id TEXT NOT NULL, generation BIGINT NOT NULL, config JSONB NOT NULL,
 PRIMARY KEY(node_id,generation)
);
CREATE TABLE lpcc.onchain_state (
 node_id TEXT PRIMARY KEY CHECK(node_id ~ '^lp-[0-9a-f]{16}$'),
 recipient TEXT NOT NULL DEFAULT '', chain_id BIGINT NOT NULL DEFAULT 0, controller TEXT NOT NULL DEFAULT '',
 generation BIGINT NOT NULL CHECK(generation>0),
 initialized BOOLEAN NOT NULL DEFAULT false, drained BOOLEAN NOT NULL DEFAULT false, recovery_required BOOLEAN NOT NULL DEFAULT false,
 FOREIGN KEY(node_id,generation) REFERENCES lpcc.onchain_configs(node_id,generation)
);
CREATE TABLE lpcc.onchain_secrets (reference TEXT PRIMARY KEY, fingerprint TEXT NOT NULL);
CREATE TABLE lpcc.onchain_grants (
 grant_id UUID PRIMARY KEY, issued_sequence BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE, node_id TEXT NOT NULL, epoch UUID NOT NULL,
 onchain_generation BIGINT NOT NULL, config_digest TEXT NOT NULL,
 pod_uid TEXT NOT NULL, launch_id TEXT NOT NULL, process_id TEXT NOT NULL,
 observed_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
 UNIQUE(node_id,epoch,onchain_generation,pod_uid,launch_id,process_id)
);
CREATE INDEX onchain_grants_machine ON lpcc.onchain_grants(node_id,epoch);

CREATE OR REPLACE FUNCTION lpcc.capture_runtime_retirement() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 UPDATE lpcc.onchain_grants SET revoked_at=COALESCE(revoked_at,now()) WHERE node_id=OLD.node_id AND epoch=OLD.enrollment_epoch;
 UPDATE lpcc.onchain_state b SET recovery_required=b.recovery_required OR (NOT b.drained AND (b.initialized OR c.config->>'mode'='onchain') AND NOT EXISTS(SELECT FROM lpcc.machine_states WHERE node_id=OLD.node_id AND epoch=OLD.enrollment_epoch AND rollout->>'onchain_settled'='true'))
 FROM lpcc.onchain_configs c WHERE b.node_id=OLD.node_id AND c.node_id=b.node_id AND c.generation=b.generation;
 UPDATE lpcc.enrollments e SET retained_bundle=c.bundle
 FROM lpcc.machine_configs c
 WHERE e.node_id=OLD.node_id AND e.epoch=OLD.enrollment_epoch AND c.node_id=OLD.node_id
 AND e.retained_bundle IS NULL;
 RETURN OLD;
END $$;
ALTER TABLE lpcc.onchain_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.onchain_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.onchain_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.onchain_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.onchain_grants ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON lpcc.onchain_revision,lpcc.onchain_state,lpcc.onchain_configs,lpcc.onchain_secrets,lpcc.onchain_grants FROM PUBLIC;
REVOKE ALL ON SEQUENCE lpcc.onchain_grants_issued_sequence_seq FROM PUBLIC;
DO $$ DECLARE r TEXT;
BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON lpcc.onchain_revision,lpcc.onchain_state,lpcc.onchain_configs,lpcc.onchain_secrets,lpcc.onchain_grants FROM %I',r);
   EXECUTE format('REVOKE ALL ON SEQUENCE lpcc.onchain_grants_issued_sequence_seq FROM %I',r);
  END IF;
 END LOOP;
END $$;
-- DOWN
DO $$ BEGIN
 IF EXISTS(SELECT FROM lpcc.onchain_state) OR EXISTS(SELECT FROM lpcc.onchain_configs)
    OR EXISTS(SELECT FROM lpcc.onchain_secrets) OR EXISTS(SELECT FROM lpcc.onchain_grants) THEN
  RAISE EXCEPTION 'retain onchain schema while onchain history exists';
 END IF;
END $$;
CREATE OR REPLACE FUNCTION lpcc.capture_runtime_retirement() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 UPDATE lpcc.enrollments e SET retained_bundle=c.bundle
 FROM lpcc.machine_configs c
 WHERE e.node_id=OLD.node_id AND e.epoch=OLD.enrollment_epoch AND c.node_id=OLD.node_id
 AND e.retained_bundle IS NULL;
 RETURN OLD;
END $$;
DROP TABLE lpcc.onchain_revision,lpcc.onchain_state,lpcc.onchain_configs,lpcc.onchain_secrets,lpcc.onchain_grants;
