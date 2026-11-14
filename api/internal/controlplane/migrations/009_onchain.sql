-- UP
-- Retain storage identity after the active machine is removed.
CREATE TABLE lpcc.onchain_configs (
 fingerprint TEXT NOT NULL, generation BIGINT NOT NULL, config JSONB NOT NULL,
 PRIMARY KEY(fingerprint,generation)
);
CREATE TABLE lpcc.onchain_state (
 fingerprint TEXT PRIMARY KEY CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
 recipient TEXT NOT NULL DEFAULT '', chain_id BIGINT NOT NULL DEFAULT 0, controller TEXT NOT NULL DEFAULT '',
 generation BIGINT NOT NULL CHECK(generation>0),
 initialized BOOLEAN NOT NULL DEFAULT false,
 FOREIGN KEY(fingerprint,generation) REFERENCES lpcc.onchain_configs(fingerprint,generation)
);
CREATE TABLE lpcc.onchain_grants (
 grant_id UUID PRIMARY KEY, issued_sequence BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE, node_id TEXT NOT NULL,
 onchain_generation BIGINT NOT NULL, config_digest TEXT NOT NULL,
 pod_uid TEXT NOT NULL, launch_id TEXT NOT NULL, process_id TEXT NOT NULL,
 ready_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
 UNIQUE(node_id,onchain_generation,pod_uid,launch_id,process_id)
);
CREATE INDEX onchain_grants_machine ON lpcc.onchain_grants(node_id);

CREATE OR REPLACE FUNCTION lpcc.capture_runtime_retirement() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 UPDATE lpcc.onchain_grants SET revoked_at=COALESCE(revoked_at,now()) WHERE node_id=OLD.node_id;
 UPDATE lpcc.enrollments e SET retained_bundle=c.bundle
 FROM lpcc.machine_configs c
 WHERE e.node_id=OLD.node_id AND c.node_id=OLD.node_id
 AND e.retained_bundle IS NULL;
 RETURN OLD;
END $$;
ALTER TABLE lpcc.onchain_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.onchain_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.onchain_grants ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON lpcc.onchain_state,lpcc.onchain_configs,lpcc.onchain_grants FROM PUBLIC;
REVOKE ALL ON SEQUENCE lpcc.onchain_grants_issued_sequence_seq FROM PUBLIC;
DO $$ DECLARE r TEXT;
BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON lpcc.onchain_state,lpcc.onchain_configs,lpcc.onchain_grants FROM %I',r);
   EXECUTE format('REVOKE ALL ON SEQUENCE lpcc.onchain_grants_issued_sequence_seq FROM %I',r);
  END IF;
 END LOOP;
END $$;
-- DOWN
DO $$ BEGIN
 IF EXISTS(SELECT FROM lpcc.onchain_state) OR EXISTS(SELECT FROM lpcc.onchain_configs)
    OR EXISTS(SELECT FROM lpcc.onchain_grants) THEN
  RAISE EXCEPTION 'retain onchain schema while onchain history exists';
 END IF;
END $$;
CREATE OR REPLACE FUNCTION lpcc.capture_runtime_retirement() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 UPDATE lpcc.enrollments e SET retained_bundle=c.bundle
 FROM lpcc.machine_configs c
 WHERE e.node_id=OLD.node_id AND c.node_id=OLD.node_id
 AND e.retained_bundle IS NULL;
 RETURN OLD;
END $$;
DROP TABLE lpcc.onchain_state,lpcc.onchain_configs,lpcc.onchain_grants;
