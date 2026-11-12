-- UP
-- Payment bindings deliberately survive enrollment and Auth account deletion.
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

CREATE OR REPLACE FUNCTION lpcc.capture_runtime_retirement() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 UPDATE lpcc.payment_grants SET revoked_at=COALESCE(revoked_at,now()) WHERE node_id=OLD.node_id AND epoch=OLD.enrollment_epoch;
 UPDATE lpcc.payment_machines SET recovery_required=recovery_required OR (NOT drained AND (initialized OR config->>'mode'='onchain') AND NOT EXISTS(SELECT FROM lpcc.machine_states WHERE node_id=OLD.node_id AND epoch=OLD.enrollment_epoch AND rollout->>'payment_settled'='true')) WHERE node_id=OLD.node_id;
 UPDATE lpcc.enrollments e SET retained_bundle=c.bundle
 FROM lpcc.machine_configs c
 WHERE e.node_id=OLD.node_id AND e.epoch=OLD.enrollment_epoch AND c.node_id=OLD.node_id
 AND e.retained_bundle IS NULL;
 RETURN OLD;
END $$;
ALTER TABLE lpcc.payment_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.payment_machines ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.payment_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.payment_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.payment_grants ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON lpcc.payment_revision,lpcc.payment_machines,lpcc.payment_versions,lpcc.payment_secrets,lpcc.payment_grants FROM PUBLIC;
REVOKE ALL ON SEQUENCE lpcc.payment_grants_issued_sequence_seq FROM PUBLIC;
DO $$ DECLARE r TEXT;
BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON lpcc.payment_revision,lpcc.payment_machines,lpcc.payment_versions,lpcc.payment_secrets,lpcc.payment_grants FROM %I',r);
   EXECUTE format('REVOKE ALL ON SEQUENCE lpcc.payment_grants_issued_sequence_seq FROM %I',r);
  END IF;
 END LOOP;
END $$;
-- DOWN
DO $$ BEGIN
 IF EXISTS(SELECT FROM lpcc.payment_machines) OR EXISTS(SELECT FROM lpcc.payment_versions)
    OR EXISTS(SELECT FROM lpcc.payment_secrets) OR EXISTS(SELECT FROM lpcc.payment_grants) THEN
  RAISE EXCEPTION 'retain payment schema while payment history exists';
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
DROP TABLE lpcc.payment_revision,lpcc.payment_machines,lpcc.payment_versions,lpcc.payment_secrets,lpcc.payment_grants;
