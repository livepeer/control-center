-- UP
-- Retain storage identity after the active machine is removed.
CREATE TABLE lpcc.onchain_configs (
 node_id TEXT NOT NULL, generation BIGINT NOT NULL CHECK(generation>0), config JSONB NOT NULL,
 PRIMARY KEY(node_id,generation)
);
CREATE INDEX onchain_configs_generation ON lpcc.onchain_configs(generation);
CREATE TABLE lpcc.onchain_grants (
 grant_id UUID PRIMARY KEY, issued_sequence BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE, node_id TEXT NOT NULL, epoch UUID NOT NULL,
 onchain_generation BIGINT NOT NULL, config_digest TEXT NOT NULL,
 pod_uid TEXT NOT NULL, launch_id TEXT NOT NULL, process_id TEXT NOT NULL,
 ready_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
 UNIQUE(node_id,epoch,onchain_generation,pod_uid,launch_id,process_id)
);
CREATE INDEX onchain_grants_machine ON lpcc.onchain_grants(node_id,epoch);

CREATE FUNCTION lpcc.revoke_onchain_grants() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 UPDATE lpcc.onchain_grants SET revoked_at=COALESCE(revoked_at,now()) WHERE node_id=OLD.node_id AND epoch=OLD.enrollment_epoch;
 RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION lpcc.revoke_onchain_grants() FROM PUBLIC;
CREATE TRIGGER onchain_retirement BEFORE DELETE ON lpcc.machines
 FOR EACH ROW EXECUTE FUNCTION lpcc.revoke_onchain_grants();
ALTER TABLE lpcc.onchain_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.onchain_grants ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON lpcc.onchain_configs,lpcc.onchain_grants FROM PUBLIC;
REVOKE ALL ON SEQUENCE lpcc.onchain_grants_issued_sequence_seq FROM PUBLIC;
DO $$ DECLARE r TEXT;
BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON lpcc.onchain_configs,lpcc.onchain_grants FROM %I',r);
   EXECUTE format('REVOKE ALL ON SEQUENCE lpcc.onchain_grants_issued_sequence_seq FROM %I',r);
  END IF;
 END LOOP;
END $$;
-- DOWN
DO $$ BEGIN
 IF EXISTS(SELECT FROM lpcc.onchain_configs)
    OR EXISTS(SELECT FROM lpcc.onchain_grants) THEN
  RAISE EXCEPTION 'retain onchain schema while onchain history exists';
 END IF;
END $$;
DROP TRIGGER onchain_retirement ON lpcc.machines;
DROP FUNCTION lpcc.revoke_onchain_grants();
DROP TABLE lpcc.onchain_configs,lpcc.onchain_grants;
