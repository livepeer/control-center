-- UP
ALTER TABLE lpcc.enrollments ADD COLUMN retained_bundle BYTEA;

-- Runs after retire_machine has captured the enrollment, before the config FK
-- cascade. The write-once terminal bundle must still be able to retain Node/routes.
CREATE FUNCTION lpcc.capture_runtime_retirement() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 UPDATE lpcc.payment_grants SET revoked_at=COALESCE(revoked_at,now()) WHERE node_id=OLD.node_id AND epoch=OLD.enrollment_epoch;
 UPDATE lpcc.payment_machines SET recovery_required=recovery_required OR (NOT drained AND (initialized OR config->>'mode'='paid') AND NOT EXISTS(SELECT FROM lpcc.machine_states WHERE node_id=OLD.node_id AND epoch=OLD.enrollment_epoch AND rollout->>'payment_settled'='true')) WHERE node_id=OLD.node_id;
 UPDATE lpcc.enrollments e SET retained_bundle=c.bundle
 FROM lpcc.machine_configs c
 WHERE e.node_id=OLD.node_id AND e.epoch=OLD.enrollment_epoch AND c.node_id=OLD.node_id
 AND e.retained_bundle IS NULL;
 RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION lpcc.capture_runtime_retirement() FROM PUBLIC;
CREATE TRIGGER runtime_retirement BEFORE DELETE ON lpcc.machines
 FOR EACH ROW EXECUTE FUNCTION lpcc.capture_runtime_retirement();

-- DOWN
DO $$ BEGIN
 IF EXISTS(SELECT FROM lpcc.enrollments WHERE retained_bundle IS NOT NULL AND removal_ack_at IS NULL) THEN
  RAISE EXCEPTION 'retain Runtime retirement snapshot until cleanup acknowledgement';
 END IF;
END $$;
DROP TRIGGER runtime_retirement ON lpcc.machines;
DROP FUNCTION lpcc.capture_runtime_retirement();
ALTER TABLE lpcc.enrollments DROP COLUMN retained_bundle;
