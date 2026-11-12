-- UP
ALTER TABLE lpcc.machine_tunnels RENAME TO machine_states;
ALTER TABLE lpcc.machine_states ADD COLUMN rollout JSONB NOT NULL DEFAULT '{"lifecycle":"active","generation":1}';
CREATE OR REPLACE FUNCTION lpcc.retire_machine() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 INSERT INTO lpcc.enrollments(node_id,owner_id,fingerprint,hostname,install_dir,k3s_version,credential_version,retired_at)
 VALUES(OLD.node_id,OLD.owner_id,OLD.fingerprint,OLD.hostname,OLD.install_dir,OLD.k3s_version,OLD.credential_version,now())
 ON CONFLICT(node_id) DO UPDATE SET retired_at=COALESCE(lpcc.enrollments.retired_at,now()),credential_version=OLD.credential_version;
 UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{lifecycle}','"removed"')-'rollout_reason',state=jsonb_set(state,'{ready}','false'),
 revision=revision+1,next_attempt_at=now() WHERE node_id=OLD.node_id;
 RETURN OLD;
END $$;
-- DOWN
DO $$ BEGIN
 IF EXISTS(SELECT FROM lpcc.machine_states) THEN
  RAISE EXCEPTION 'retain machine configuration schema while enrollment state exists';
 END IF;
END $$;
ALTER TABLE lpcc.machine_states DROP COLUMN rollout;
ALTER TABLE lpcc.machine_states RENAME TO machine_tunnels;
CREATE OR REPLACE FUNCTION lpcc.retire_machine() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 INSERT INTO lpcc.enrollments(node_id,owner_id,fingerprint,hostname,install_dir,k3s_version,credential_version,retired_at)
 VALUES(OLD.node_id,OLD.owner_id,OLD.fingerprint,OLD.hostname,OLD.install_dir,OLD.k3s_version,OLD.credential_version,now())
 ON CONFLICT(node_id) DO UPDATE SET retired_at=COALESCE(lpcc.enrollments.retired_at,now()),credential_version=OLD.credential_version;
 UPDATE lpcc.machine_tunnels SET state=jsonb_set(jsonb_set(state,'{lifecycle}','"removed"'),'{ready}','false'),
 revision=revision+1,next_attempt_at=now() WHERE node_id=OLD.node_id;
 RETURN OLD;
END $$;
