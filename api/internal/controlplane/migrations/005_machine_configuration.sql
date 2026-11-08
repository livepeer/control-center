-- UP
ALTER TABLE lpcc.machine_tunnels RENAME TO machine_states;
ALTER TABLE lpcc.machine_states ADD COLUMN rollout JSONB NOT NULL DEFAULT '{"lifecycle":"active","generation":1}';
UPDATE lpcc.machine_states SET rollout = jsonb_strip_nulls(jsonb_build_object(
 'lifecycle',COALESCE(state->'lifecycle','"active"'::jsonb),
 'generation',COALESCE(state->'generation','1'::jsonb),
 'drain_requested',state->'drain_requested','drain_started_at',state->'drain_started_at',
 'target',state->'endpoint_drain_url','held_orchestrator',state->'held_orchestrator',
 'pending_config_digest',state->'pending_config_digest','approved_config_digest',state->'approved_config_digest',
 'rollout_reason',CASE WHEN state->>'reason' IN ('drain_pending','drain_timeout') THEN state->'reason' END));
UPDATE lpcc.machine_states SET state=jsonb_set(state,'{ready_generation}',COALESCE(state->'generation','1'::jsonb));
UPDATE lpcc.machine_states SET state=state-ARRAY['lifecycle','generation','drain_requested','drain_started_at','held_orchestrator','pending_config_digest','approved_config_digest','endpoint_drain_url'];
CREATE OR REPLACE FUNCTION lpcc.retire_machine() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 INSERT INTO lpcc.enrollments(node_id,epoch,owner_id,fingerprint,hostname,install_dir,k3s_version,credential_version,retired_at)
 VALUES(OLD.node_id,OLD.enrollment_epoch,OLD.owner_id,OLD.fingerprint,OLD.hostname,OLD.install_dir,OLD.k3s_version,OLD.credential_version,now())
 ON CONFLICT(node_id,epoch) DO UPDATE SET retired_at=COALESCE(lpcc.enrollments.retired_at,now()),credential_version=OLD.credential_version;
 UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{lifecycle}','"removed"')-'rollout_reason',state=jsonb_set(state,'{ready}','false'),
 revision=revision+1,next_attempt_at=now() WHERE node_id=OLD.node_id AND epoch=OLD.enrollment_epoch;
 RETURN OLD;
END $$;
-- DOWN
UPDATE lpcc.machine_states SET state='{"endpoint_generation":1,"credential_generation":1,"source_generation":1,"access_version":1,"resources":{}}'::jsonb || state;
UPDATE lpcc.machine_states SET state=jsonb_set(state,'{ready}','false') WHERE COALESCE((state->>'ready_generation')::bigint,0)<>(rollout->>'generation')::bigint;
UPDATE lpcc.machine_states SET state=(state-'ready_generation') || (rollout-'target'-'rollout_reason') || jsonb_strip_nulls(jsonb_build_object('endpoint_drain_url',rollout->'target','reason',COALESCE(CASE WHEN rollout->>'lifecycle'<>'removed' THEN NULLIF(rollout->>'rollout_reason','') END,state->>'reason')));
ALTER TABLE lpcc.machine_states DROP COLUMN rollout;
ALTER TABLE lpcc.machine_states RENAME TO machine_tunnels;
CREATE OR REPLACE FUNCTION lpcc.retire_machine() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 INSERT INTO lpcc.enrollments(node_id,epoch,owner_id,fingerprint,hostname,install_dir,k3s_version,credential_version,retired_at)
 VALUES(OLD.node_id,OLD.enrollment_epoch,OLD.owner_id,OLD.fingerprint,OLD.hostname,OLD.install_dir,OLD.k3s_version,OLD.credential_version,now())
 ON CONFLICT(node_id,epoch) DO UPDATE SET retired_at=COALESCE(lpcc.enrollments.retired_at,now()),credential_version=OLD.credential_version;
 UPDATE lpcc.machine_tunnels SET state=jsonb_set(jsonb_set(state,'{lifecycle}','"removed"'),'{ready}','false'),
 revision=revision+1,next_attempt_at=now() WHERE node_id=OLD.node_id AND epoch=OLD.enrollment_epoch;
 RETURN OLD;
END $$;
