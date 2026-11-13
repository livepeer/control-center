-- UP
DO $$ BEGIN
 IF EXISTS(SELECT FROM lpcc.machines) OR EXISTS(SELECT FROM lpcc.enrollments)
 OR EXISTS(SELECT FROM lpcc.operator_app_policy) OR EXISTS(SELECT FROM lpcc.operator_policy_generation)
 OR EXISTS(SELECT FROM lpcc.enrollment_audit) OR EXISTS(SELECT FROM lpcc.revoked_enrollment_grants) THEN
 RAISE EXCEPTION 'orchestrator ownership requires a fresh deployment';
 END IF;
END $$;
CREATE TABLE lpcc.orchestrators (
 address text PRIMARY KEY CHECK(address ~ '^0x[0-9a-f]{40}$' AND address <> '0x0000000000000000000000000000000000000000'),
 display_name text CHECK(length(display_name) BETWEEN 1 AND 120)
);
CREATE TABLE lpcc.orchestrator_memberships (
 user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
 orchestrator_address text NOT NULL REFERENCES lpcc.orchestrators(address),
 PRIMARY KEY(user_id,orchestrator_address)
);
ALTER TABLE lpcc.machines DROP CONSTRAINT machines_owner_id_fkey;
DROP INDEX lpcc.machines_owner;
ALTER TABLE lpcc.machines RENAME COLUMN owner_id TO orchestrator_address;
ALTER TABLE lpcc.machines ALTER COLUMN orchestrator_address TYPE text USING orchestrator_address::text;
ALTER TABLE lpcc.machines ADD FOREIGN KEY(orchestrator_address) REFERENCES lpcc.orchestrators(address);
ALTER TABLE lpcc.enrollments RENAME COLUMN owner_id TO orchestrator_address;
ALTER TABLE lpcc.enrollments ALTER COLUMN orchestrator_address TYPE text USING orchestrator_address::text;
ALTER TABLE lpcc.enrollments ADD FOREIGN KEY(orchestrator_address) REFERENCES lpcc.orchestrators(address);
ALTER TABLE lpcc.operator_app_policy RENAME COLUMN owner_id TO orchestrator_address;
ALTER TABLE lpcc.operator_app_policy ALTER COLUMN orchestrator_address TYPE text USING orchestrator_address::text;
ALTER TABLE lpcc.operator_app_policy ADD FOREIGN KEY(orchestrator_address) REFERENCES lpcc.orchestrators(address);
ALTER TABLE lpcc.operator_policy_generation RENAME COLUMN owner_id TO orchestrator_address;
ALTER TABLE lpcc.operator_policy_generation ALTER COLUMN orchestrator_address TYPE text USING orchestrator_address::text;
ALTER TABLE lpcc.operator_policy_generation ADD FOREIGN KEY(orchestrator_address) REFERENCES lpcc.orchestrators(address);
CREATE INDEX machines_orchestrator ON lpcc.machines(orchestrator_address,created_at DESC);
ALTER TABLE lpcc.revoked_enrollment_grants RENAME COLUMN owner_id TO actor_user_id;
ALTER TABLE lpcc.revoked_enrollment_grants ADD COLUMN orchestrator_address text NOT NULL REFERENCES lpcc.orchestrators(address);
ALTER TABLE lpcc.enrollment_audit RENAME COLUMN owner_id TO actor_user_id;
ALTER TABLE lpcc.enrollment_audit ADD COLUMN orchestrator_address text NOT NULL REFERENCES lpcc.orchestrators(address);
CREATE OR REPLACE FUNCTION lpcc.retire_machine() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 INSERT INTO lpcc.enrollments(node_id,orchestrator_address,fingerprint,hostname,install_dir,k3s_version,credential_version,retired_at)
 VALUES(OLD.node_id,OLD.orchestrator_address,OLD.fingerprint,OLD.hostname,OLD.install_dir,OLD.k3s_version,OLD.credential_version,now())
 ON CONFLICT(node_id) DO UPDATE SET retired_at=COALESCE(lpcc.enrollments.retired_at,now()),credential_version=OLD.credential_version;
 PERFORM lpcc.remove_machine_apps(OLD.node_id,'system:machine-retirement');
 UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{lifecycle}','"removed"')-'rollout_reason',state=jsonb_set(state,'{ready}','false'),
 revision=revision+1,next_attempt_at=now() WHERE node_id=OLD.node_id;
 RETURN OLD;
END $$;
ALTER TABLE lpcc.orchestrators ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.orchestrator_memberships ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON lpcc.orchestrators,lpcc.orchestrator_memberships FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
 IF EXISTS(SELECT FROM pg_roles WHERE rolname=r) THEN
 EXECUTE format('REVOKE ALL ON lpcc.orchestrators,lpcc.orchestrator_memberships FROM %I',r);
 END IF;
 END LOOP;
END $$;
-- DOWN
DO $$ BEGIN
 IF EXISTS(SELECT FROM lpcc.machines) OR EXISTS(SELECT FROM lpcc.enrollments)
 OR EXISTS(SELECT FROM lpcc.operator_app_policy) OR EXISTS(SELECT FROM lpcc.operator_policy_generation)
 OR EXISTS(SELECT FROM lpcc.enrollment_audit) OR EXISTS(SELECT FROM lpcc.revoked_enrollment_grants) THEN
 RAISE EXCEPTION 'orchestrator ownership requires a fresh deployment';
 END IF;
END $$;
ALTER TABLE lpcc.revoked_enrollment_grants DROP COLUMN orchestrator_address;
ALTER TABLE lpcc.revoked_enrollment_grants RENAME COLUMN actor_user_id TO owner_id;
ALTER TABLE lpcc.enrollment_audit DROP COLUMN orchestrator_address;
ALTER TABLE lpcc.enrollment_audit RENAME COLUMN actor_user_id TO owner_id;
DROP INDEX lpcc.machines_orchestrator;
ALTER TABLE lpcc.machines DROP CONSTRAINT machines_orchestrator_address_fkey;
ALTER TABLE lpcc.machines ALTER COLUMN orchestrator_address TYPE uuid USING orchestrator_address::uuid;
ALTER TABLE lpcc.machines RENAME COLUMN orchestrator_address TO owner_id;
ALTER TABLE lpcc.enrollments DROP CONSTRAINT enrollments_orchestrator_address_fkey;
ALTER TABLE lpcc.enrollments ALTER COLUMN orchestrator_address TYPE uuid USING orchestrator_address::uuid;
ALTER TABLE lpcc.enrollments RENAME COLUMN orchestrator_address TO owner_id;
ALTER TABLE lpcc.operator_app_policy DROP CONSTRAINT operator_app_policy_orchestrator_address_fkey;
ALTER TABLE lpcc.operator_app_policy ALTER COLUMN orchestrator_address TYPE uuid USING orchestrator_address::uuid;
ALTER TABLE lpcc.operator_app_policy RENAME COLUMN orchestrator_address TO owner_id;
ALTER TABLE lpcc.operator_policy_generation DROP CONSTRAINT operator_policy_generation_orchestrator_address_fkey;
ALTER TABLE lpcc.operator_policy_generation ALTER COLUMN orchestrator_address TYPE uuid USING orchestrator_address::uuid;
ALTER TABLE lpcc.operator_policy_generation RENAME COLUMN orchestrator_address TO owner_id;
ALTER TABLE lpcc.machines ADD FOREIGN KEY(owner_id) REFERENCES auth.users(id) ON DELETE CASCADE;
CREATE INDEX machines_owner ON lpcc.machines(owner_id,created_at DESC);
CREATE OR REPLACE FUNCTION lpcc.retire_machine() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 INSERT INTO lpcc.enrollments(node_id,owner_id,fingerprint,hostname,install_dir,k3s_version,credential_version,retired_at)
 VALUES(OLD.node_id,OLD.owner_id,OLD.fingerprint,OLD.hostname,OLD.install_dir,OLD.k3s_version,OLD.credential_version,now())
 ON CONFLICT(node_id) DO UPDATE SET retired_at=COALESCE(lpcc.enrollments.retired_at,now()),credential_version=OLD.credential_version;
 PERFORM lpcc.remove_machine_apps(OLD.node_id,'system:machine-retirement');
 UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{lifecycle}','"removed"')-'rollout_reason',state=jsonb_set(state,'{ready}','false'),
 revision=revision+1,next_attempt_at=now() WHERE node_id=OLD.node_id;
 RETURN OLD;
END $$;
DROP TABLE lpcc.orchestrator_memberships,lpcc.orchestrators;
