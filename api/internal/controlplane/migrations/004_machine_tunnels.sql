-- UP
ALTER TABLE lpcc.machines ADD COLUMN enrollment_epoch UUID NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE lpcc.machines ADD COLUMN credential_version BIGINT NOT NULL DEFAULT 0 CHECK(credential_version>=0);
ALTER TABLE lpcc.machines ADD COLUMN tunnel_eligible BOOLEAN NOT NULL DEFAULT false;
CREATE TABLE lpcc.enrollments (
 node_id TEXT NOT NULL, epoch UUID NOT NULL, owner_id UUID NOT NULL,
 fingerprint TEXT NOT NULL, hostname TEXT NOT NULL, install_dir TEXT NOT NULL, k3s_version TEXT NOT NULL,
 credential_version BIGINT NOT NULL CHECK(credential_version>=0),
 retired_at TIMESTAMPTZ, removal_ack_at TIMESTAMPTZ,
 terminal_bundle BYTEA, terminal_sha256 TEXT,
 PRIMARY KEY(node_id,epoch),
 CHECK((terminal_bundle IS NULL)=(terminal_sha256 IS NULL))
);
INSERT INTO lpcc.enrollments(node_id,epoch,owner_id,fingerprint,hostname,install_dir,k3s_version,credential_version)
 SELECT node_id,enrollment_epoch,owner_id,fingerprint,hostname,install_dir,k3s_version,credential_version FROM lpcc.machines;
CREATE TABLE lpcc.credential_refreshes (
 node_id TEXT NOT NULL, epoch UUID NOT NULL, operation_id UUID NOT NULL,
 expected_version BIGINT NOT NULL, resulting_version BIGINT NOT NULL,
 PRIMARY KEY(node_id,epoch,operation_id)
);
CREATE TABLE lpcc.machine_reports (
 node_id TEXT NOT NULL, epoch UUID NOT NULL, component TEXT NOT NULL,
 generation BIGINT NOT NULL, credential_version BIGINT NOT NULL,
 report JSONB NOT NULL, received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(node_id,epoch,component)
);
CREATE TABLE lpcc.machine_tunnels (
 node_id TEXT NOT NULL, epoch UUID NOT NULL,
 state JSONB NOT NULL, revision BIGINT NOT NULL DEFAULT 1,
 lease_id UUID, lease_until TIMESTAMPTZ,
 next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(), failures INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(node_id,epoch), FOREIGN KEY(node_id,epoch) REFERENCES lpcc.enrollments(node_id,epoch)
);
CREATE TABLE lpcc.access_credentials (
 node_id TEXT NOT NULL, epoch UUID NOT NULL, version BIGINT NOT NULL,
 provider_id TEXT NOT NULL, key_id TEXT NOT NULL, ciphertext BYTEA NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL, acknowledged_at TIMESTAMPTZ, acknowledged_generation BIGINT, revoked_at TIMESTAMPTZ,
 PRIMARY KEY(node_id,epoch,version), FOREIGN KEY(node_id,epoch) REFERENCES lpcc.enrollments(node_id,epoch)
);
-- Auth deletion bypasses the HTTP API. This trigger captures retirement in the
-- same transaction as the cascade, without relying on an application process.
CREATE FUNCTION lpcc.retire_machine() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 INSERT INTO lpcc.enrollments(node_id,epoch,owner_id,fingerprint,hostname,install_dir,k3s_version,credential_version,retired_at)
 VALUES(OLD.node_id,OLD.enrollment_epoch,OLD.owner_id,OLD.fingerprint,OLD.hostname,OLD.install_dir,OLD.k3s_version,OLD.credential_version,now())
 ON CONFLICT(node_id,epoch) DO UPDATE SET retired_at=COALESCE(lpcc.enrollments.retired_at,now()),credential_version=OLD.credential_version;
 UPDATE lpcc.machine_tunnels SET state=jsonb_set(jsonb_set(state,'{lifecycle}','"removed"'),'{ready}','false'),
 revision=revision+1,next_attempt_at=now() WHERE node_id=OLD.node_id AND epoch=OLD.enrollment_epoch;
 RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION lpcc.retire_machine() FROM PUBLIC;
CREATE TRIGGER retire_machine BEFORE DELETE ON lpcc.machines FOR EACH ROW EXECUTE FUNCTION lpcc.retire_machine();
ALTER TABLE lpcc.enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.credential_refreshes ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.machine_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.machine_tunnels ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.access_credentials ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON lpcc.enrollments,lpcc.credential_refreshes,lpcc.machine_reports,lpcc.machine_tunnels,lpcc.access_credentials FROM PUBLIC;
DO $$ DECLARE browser_role TEXT;
BEGIN
 FOREACH browser_role IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=browser_role) THEN
   EXECUTE format('REVOKE ALL ON SCHEMA lpcc FROM %I',browser_role);
   EXECUTE format('REVOKE ALL ON lpcc.enrollments,lpcc.credential_refreshes,lpcc.machine_reports,lpcc.machine_tunnels,lpcc.access_credentials FROM %I',browser_role);
   EXECUTE format('REVOKE ALL ON FUNCTION lpcc.retire_machine() FROM %I',browser_role);
  END IF;
 END LOOP;
END $$;
-- DOWN
DROP TRIGGER retire_machine ON lpcc.machines;
DROP FUNCTION lpcc.retire_machine();
DROP TABLE lpcc.access_credentials,lpcc.machine_tunnels,lpcc.machine_reports,lpcc.credential_refreshes,lpcc.enrollments;
ALTER TABLE lpcc.machines DROP COLUMN tunnel_eligible,DROP COLUMN credential_version,DROP COLUMN enrollment_epoch;
