-- UP
ALTER TABLE lpcc.machine_states ADD COLUMN apps_generation BIGINT NOT NULL DEFAULT 0 CHECK(apps_generation>=0);
ALTER TABLE lpcc.machine_states ADD COLUMN apps_error TEXT;
CREATE TABLE lpcc.machine_app_versions (
 node_id TEXT NOT NULL, revision_id UUID NOT NULL REFERENCES lpcc.app_revisions(revision_id),
 generation BIGINT NOT NULL CHECK(generation>0), intent JSONB NOT NULL,
 actor_id TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(node_id,revision_id,generation),
 FOREIGN KEY(node_id) REFERENCES lpcc.enrollments(node_id),
 CHECK(intent->>'revision_id'=revision_id::text AND (intent->>'generation')::bigint=generation),
 CHECK(intent->>'desired' IN ('present','absent')),
 CHECK((intent->>'activation_generation')::bigint BETWEEN 1 AND generation)
);
CREATE INDEX machine_app_latest ON lpcc.machine_app_versions(node_id,revision_id,generation DESC);
CREATE VIEW lpcc.machine_app_heads WITH (security_invoker=true) AS
 SELECT DISTINCT ON(node_id,revision_id) * FROM lpcc.machine_app_versions
 ORDER BY node_id,revision_id,generation DESC;
CREATE TABLE lpcc.machine_app_deliveries (
 node_id TEXT NOT NULL, apps_digest TEXT NOT NULL CHECK(apps_digest ~ '^sha256:[0-9a-f]{64}$'),
 bundle_sha256 TEXT NOT NULL CHECK(bundle_sha256 ~ '^[0-9a-f]{64}$'),
 apps_generation BIGINT NOT NULL CHECK(apps_generation>0), entries JSONB NOT NULL,
 terminal BOOLEAN NOT NULL, published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(node_id,apps_digest,bundle_sha256),
 FOREIGN KEY(node_id) REFERENCES lpcc.enrollments(node_id)
);
CREATE TABLE lpcc.machine_app_completions (
 node_id TEXT NOT NULL, revision_id UUID NOT NULL, generation BIGINT NOT NULL,
 activation_generation BIGINT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('applied','removed')),
 apps_digest TEXT NOT NULL, received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(node_id,revision_id,generation,phase),
 FOREIGN KEY(node_id,revision_id,generation) REFERENCES lpcc.machine_app_versions(node_id,revision_id,generation)
);
CREATE TABLE lpcc.machine_app_diagnostics (
 node_id TEXT NOT NULL, revision_id UUID NOT NULL, generation BIGINT NOT NULL,
 reason TEXT NOT NULL CHECK(reason ~ '^[a-z][a-z0-9_]{0,63}$'), received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(node_id,revision_id),
 FOREIGN KEY(node_id,revision_id,generation) REFERENCES lpcc.machine_app_versions(node_id,revision_id,generation)
);
CREATE TRIGGER immutable_app_intent BEFORE UPDATE OR DELETE ON lpcc.machine_app_versions FOR EACH ROW EXECUTE FUNCTION lpcc.immutable_app_revision();
CREATE TRIGGER immutable_app_completion BEFORE UPDATE OR DELETE ON lpcc.machine_app_completions FOR EACH ROW EXECUTE FUNCTION lpcc.immutable_app_revision();
CREATE TRIGGER immutable_app_delivery BEFORE UPDATE OR DELETE ON lpcc.machine_app_deliveries FOR EACH ROW EXECUTE FUNCTION lpcc.immutable_app_revision();
-- Both administrative removal and auth.users cascades use this transition.
CREATE FUNCTION lpcc.remove_machine_apps(n TEXT,actor TEXT) RETURNS integer LANGUAGE plpgsql
 SET search_path=pg_catalog,lpcc AS $$
DECLARE changed integer;
BEGIN
 INSERT INTO lpcc.machine_app_versions(node_id,revision_id,generation,intent,actor_id)
 SELECT node_id,revision_id,generation+1,
 (intent-ARRAY['revision','replicas','start_after','replacement']) || jsonb_build_object('generation',generation+1,'desired','absent','start_allowed',false),actor
 FROM lpcc.machine_app_heads WHERE node_id=n AND intent->>'desired'='present';
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed>0 THEN
  UPDATE lpcc.machine_states SET apps_generation=apps_generation+1,revision=revision+1,apps_error=NULL WHERE node_id=n;
 END IF;
 RETURN changed;
END $$;
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
ALTER TABLE lpcc.machine_app_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.machine_app_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.machine_app_completions ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.machine_app_diagnostics ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON lpcc.machine_app_versions,lpcc.machine_app_heads,lpcc.machine_app_deliveries,lpcc.machine_app_completions,lpcc.machine_app_diagnostics FROM PUBLIC;
REVOKE ALL ON FUNCTION lpcc.remove_machine_apps(TEXT,TEXT) FROM PUBLIC;
DO $$ DECLARE r TEXT;
BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON lpcc.machine_app_versions,lpcc.machine_app_heads,lpcc.machine_app_deliveries,lpcc.machine_app_completions,lpcc.machine_app_diagnostics FROM %I',r);
   EXECUTE format('REVOKE ALL ON FUNCTION lpcc.remove_machine_apps(TEXT,TEXT) FROM %I',r);
  END IF;
 END LOOP;
END $$;
-- DOWN
DO $$ BEGIN
 IF EXISTS(SELECT FROM lpcc.machine_app_versions) THEN RAISE EXCEPTION 'retain assignment schema while history exists'; END IF;
END $$;
CREATE OR REPLACE FUNCTION lpcc.retire_machine() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,lpcc AS $$
BEGIN
 INSERT INTO lpcc.enrollments(node_id,owner_id,fingerprint,hostname,install_dir,k3s_version,credential_version,retired_at)
 VALUES(OLD.node_id,OLD.owner_id,OLD.fingerprint,OLD.hostname,OLD.install_dir,OLD.k3s_version,OLD.credential_version,now())
 ON CONFLICT(node_id) DO UPDATE SET retired_at=COALESCE(lpcc.enrollments.retired_at,now()),credential_version=OLD.credential_version;
 UPDATE lpcc.machine_states SET rollout=jsonb_set(rollout,'{lifecycle}','"removed"')-'rollout_reason',state=jsonb_set(state,'{ready}','false'),revision=revision+1,next_attempt_at=now() WHERE node_id=OLD.node_id;
 RETURN OLD;
END $$;
DROP FUNCTION lpcc.remove_machine_apps(TEXT,TEXT);
DROP VIEW lpcc.machine_app_heads;
DROP TABLE lpcc.machine_app_diagnostics,lpcc.machine_app_completions,lpcc.machine_app_deliveries,lpcc.machine_app_versions;
ALTER TABLE lpcc.machine_states DROP COLUMN apps_generation,DROP COLUMN apps_error;
