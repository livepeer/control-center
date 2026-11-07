-- UP
CREATE TABLE lpcc.apps (
 name TEXT COLLATE "C" PRIMARY KEY CHECK(name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
 next_revision BIGINT NOT NULL DEFAULT 1 CHECK(next_revision > 0),
 head_revision_id UUID,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE lpcc.app_revisions (
 revision_id UUID PRIMARY KEY,
 app_name TEXT COLLATE "C" NOT NULL REFERENCES lpcc.apps(name),
 revision BIGINT NOT NULL CHECK(revision > 0),
 app_version TEXT NOT NULL CHECK(octet_length(app_version)<=128),
 schema_version INTEGER NOT NULL CHECK(schema_version=1),
 canonical_format TEXT NOT NULL CHECK(canonical_format='app-schema-json-v1'),
 canonical BYTEA NOT NULL CHECK(octet_length(canonical) BETWEEN 1 AND 524288),
 digest TEXT NOT NULL CHECK(digest ~ '^sha256:[0-9a-f]{64}$'),
 source_toml TEXT NOT NULL CHECK(octet_length(source_toml) BETWEEN 1 AND 65536),
 published_by UUID NOT NULL,
 published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(app_name,revision), UNIQUE(app_name,digest), UNIQUE(app_name,revision_id)
);
ALTER TABLE lpcc.apps ADD CONSTRAINT app_head_same_app
 FOREIGN KEY(name,head_revision_id) REFERENCES lpcc.app_revisions(app_name,revision_id);
CREATE TABLE lpcc.app_revision_state (
 revision_id UUID PRIMARY KEY REFERENCES lpcc.app_revisions(revision_id),
 version BIGINT NOT NULL DEFAULT 1,
 retired_at TIMESTAMPTZ,
 retired_by UUID,
 CHECK((version=1 AND retired_at IS NULL AND retired_by IS NULL) OR
       (version=2 AND retired_at IS NOT NULL AND retired_by IS NOT NULL))
);
CREATE FUNCTION lpcc.immutable_app_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'app revisions are immutable'; END $$;
CREATE TRIGGER immutable_revision BEFORE UPDATE OR DELETE ON lpcc.app_revisions
 FOR EACH ROW EXECUTE FUNCTION lpcc.immutable_app_revision();
CREATE FUNCTION lpcc.retire_app_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND OLD.version=1 AND NEW.version=2 AND NEW.revision_id=OLD.revision_id THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'app retirement is permanent';
END $$;
CREATE TRIGGER permanent_retirement BEFORE UPDATE OR DELETE ON lpcc.app_revision_state
 FOR EACH ROW EXECUTE FUNCTION lpcc.retire_app_revision();
ALTER TABLE lpcc.apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.app_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.app_revision_state ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON SCHEMA lpcc FROM PUBLIC;
REVOKE ALL ON lpcc.apps,lpcc.app_revisions,lpcc.app_revision_state FROM PUBLIC;
DO $$ DECLARE browser_role TEXT;
BEGIN
 FOREACH browser_role IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=browser_role) THEN
   EXECUTE format('REVOKE ALL ON SCHEMA lpcc FROM %I',browser_role);
   EXECUTE format('REVOKE ALL ON lpcc.apps,lpcc.app_revisions,lpcc.app_revision_state FROM %I',browser_role);
  END IF;
 END LOOP;
END $$;
-- DOWN
ALTER TABLE lpcc.apps DROP CONSTRAINT app_head_same_app;
DROP TABLE lpcc.app_revision_state;
DROP TABLE lpcc.app_revisions;
DROP TABLE lpcc.apps;
DROP FUNCTION lpcc.retire_app_revision();
DROP FUNCTION lpcc.immutable_app_revision();
