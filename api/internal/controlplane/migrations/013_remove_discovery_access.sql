-- UP
DROP TABLE lpcc.access_credentials;
-- DOWN
-- Provider resources and retired credentials require an explicit operational
-- recovery; recreating the table cannot restore them.
CREATE TABLE lpcc.access_credentials (
 node_id TEXT NOT NULL REFERENCES lpcc.enrollments(node_id),
 version BIGINT NOT NULL,
 provider_id TEXT NOT NULL,
 key_id TEXT NOT NULL,
 ciphertext BYTEA NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 acknowledged_at TIMESTAMPTZ,
 acknowledged_generation BIGINT,
 revoked_at TIMESTAMPTZ,
 PRIMARY KEY(node_id,version)
);
ALTER TABLE lpcc.access_credentials ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON lpcc.access_credentials FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON lpcc.access_credentials FROM %I',r);
  END IF;
 END LOOP;
END $$;
