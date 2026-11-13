-- UP
-- Existing assignments and app-name policies do not establish operator consent.
CREATE TABLE lpsecrets.app_policy_generation(owner_id uuid PRIMARY KEY,generation bigint NOT NULL DEFAULT 0);
CREATE TABLE lpsecrets.app_approvals(owner_id uuid NOT NULL,app_name text NOT NULL,denied boolean NOT NULL,approvals jsonb NOT NULL DEFAULT '[]',PRIMARY KEY(owner_id,app_name));
ALTER TABLE lpsecrets.app_policy_generation ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpsecrets.app_approvals ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON lpsecrets.app_policy_generation,lpsecrets.app_approvals FROM PUBLIC;
DO $$ DECLARE r text; BEGIN FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP IF EXISTS(SELECT FROM pg_roles WHERE rolname=r) THEN EXECUTE format('REVOKE ALL ON lpsecrets.app_policy_generation,lpsecrets.app_approvals FROM %I',r); END IF; END LOOP; END $$;

-- DOWN
DO $$ BEGIN
 RAISE EXCEPTION 'operator consent and revocations must be preserved';
END $$;
