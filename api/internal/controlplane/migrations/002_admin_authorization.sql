-- UP
CREATE TABLE lpcc.administrator_grants (
 grant_id UUID PRIMARY KEY,
 email TEXT NOT NULL CHECK(length(email) BETWEEN 3 AND 254 AND email = lower(btrim(email))),
 -- Retain identity/history after Auth account deletion. Never reopen a bound grant.
 bound_user_id UUID,
 revision BIGINT NOT NULL DEFAULT 1 CHECK(revision > 0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 bound_at TIMESTAMPTZ,
 revoked_at TIMESTAMPTZ,
 CHECK ((bound_user_id IS NULL) = (bound_at IS NULL))
);
CREATE UNIQUE INDEX administrator_active_user ON lpcc.administrator_grants(bound_user_id)
 WHERE revoked_at IS NULL AND bound_user_id IS NOT NULL;
CREATE UNIQUE INDEX administrator_pending_email ON lpcc.administrator_grants(email)
 WHERE revoked_at IS NULL AND bound_user_id IS NULL;
CREATE TABLE lpcc.admin_audit_events (
 event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 actor_kind TEXT NOT NULL CHECK(actor_kind IN ('user','system')),
 actor_id TEXT NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 128),
 action TEXT NOT NULL CHECK(action ~ '^[a-z][a-z0-9_.:-]{0,63}$'),
 target_kind TEXT NOT NULL CHECK(length(target_kind) BETWEEN 1 AND 64),
 target_id TEXT NOT NULL CHECK(length(target_id) BETWEEN 1 AND 254),
 revision TEXT CHECK(length(revision) BETWEEN 1 AND 128),
 outcome TEXT NOT NULL CHECK(outcome IN ('success','failure')),
 reason TEXT NOT NULL CHECK(reason ~ '^[a-z][a-z0-9_]{0,63}$')
);
ALTER TABLE lpcc.administrator_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.admin_audit_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON SCHEMA lpcc FROM PUBLIC;
REVOKE ALL ON lpcc.administrator_grants, lpcc.admin_audit_events FROM PUBLIC;
REVOKE ALL ON SEQUENCE lpcc.admin_audit_events_event_id_seq FROM PUBLIC;
DO $$
DECLARE browser_role TEXT;
BEGIN
 FOREACH browser_role IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS (SELECT FROM pg_roles WHERE rolname=browser_role) THEN
   EXECUTE format('REVOKE ALL ON SCHEMA lpcc FROM %I', browser_role);
   EXECUTE format('REVOKE ALL ON lpcc.administrator_grants, lpcc.admin_audit_events FROM %I', browser_role);
   EXECUTE format('REVOKE ALL ON SEQUENCE lpcc.admin_audit_events_event_id_seq FROM %I', browser_role);
  END IF;
 END LOOP;
END $$;
-- DOWN
DROP TABLE lpcc.admin_audit_events;
DROP TABLE lpcc.administrator_grants;
