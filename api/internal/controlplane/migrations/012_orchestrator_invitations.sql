-- UP
-- Issuance is stateless. Receipts survive account deletion to prevent replay and
-- retain the identities behind accepted invitations.
CREATE TABLE lpcc.orchestrator_invitation_acceptances (
 invitation_id uuid PRIMARY KEY,
 orchestrator_address text NOT NULL REFERENCES lpcc.orchestrators(address),
 inviter_user_id uuid NOT NULL,
 accepted_by_user_id uuid NOT NULL,
 accepted_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE lpcc.orchestrator_invitation_acceptances ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON lpcc.orchestrator_invitation_acceptances FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
 IF EXISTS(SELECT FROM pg_roles WHERE rolname=r) THEN
 EXECUTE format('REVOKE ALL ON lpcc.orchestrator_invitation_acceptances FROM %I',r);
 END IF;
 END LOOP;
END $$;
-- DOWN
DROP TABLE lpcc.orchestrator_invitation_acceptances;
