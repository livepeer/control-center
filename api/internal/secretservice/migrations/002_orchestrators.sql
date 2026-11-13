-- UP
DO $$ BEGIN
 IF EXISTS(SELECT FROM lpsecrets.identities) OR EXISTS(SELECT FROM lpsecrets.secrets)
 OR EXISTS(SELECT FROM lpsecrets.audit) OR EXISTS(SELECT FROM lpsecrets.revoked_grants) THEN
 RAISE EXCEPTION 'orchestrator secrets require a fresh deployment; ciphertext cannot be relabeled';
 END IF;
END $$;
ALTER TABLE lpsecrets.identities RENAME COLUMN owner_id TO orchestrator_address;
ALTER TABLE lpsecrets.identities ALTER COLUMN orchestrator_address TYPE text USING orchestrator_address::text;
ALTER TABLE lpsecrets.identities ADD CHECK(orchestrator_address ~ '^0x[0-9a-f]{40}$' AND orchestrator_address <> '0x0000000000000000000000000000000000000000');
ALTER TABLE lpsecrets.secrets RENAME COLUMN owner_id TO orchestrator_address;
ALTER TABLE lpsecrets.secrets ALTER COLUMN orchestrator_address TYPE text USING orchestrator_address::text;
ALTER TABLE lpsecrets.secrets ADD CHECK(orchestrator_address ~ '^0x[0-9a-f]{40}$' AND orchestrator_address <> '0x0000000000000000000000000000000000000000');
ALTER TABLE lpsecrets.audit RENAME COLUMN owner_id TO orchestrator_address;
ALTER TABLE lpsecrets.audit ALTER COLUMN orchestrator_address TYPE text USING orchestrator_address::text;
ALTER TABLE lpsecrets.audit ADD CHECK(orchestrator_address ~ '^0x[0-9a-f]{40}$' AND orchestrator_address <> '0x0000000000000000000000000000000000000000');
ALTER TABLE lpsecrets.audit ADD COLUMN actor_id text NOT NULL;
ALTER TABLE lpsecrets.revoked_grants RENAME COLUMN owner_id TO actor_user_id;
ALTER TABLE lpsecrets.revoked_grants ADD COLUMN orchestrator_address text NOT NULL CHECK(orchestrator_address ~ '^0x[0-9a-f]{40}$');
-- DOWN
DO $$ BEGIN RAISE EXCEPTION 'orchestrator ciphertext ownership cannot be rolled back'; END $$;
