-- UP
CREATE SCHEMA IF NOT EXISTS lpsecrets;
CREATE TABLE IF NOT EXISTS lpsecrets.revoked_grants(jti text PRIMARY KEY,owner_id uuid NOT NULL,expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS lpsecrets.identities(node_id text PRIMARY KEY,owner_id uuid NOT NULL,public_key text NOT NULL,generation bigint NOT NULL DEFAULT 1,revoked boolean NOT NULL DEFAULT false);
ALTER TABLE lpsecrets.identities ADD COLUMN IF NOT EXISTS reset_pending boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS lpsecrets.retired_keys(node_id text NOT NULL REFERENCES lpsecrets.identities,public_key text NOT NULL,PRIMARY KEY(node_id,public_key));
DROP TABLE IF EXISTS lpsecrets.challenges;
CREATE TABLE IF NOT EXISTS lpsecrets.request_nonces(node_id text NOT NULL REFERENCES lpsecrets.identities,nonce text NOT NULL,expires_at timestamptz NOT NULL,PRIMARY KEY(node_id,nonce));
CREATE INDEX IF NOT EXISTS request_nonce_expiry ON lpsecrets.request_nonces(expires_at);
CREATE TABLE IF NOT EXISTS lpsecrets.secrets(id uuid PRIMARY KEY,owner_id uuid NOT NULL,name text NOT NULL,key text NOT NULL,head uuid,revision bigint NOT NULL DEFAULT 1,deleted boolean NOT NULL DEFAULT false,updated_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX IF NOT EXISTS active_secret_reference ON lpsecrets.secrets(owner_id,name,key) WHERE NOT deleted;
CREATE TABLE IF NOT EXISTS lpsecrets.versions(id uuid PRIMARY KEY,secret_id uuid NOT NULL REFERENCES lpsecrets.secrets,base_revision bigint NOT NULL,nonce bytea,ciphertext bytea,wrapped_key text,created_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE lpsecrets.versions ADD COLUMN IF NOT EXISTS superseded_at timestamptz;
CREATE TABLE IF NOT EXISTS lpsecrets.audit(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,owner_id uuid NOT NULL,action text NOT NULL,target text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
REVOKE ALL ON SCHEMA lpsecrets FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA lpsecrets FROM PUBLIC;

-- DOWN
DO $$ BEGIN
 RAISE EXCEPTION 'the secrets baseline cannot be rolled back; it may contain existing data';
END $$;
