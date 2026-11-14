-- UP
CREATE TABLE lpsecrets.revoked_grants(jti text PRIMARY KEY,actor_user_id uuid NOT NULL,orchestrator_address text NOT NULL CHECK(orchestrator_address ~ '^0x[0-9a-f]{40}$'),expires_at timestamptz NOT NULL);
CREATE TABLE lpsecrets.identities(node_id text PRIMARY KEY,orchestrator_address text NOT NULL CHECK(orchestrator_address ~ '^0x[0-9a-f]{40}$'),public_key text NOT NULL,generation bigint NOT NULL DEFAULT 1,revoked boolean NOT NULL DEFAULT false,reset_pending boolean NOT NULL DEFAULT false);
CREATE TABLE lpsecrets.retired_keys(node_id text NOT NULL REFERENCES lpsecrets.identities,public_key text NOT NULL,PRIMARY KEY(node_id,public_key));
CREATE TABLE lpsecrets.request_nonces(node_id text NOT NULL REFERENCES lpsecrets.identities,nonce text NOT NULL,expires_at timestamptz NOT NULL,PRIMARY KEY(node_id,nonce));
CREATE INDEX request_nonce_expiry ON lpsecrets.request_nonces(expires_at);
CREATE TABLE lpsecrets.secrets(id uuid PRIMARY KEY,orchestrator_address text NOT NULL CHECK(orchestrator_address ~ '^0x[0-9a-f]{40}$'),name text NOT NULL,key text NOT NULL,head uuid,revision bigint NOT NULL DEFAULT 1,deleted boolean NOT NULL DEFAULT false,updated_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX active_secret_reference ON lpsecrets.secrets(orchestrator_address,name,key) WHERE NOT deleted;
CREATE INDEX secrets_orchestrator ON lpsecrets.secrets(orchestrator_address);
CREATE TABLE lpsecrets.versions(id uuid PRIMARY KEY,secret_id uuid NOT NULL REFERENCES lpsecrets.secrets,base_revision bigint NOT NULL,nonce bytea,ciphertext bytea,wrapped_key text,created_at timestamptz NOT NULL DEFAULT now(),superseded_at timestamptz);
CREATE TABLE lpsecrets.audit(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,orchestrator_address text NOT NULL CHECK(orchestrator_address ~ '^0x[0-9a-f]{40}$'),actor_id text NOT NULL,action text NOT NULL,target text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
REVOKE ALL ON SCHEMA lpsecrets FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA lpsecrets FROM PUBLIC;

-- DOWN
DROP TABLE lpsecrets.audit,lpsecrets.versions,lpsecrets.secrets,lpsecrets.request_nonces,lpsecrets.retired_keys,lpsecrets.identities,lpsecrets.revoked_grants;
