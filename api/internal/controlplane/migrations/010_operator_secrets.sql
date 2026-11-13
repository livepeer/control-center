-- UP
CREATE TABLE lpcc.revoked_enrollment_grants(jti text PRIMARY KEY,owner_id uuid NOT NULL,expires_at timestamptz NOT NULL);
CREATE TABLE lpcc.enrollment_audit(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,owner_id uuid NOT NULL,action text NOT NULL,target text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE lpcc.revoked_enrollment_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.enrollment_audit ENABLE ROW LEVEL SECURITY;
CREATE TABLE lpcc.secret_machines (
 node_id text PRIMARY KEY REFERENCES lpcc.enrollments(node_id), public_key text NOT NULL DEFAULT '',
 managed boolean NOT NULL DEFAULT false,encryption_ready boolean NOT NULL DEFAULT false
);
CREATE TABLE lpcc.operator_app_policy(owner_id uuid NOT NULL,app_name text NOT NULL,denied boolean NOT NULL,generation bigint NOT NULL DEFAULT 1,PRIMARY KEY(owner_id,app_name));
CREATE TABLE lpcc.operator_policy_generation(owner_id uuid PRIMARY KEY,generation bigint NOT NULL DEFAULT 1);
CREATE TABLE lpcc.machine_app_requests(node_id text NOT NULL REFERENCES lpcc.enrollments(node_id),revision_id uuid NOT NULL REFERENCES lpcc.app_revisions(revision_id),intent jsonb NOT NULL,PRIMARY KEY(node_id,revision_id));
INSERT INTO lpcc.machine_app_requests SELECT node_id,revision_id,intent FROM lpcc.machine_app_heads;
ALTER TABLE lpcc.secret_machines ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.operator_app_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.operator_policy_generation ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.machine_app_requests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON lpcc.secret_machines,lpcc.operator_app_policy,lpcc.operator_policy_generation,lpcc.machine_app_requests,lpcc.revoked_enrollment_grants,lpcc.enrollment_audit FROM PUBLIC;
DO $$ DECLARE r text;BEGIN FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP IF EXISTS(SELECT FROM pg_roles WHERE rolname=r) THEN EXECUTE format('REVOKE ALL ON lpcc.secret_machines,lpcc.operator_app_policy,lpcc.operator_policy_generation,lpcc.machine_app_requests,lpcc.revoked_enrollment_grants,lpcc.enrollment_audit FROM %I',r); END IF;END LOOP;END $$;
-- DOWN
DO $$ BEGIN
 IF EXISTS(SELECT FROM lpcc.revoked_enrollment_grants) OR EXISTS(SELECT FROM lpcc.enrollment_audit) OR EXISTS(SELECT FROM lpcc.machine_app_requests) OR EXISTS(SELECT FROM lpcc.operator_app_policy) OR EXISTS(SELECT FROM lpcc.secret_machines) THEN
 RAISE EXCEPTION 'retain operator secrets schema while enrollment, policy, or assignment history exists';
 END IF;
END $$;
DROP TABLE lpcc.revoked_enrollment_grants,lpcc.enrollment_audit,lpcc.machine_app_requests,lpcc.operator_policy_generation,lpcc.operator_app_policy,lpcc.secret_machines;
