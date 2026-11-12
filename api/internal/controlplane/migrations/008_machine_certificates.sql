-- UP
-- Certificate ownership follows the stable DNS namespace, not an enrollment.
-- Keep these records after removal so late provider results remain recoverable.
CREATE TABLE lpcc.machine_certificates (
    zone_id text NOT NULL,
    wildcard_host text NOT NULL,
    account_id text NOT NULL,
    state jsonb NOT NULL DEFAULT '{}',
    lease_id uuid,
    lease_until timestamptz,
    PRIMARY KEY (zone_id, wildcard_host)
);
CREATE TABLE lpcc.machine_certificate_refs (
    zone_id text NOT NULL,
    wildcard_host text NOT NULL,
    node_id text NOT NULL,
    PRIMARY KEY (zone_id, wildcard_host, node_id),
    FOREIGN KEY (zone_id, wildcard_host) REFERENCES lpcc.machine_certificates,
    FOREIGN KEY (node_id) REFERENCES lpcc.enrollments
);
ALTER TABLE lpcc.machine_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE lpcc.machine_certificate_refs ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON lpcc.machine_certificates,lpcc.machine_certificate_refs FROM PUBLIC;
DO $$ DECLARE r TEXT;
BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON lpcc.machine_certificates,lpcc.machine_certificate_refs FROM %I',r);
  END IF;
 END LOOP;
END $$;

-- DOWN
DO $$ BEGIN
 IF EXISTS(SELECT FROM lpcc.machine_certificates) THEN
  RAISE EXCEPTION 'retain certificate ledger while ownership or late-result watches exist';
 END IF;
END $$;
DROP TABLE lpcc.machine_certificate_refs;
DROP TABLE lpcc.machine_certificates;
