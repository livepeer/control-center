package controlplane

import (
	"github.com/livepeer/control-center/api/internal/migrations"
	"github.com/livepeer/control-center/api/internal/testdb"
	"io/fs"
	"testing"
)

func TestAdministratorDatabasePrivileges(t *testing.T) {
	db := testdb.Open(t)
	// A plain PostgreSQL cluster need not contain Supabase roles.
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	files, err := fs.Sub(MigrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrations.Down(t.Context(), db, files); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"anon", "authenticated"} {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			if _, err := db.Exec(`CREATE ROLE ` + role + ` NOLOGIN`); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := db.Exec(`DROP OWNED BY ` + role + `; DROP ROLE ` + role); err != nil {
					t.Error(err)
				}
			})
		}
		// Deliberately hostile existing schema/default grants.
		if _, err := db.Exec(`GRANT ALL ON SCHEMA lpcc TO ` + role + `; ALTER DEFAULT PRIVILEGES IN SCHEMA lpcc GRANT ALL ON TABLES TO ` + role); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"anon", "authenticated"} {
		var usage bool
		if err := db.QueryRow(`SELECT has_schema_privilege($1,'lpcc','USAGE')`, role).Scan(&usage); err != nil || usage {
			t.Fatal("schema access", role, usage, err)
		}
		for _, table := range []string{"administrator_grants", "admin_audit_events"} {
			var privilege, rls bool
			var policies int
			if err := db.QueryRow(`SELECT has_table_privilege($1,$2,'SELECT,INSERT,UPDATE,DELETE')`, role, "lpcc."+table).Scan(&privilege); err != nil || privilege {
				t.Fatal("table access", role, table, err)
			}
			if err := db.QueryRow(`SELECT relrowsecurity,(SELECT count(*) FROM pg_policy WHERE polrelid=c.oid) FROM pg_class c WHERE oid=$1::regclass`, "lpcc."+table).Scan(&rls, &policies); err != nil || !rls || policies != 0 {
				t.Fatal("RLS", table, rls, policies, err)
			}
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`SET LOCAL ROLE ` + role); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`SELECT * FROM lpcc.` + table); err == nil {
				t.Fatal("browser role read private table")
			}
			tx.Rollback()
			tx, err = db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`SET LOCAL ROLE ` + role); err != nil {
				t.Fatal(err)
			}
			write := `INSERT INTO lpcc.administrator_grants(grant_id,email) VALUES('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','attacker@example.invalid')`
			if table == "admin_audit_events" {
				write = `INSERT INTO lpcc.admin_audit_events(actor_kind,actor_id,action,target_kind,target_id,outcome,reason) VALUES('system','attacker','administrator.grant','request','fake','success','changed')`
			}
			if _, err := tx.Exec(write); err == nil {
				t.Fatal("browser role wrote private table")
			}
			tx.Rollback()
		}
	}
	// Even accidental table/schema grants must not bypass the no-policy RLS layer.
	if _, err := db.Exec(`INSERT INTO lpcc.administrator_grants(grant_id,email) VALUES('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','admin@example.invalid'); GRANT USAGE ON SCHEMA lpcc TO authenticated; GRANT ALL ON lpcc.administrator_grants,lpcc.admin_audit_events TO authenticated`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SET LOCAL ROLE authenticated`); err != nil {
		t.Fatal(err)
	}
	var visible int
	if err := tx.QueryRow(`SELECT count(*) FROM lpcc.administrator_grants`).Scan(&visible); err != nil || visible != 0 {
		t.Fatal("RLS exposed grants", visible, err)
	}
	if _, err := tx.Exec(`INSERT INTO lpcc.administrator_grants(grant_id,email) VALUES('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','attacker@example.invalid')`); err == nil {
		t.Fatal("RLS allowed browser mutation")
	}
}
