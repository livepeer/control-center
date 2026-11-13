package secretservice

import (
	"context"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/livepeer/control-center/api/internal/migrations"
	"github.com/livepeer/control-center/api/internal/testdb"
)

func TestMigrateRefusesToRelabelExistingSecretsAndIsolatesHistory(t *testing.T) {
	db := testdb.Open(t)
	ctx := t.Context()
	// Represent a database initialized by an older secrets-service binary.
	_, err := db.Exec(`CREATE SCHEMA lpsecrets;
CREATE TABLE lpsecrets.identities(node_id text PRIMARY KEY,owner_id uuid NOT NULL,public_key text NOT NULL,generation bigint NOT NULL DEFAULT 1,revoked boolean NOT NULL DEFAULT false);
CREATE TABLE lpsecrets.challenges(id uuid PRIMARY KEY,node_id text NOT NULL REFERENCES lpsecrets.identities,nonce bytea NOT NULL,expires_at timestamptz NOT NULL);
CREATE TABLE lpsecrets.secrets(id uuid PRIMARY KEY,owner_id uuid NOT NULL,name text NOT NULL,key text NOT NULL,head uuid,revision bigint NOT NULL DEFAULT 1,deleted boolean NOT NULL DEFAULT false,updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE lpsecrets.versions(id uuid PRIMARY KEY,secret_id uuid NOT NULL REFERENCES lpsecrets.secrets,base_revision bigint NOT NULL,nonce bytea,ciphertext bytea,wrapped_key text,created_at timestamptz NOT NULL DEFAULT now());
INSERT INTO lpsecrets.identities(node_id,owner_id,public_key) VALUES('node','11111111-1111-4111-8111-111111111111','key');
INSERT INTO lpsecrets.secrets(id,owner_id,name,key) VALUES('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111','app','token');
INSERT INTO lpsecrets.versions(id,secret_id,base_revision,ciphertext) VALUES('33333333-3333-4333-8333-333333333333','22222222-2222-4222-8222-222222222222',1,decode('1234','hex'));`)
	if err != nil {
		t.Fatal(err)
	}
	controlFiles := fstest.MapFS{"001_control.sql": {Data: []byte("-- UP\nSELECT 1;\n-- DOWN\nSELECT 1;")}}
	if err := migrations.Up(ctx, db, controlFiles); err != nil {
		t.Fatal(err)
	}
	s := New(db, Config{})
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- s.Migrate(context.Background()) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil || !strings.Contains(err.Error(), "fresh deployment") {
			t.Fatal("populated secrets database was relabeled", err)
		}
	}
	var publicKey, name, ciphertext string
	var reset bool
	if err := db.QueryRow(`SELECT public_key, reset_pending FROM lpsecrets.identities WHERE node_id='node'`).Scan(&publicKey, &reset); err != nil || publicKey != "key" || reset {
		t.Fatalf("identity changed: %q %v %v", publicKey, reset, err)
	}
	if err := db.QueryRow(`SELECT s.name, encode(v.ciphertext,'hex') FROM lpsecrets.secrets s JOIN lpsecrets.versions v ON v.secret_id=s.id WHERE v.superseded_at IS NULL`).Scan(&name, &ciphertext); err != nil || name != "app" || ciphertext != "1234" {
		t.Fatalf("secret changed: %q %q %v", name, ciphertext, err)
	}
	var challenge *string
	if err := db.QueryRow(`SELECT to_regclass('lpsecrets.challenges')::text`).Scan(&challenge); err != nil || challenge != nil {
		t.Fatalf("obsolete challenge table remains: %v %v", challenge, err)
	}
	files, err := fs.Sub(MigrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	status, err := Migrator.List(ctx, db, files)
	if err != nil || len(status) != 2 || !status[0].Applied || status[1].Applied {
		t.Fatalf("secrets history: %v %v", status, err)
	}
	controlStatus, err := migrations.List(ctx, db, controlFiles)
	if err != nil || len(controlStatus) != 1 || !controlStatus[0].Applied {
		t.Fatalf("control-plane history: %v %v", controlStatus, err)
	}
	if err := Migrator.Down(ctx, db, files); err == nil || !strings.Contains(err.Error(), "cannot be rolled back") {
		t.Fatalf("baseline rollback: %v", err)
	}
	if _, err := db.Exec(`UPDATE lpsecrets.migrations SET sha256=repeat('0',64)`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("changed history accepted: %v", err)
	}
}

func TestMigrationStatusDoesNotInitializeDatabase(t *testing.T) {
	db := testdb.Open(t)
	files, err := fs.Sub(MigrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	status, err := Migrator.List(t.Context(), db, files)
	if err != nil || len(status) != 2 || status[0].Applied || status[1].Applied {
		t.Fatalf("fresh status: %v %v", status, err)
	}
	var schema *string
	if err := db.QueryRow(`SELECT to_regnamespace('lpsecrets')::text`).Scan(&schema); err != nil || schema != nil {
		t.Fatalf("status created schema: %v %v", schema, err)
	}
}
