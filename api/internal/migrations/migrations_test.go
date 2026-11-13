package migrations

import (
	"context"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/livepeer/control-center/api/internal/testdb"
)

func fixtures() fs.FS {
	return fstest.MapFS{
		"001_initial.sql": {Data: []byte("-- UP\nCREATE TABLE lpcc.first_items(id INTEGER PRIMARY KEY);\n-- DOWN\nDROP TABLE lpcc.first_items;")},
		"002_second.sql":  {Data: []byte("-- UP\nCREATE TABLE lpcc.second_items(id INTEGER PRIMARY KEY);\n-- DOWN\nDROP TABLE lpcc.second_items;")},
	}
}

func TestRoundTrip(t *testing.T) {
	db := testdb.Open(t)
	ctx := t.Context()
	files := fixtures()
	status, err := List(ctx, db, files)
	if err != nil {
		t.Fatal(err)
	}
	if len(status) != 2 || status[0].Applied {
		t.Fatal(status)
	}
	var schema *string
	if err := db.QueryRow(`SELECT to_regnamespace('lpcc')::text`).Scan(&schema); err != nil || schema != nil {
		t.Fatalf("status created schema: %v, %v", schema, err)
	}
	if err := Up(ctx, db, files); err != nil {
		t.Fatal(err)
	}
	before, err := List(ctx, db, files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO lpcc.first_items VALUES(7)`); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, db, files); err != nil {
		t.Fatal(err)
	}
	after, err := List(ctx, db, files)
	if err != nil {
		t.Fatal(err)
	}
	for i := range before {
		if !after[i].Applied || *before[i].AppliedAtMS != *after[i].AppliedAtMS {
			t.Fatal("repeated up changed history")
		}
	}
	if err := Down(ctx, db, files); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT id FROM lpcc.first_items`).Scan(&count); err != nil || count != 7 {
		t.Fatal(err, count)
	}
	status, err = List(ctx, db, files)
	if err != nil || status[1].Applied {
		t.Fatal(status, err)
	}
	for range 2 {
		if err := Down(ctx, db, files); err != nil {
			t.Fatal(err)
		}
	}
	if err := Up(ctx, db, files); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataFailureIsAtomic(t *testing.T) {
	db := testdb.Open(t)
	ctx := t.Context()
	files := fixtures()
	if err := Up(ctx, db, files); err != nil {
		t.Fatal(err)
	}
	if err := Down(ctx, db, files); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE lpcc.migrations ADD CONSTRAINT reject_second CHECK(version<>2) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, db, files); err == nil {
		t.Fatal("metadata failure accepted")
	}
	var table *string
	if err := db.QueryRow(`SELECT to_regclass('lpcc.second_items')::text`).Scan(&table); err != nil || table != nil {
		t.Fatal("schema survived failed metadata write", err)
	}
	if _, err := db.Exec(`ALTER TABLE lpcc.migrations DROP CONSTRAINT reject_second`); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, db, files); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE FUNCTION lpcc.reject_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END $$;
 CREATE TRIGGER reject_delete BEFORE DELETE ON lpcc.migrations FOR EACH ROW EXECUTE FUNCTION lpcc.reject_delete()`); err != nil {
		t.Fatal(err)
	}
	if err := Down(ctx, db, files); err == nil {
		t.Fatal("metadata delete failure accepted")
	}
	if err := db.QueryRow(`SELECT to_regclass('lpcc.second_items')::text`).Scan(&table); err != nil || table == nil {
		t.Fatal("table dropped despite failed metadata deletion", err)
	}
}

func TestHistoryMismatch(t *testing.T) {
	for name, statement := range map[string]string{
		"filename":          `UPDATE lpcc.migrations SET filename='001_other.sql' WHERE version=1`,
		"checksum":          `UPDATE lpcc.migrations SET sha256=repeat('0',64) WHERE version=1`,
		"unknown migration": `INSERT INTO lpcc.migrations VALUES(999,'999_unknown.sql',repeat('0',64),0)`,
		"gap":               `DELETE FROM lpcc.migrations WHERE version=1`,
	} {
		t.Run(name, func(t *testing.T) {
			db := testdb.Open(t)
			files := fixtures()
			ctx := t.Context()
			if err := Up(ctx, db, files); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if _, err := List(ctx, db, files); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatal(err)
			}
			if err := Up(ctx, db, files); err == nil {
				t.Fatal("up accepted corrupt history")
			}
			if err := Down(ctx, db, files); err == nil {
				t.Fatal("down accepted corrupt history")
			}
		})
	}
}

func TestConcurrentUp(t *testing.T) {
	db := testdb.Open(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- Up(context.Background(), db, fixtures()) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	status, err := List(t.Context(), db, fixtures())
	if err != nil || len(status) != 2 || !status[1].Applied {
		t.Fatal(status, err)
	}
}

func TestInvalidCatalog(t *testing.T) {
	valid := []byte("-- UP\nSELECT 1;\n-- DOWN\nSELECT 1;")
	for name, files := range map[string]fstest.MapFS{
		"filename": {"1_initial.sql": {Data: valid}}, "zero": {"000_initial.sql": {Data: valid}},
		"gap": {"002_second.sql": {Data: valid}}, "duplicate": {"001_a.sql": {Data: valid}, "001_b.sql": {Data: valid}},
		"missing down": {"001_initial.sql": {Data: []byte("-- UP\nSELECT 1;")}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := catalog(files); err == nil {
				t.Fatal("invalid catalog accepted")
			}
		})
	}
}

func TestSchemaNames(t *testing.T) {
	schema, table, err := ForSchema(`quote"schema`).names()
	if err != nil || schema != `"quote""schema"` || table != `"quote""schema"."migrations"` {
		t.Fatalf("schema quoting: %q %q %v", schema, table, err)
	}
	for _, invalid := range []string{"", strings.Repeat("a", 64), "bad\x00schema"} {
		if _, _, err := ForSchema(invalid).names(); err == nil {
			t.Fatalf("accepted invalid schema %q", invalid)
		}
	}
}
