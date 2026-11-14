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

func TestConcurrentMigrationsIsolateHistory(t *testing.T) {
	db := testdb.Open(t)
	ctx := t.Context()
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
		if err != nil {
			t.Fatal(err)
		}
	}
	files, err := fs.Sub(MigrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	status, err := Migrator.List(ctx, db, files)
	if err != nil || len(status) != 2 || !status[0].Applied || !status[1].Applied {
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
