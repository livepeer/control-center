// Package testdb creates disposable databases only when TEST_DATABASE_URL is set.
package testdb

import (
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"uuid"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func Open(t *testing.T) *sql.DB {
	t.Helper()
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("set TEST_DATABASE_URL to a disposable PostgreSQL instance; application configuration is never used")
	}
	admin, err := sql.Open("pgx", raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	name := "lpcc_test_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(`CREATE DATABASE ` + quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP DATABASE ` + quoted + ` WITH (FORCE)`); err != nil {
			t.Error(err)
		}
	})
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE SCHEMA auth; CREATE TABLE auth.users(
 id UUID PRIMARY KEY, email TEXT, email_confirmed_at TIMESTAMPTZ,
 deleted_at TIMESTAMPTZ, is_anonymous BOOLEAN NOT NULL DEFAULT false)`); err != nil {
		t.Fatal(err)
	}
	return db
}
