package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"time"
)

type querier interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// List never creates schema or migration metadata, including on a fresh database.
func List(ctx context.Context, db *sql.DB, files fs.FS) ([]Status, error) {
	specs, err := catalog(files)
	if err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return list(ctx, tx, specs)
}

func list(ctx context.Context, q querier, specs []migration) ([]Status, error) {
	out := make([]Status, len(specs))
	for i := range specs {
		out[i] = specs[i].Status
	}
	var table sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT to_regclass('lpcc.migrations')::text`).Scan(&table); err != nil {
		return nil, err
	}
	if !table.Valid {
		return out, nil
	}
	rows, err := q.QueryContext(ctx, `SELECT version, filename, sha256, applied_at_ms FROM lpcc.migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("read migration metadata: %w", err)
	}
	defer rows.Close()
	next := 1
	for rows.Next() {
		var saved Status
		var appliedAt int64
		if err := rows.Scan(&saved.Version, &saved.Filename, &saved.SHA256, &appliedAt); err != nil {
			return nil, err
		}
		if saved.Version < 1 || saved.Version > len(specs) {
			return nil, fmt.Errorf("database has unknown migration version %d", saved.Version)
		}
		expected := specs[saved.Version-1]
		if saved.Filename != expected.Filename {
			return nil, fmt.Errorf("migration version %d filename mismatch", saved.Version)
		}
		if saved.SHA256 != expected.SHA256 {
			return nil, fmt.Errorf("migration %s checksum mismatch", saved.Filename)
		}
		if saved.Version != next {
			return nil, fmt.Errorf("database migration history has a gap before version %d", saved.Version)
		}
		saved.Applied, saved.AppliedAtMS = true, &appliedAt
		out[saved.Version-1] = saved
		next++
	}
	return out, rows.Err()
}

// Up commits each pending migration and its metadata in the same transaction.
func Up(ctx context.Context, db *sql.DB, files fs.FS) error {
	specs, err := catalog(files)
	if err != nil {
		return err
	}
	for {
		changed, err := applyNext(ctx, db, specs, false)
		if err != nil || !changed {
			return err
		}
	}
}

// Down rolls back exactly the latest migration. It can destroy application data.
func Down(ctx context.Context, db *sql.DB, files fs.FS) error {
	specs, err := catalog(files)
	if err != nil {
		return err
	}
	_, err = applyNext(ctx, db, specs, true)
	return err
}

func applyNext(ctx context.Context, db *sql.DB, specs []migration, down bool) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	// Transaction locks work with both direct and transaction-pooled connections.
	// Validate history inside the lock so concurrent starters cannot race the DDL.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1129073483, 1)`); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS lpcc;
 CREATE TABLE IF NOT EXISTS lpcc.migrations (
  version INTEGER PRIMARY KEY CHECK(version > 0),
  filename TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
  applied_at_ms BIGINT NOT NULL
 )`); err != nil {
		return false, err
	}
	statuses, err := list(ctx, tx, specs)
	if err != nil {
		return false, err
	}
	index := -1
	for i, status := range statuses {
		if down && status.Applied {
			index = i
		}
		if !down && !status.Applied {
			index = i
			break
		}
	}
	if index == -1 {
		return false, tx.Commit()
	}
	item := specs[index]
	script := item.up
	if down {
		script = item.down
	}
	if _, err = tx.ExecContext(ctx, script); err != nil {
		return false, fmt.Errorf("migration %s: %w", item.Filename, err)
	}
	if down {
		_, err = tx.ExecContext(ctx, `DELETE FROM lpcc.migrations WHERE version=$1`, item.Version)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO lpcc.migrations(version,filename,sha256,applied_at_ms) VALUES($1,$2,$3,$4)`, item.Version, item.Filename, item.SHA256, time.Now().UnixMilli())
	}
	if err != nil {
		return false, err
	}
	return true, tx.Commit()
}
