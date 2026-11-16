package testdb

import (
	"context"
	"database/sql"
)

// Observer counts reads and can commit a concurrent change after a statement
// has acquired its snapshot, before its caller consumes the rows.
type Observer struct {
	*sql.DB
	Reads      int
	AfterQuery func()
}

func (q *Observer) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	q.Reads++
	rows, err := q.DB.QueryContext(ctx, query, args...)
	if err == nil && q.AfterQuery != nil {
		q.AfterQuery()
	}
	return rows, err
}

func (q *Observer) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	q.Reads++
	return q.DB.QueryRowContext(ctx, query, args...)
}
