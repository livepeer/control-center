package payments

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/livepeer/control-center/runtime/payment"
)

type Querier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func Load(ctx context.Context, q Querier, node string) (payment.Config, error) {
	c := payment.Offchain()
	var b []byte
	err := q.QueryRowContext(ctx, `SELECT config FROM lpcc.payment_machines WHERE node_id=$1`, node).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	if err == nil {
		err = c.Validate()
	}
	return c, err
}
