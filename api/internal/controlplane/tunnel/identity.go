package tunnel

import (
	"context"
	"encoding/base32"
	"errors"
	"io"
	"strings"
)

func (s *Manager) newEndpointSuffix(ctx context.Context, m Machine) (string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT state->>'endpoint_suffix' FROM lpcc.machine_states WHERE node_id=$1 AND epoch<>$2 AND state->>'endpoint_suffix' IS NOT NULL`, m.NodeID, m.Epoch)
	if err != nil {
		return "", err
	}
	previous := map[string]bool{}
	for rows.Next() {
		var suffix string
		if err := rows.Scan(&suffix); err != nil {
			rows.Close()
			return "", err
		}
		previous[suffix] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	for range 32 {
		var raw [4]byte
		if _, err := io.ReadFull(s.endpointRandom, raw[:]); err != nil {
			return "", errors.New("endpoint randomness unavailable")
		}
		suffix := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]))
		if !previous[suffix] {
			return suffix, nil
		}
	}
	return "", errors.New("endpoint randomness repeatedly reused an enrollment suffix")
}
