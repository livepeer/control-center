package secrets

import (
	"encoding/hex"
	"strings"
)

// OrchestratorAddress is the canonical resource owner shared by both services.
// User UUIDs identify actors and must never be used as resource owners.
func OrchestratorAddress(raw string) (string, error) {
	if len(raw) != 42 || !strings.HasPrefix(raw, "0x") {
		return "", ErrInvalid
	}
	b, err := hex.DecodeString(raw[2:])
	if err != nil {
		return "", ErrInvalid
	}
	if len(b) != 20 {
		return "", ErrInvalid
	}
	return strings.ToLower(raw), nil
}
