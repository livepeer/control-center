package consumer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// The kernel start counter survives exec. Combining it with boot and namespace
// identity distinguishes replacement containers without wall clocks or API status.
func hashProcess(boot, namespace, stat string) (string, error) {
	end := strings.LastIndexByte(stat, ')')
	if boot == "" || namespace == "" || end < 0 {
		return "", errors.New("connector_process_identity")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) <= 19 {
		return "", errors.New("connector_process_identity")
	}
	start := fields[19] // /proc/PID/stat field 22; the suffix starts at field 3.
	for _, c := range start {
		if c < '0' || c > '9' {
			return "", errors.New("connector_process_identity")
		}
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(boot) + "\n" + namespace + "\n" + start))
	return hex.EncodeToString(digest[:]), nil
}
