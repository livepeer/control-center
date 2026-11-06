// Package migrations ports livepeer/node's embedded, checksum-verified SQL migrations to PostgreSQL.
package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var migrationName = regexp.MustCompile(`^([0-9]{3,})_[a-z0-9_]+\.sql$`)

type Status struct {
	Version     int    `json:"version"`
	Filename    string `json:"filename"`
	SHA256      string `json:"sha256"`
	AppliedAtMS *int64 `json:"applied_at_ms"`
	Applied     bool   `json:"applied"`
}

type migration struct {
	Status
	up, down string
}

func catalog(files fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, err
	}
	out := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		matches := migrationName.FindStringSubmatch(entry.Name())
		if matches == nil {
			return nil, fmt.Errorf("invalid migration filename %s", entry.Name())
		}
		version, err := strconv.Atoi(matches[1])
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("invalid migration version in %s", entry.Name())
		}
		contents, err := fs.ReadFile(files, entry.Name())
		if err != nil {
			return nil, err
		}
		up, down, err := sections(entry.Name(), contents)
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(contents)
		out = append(out, migration{Status: Status{Version: version, Filename: entry.Name(), SHA256: hex.EncodeToString(hash[:])}, up: up, down: down})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, item := range out {
		if item.Version != i+1 {
			return nil, fmt.Errorf("migration versions must be contiguous from 1: found %d at %s", item.Version, item.Filename)
		}
	}
	return out, nil
}

func sections(name string, contents []byte) (string, string, error) {
	s := strings.TrimSpace(string(contents))
	up, down, ok := strings.Cut(s, "-- DOWN")
	if !ok || !strings.HasPrefix(up, "-- UP") || strings.Contains(down, "-- DOWN") {
		return "", "", fmt.Errorf("invalid UP/DOWN migration %s", name)
	}
	return strings.TrimPrefix(up, "-- UP"), down, nil
}
