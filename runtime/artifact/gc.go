package artifact

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type storedFile struct {
	name, digest string
	size         int64
	modified     time.Time
}

func (s Store) files() ([]storedFile, int64, error) {
	entries, err := os.ReadDir(s.Directory)
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	files := []storedFile{}
	var total int64
	for _, entry := range entries {
		digest := "sha256:" + strings.TrimSuffix(entry.Name(), ".tar.gz")
		if !strings.HasSuffix(entry.Name(), ".tar.gz") || !HashPattern.MatchString(digest) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, 0, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		files = append(files, storedFile{entry.Name(), digest, info.Size(), info.ModTime()})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modified.Before(files[j].modified) })
	return files, total, nil
}
func (s Store) Usage() (int64, error) { _, size, err := s.files(); return size, err }

// Collect retains explicit references and a short fetch grace. Unreferenced older
// requests can retry the latest publication if the storage budget requires eviction.
func (s Store) Collect(pinned map[string]bool, budget int64, now time.Time) error {
	files, total, err := s.files()
	if err != nil {
		return err
	}
	for n, file := range files {
		if pinned[file.digest] {
			continue
		}
		if total <= budget && (len(files)-n <= 10 || now.Sub(file.modified) < time.Hour) {
			continue
		}
		if err := os.Remove(filepath.Join(s.Directory, file.name)); err != nil && !os.IsNotExist(err) {
			return err
		}
		total -= file.size
	}
	return nil
}
