// Package artifact implements bounded archives and durable content-addressed storage.
package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const MaxArchive = 16 << 20
const MaxContent = 64 << 20
const MaxFiles = 2048

var HashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var artifactPath = regexp.MustCompile(`^/artifacts/([0-9a-f]{64})\.tar\.gz$`)

func Digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

func Read(data []byte) (map[string][]byte, error) {
	if len(data) == 0 || len(data) > MaxArchive {
		return nil, errors.New("archive_size")
	}
	z, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("archive_gzip")
	}
	content, err := io.ReadAll(io.LimitReader(z, MaxContent+1))
	closeErr := z.Close()
	if err != nil || closeErr != nil || len(content) > MaxContent {
		return nil, errors.New("archive_content")
	}
	t := tar.NewReader(bytes.NewReader(content))
	files := map[string][]byte{}
	total := int64(0)
	for {
		h, err := t.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("archive_tar")
		}
		if h.Typeflag != tar.TypeReg || h.Name == "." || h.Name == ".." || path.IsAbs(h.Name) || path.Clean(h.Name) != h.Name || strings.Contains(h.Name, "\\") || strings.HasPrefix(h.Name, "../") || h.Size < 0 || len(files) >= MaxFiles {
			return nil, errors.New("archive_member")
		}
		if _, ok := files[h.Name]; ok {
			return nil, errors.New("archive_duplicate")
		}
		total += h.Size
		if total > MaxContent {
			return nil, errors.New("archive_content")
		}
		b, err := io.ReadAll(io.LimitReader(t, h.Size+1))
		if err != nil || int64(len(b)) != h.Size {
			return nil, errors.New("archive_truncated")
		}
		files[h.Name] = b
	}
	if _, ok := files["kustomization.yaml"]; !ok {
		if _, ok = files["kustomization.yml"]; !ok {
			if _, ok = files["Kustomization"]; !ok {
				return nil, errors.New("archive_root")
			}
		}
	}
	return files, nil
}

func Pack(files map[string][]byte) ([]byte, error) {
	if len(files) > MaxFiles {
		return nil, errors.New("archive_members")
	}
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	t := tar.NewWriter(z)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	total := 0
	for _, name := range names {
		data := files[name]
		total += len(data)
		if total > MaxContent {
			return nil, errors.New("archive_content")
		}
		if err := t.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			return nil, err
		}
		if _, err := t.Write(data); err != nil {
			return nil, err
		}
	}
	if err := t.Close(); err != nil {
		return nil, err
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	data := b.Bytes()
	if _, err := Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

// AtomicWrite commits both file contents and the directory entry before returning.
func AtomicWrite(name string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(name), ".commit-")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temp, name); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

type Store struct{ Directory string }

func (s Store) Put(data []byte) (string, error) {
	if _, err := Read(data); err != nil {
		return "", err
	}
	if err := os.MkdirAll(s.Directory, 0700); err != nil {
		return "", err
	}
	digest := Digest(data)
	name := filepath.Join(s.Directory, digest[7:]+".tar.gz")
	if old, err := os.ReadFile(name); err == nil && Digest(old) == digest {
		return digest, nil
	}
	if err := AtomicWrite(name, data, 0644); err != nil {
		return "", err
	}
	return digest, nil
}

func (s Store) Get(digest string) ([]byte, error) {
	if !HashPattern.MatchString(digest) {
		return nil, errors.New("artifact_digest")
	}
	f, err := os.Open(filepath.Join(s.Directory, digest[7:]+".tar.gz"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxArchive+1))
	if err != nil || len(b) > MaxArchive || Digest(b) != digest {
		return nil, errors.New("artifact_corrupt")
	}
	return b, nil
}

func (s Store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
		w.Write([]byte("ok\n"))
		return
	}
	m := artifactPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.NotFound(w, r)
		return
	}
	b, err := s.Get("sha256:" + m[1])
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Cache-Control", "private, immutable")
	w.Write(b)
}
