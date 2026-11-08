package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func archive(t *testing.T, headers ...*tar.Header) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	w := tar.NewWriter(z)
	for _, h := range headers {
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := io.CopyN(w, bytes.NewReader(bytes.Repeat([]byte("x"), int(h.Size))), h.Size); err != nil {
				t.Fatal(err)
			}
		}
	}
	w.Close()
	z.Close()
	return b.Bytes()
}
func TestArchiveBoundaries(t *testing.T) {
	root := &tar.Header{Name: "kustomization.yaml", Mode: 0600, Typeflag: tar.TypeReg}
	for _, h := range []*tar.Header{{Name: "..", Typeflag: tar.TypeReg}, {Name: "../escape", Typeflag: tar.TypeReg}, {Name: "/escape", Typeflag: tar.TypeReg}, {Name: `a\b`, Typeflag: tar.TypeReg}, {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "secret"}, root} {
		if _, err := Read(archive(t, root, h)); err == nil {
			t.Fatalf("accepted unsafe/duplicate member %q", h.Name)
		}
	}
	var bomb bytes.Buffer
	z := gzip.NewWriter(&bomb)
	block := make([]byte, 1<<20)
	for i := 0; i < 65; i++ {
		z.Write(block)
	}
	z.Close()
	if _, err := Read(bomb.Bytes()); err == nil {
		t.Fatal("accepted expanded archive overflow")
	}
	b, err := Pack(map[string][]byte{"kustomization.yaml": []byte("resources: []\n"), "metadata.json": []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Pack(map[string][]byte{"metadata.json": []byte("{}"), "kustomization.yaml": []byte("resources: []\n")})
	if !bytes.Equal(b, again) {
		t.Fatal("packing is nondeterministic")
	}
	b[len(b)-1] ^= 1
	if _, err := Read(b); err == nil {
		t.Fatal("accepted corrupt gzip trailer")
	}
}
func TestStoreRepairsCorruptionAndServesOnlyImmutablePaths(t *testing.T) {
	s := Store{t.TempDir()}
	b, _ := Pack(map[string][]byte{"kustomization.yaml": []byte("resources: []\n")})
	digest, err := s.Put(b)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(s.Directory, digest[7:]+".tar.gz")
	os.WriteFile(name, []byte("corrupt"), 0600)
	if _, err := s.Get(digest); err == nil {
		t.Fatal("served corrupt artifact")
	}
	if other, err := s.Put(b); err != nil || other != digest {
		t.Fatal(other, err)
	}
	for _, test := range []struct {
		method, path string
		want         int
	}{{"GET", "/artifacts/" + digest[7:] + ".tar.gz", 200}, {"GET", "/artifacts/" + digest[7:] + ".tar.gz?token=secret", 404}, {"POST", "/artifacts/" + digest[7:] + ".tar.gz", 404}, {"GET", "/artifacts/%61" + digest[8:] + ".tar.gz", 404}, {"GET", "/healthz", 200}} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(test.method, test.path, nil))
		if w.Code != test.want {
			t.Fatalf("%s %s: %d", test.method, test.path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/artifacts/"+digest[7:]+".tar.gz", nil))
	if !bytes.Equal(w.Body.Bytes(), b) {
		t.Fatal("wrong served bytes")
	}
}
