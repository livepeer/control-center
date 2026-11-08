package machineconfig

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
)

func ReadApplied(data []byte) (Runtime, string, error) {
	var d Runtime
	z, e := gzip.NewReader(bytes.NewReader(data))
	if e != nil {
		return d, "", e
	}
	defer z.Close()
	t := tar.NewReader(z)
	var manifest string
	for {
		h, e := t.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return d, "", e
		}
		if h.Name != "runtime.json" && h.Name != "orchestrator.yaml" && h.Name != "management/orchestrator.yaml" {
			continue
		}
		if h.Size > 1<<20 || h.Typeflag != tar.TypeReg {
			return d, "", errors.New("invalid stored Node configuration")
		}
		b, e := io.ReadAll(t)
		if e != nil {
			return d, "", e
		}
		if h.Name == "runtime.json" {
			if e = json.Unmarshal(b, &d); e != nil {
				return d, "", e
			}
		} else {
			manifest = string(b)
		}
	}
	// Pre-migration bundles lack runtime.json; derive their exact Node digest.
	if manifest == "" {
		return d, "", errors.New("stored bundle has no Node workload")
	}
	if d.ConfigDigest == "" {
		d.ConfigDigest = Digest(Desired{State: State{HeldOrchestrator: manifest}})
	}
	return d, manifest, nil
}
