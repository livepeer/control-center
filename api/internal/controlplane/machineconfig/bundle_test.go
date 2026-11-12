package machineconfig

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"
)

func TestConfigurationBundle(t *testing.T) {
	m := Desired{Machine: Machine{NodeID: strings.Repeat("a", 26), CredentialVersion: 1, InstallDir: "/srv/livepeer", K3sVersion: "v1.37.2+k3s1"}, RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64)}
	first, digest, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	second, other, err := Build(m)
	if err != nil || !bytes.Equal(first, second) || digest != other {
		t.Fatal("archive is not deterministic", err)
	}
	files := archiveFiles(t, first)
	for _, name := range []string{"kustomization.yaml", "system/node/orchestrator.yaml", "system/upgrade-controller/suc.yaml", "system/upgrade-controller/suc-crd.yaml", "upgrade-plan/kustomization.yaml", "upgrade-plan/plan.yaml"} {
		if _, ok := files[name]; !ok {
			t.Fatal("missing", name)
		}
	}
	for name, expected := range map[string]string{
		"system/upgrade-controller/suc-crd.yaml": "1393ba034e7691273fc519b721a7f72a0cdbef8c7b051c9e408be96090b8478d",
		"system/upgrade-controller/suc.yaml":     "81ef8c40f85b8822c87e0cf790612fc6d4dcf1eebb83f89e522bc929ef85e18c",
	} {
		hash := sha256.Sum256([]byte(files[name]))
		if hex.EncodeToString(hash[:]) != expected {
			t.Fatalf("rendering changed pinned asset %s", name)
		}
	}
	if strings.Contains(files["system/node/orchestrator.yaml"], "@INSTALL_DIR@") || strings.Contains(files["system/node/orchestrator.yaml"], "@NODE_ID@") || !strings.Contains(files["system/node/orchestrator.yaml"], "/srv/livepeer/volumes/orchestrator") {
		t.Fatal("incorrect machine rendering")
	}
	reenrolled := m
	reenrolled.NodeID = strings.Repeat("b", 26)
	fresh, _, err := Build(reenrolled)
	if err != nil {
		t.Fatal(err)
	}
	oldPV := strings.Split(files["system/node/orchestrator.yaml"], "---")[1]
	newPV := strings.Split(archiveFiles(t, fresh)["system/node/orchestrator.yaml"], "---")[1]
	if oldPV != newPV {
		t.Fatal("re-enrollment changed the retained local volume")
	}
	if !strings.Contains(files["upgrade-plan/plan.yaml"], m.K3sVersion) {
		t.Fatal("upgrade plan version missing")
	}
	hash := sha256.Sum256(first)
	if hex.EncodeToString(hash[:]) != digest {
		t.Fatal("wrong digest")
	}
	for _, tc := range []struct {
		name    string
		value   *time.Duration
		want    string
		invalid bool
	}{
		{name: "default", want: "12h0m0s"}, {name: "zero", value: new(time.Duration(0)), want: "0s"}, {name: "maximum", value: new(12 * time.Hour), want: "12h0m0s"}, {name: "negative", value: new(-time.Second), invalid: true}, {name: "excessive", value: new(13 * time.Hour), invalid: true},
	} {
		t.Run("node-drain/"+tc.name, func(t *testing.T) {
			desired := m
			desired.NodeDrainTimeout = tc.value
			desired.DrainTimeout = time.Minute
			data, _, err := Build(desired)
			if tc.invalid {
				if err == nil {
					t.Fatal("accepted invalid timeout")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			files := archiveFiles(t, data)
			if !strings.Contains(files["system/node/orchestrator.yaml"], `DrainTimeout = "`+tc.want+`"`) {
				t.Fatal("timeout lost during rendering")
			}
		})
	}

}

func archiveFiles(t *testing.T, data []byte) map[string]string {
	t.Helper()
	z, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	tarReader := tar.NewReader(io.LimitReader(z, 64<<20))
	files := map[string]string{}
	for {
		h, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg || strings.HasPrefix(h.Name, "/") || strings.Contains(h.Name, "..") {
			t.Fatal("unsafe archive member")
		}
		if _, ok := files[h.Name]; ok {
			t.Fatal("duplicate archive member")
		}
		contents, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatal(err)
		}
		files[h.Name] = string(contents)
	}
	return files
}
