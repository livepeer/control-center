package machineconfig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/livepeer/control-center/api/internal/testdb"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/ingressauth"
	"go.yaml.in/yaml/v3"
)

func ingressDesired() (Desired, *ingressauth.Signer) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signer := &ingressauth.Signer{Private: key, Keys: ingressauth.Keys{"test": key.Public().(ed25519.PublicKey)}}
	m := Desired{Machine: Machine{NodeID: "vkvkvkvkvkvkuaaaaaaaaaaaaa"}, RuntimeImage: "registry.invalid/runtime@sha256:" + strings.Repeat("a", 64), IngressPublicKeys: signer.Keys.JSON(), Exposure: &Exposure{IngressVersion: 1, TunnelID: "tunnel", ServiceURL: "https://api.node.example", DiscoveryURL: "https://discovery.node.example/discovery", ProxyURLTemplate: "https://{proxy}.node.example"}}
	return m, signer
}

// Exercise the generated rules and middleware with the actual pinned Traefik
// process. Only Kubernetes resource discovery is replaced by the file provider.
func TestTraefikIngressRoutingAndAuthentication(t *testing.T) {
	binary := os.Getenv("TRAEFIK_BINARY")
	if binary == "" {
		t.Skip("set TRAEFIK_BINARY to Traefik 3.7.15 (bundled with K3s v1.37.2+k3s1)")
	}
	version, err := exec.CommandContext(t.Context(), binary, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "3.7.15") {
		t.Fatal("incorrect Traefik fixture", err)
	}
	m, signer := ingressDesired()
	handler, _ := ingressauth.Handler(signer.Keys, m.NodeID)
	auth := httptest.NewServer(handler)
	defer auth.Close()
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, "incomplete upload", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"host": r.Host, "authorization": r.Header.Get("Authorization")})
	}))
	defer node.Close()
	files := map[string][]byte{}
	if err := addIngress(files, m); err != nil {
		t.Fatal(err)
	}
	routers, middlewares := map[string]any{}, map[string]any{}
	decoder := yaml.NewDecoder(bytes.NewReader(files["system/ingress/routes.yaml"]))
	for {
		var doc struct {
			Kind     string
			Metadata struct{ Name string }
			Spec     map[string]any
		}
		if err := decoder.Decode(&doc); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		switch doc.Kind {
		case "Middleware":
			if forward, ok := doc.Spec["forwardAuth"].(map[string]any); ok {
				forward["address"] = auth.URL + "/authorize"
			}
			middlewares[doc.Metadata.Name] = doc.Spec
		case "IngressRoute":
			for _, item := range doc.Spec["routes"].([]any) {
				route := item.(map[string]any)
				router := map[string]any{"entryPoints": doc.Spec["entryPoints"], "rule": route["match"], "service": "node"}
				if chain, ok := route["middlewares"].([]any); ok {
					names := []string{}
					for _, item := range chain {
						names = append(names, item.(map[string]any)["name"].(string))
					}
					router["middlewares"] = names
				}
				routers[doc.Metadata.Name] = router
			}
		}
	}
	config := map[string]any{"http": map[string]any{"routers": routers, "middlewares": middlewares, "services": map[string]any{"node": map[string]any{"loadBalancer": map[string]any{"passHostHeader": true, "servers": []any{map[string]any{"url": node.URL}}}}}}}
	data, _ := yaml.Marshal(config)
	dir := t.TempDir()
	path := filepath.Join(dir, "dynamic.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	addresses := map[string]string{}
	ports := readTraefikBootstrapValues(t).Ports
	args := []string{"--providers.file.filename=" + path, "--log.level=ERROR"}
	for _, entry := range []string{"livepeer-api", "livepeer-discovery", "livepeer-apps"} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addresses[entry] = listener.Addr().String()
		listener.Close()
		args = append(args, "--entrypoints."+entry+".address="+addresses[entry])
		if timeout := ports[entry].Transport.RespondingTimeouts.ReadTimeout; timeout != "" {
			args = append(args, "--entrypoints."+entry+".transport.respondingtimeouts.readtimeout="+timeout)
		}
	}
	log, err := os.Create(filepath.Join(dir, "traefik.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), binary, args...)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		if t.Failed() {
			data, _ := os.ReadFile(log.Name())
			t.Log(string(data))
		}
	})
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for deadline := time.Now().Add(10 * time.Second); ; {
		probe, _ := http.NewRequest("GET", "http://"+addresses["livepeer-api"]+"/apps/a/session", nil)
		probe.Host = "orchestrator.livepeer.svc.cluster.local:8935"
		res, err := client.Do(probe)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Traefik did not start", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	valid, _ := signer.Discovery("test", m.NodeID, time.Now())
	wrong, _ := signer.Discovery("test", strings.Repeat("a", 26), time.Now())
	expired, _ := signer.Discovery("test", m.NodeID, time.Now().Add(-ingressauth.Lifetime-time.Minute))
	for _, check := range []struct {
		entry, host, path, method, bearer string
		status                            int
	}{
		{"livepeer-api", "orchestrator.livepeer.svc.cluster.local:8935", "/apps/a/session", "GET", "", 200},
		{"livepeer-api", "orchestrator.livepeer.svc.cluster.local:8935", "/discovery", "GET", valid, 404},
		{"livepeer-api", "orchestrator.livepeer.svc.cluster.local:8935", "/apps/a/app", "GET", "", 404},
		{"livepeer-apps", "app.node.example", "/v1/completions", "POST", "application-token", 200},
		{"livepeer-apps", "app.node.example", "/discovery", "GET", valid, 404},
		{"livepeer-apps", "app.node.example", "/%64iscovery", "GET", valid, 404},
		{"livepeer-apps", "app.node.example", "/./discovery", "GET", valid, 404},
		{"livepeer-apps", "app.node.example", "/runners/heartbeat", "POST", "", 404},
		{"livepeer-apps", "app.node.example", "/ai/trickle/private/0", "GET", "", 404},
		{"livepeer-apps", "unknown.example", "/v1/completions", "GET", "", 404},
		{"livepeer-discovery", "orchestrator.livepeer.svc.cluster.local:8935", "/discovery", "GET", valid, 200},
		{"livepeer-discovery", "orchestrator.livepeer.svc.cluster.local:8935", "/discovery", "GET", "", 401},
		{"livepeer-discovery", "orchestrator.livepeer.svc.cluster.local:8935", "/discovery", "GET", wrong, 401},
		{"livepeer-discovery", "orchestrator.livepeer.svc.cluster.local:8935", "/discovery", "GET", expired, 401},
		{"livepeer-discovery", "orchestrator.livepeer.svc.cluster.local:8935", "/discovery", "GET", valid + "x", 401},
		{"livepeer-discovery", "orchestrator.livepeer.svc.cluster.local:8935", "/discovery", "POST", valid, 404},
		{"livepeer-discovery", "orchestrator.livepeer.svc.cluster.local:8935", "/apps/a/session", "GET", valid, 404},
	} {
		t.Run(check.entry+check.path+check.bearer[:min(len(check.bearer), 8)], func(t *testing.T) {
			r, _ := http.NewRequest(check.method, "http://"+addresses[check.entry]+check.path, nil)
			r.Host = check.host
			if check.bearer != "" {
				r.Header.Set("Authorization", "Bearer "+check.bearer)
			}
			r.Header.Set("X-Forwarded-Host", "attacker.example")
			r.Header.Set("X-Forwarded-Uri", "/readyz")
			res, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != check.status {
				t.Fatalf("status=%d want=%d", res.StatusCode, check.status)
			}
			if res.StatusCode == 200 {
				var echo map[string]string
				json.NewDecoder(res.Body).Decode(&echo)
				if echo["host"] != check.host {
					t.Fatal("Host changed", echo)
				}
				if check.entry == "livepeer-discovery" && echo["authorization"] != "" {
					t.Fatal("discovery bearer forwarded")
				}
				if check.entry == "livepeer-apps" && echo["authorization"] != "Bearer "+check.bearer {
					t.Fatal("app authorization removed")
				}
			}
		})
	}
	t.Run("streaming-upload", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 75*time.Second)
		defer cancel()
		body, writer := io.Pipe()
		defer body.Close()
		go func() {
			defer writer.Close()
			if _, err := writer.Write([]byte("start")); err != nil {
				return
			}
			select {
			case <-time.After(61 * time.Second):
			case <-ctx.Done():
				return
			}
			_, _ = writer.Write([]byte("end"))
		}()
		r, _ := http.NewRequestWithContext(ctx, "POST", "http://"+addresses["livepeer-apps"]+"/v1/completions", body)
		r.Host = "app.node.example"
		res, err := (&http.Client{Timeout: 75 * time.Second}).Do(r)
		if err != nil {
			t.Fatal("streaming upload interrupted", err)
		}
		res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatal("streaming upload rejected", res.StatusCode)
		}
	})
	auth.Close()
	r, _ := http.NewRequest("GET", "http://"+addresses["livepeer-discovery"]+"/discovery", nil)
	r.Host = "orchestrator.livepeer.svc.cluster.local:8935"
	r.Header.Set("Authorization", "Bearer "+valid)
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode < 500 {
		t.Fatal("verifier failure allowed access", res.StatusCode)
	}
}

func TestManagementRepairPreservesIngressVersion(t *testing.T) {
	db := testdb.Open(t)
	if _, err := db.Exec(`CREATE SCHEMA lpcc; CREATE TABLE lpcc.machine_configs(node_id TEXT PRIMARY KEY, bundle BYTEA)`); err != nil {
		t.Fatal(err)
	}
	m, _ := ingressDesired()
	m.InstallDir, m.K3sVersion = "/opt/livepeer", "v1.37.2+k3s1"
	m.CredentialVersion = 1
	m.State = InitialState(false)
	m.Connector.Image = m.RuntimeImage
	m.Exposure.IngressDigest = "provider-ingress"
	data, _, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO lpcc.machine_configs VALUES($1,$2)`, m.NodeID, data); err != nil {
		t.Fatal(err)
	}
	manager := New(Config{RuntimeImage: m.RuntimeImage, Connector: m.Connector,
		IngressPublicKeys: []byte(`{"next":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`)},
		Dependencies{DB: db, Exposure: func(json.RawMessage) (*Exposure, error) {
			return nil, errors.New("lifecycle observation unavailable")
		}})
	record := Record{State: m.State}
	exposure, _, err := manager.planManagement(t.Context(), m.Machine, &record)
	if err != nil || exposure == nil || exposure.IngressVersion != m.Exposure.IngressVersion {
		t.Fatal("repair lost applied ingress identity", exposure, err)
	}
	repair := manager.Desired(m.Machine, record.State, exposure)
	updated, _, err := Build(repair)
	if err != nil {
		t.Fatal("repair blocked by lifecycle observation failure", err)
	}
	before, _ := artifact.Read(data)
	after, _ := artifact.Read(updated)
	if string(before["system/node/orchestrator.yaml"]) != string(after["system/node/orchestrator.yaml"]) ||
		string(before["system/ingress/auth.yaml"]) == string(after["system/ingress/auth.yaml"]) {
		t.Fatal("key repair changed Node or failed to update ingress")
	}
	// An old, unversioned bundle must still require the explicit migration.
	exposure.IngressVersion = 0
	if _, _, err = Build(manager.Desired(m.Machine, record.State, exposure)); err == nil {
		t.Fatal("repair bypassed the external migration prerequisite")
	}
}

type traefikBootstrapValues struct {
	Service struct{ Spec struct{ Type string } }
	Ports   map[string]struct {
		Port        int
		ExposedPort int `yaml:"exposedPort"`
		Expose      struct{ Default bool }
		Transport   struct {
			RespondingTimeouts struct {
				ReadTimeout string `yaml:"readTimeout"`
			} `yaml:"respondingTimeouts"`
		}
	}
}

func readTraefikBootstrapValues(t *testing.T) traefikBootstrapValues {
	t.Helper()
	data, err := os.ReadFile("../../../../runtime/config/traefik.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var chart struct {
		Spec struct {
			ValuesContent string `yaml:"valuesContent"`
		}
	}
	if err := yaml.Unmarshal(data, &chart); err != nil {
		t.Fatal(err)
	}
	var values traefikBootstrapValues
	if err := yaml.Unmarshal([]byte(chart.Spec.ValuesContent), &values); err != nil {
		t.Fatal(err)
	}
	return values
}

func TestPrivateTraefikBootstrapValues(t *testing.T) {
	values := readTraefikBootstrapValues(t)
	if values.Service.Spec.Type != "ClusterIP" {
		t.Fatal("ingress must remain private")
	}
	used := map[int]bool{}
	for _, entry := range []string{"traefik", "livepeer-api", "livepeer-discovery", "livepeer-apps"} {
		port := values.Ports[entry]
		if port.Port == 0 || used[port.Port] {
			t.Fatal("ingress listener collision", entry)
		}
		used[port.Port] = true
		if entry == "traefik" && port.Expose.Default {
			t.Fatal("management entrypoint exposed")
		}
		if entry != "traefik" && (!port.Expose.Default || port.ExposedPort != port.Port) {
			t.Fatal("incorrect tunnel entrypoint", entry)
		}
	}
	if values.Ports["livepeer-apps"].Transport.RespondingTimeouts.ReadTimeout != "0s" {
		t.Fatal("app uploads have an ingress timeout")
	}
	data, err := os.ReadFile("../../../../runtime/config/k3s.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var k3s struct{ Disable []string }
	if err := yaml.Unmarshal(data, &k3s); err != nil {
		t.Fatal(err)
	}
	serviceLBDisabled := false
	for _, item := range k3s.Disable {
		if item == "traefik" {
			t.Fatal("ingress disabled")
		}
		if item == "servicelb" {
			serviceLBDisabled = true
		}
	}
	if !serviceLBDisabled {
		t.Fatal("public ServiceLB enabled")
	}
}
