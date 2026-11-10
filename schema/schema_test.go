package schema_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"uuid"

	"github.com/livepeer/control-center/schema"
	liverunner "github.com/livepeer/golang-runner"
)

func fixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../runtime/tests/fixtures/whoami.toml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func parse(t *testing.T, s string) schema.DefinitionV1 {
	t.Helper()
	d, err := schema.ParseTOML([]byte(s))
	if err != nil {
		t.Fatalf("%v: %+v", err, err)
	}
	return d
}
func TestCanonicalFixtureAndConsumer(t *testing.T) {
	d := parse(t, fixture(t))
	b, err := schema.CanonicalBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile("../runtime/tests/fixtures/whoami.canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := os.ReadFile("../runtime/tests/fixtures/whoami.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, golden) || schema.Digest(b) != strings.TrimSpace(string(digest)) {
		t.Fatalf("canonical golden mismatch: %s / %s", b, schema.Digest(b))
	}
	r := schema.ResolvedRevision{RevisionRef: schema.RevisionRef{RevisionID: uuid.New().String(), Digest: schema.Digest(b)}, Name: d.Name, AppVersion: d.AppVersion, Revision: 1, SchemaVersion: 1, CanonicalFormat: schema.CanonicalFormat, Definition: d}
	wire, _ := json.MarshalIndent(r, "", " ")
	decoded, err := schema.DecodeRevision(wire)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := schema.CanonicalBytes(decoded.Definition)
	if !bytes.Equal(b, again) {
		t.Fatal("consumer changed definition")
	}
	// The original is valid design input but is deliberately not the runnable fixture.
	original, err := os.ReadFile("testdata/proposed-whoami.toml")
	if err != nil {
		t.Fatal(err)
	}
	p := parse(t, string(original))
	if p.Container.Environment["PORT"] != "8080" || *p.Health.Readiness.Path != "/healthz" {
		t.Fatal("original design input was changed")
	}
}
func TestDefaultsAndIndependentModes(t *testing.T) {
	minimal := "name='example'\nschema_version=1\n[container]\nimage='traefik/whoami@sha256:c4717a8d1f0134a7444e24f881160e033991f23027c6c5a9a3f8fd22e70d1d44'\n[resources.limits]\nmemory='1GiB'\n[http]\nport=8080\n"
	d := parse(t, minimal)
	expected, err := os.ReadFile("testdata/minimal.canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	actual, err := schema.CanonicalBytes(d)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatal("v1 defaults changed", err, string(actual))
	}
	if d.AppVersion != "" || d.Container.User != nil || d.Container.Platform != nil || d.Container.Command != nil || d.Lifecycle.StopSignal != nil || d.Health.Readiness.Type != "tcp" || d.Health.Readiness.Path != nil || d.Resources.Limits.CPU != "1000m" || d.Resources.Limits.EphemeralStorage != "100000000B" || d.Resources.Requests != d.Resources.Limits || d.Instances.Replicas != 1 || d.Price.Amount != "0" {
		t.Fatalf("wrong defaults: %+v", d)
	}
	if schema.ValidatePolicy(d, schema.Offchain) != nil || schema.ValidatePolicy(d, schema.Onchain) == nil {
		t.Fatal("payment policy mismatch")
	}
	for _, life := range []string{"reusable", "single-session"} {
		for _, mode := range []string{"persistent", "single-shot"} {
			d.Instances.Mode = life
			d.Runner.Mode = mode
			if err := schema.Validate(d); err != nil {
				t.Fatal(life, mode, err)
			}
		}
	}
}
func TestSourceValidation(t *testing.T) {
	base := fixture(t)
	cases := []struct{ name, old, new, path string }{
		{"required schema", "schema_version = 1", "", "schema_version"}, {"schema", "schema_version = 1", "schema_version = 2", "schema_version"},
		{"case", "name =", "Name =", "Name"}, {"unknown", "platform =", "privileged = true\nplatform =", "container.privileged"},
		{"array unknown", "size = \"512MiB\"", "size = \"512MiB\"\nsecret = 'no'", "filesystem.scratch[0].secret"},
		{"numeric price", "amount = \"0.001\"", "amount = 0.001", "price.amount"}, {"numeric cpu fraction", "cpu = 1", "cpu = 0.5", "resources.limits.cpu"},
		{"bad decimal", "amount = \"0.001\"", "amount = '1/2'", "price.amount"}, {"exponent", "amount = \"0.001\"", "amount = '1e2'", "price.amount"},
		{"unit", "unit = \"fixed\"", "unit = '720p'", "price.unit"}, {"image", "@sha256:c4717a8d1f0134a7444e24f881160e033991f23027c6c5a9a3f8fd22e70d1d44", ":latest", "container.image"},
		{"empty args", "user =", "command = []\nuser =", "container.command"}, {"nul args", "user =", "command = [\"x\\u0000y\"]\nuser =", "container.command[0]"},
		{"user", "user = \"10001:10001\"", "user = '0:0'", "container.user"}, {"platform", "linux/amd64", "linux/arm64", "container.platform"},
		{"timeout", "timeout = \"2s\"", "timeout = '6s'", "health.readiness.timeout"}, {"duration", "interval = \"5s\"", "interval = '5ms'", "health.readiness.interval"},
		{"empty fragment", "path = \"/health\"", "path = '/health#'", "health.readiness.path"},
		{"readonly", "read_only_root = true", "read_only_root = false", "filesystem.read_only_root"}, {"egress", "egress = \"deny\"", "egress = 'allow'", "network.egress"},
		{"mount", "path = \"/tmp\"", "path = '/dev/shm'", "filesystem.scratch[0].path"}, {"memory budget", "size = \"512MiB\"", "size = '1GiB'", "filesystem.scratch"},
		{"single session capacity", "mode = \"reusable\"", "mode = 'single-session'", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := strings.Replace(base, c.old, c.new, 1)
			if c.name == "single session capacity" {
				s = strings.Replace(s, "capacity_per_instance = 1", "capacity_per_instance = 2", 1)
				c.path = "instances.capacity_per_instance"
			}
			_, err := schema.ParseTOML([]byte(s))
			var v *schema.ValidationError
			if !errors.As(err, &v) {
				t.Fatalf("expected field error, got %v", err)
			}
			for _, f := range v.Fields {
				if f.Path == c.path {
					return
				}
			}
			t.Fatalf("missing path %s: %+v", c.path, v.Fields)
		})
	}
	encoded := parse(t, strings.Replace(base, `path = "/health"`, `path = "/health%23ready"`, 1))
	b, _ := schema.CanonicalBytes(encoded)
	if _, err := schema.DecodeCanonical(b); err != nil {
		t.Fatal("encoded hash is a valid path character", err)
	}
}
func TestExactQuantitiesPricesAndEscaping(t *testing.T) {
	base := fixture(t)
	d := parse(t, strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(base, "cpu = 1", "cpu = '1.000'"), "memory = \"1GiB\"", "memory = '1.073741824GB'"), "amount = \"0.001\"", "amount = '000.001000'"))
	canonical, _ := schema.CanonicalBytes(d)
	original, _ := schema.CanonicalBytes(parse(t, base))
	if !bytes.Equal(canonical, original) {
		t.Fatal("equivalent quantities differ")
	}
	leading := parse(t, strings.Replace(base, `memory = "1GiB"`, `memory = "001024MiB"`, 1))
	if leading.Resources.Limits.Memory != "1073741824B" {
		t.Fatal("leading zeros changed decimal quantity")
	}
	for _, amount := range []string{"0.001", "12.5", "0.123456789012345678901234567890123456"} {
		price, err := liverunner.NewPriceInfo(amount, "usd", "fixed")
		if err != nil || price.Price.String() != amount {
			t.Fatal("SDK registration loses exact decimal", err)
		}
		wire, _ := json.Marshal(price)
		if !bytes.Contains(wire, []byte(`"price":`+amount)) {
			t.Fatal(string(wire))
		}
	}
	d.Container.Environment["ESCAPES"] = "<>&\u2028\u2029$(HOME)$$"
	b, err := schema.CanonicalBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`\u003c\u003e\u0026\u2028\u2029$(HOME)$$`)) {
		t.Fatal(string(b))
	}
	if _, err := schema.DecodeCanonical(b); err != nil {
		t.Fatal(err)
	}
}
func TestConsumerRejectsSelfConsistentInvalidData(t *testing.T) {
	d := parse(t, fixture(t))
	b, _ := schema.CanonicalBytes(d)
	bad := []string{
		strings.Replace(string(b), `"port":8080`, `"port":8080,"port":8080`, 1),
		strings.Replace(string(b), `"command":null,`, "", 1),
		strings.Replace(string(b), `"port":8080`, `"Port":8080`, 1),
		strings.Replace(string(b), `"capacity_per_instance":1`, `"capacity_per_instance":10001`, 1),
		strings.Replace(string(b), `"timeout":"2s"`, `"timeout":"6s"`, 1),
		strings.Replace(string(b), `"requests":{"cpu":"1000m"`, `"requests":{"cpu":"2000m"`, 1),
		strings.Replace(string(b), `"command":null`, `"command":["a\u0000b"]`, 1),
		strings.Replace(string(b), `"LOG_LEVEL":"info"`, `"LOG_LEVEL":null`, 1),
		strings.Replace(string(b), `"entrypoint":null`, `"entrypoint":[null]`, 1),
		strings.Replace(string(b), `"command":null`, `"command":[null]`, 1),
		strings.Replace(string(b), `"path":"/health"`, `"path":"/health#"`, 1),
	}
	for _, s := range bad {
		if _, err := schema.DecodeCanonical([]byte(s)); err == nil {
			t.Fatal("accepted invalid normalized data", s)
		}
		// Even a digest matching a permissively coerced definition must not
		// conceal malformed wire data from the revision decoder.
		var coerced schema.DefinitionV1
		if json.Unmarshal([]byte(s), &coerced) == nil {
			if canonical, err := schema.CanonicalBytes(coerced); err == nil {
				wire, _ := json.Marshal(map[string]any{
					"revision_id": uuid.New().String(), "digest": schema.Digest(canonical),
					"name": coerced.Name, "app_version": coerced.AppVersion, "revision": 1,
					"schema_version": 1, "canonical_format": schema.CanonicalFormat,
					"definition": json.RawMessage(s),
				})
				if _, err := schema.DecodeRevision(wire); err == nil {
					t.Fatal("accepted malformed revision with matching coerced digest", s)
				}
			}
		}
	}
}

func TestSourceSyntaxAndSizeFailures(t *testing.T) {
	for name, input := range map[string][]byte{
		"empty":        nil,
		"oversized":    []byte(strings.Repeat(" ", schema.MaxSourceBytes+1)),
		"invalid_utf8": {0xff},
		"syntax":       []byte("name = [\n"),
		"duplicate":    []byte("name='one'\nname='two'\n"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := schema.ParseTOML(input)
			var fields *schema.ValidationError
			if !errors.As(err, &fields) || len(fields.Fields) == 0 || fields.Fields[0].Path != "$" {
				t.Fatal(err)
			}
		})
	}
}

func TestCollectionBoundsAndErrorLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
		set   func(*schema.DefinitionV1, int)
	}{
		{"environment", 64, func(d *schema.DefinitionV1, n int) {
			d.Container.Environment = map[string]string{}
			for i := range n {
				d.Container.Environment[fmt.Sprintf("E_%d", i)] = "x"
			}
		}},
		{"arguments", 64, func(d *schema.DefinitionV1, n int) {
			args := make([]string, n)
			for i := range args {
				args[i] = "literal"
			}
			d.Container.Command = &args
		}},
		{"scratch", 16, func(d *schema.DefinitionV1, n int) {
			d.Filesystem.Scratch = make([]schema.Scratch, n)
			for i := range n {
				d.Filesystem.Scratch[i] = schema.Scratch{Path: fmt.Sprintf("/scratch-%d", i), Size: "1048576B"}
			}
		}},
	} {
		for _, n := range []int{tc.limit, tc.limit + 1} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, n), func(t *testing.T) {
				d := parse(t, fixture(t))
				tc.set(&d, n)
				if err := schema.Validate(d); (err == nil) != (n == tc.limit) {
					t.Fatal(n, err)
				}
			})
		}
	}
	input := fixture(t)
	for i := range 40 {
		input += fmt.Sprintf("\nunknown_%d = true", i)
	}
	_, err := schema.ParseTOML([]byte(input))
	var fields *schema.ValidationError
	if !errors.As(err, &fields) || len(fields.Fields) != 32 {
		t.Fatal("field error bound", err)
	}
}

func TestAppTOMLDefaults(t *testing.T) {
	for _, price := range []string{"", `price = { amount = "0.01" }`} {
		d := parse(t, fixture(t)+"\n[[apps]]\nname = \"test\"\npath = \"/test\"\n"+price)
		app := d.Apps[0]
		if app.Capacity != 1 || app.Price.Currency != "usd" || app.Price.Unit != "hour" || (price == "" && app.Price.Amount != "0") {
			t.Fatalf("missing app defaults: %+v", app)
		}
	}
	for _, explicit := range []string{`capacity = 0`, `price = { amount = "" }`, `price = { currency = "" }`} {
		if _, err := schema.ParseTOML([]byte(fixture(t) + "\n[[apps]]\nname = \"test\"\npath = \"/test\"\n" + explicit)); err == nil {
			t.Fatalf("defaults replaced explicit invalid value: %s", explicit)
		}
	}
}

func TestPooledAppBoundaries(t *testing.T) {
	d := parse(t, fixture(t))
	d.Apps = []schema.App{{Name: "storyboard/fal-cheap", Path: "/apps/cheap", Capacity: 2, Price: d.Price}, {Name: "ffmpeg-trim", Path: "/apps/trim", Capacity: 1, Price: d.Price}}
	d.Network.Egress = "public-https"
	d.Container.Secrets = []schema.SecretEnvironment{{Name: "FAL_KEY", Secret: "lp-app-fal", Key: "key"}}
	if err := schema.Validate(d); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*schema.DefinitionV1)
	}{
		{"nested prefix", func(d *schema.DefinitionV1) { d.Apps[1].Path = "/apps/cheap/nested" }},
		{"duplicate name", func(d *schema.DefinitionV1) { d.Apps[1].Name = d.Apps[0].Name }},
		{"escaped path", func(d *schema.DefinitionV1) { d.Apps[0].Path = "/apps/%2e%2e" }},
		{"secret authority", func(d *schema.DefinitionV1) { d.Container.Secrets[0].Secret = "runner-bootstrap" }},
		{"reserved environment", func(d *schema.DefinitionV1) { d.Container.Secrets[0].Name = "LIVEPEER_RUNTIME_INSTANCE_ID" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := d
			v.Apps = append([]schema.App(nil), d.Apps...)
			v.Container.Secrets = append([]schema.SecretEnvironment(nil), d.Container.Secrets...)
			c.change(&v)
			if schema.Validate(v) == nil {
				t.Fatal("unsafe definition accepted")
			}
		})
	}
}
