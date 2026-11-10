package schema

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/distribution/reference"
	"github.com/j0sh/boa/pkg/boa"
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var envPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var dotSegment = regexp.MustCompile(`(^|/)\.{1,2}(/|$)`)

func cleanText(s string, max int) bool {
	return utf8.ValidString(s) && len(s) <= max && !strings.ContainsFunc(s, unicode.IsControl)
}
func absolute(s string) bool {
	return cleanText(s, 4096) && strings.HasPrefix(s, "/") && path.Clean(s) == s
}
func ValidName(name string) bool { return namePattern.MatchString(name) }

func ValidateReplicaCount(n int) error {
	if n < 1 || n > MaxReplicas {
		return fmt.Errorf("replicas must be between 1 and %d", MaxReplicas)
	}
	return nil
}

// Validate checks the entire normalized v1 contract, including cross-field
// invariants. It applies neither defaults nor deployment/payment policy.
func Validate(d DefinitionV1) error {
	if err := boa.Validate(d); err != nil {
		return schemaError(err)
	}
	return validateSemantics(d)
}

func validateSemantics(d DefinitionV1) error {
	e := new(ValidationError)
	check := func(ok bool, p, msg string) {
		if !ok {
			e.add(p, msg)
		}
	}
	number := func(s, suffix, p string, min, max int64) int64 {
		n, err := strconv.ParseInt(strings.TrimSuffix(s, suffix), 10, 64)
		check(err == nil && n >= min && n <= max, p, "Quantity is outside the supported range.")
		return n
	}
	check(cleanText(d.AppVersion, 128) && strings.TrimSpace(d.AppVersion) == d.AppVersion, "app_version", "Use an opaque string of at most 128 bytes, without surrounding whitespace or controls.")
	ref, err := reference.Parse(d.Container.Image)
	_, pinned := ref.(reference.Digested)
	check(err == nil && pinned && digestPattern.MatchString(refDigest(ref)), "container.image", "Use a valid OCI image reference pinned by sha256 digest.")
	for _, a := range []struct {
		p string
		v *[]string
	}{{"container.entrypoint", d.Container.Entrypoint}, {"container.command", d.Container.Command}} {
		if a.v != nil {
			for i, s := range *a.v {
				check(utf8.ValidString(s) && len(s) <= 4096 && !strings.ContainsRune(s, 0), fmt.Sprintf("%s[%d]", a.p, i), "Arguments must be UTF-8, at most 4 KiB, and contain no NUL.")
			}
		}
	}
	if d.Container.WorkingDir != nil {
		check(absolute(*d.Container.WorkingDir), "container.working_dir", "Use a canonical absolute path.")
	}
	if d.Container.User != nil {
		parts := strings.Split(*d.Container.User, ":")
		valid := len(parts) == 2
		for _, s := range parts {
			n, err := strconv.ParseUint(s, 10, 31)
			valid = valid && err == nil && n > 0 && strconv.FormatUint(n, 10) == s
		}
		check(valid, "container.user", "Use nonzero numeric UID:GID, each at most 2147483647.")
	}
	reservedEnv := func(s string) bool { return strings.HasPrefix(s, "LIVEPEER_RUNTIME_") }
	names := map[string]bool{}
	for n, secret := range d.Container.Secrets {
		p := fmt.Sprintf("container.secrets[%d]", n)
		check(envPattern.MatchString(secret.Name) && !reservedEnv(secret.Name) && !names[secret.Name], p+".name", "Use a unique, nonreserved environment name.")
		names[secret.Name] = true
		check(regexp.MustCompile(`^lp-app-[a-z0-9]([-a-z0-9]*[a-z0-9])?$`).MatchString(secret.Secret) && len(secret.Secret) <= 63, p+".secret", "Use an operator-provisioned lp-app-* Secret in livepeer-apps.")
		check(regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`).MatchString(secret.Key), p+".key", "Invalid Secret key.")
	}
	envBytes := 0
	for k, v := range d.Container.Environment {
		check(envPattern.MatchString(k) && !reservedEnv(k) && !names[k], "container.environment", "Invalid, duplicate or reserved environment name.")
		check(utf8.ValidString(v) && !strings.ContainsRune(v, 0), "container.environment."+k, "Environment values must be UTF-8 without NUL.")
		envBytes += len(k) + len(v)
	}
	check(envBytes <= 16<<10, "container.environment", "Environment exceeds 16 KiB.")
	quantities := func(q Quantities, kind string) [3]int64 {
		p := "resources." + kind + "."
		return [3]int64{
			number(q.CPU, "m", p+"cpu", 1, 1024000),
			number(q.Memory, "B", p+"memory", 1<<20, 1<<40),
			number(q.EphemeralStorage, "B", p+"ephemeral_storage", 1<<20, 1<<40),
		}
	}
	limits, requests := quantities(d.Resources.Limits, "limits"), quantities(d.Resources.Requests, "requests")
	for i, key := range []string{"cpu", "memory", "ephemeral_storage"} {
		check(requests[i] <= limits[i], "resources.requests."+key, "Request exceeds its limit.")
	}
	r := d.Health.Readiness
	if r.Type == "http" {
		valid := r.Path != nil
		if valid {
			u, err := url.Parse(*r.Path)
			valid = err == nil && strings.HasPrefix(*r.Path, "/") && !strings.HasPrefix(*r.Path, "//") && !strings.ContainsRune(*r.Path, '#') && cleanText(*r.Path, 4096) && u.Scheme == "" && u.Host == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !dotSegment.MatchString(u.Path)
		}
		check(valid, "health.readiness.path", "HTTP readiness requires a local absolute path without query, fragment, or traversal.")
	} else {
		check(r.Path == nil, "health.readiness.path", "TCP readiness cannot specify a path.")
	}
	interval := number(r.Interval, "s", "health.readiness.interval", 1, 300)
	timeout := number(r.Timeout, "s", "health.readiness.timeout", 1, 60)
	check(timeout <= interval, "health.readiness.timeout", "Timeout exceeds interval.")
	scratch := number(d.Filesystem.ShmSize, "B", "filesystem.shm_size", 1<<20, 1<<40)
	reserved := []string{"/proc", "/sys", "/dev", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/var/run/secrets", "/run/secrets"}
	overlaps := func(a, b string) bool { return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/") }
	for i, m := range d.Filesystem.Scratch {
		p := fmt.Sprintf("filesystem.scratch[%d]", i)
		valid := absolute(m.Path) && m.Path != "/"
		for _, r := range reserved {
			valid = valid && !overlaps(m.Path, r)
		}
		check(valid, p+".path", "Scratch path overlaps a reserved path or is not canonical.")
		for j := 0; j < i; j++ {
			check(!overlaps(m.Path, d.Filesystem.Scratch[j].Path), p+".path", "Scratch mounts overlap.")
		}
		scratch += number(m.Size, "B", p+".size", 1<<20, 1<<40)
	}
	check(scratch <= limits[1], "filesystem.scratch", "Scratch plus shared memory exceeds the memory limit.")
	number(d.Lifecycle.StartupTimeout, "s", "lifecycle.startup_timeout", 1, 3600)
	number(d.Lifecycle.StopGracePeriod, "s", "lifecycle.stop_grace_period", 0, 300)
	check(d.Instances.Mode != "single-session" || d.Instances.CapacityPerInstance == 1, "instances.capacity_per_instance", "Single-session instances require capacity one.")
	names = map[string]bool{}
	paths := map[string]bool{}
	for n, app := range d.Apps {
		p := fmt.Sprintf("apps[%d]", n)
		validName := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`).MatchString(app.Name) && !dotSegment.MatchString(app.Name) && !strings.Contains(app.Name, "//") && !strings.HasSuffix(app.Name, "/")
		check(validName && !names[app.Name], p+".name", "Use a unique public app name without traversal or controls.")
		check(absolute(app.Path) && app.Path != "/" && !strings.ContainsAny(app.Path, "%?#\\") && !paths[app.Path], p+".path", "Use a unique canonical backend prefix.")
		for previous := range paths {
			check(!strings.HasPrefix(app.Path, previous+"/") && !strings.HasPrefix(previous, app.Path+"/"), p+".path", "App prefixes cannot overlap.")
		}
		names[app.Name], paths[app.Path] = true, true
	}
	return e.err()
}
func refDigest(r reference.Reference) string {
	if d, ok := r.(reference.Digested); ok {
		return d.Digest().String()
	}
	return ""
}
func ValidatePolicy(d DefinitionV1, mode PaymentMode) error {
	e := new(ValidationError)
	if mode != Offchain && mode != Onchain {
		e.add("price", "Unknown registry payment mode.")
	} else if mode == Onchain && len(d.Apps) == 0 && d.Price.Amount == "0" {
		e.add("price.amount", "Onchain publications and new bindings require an explicit positive price.")
	}
	if mode == Onchain {
		for n, o := range d.Apps {
			if o.Price.Amount == "0" {
				e.add(fmt.Sprintf("apps[%d].price.amount", n), "Onchain apps require a positive price.")
			}
		}
	}
	return e.err()
}
