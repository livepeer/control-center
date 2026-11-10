package schema

import (
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var decimalPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
var bytesPattern = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)(B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)$`)
var units = map[string]int64{"B": 1, "KB": 1000, "MB": 1000000, "GB": 1000000000, "TB": 1000000000000, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}

func decimal(s string) (string, error) {
	if len(s) > 128 || !decimalPattern.MatchString(s) {
		return "", fmt.Errorf("use a quoted nonnegative decimal, without signs, exponents, or rational notation")
	}
	parts := strings.SplitN(s, ".", 2)
	whole := strings.TrimLeft(parts[0], "0")
	if whole == "" {
		whole = "0"
	}
	if len(parts) == 2 {
		frac := strings.TrimRight(parts[1], "0")
		if frac != "" {
			whole += "." + frac
		}
	}
	return whole, nil
}
func exactScaled(s string, scale int64) (int64, error) {
	if len(s) > 128 || !decimalPattern.MatchString(s) {
		return 0, fmt.Errorf("invalid quantity")
	}
	normalized, err := decimal(s)
	if err != nil {
		return 0, err
	}
	r, ok := new(big.Rat).SetString(normalized)
	if !ok {
		return 0, fmt.Errorf("invalid quantity")
	}
	r.Mul(r, big.NewRat(scale, 1))
	if !r.IsInt() || !r.Num().IsInt64() {
		return 0, fmt.Errorf("quantity must resolve exactly to an integer within range")
	}
	return r.Num().Int64(), nil
}
func cpu(s string) (string, error) {
	scale := int64(1000)
	if strings.HasSuffix(s, "m") {
		s = strings.TrimSuffix(s, "m")
		scale = 1
		if strings.Contains(s, ".") {
			return "", fmt.Errorf("millicores must be integers")
		}
	}
	n, err := exactScaled(s, scale)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(n, 10) + "m", nil
}
func byteSize(s string) (string, error) {
	m := bytesPattern.FindStringSubmatch(s)
	if m == nil {
		return "", fmt.Errorf("use a quoted byte quantity with B, KB–TB, or KiB–TiB")
	}
	n, err := exactScaled(m[1], units[m[2]])
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(n, 10) + "B", nil
}
func duration(s string) (string, error) {
	if len(s) > 128 {
		return "", fmt.Errorf("duration too long")
	}
	d, err := time.ParseDuration(s)
	if err != nil || d%time.Second != 0 {
		return "", fmt.Errorf("use a duration resolving to whole seconds")
	}
	return strconv.FormatInt(int64(d/time.Second), 10) + "s", nil
}
func normalize(d *DefinitionV1, e *ValidationError) {
	convert := func(path string, value *string, fn func(string) (string, error)) {
		s, err := fn(*value)
		if err != nil {
			e.add(path, err.Error())
			return
		}
		*value = s
	}
	for _, q := range []struct {
		name  string
		value *Quantities
	}{{"limits", &d.Resources.Limits}, {"requests", &d.Resources.Requests}} {
		if q.name == "requests" {
			if q.value.CPU == "" {
				q.value.CPU = d.Resources.Limits.CPU
			}
			if q.value.Memory == "" {
				q.value.Memory = d.Resources.Limits.Memory
			}
			if q.value.EphemeralStorage == "" {
				q.value.EphemeralStorage = d.Resources.Limits.EphemeralStorage
			}
		}
		p := "resources." + q.name + "."
		convert(p+"cpu", &q.value.CPU, cpu)
		convert(p+"memory", &q.value.Memory, byteSize)
		convert(p+"ephemeral_storage", &q.value.EphemeralStorage, byteSize)
	}
	convert("filesystem.shm_size", &d.Filesystem.ShmSize, byteSize)
	for i := range d.Filesystem.Scratch {
		convert(fmt.Sprintf("filesystem.scratch[%d].size", i), &d.Filesystem.Scratch[i].Size, byteSize)
	}
	for _, v := range []struct {
		p string
		s *string
	}{{"health.readiness.interval", &d.Health.Readiness.Interval}, {"health.readiness.timeout", &d.Health.Readiness.Timeout}, {"lifecycle.startup_timeout", &d.Lifecycle.StartupTimeout}, {"lifecycle.stop_grace_period", &d.Lifecycle.StopGracePeriod}} {
		convert(v.p, v.s, duration)
	}
	for n := range d.Apps {
		o := &d.Apps[n]
		convert(fmt.Sprintf("apps[%d].price.amount", n), &o.Price.Amount, decimal)
		o.Price.Currency = strings.ToLower(strings.TrimSpace(o.Price.Currency))
		o.Price.Unit = strings.ToLower(strings.TrimSpace(o.Price.Unit))
	}
	convert("price.amount", &d.Price.Amount, decimal)
	d.Price.Currency = strings.ToLower(strings.TrimSpace(d.Price.Currency))
	d.Price.Unit = strings.ToLower(strings.TrimSpace(d.Price.Unit))
}
