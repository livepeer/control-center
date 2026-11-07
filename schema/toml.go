package schema

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"github.com/j0sh/boa/pkg/boa"
)

var fieldBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`)

func schemaError(err error) error {
	var fields *boa.ValidationError
	if !errors.As(err, &fields) {
		return err
	}
	e := new(ValidationError)
	for _, field := range fields.Fields {
		e.add(strings.ToLower(fieldBoundary.ReplaceAllString(field.Path, "${1}_${2}")), field.Err.Error())
	}
	return e.err()
}

// ParseTOML checks original keys/kinds before decoding: TextUnmarshaler and
// BurntSushi's case-insensitive field matching would otherwise coerce input.
func ParseTOML(data []byte) (DefinitionV1, error) {
	d, err := boa.ParseConfigBytes[DefinitionV1](data, decodeTOML)
	if err == nil {
		err = validateSemantics(d)
	}
	return d, schemaError(err)
}

func decodeTOML(data []byte, target any) error {
	d := target.(*DefinitionV1)
	d.Resources.Limits.CPU, d.Resources.Limits.EphemeralStorage = "1000m", "100000000B"
	e := new(ValidationError)
	if len(data) == 0 || len(data) > MaxSourceBytes || !utf8.Valid(data) {
		e.add("$", "Provide UTF-8 TOML of at most 64 KiB.")
		return e
	}
	var tree map[string]any
	if _, err := toml.Decode(string(data), &tree); err != nil {
		message := "Invalid TOML syntax."
		var parseError toml.ParseError
		if errors.As(err, &parseError) {
			message = fmt.Sprintf("Invalid TOML at line %d, column %d.", parseError.Position.Line, parseError.Position.Col)
		}
		e.add("$", message)
		return e
	}
	if h, ok := tree["health"].(map[string]any); ok {
		if _, exists := h["readiness"]; exists {
			d.Health.Readiness.Type = "http"
		}
	}
	assignTOML(reflect.ValueOf(d).Elem(), tree, "", e)
	if err := e.err(); err != nil {
		return err
	}
	normalize(d, e)
	return e.err()
}
func member(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}
func assignTOML(dst reflect.Value, raw any, path string, e *ValidationError) {
	if dst.Kind() == reflect.Pointer {
		dst.Set(reflect.New(dst.Type().Elem()))
		assignTOML(dst.Elem(), raw, path, e)
		return
	}
	switch dst.Kind() {
	case reflect.Struct:
		object, ok := raw.(map[string]any)
		if !ok {
			e.add(path, "Expected a table.")
			return
		}
		fields := map[string]int{}
		for i := 0; i < dst.NumField(); i++ {
			fields[dst.Type().Field(i).Tag.Get("json")] = i
		}
		for key, value := range object {
			i, ok := fields[key]
			if !ok {
				e.add(member(path, key), "Unknown field (names are case-sensitive).")
				continue
			}
			assignTOML(dst.Field(i), value, member(path, key), e)
		}
	case reflect.Map:
		object, ok := raw.(map[string]any)
		if !ok {
			e.add(path, "Expected a string table.")
			return
		}
		dst.Set(reflect.MakeMap(dst.Type()))
		for k, v := range object {
			s, ok := v.(string)
			if !ok {
				e.add(member(path, k), "Expected a string.")
				continue
			}
			dst.SetMapIndex(reflect.ValueOf(k), reflect.ValueOf(s))
		}
	case reflect.Slice:
		v := reflect.ValueOf(raw)
		if v.Kind() != reflect.Slice {
			e.add(path, "Expected an array.")
			return
		}
		dst.Set(reflect.MakeSlice(dst.Type(), v.Len(), v.Len()))
		for i := 0; i < v.Len(); i++ {
			if dst.Type().Elem() == reflect.TypeFor[Scratch]() {
				dst.Index(i).FieldByName("Size").SetString("67108864B")
			}
			assignTOML(dst.Index(i), v.Index(i).Interface(), fmt.Sprintf("%s[%d]", path, i), e)
		}
	case reflect.String:
		s, ok := raw.(string)
		if !ok && strings.HasSuffix(path, ".cpu") {
			if n, yes := raw.(int64); yes {
				s = strconv.FormatInt(n, 10)
				ok = true
			}
		}
		if !ok {
			e.add(path, "Expected a string (CPU also accepts integer cores).")
			return
		}
		if s == "" && strings.HasPrefix(path, "resources.") {
			e.add(path, "Explicit resource quantities cannot be empty.")
			return
		}
		dst.SetString(s)
	case reflect.Int:
		n, ok := raw.(int64)
		if !ok || dst.OverflowInt(n) {
			e.add(path, "Expected an integer.")
			return
		}
		dst.SetInt(n)
	case reflect.Bool:
		b, ok := raw.(bool)
		if !ok {
			e.add(path, "Expected a boolean.")
			return
		}
		dst.SetBool(b)
	}
}
