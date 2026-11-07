package schema

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"reflect"
	"unicode/utf8"
	"uuid"
)

// CanonicalBytes uses fixed declaration order and Go's default HTML/Unicode
// escaping. Transport need not preserve these bytes; storage must preserve them.
func CanonicalBytes(d DefinitionV1) ([]byte, error) {
	if err := Validate(d); err != nil {
		return nil, err
	}
	b, err := json.Marshal(d)
	if len(b) > MaxCanonicalBytes {
		return nil, fmt.Errorf("canonical definition exceeds 512 KiB")
	}
	return b, err
}
func Digest(b []byte) string { sum := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(sum[:]) }

// DecodeCanonical validates complete normalized data, not current publication
// policy. Recompute the digest after canonical encoding, not over wire bytes.
func DecodeCanonical(b []byte) (DefinitionV1, error) {
	var d DefinitionV1
	e := new(ValidationError)
	if len(b) > MaxCanonicalBytes || !utf8.Valid(b) {
		e.add("$", "Invalid or oversized normalized JSON.")
		return d, e
	}
	if err := jsonv2.Unmarshal(b, &d, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		e.add("$", "Invalid normalized JSON: duplicate, unknown, or wrongly typed field.")
		return d, e
	}
	presence(b, reflect.TypeFor[DefinitionV1](), "", e)
	if err := e.err(); err != nil {
		return d, err
	}
	return d, Validate(d)
}
func presence(b json.RawMessage, t reflect.Type, p string, e *ValidationError) {
	null := bytes.Equal(bytes.TrimSpace(b), []byte("null"))
	if t.Kind() == reflect.Pointer {
		if !null {
			presence(b, t.Elem(), p, e)
		}
		return
	}
	if null {
		e.add(p, "Normalized field cannot be null.")
		return
	}
	if t.Kind() == reflect.Struct {
		var object map[string]json.RawMessage
		if json.Unmarshal(b, &object) != nil {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := f.Tag.Get("json")
			v, ok := object[name]
			if !ok {
				e.add(member(p, name), "Normalized field is missing.")
				continue
			}
			presence(v, f.Type, member(p, name), e)
		}
	} else if t.Kind() == reflect.Slice {
		var a []json.RawMessage
		_ = json.Unmarshal(b, &a)
		for i, v := range a {
			presence(v, t.Elem(), fmt.Sprintf("%s[%d]", p, i), e)
		}
	} else if t.Kind() == reflect.Map {
		var object map[string]json.RawMessage
		_ = json.Unmarshal(b, &object)
		for k, v := range object {
			presence(v, t.Elem(), member(p, k), e)
		}
	}
}

type RevisionRef struct {
	RevisionID string `json:"revision_id"`
	Digest     string `json:"digest"`
}
type ResolvedRevision struct {
	RevisionRef
	Name            string       `json:"name"`
	AppVersion      string       `json:"app_version"`
	Revision        int64        `json:"revision"`
	SchemaVersion   int          `json:"schema_version"`
	CanonicalFormat string       `json:"canonical_format"`
	Definition      DefinitionV1 `json:"definition"`
}

func (r ResolvedRevision) Verify() error {
	id, err := uuid.Parse(r.RevisionID)
	if err != nil || id.String() != r.RevisionID || id == (uuid.UUID{}) {
		return fmt.Errorf("invalid revision UUID")
	}
	if r.Revision < 1 || r.CanonicalFormat != CanonicalFormat || r.Name != r.Definition.Name || r.AppVersion != r.Definition.AppVersion || r.SchemaVersion != r.Definition.SchemaVersion {
		return fmt.Errorf("revision envelope mismatch")
	}
	b, err := CanonicalBytes(r.Definition)
	if err != nil {
		return err
	}
	if r.Digest != Digest(b) {
		return fmt.Errorf("revision digest mismatch")
	}
	return nil
}
func DecodeRevision(b []byte) (ResolvedRevision, error) {
	var r ResolvedRevision
	if len(b) > MaxCanonicalBytes+4096 || !utf8.Valid(b) {
		return r, fmt.Errorf("invalid revision envelope")
	}
	// Inspect the definition before typed envelope decoding so missing fields
	// cannot silently acquire zero values. Unknown envelope keys are also rejected.
	var object map[string]json.RawMessage
	if err := jsonv2.Unmarshal(b, &object, jsontext.AllowDuplicateNames(false)); err != nil {
		return r, err
	}
	for _, k := range []string{"revision_id", "digest", "name", "app_version", "revision", "schema_version", "canonical_format", "definition"} {
		v, ok := object[k]
		if !ok || string(v) == "null" {
			return r, fmt.Errorf("missing revision field %s", k)
		}
	}
	if _, err := DecodeCanonical(object["definition"]); err != nil {
		return r, err
	}
	if err := jsonv2.Unmarshal(b, &r, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return r, err
	}
	return r, r.Verify()
}
