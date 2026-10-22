// Package settingsrules implements the closed, frozen settings schema vocabulary.
// It performs no network or repository access. Resource references are resolved
// by the caller after this pure validation succeeds.
package settingsrules

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/mail"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Error identifies the public field rejected by validation.
type Error struct {
	Field   string
	Message string
}

func (e *Error) Error() string           { return e.Field + ": " + e.Message }
func (e *Error) Unwrap() error           { return store.ErrInvalid }
func Invalid(path, message string) error { return &Error{Field: path, Message: message} }

// Schema is deliberately limited to the keywords present in the frozen inventory.
type Schema struct {
	Type          any                `json:"type"`
	Properties    map[string]*Schema `json:"properties"`
	Additional    any                `json:"additionalProperties"`
	Items         *Schema            `json:"items"`
	Required      []string           `json:"required"`
	Enum          []string           `json:"enum"`
	Minimum       *int64             `json:"minimum"`
	Maximum       *int64             `json:"maximum"`
	MinLength     *int               `json:"minLength"`
	MaxLength     *int               `json:"maxLength"`
	MinItems      *int               `json:"minItems"`
	MaxItems      *int               `json:"maxItems"`
	MinProperties *int               `json:"minProperties"`
	MaxProperties *int               `json:"maxProperties"`
	Pattern       string             `json:"pattern"`
	Format        string             `json:"format"`
	ReadOnly      bool               `json:"readOnly"`
	AnyOf         []*Schema          `json:"anyOf"`
	OneOf         []*Schema          `json:"oneOf"`
}

func Parse(raw string) *Schema {
	var s Schema
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		panic(err)
	}
	return &s
}
func ParseFeatures(raw string) map[string]*Schema {
	var s map[string]*Schema
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		panic(err)
	}
	return s
}

// Integer accepts exact integral JSON numbers and native integer inputs, without
// silently truncating floating point or overflowing a platform int.
func Integer(v any) (int64, bool) {
	var raw string
	switch n := v.(type) {
	case json.Number:
		raw = string(n)
	case float64:
		raw = fmt.Sprintf("%.17g", n)
	case float32:
		raw = fmt.Sprintf("%.9g", n)
	default:
		rv := reflect.ValueOf(v)
		if !rv.IsValid() {
			return 0, false
		}
		switch rv.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return rv.Int(), true
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if rv.Uint() > 1<<63-1 {
				return 0, false
			}
			return int64(rv.Uint()), true
		default:
			return 0, false
		}
	}
	n, ok := new(big.Rat).SetString(raw)
	if !ok || !n.IsInt() || !n.Num().IsInt64() {
		return 0, false
	}
	return n.Num().Int64(), true
}
func (s *Schema) Validate(value any, path string) error {
	bad := func(msg string) error { return Invalid(path, msg) }
	if s.ReadOnly {
		return bad("read-only field")
	}
	types := []string{}
	switch v := s.Type.(type) {
	case string:
		types = []string{v}
	case []any:
		for _, t := range v {
			types = append(types, t.(string))
		}
	}
	if value == nil {
		if slices.Contains(types, "null") {
			return nil
		}
		return bad("null is not allowed")
	}
	typ := ""
	switch value.(type) {
	case map[string]any:
		typ = "object"
	case []any, []string:
		typ = "array"
	case string:
		typ = "string"
	case bool:
		typ = "boolean"
	default:
		if _, ok := Integer(value); ok {
			typ = "integer"
		}
	}
	if len(types) > 0 && !slices.Contains(types, typ) {
		return bad("invalid type")
	}
	if len(s.AnyOf) > 0 || len(s.OneOf) > 0 {
		alternatives := s.AnyOf
		if len(alternatives) == 0 {
			alternatives = s.OneOf
		}
		count := 0
		for _, a := range alternatives {
			if a.Validate(value, path) == nil {
				count++
			}
		}
		if count == 0 || len(s.OneOf) > 0 && count != 1 {
			return bad("invalid format")
		}
	}
	switch v := value.(type) {
	case map[string]any:
		if s.MinProperties != nil && len(v) < *s.MinProperties || s.MaxProperties != nil && len(v) > *s.MaxProperties {
			return bad("invalid property count")
		}
		for _, key := range s.Required {
			if _, ok := v[key]; !ok {
				return Invalid(join(path, key), "required field")
			}
		}
		for key, val := range v {
			child, ok := s.Properties[key]
			if !ok {
				switch extra := s.Additional.(type) {
				case bool:
					if !extra {
						return Invalid(join(path, key), "unknown field")
					}
					continue
				case map[string]any:
					b, _ := json.Marshal(extra)
					child = Parse(string(b))
				default:
					return Invalid(join(path, key), "unknown field")
				}
			}
			if err := child.Validate(val, join(path, key)); err != nil {
				return err
			}
		}
	case string:
		size := utf8.RuneCountInString(v)
		if s.MinLength != nil && size < *s.MinLength || s.MaxLength != nil && size > *s.MaxLength {
			return bad("invalid length")
		}
		if len(s.Enum) > 0 && !slices.Contains(s.Enum, v) {
			return bad("invalid enum value")
		}
		if s.Pattern != "" && !regexp.MustCompile(s.Pattern).MatchString(v) {
			return bad("invalid pattern")
		}
		if !validFormat(s.Format, v) {
			return bad("invalid format")
		}
	case []any:
		return s.validateArray(v, path)
	case []string:
		a := make([]any, len(v))
		for i, x := range v {
			a[i] = x
		}
		return s.validateArray(a, path)
	default:
		if typ == "integer" {
			n, _ := Integer(value)
			if s.Minimum != nil && n < *s.Minimum || s.Maximum != nil && n > *s.Maximum {
				return bad("out of range")
			}
		}
	}
	return nil
}
func (s *Schema) validateArray(a []any, path string) error {
	if s.MinItems != nil && len(a) < *s.MinItems || s.MaxItems != nil && len(a) > *s.MaxItems {
		return Invalid(path, "invalid item count")
	}
	if s.Items != nil {
		for i, v := range a {
			if err := s.Items.Validate(v, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}
func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
func validFormat(format, v string) bool {
	switch format {
	case "":
		return true
	case "email-or-empty":
		if v == "" {
			return true
		}
		a, err := mail.ParseAddress(v)
		return err == nil && a.Address == v && strings.Contains(v, "@")
	case "absolute-uri-or-empty", "absolute-https-uri-or-empty":
		if v == "" {
			return true
		}
		u, err := url.Parse(v)
		return err == nil && u.IsAbs() && (format != "absolute-https-uri-or-empty" || u.Scheme == "https" && u.Host != "")
	case "url-with-placeholders":
		return clientrules.CheckURL(v) == nil
	case "ipv4", "ipv6":
		a, err := netip.ParseAddr(v)
		return err == nil && a.Zone() == "" && (format == "ipv4" && a.Is4() || format == "ipv6" && a.Is6())
	case "cidr", "ipv6_cidr":
		p, err := netip.ParsePrefix(v)
		return err == nil && (format == "cidr" && p.Addr().Is4() || format == "ipv6_cidr" && p.Addr().Is6())
	case "acr":
		return v != "" && !strings.ContainsAny(v, " \t\r\n")
	default:
		return false
	}
}

// Merge recursively merges objects and replaces arrays, owning every result.
// Legal nulls remove fields so public rendering may supply local defaults.
func Merge(current, patch map[string]any) map[string]any {
	out := store.CloneSettings(current)
	if out == nil {
		out = map[string]any{}
	}
	for key, value := range patch {
		if value == nil {
			delete(out, key)
			continue
		}
		if obj, ok := value.(map[string]any); ok {
			prior, _ := out[key].(map[string]any)
			out[key] = Merge(prior, obj)
		} else {
			out[key] = store.CloneSettings(map[string]any{"v": value})["v"]
		}
	}
	return out
}

// Normalize converts validated integer fields to int64 so spellings such as
// JSON 1e1 remain valid when decoding into typed policies. Open maps retain
// their original numeric values; only inventoried integer fields are changed.
func (s *Schema) Normalize(value any) any {
	if s.Type == "integer" {
		if n, ok := Integer(value); ok {
			return n
		}
	}
	switch v := value.(type) {
	case map[string]any:
		out := store.CloneSettings(v)
		for key, child := range s.Properties {
			if x, ok := out[key]; ok {
				out[key] = child.Normalize(x)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			if s.Items != nil {
				out[i] = s.Items.Normalize(x)
			} else {
				out[i] = x
			}
		}
		return out
	default:
		return value
	}
}
