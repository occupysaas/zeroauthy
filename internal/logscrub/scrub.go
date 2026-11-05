// Package logscrub removes secret-named properties and registered request values
// before log data reaches a sink.
package logscrub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
)

// Marker is the shared, frozen replacement for a hidden log value.
const Marker = logrules.Marker

var keyNormalizer = strings.NewReplacer("_", "", "-", "", ".", "")

// SensitiveKey deliberately accepts false positives: over-hiding is safer than
// allowing a secret through because its name has a prefix or different casing.
func SensitiveKey(name string) bool {
	name = keyNormalizer.Replace(strings.ToLower(name))
	if name == "code" || name == "ticket" || name == "cookie" || name == "bindingcode" {
		return true
	}
	for _, part := range [...]string{"password", "passwd", "pwd", "secret", "token", "authorization", "apikey", "privatekey", "credential", "otp", "recoverycode", "mfacode", "oobcode", "challenge", "enrollmentticket", "rememberbrowsercookie", "authnresponse", "authsession", "attestationobject", "authenticatordata", "clientdatajson", "signature", "userhandle"} {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}

// Scrub scrubs exactly one JSON document without rounding JSON numbers.
// Malformed input returns an error and no output; callers must not log the input.
func Scrub(doc []byte) ([]byte, error) {
	v, err := decode(doc)
	if err != nil {
		return nil, err
	}
	return json.Marshal(ScrubValue(v))
}

// ScrubContext applies both the secret-key policy and the current request's
// registered value masks to exactly one JSON document, including dynamic object
// keys and JSON objects/arrays encoded in strings. Sinks with a request context
// should use this instead of Scrub. Colliding masked keys retain one Marker value.
func ScrubContext(ctx context.Context, doc []byte) ([]byte, error) {
	v, err := decode(doc)
	if err != nil {
		return nil, err
	}
	return json.Marshal(ScrubValueContext(ctx, v))
}

// ScrubValueContext is the context-aware, immutable counterpart of ScrubValue.
// SensitiveKey is evaluated against original names before dynamic keys are
// masked. If different names mask to the same key, their values become Marker.
func ScrubValueContext(ctx context.Context, v any) any {
	return maskValue(ctx, ScrubValue(v))
}

func decode(doc []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(doc))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("logscrub: multiple JSON documents")
	}
	return v, nil
}

// ScrubValue returns an independent JSON-compatible map/slice tree. Embedded
// object/array JSON strings are scrubbed recursively; ordinary text is unchanged.
// Non-JSON values fail closed to Marker rather than escaping the scrubber.
func ScrubValue(v any) any {
	return scrubValue(v, make(map[visit]bool))
}

type visit struct {
	ptr    uintptr
	length int // -1 for a map; slices sharing a prefix are distinct by length
}

func scrubValue(v any, path map[visit]bool) any {
	switch v := v.(type) {
	case map[string]any:
		if v == nil {
			return v
		}
		seen := visit{ptr: uintptr(reflect.ValueOf(v).UnsafePointer()), length: -1}
		if path[seen] {
			return Marker
		}
		path[seen] = true
		defer delete(path, seen)
		out := make(map[string]any, len(v))
		for key, value := range v {
			if SensitiveKey(key) {
				out[key] = Marker
			} else {
				out[key] = scrubValue(value, path)
			}
		}
		return out
	case []any:
		if v == nil {
			return v
		}
		seen := visit{ptr: uintptr(reflect.ValueOf(v).UnsafePointer()), length: len(v)}
		if path[seen] {
			return Marker
		}
		path[seen] = true
		defer delete(path, seen)
		out := make([]any, len(v))
		for i, value := range v {
			out[i] = scrubValue(value, path)
		}
		return out
	case string:
		trimmed := strings.TrimSpace(v)
		if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
			return v
		}
		decoded, err := decode([]byte(trimmed))
		if err != nil {
			return v
		}
		out, err := json.Marshal(scrubValue(decoded, path))
		if err != nil {
			return Marker
		}
		return string(out)
	case json.Number:
		if _, err := json.Marshal(v); err != nil {
			return Marker
		}
		return v
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return Marker
		}
		return v
	case float32:
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			return Marker
		}
		return v
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return v
	default:
		// Typed maps, slices, structs and json.RawMessage must pass the same
		// policy as decoded JSON. Do not hand them unchanged to a JSON sink.
		doc, err := json.Marshal(v)
		if err != nil {
			return Marker
		}
		decoded, err := decode(doc)
		if err != nil {
			return Marker
		}
		return scrubValue(decoded, path)
	}
}
