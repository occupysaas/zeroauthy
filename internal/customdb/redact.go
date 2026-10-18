package customdb

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// Mask replaces a configuration value in script output, whatever its length
// (Auth0 masks the secrets a script logs the same way).
const Mask = "■■■■■■■■"

// Redactor replaces the values of a connection's configuration with Mask.
// It is the single place output of a script is masked: the try response
// and the server log lines both go through it. A nil Redactor, or one
// built from no values, passes everything through unchanged.
type Redactor struct {
	r *strings.Replacer
}

// NewRedactor masks every non-empty value of cfg. Values match as exact,
// case-sensitive substrings; a longer value is replaced before a shorter
// one, so a value that contains another is masked whole. Keys are not
// masked.
func NewRedactor(cfg map[string]string) *Redactor {
	seen := map[string]struct{}{}
	var vals []string
	for _, v := range cfg {
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		vals = append(vals, v)
	}
	if len(vals) == 0 {
		return &Redactor{}
	}
	sort.Slice(vals, func(i, j int) bool {
		if len(vals[i]) != len(vals[j]) {
			return len(vals[i]) > len(vals[j])
		}
		return vals[i] < vals[j]
	})
	pairs := make([]string, 0, 2*len(vals))
	for _, v := range vals {
		pairs = append(pairs, v, Mask)
	}
	// A Replacer tries its pairs in argument order at each position, so the
	// longest value wins, and it never rescans what it has written.
	return &Redactor{r: strings.NewReplacer(pairs...)}
}

// Redact returns s with every configuration value masked.
func (d *Redactor) Redact(s string) string {
	if d == nil || d.r == nil {
		return s
	}
	return d.r.Replace(s)
}

// RedactAll masks every string of ss in place and returns it.
func (d *Redactor) RedactAll(ss []string) []string {
	if d == nil || d.r == nil {
		return ss
	}
	for i, s := range ss {
		ss[i] = d.r.Replace(s)
	}
	return ss
}

// RedactError returns err with the code and message of a *ScriptError
// masked; any other error is returned as it is.
func (d *Redactor) RedactError(err error) error {
	var se *ScriptError
	if d == nil || d.r == nil || !errors.As(err, &se) {
		return err
	}
	return &ScriptError{Kind: se.Kind, Code: d.r.Replace(se.Code), Message: d.r.Replace(se.Message)}
}

// RedactJSON masks every string of a JSON value, object keys included.
// Numbers keep their text. A value that is not valid JSON is masked as text.
func (d *Redactor) RedactJSON(raw json.RawMessage) json.RawMessage {
	if d == nil || d.r == nil || len(raw) == 0 {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return json.RawMessage(d.r.Replace(string(raw)))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(d.walk(v)); err != nil {
		return json.RawMessage("null")
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n"))
}

func (d *Redactor) walk(v any) any {
	switch t := v.(type) {
	case string:
		return d.r.Replace(t)
	case []any:
		for i := range t {
			t[i] = d.walk(t[i])
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[d.r.Replace(k)] = d.walk(e)
		}
		return out
	}
	return v
}
