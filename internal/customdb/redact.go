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

// cutMin is the length from which RedactLine assumes a console line or an
// error message may have been cut short by the runner (it keeps 2048
// characters of a console line and 1024 of an error message).
const cutMin = 1024

// Redactor replaces the values of a connection's configuration with Mask.
// It is the single place output of a script is masked: the try response
// and the server log both go through it. A nil Redactor, or one built from
// no values, passes everything through unchanged.
type Redactor struct {
	vals []string // distinct, non-empty, longest first
	set  map[string]struct{}
	r    *strings.Replacer
}

// NewRedactor masks every non-empty value of cfg. Values match as exact,
// case-sensitive substrings; a longer value is replaced before a shorter
// one, so a value that contains another is masked whole. Keys are not
// masked.
func NewRedactor(cfg map[string]string) *Redactor {
	vals := make([]string, 0, len(cfg))
	for _, v := range cfg {
		vals = append(vals, v)
	}
	return newRedactor(vals)
}

func newRedactor(in []string) *Redactor {
	d := &Redactor{set: map[string]struct{}{}}
	for _, v := range in {
		if _, dup := d.set[v]; v == "" || dup {
			continue
		}
		d.set[v] = struct{}{}
		d.vals = append(d.vals, v)
	}
	if len(d.vals) == 0 {
		return d
	}
	sort.Slice(d.vals, func(i, j int) bool {
		if len(d.vals[i]) != len(d.vals[j]) {
			return len(d.vals[i]) > len(d.vals[j])
		}
		return d.vals[i] < d.vals[j]
	})
	pairs := make([]string, 0, 2*len(d.vals))
	for _, v := range d.vals {
		pairs = append(pairs, v, Mask)
	}
	// A Replacer tries its pairs in argument order at each position, so the
	// longest value wins, and it never rescans what it has written.
	d.r = strings.NewReplacer(pairs...)
	return d
}

// Union returns a Redactor masking the values of d and of o. It returns d
// itself when o adds none.
func (d *Redactor) Union(o *Redactor) *Redactor {
	if o == nil || len(o.vals) == 0 {
		return d
	}
	if d == nil {
		return o
	}
	added := false
	for _, v := range o.vals {
		if _, ok := d.set[v]; !ok {
			added = true
			break
		}
	}
	if !added {
		return d
	}
	return newRedactor(append(append([]string(nil), d.vals...), o.vals...))
}

// RedactLine masks a console line or an error message, which the runner may
// have cut short: besides whole values, a line of cutMin bytes or more that
// ends in the start of a value has that start masked too, so a cut never
// leaves a value's prefix.
func (d *Redactor) RedactLine(s string) string {
	if d == nil || d.r == nil {
		return s
	}
	s = d.r.Replace(s)
	if len(s) < cutMin {
		return s
	}
	best := 0
	for _, v := range d.vals {
		for k := min(len(v)-1, len(s)); k > best; k-- {
			if strings.HasSuffix(s, v[:k]) {
				best = k
				break
			}
		}
	}
	if best > 0 {
		s = s[:len(s)-best] + Mask
	}
	return s
}

// Redact returns s with every configuration value masked.
func (d *Redactor) Redact(s string) string {
	if d == nil || d.r == nil {
		return s
	}
	return d.r.Replace(s)
}

// RedactAll masks every console line of ss in place (see RedactLine) and
// returns it.
func (d *Redactor) RedactAll(ss []string) []string {
	if d == nil || d.r == nil {
		return ss
	}
	for i, s := range ss {
		ss[i] = d.RedactLine(s)
	}
	return ss
}

// RedactError returns err with the message of a *ScriptError masked (see
// RedactLine). Its Kind and Code are kept: callers act on them. Any other
// error is returned as it is.
func (d *Redactor) RedactError(err error) error {
	var se *ScriptError
	if d == nil || d.r == nil || !errors.As(err, &se) {
		return err
	}
	return &ScriptError{Kind: se.Kind, Code: se.Code, Message: d.RedactLine(se.Message)}
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
