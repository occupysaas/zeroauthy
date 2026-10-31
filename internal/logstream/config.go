package logstream

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"golang.org/x/net/http/httpguts"
)

var errLogStreamInvalid = store.ErrInvalid
var streamRFC3339 = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

// Freeze the inventory's string lists once. Validation may visit thousands of
// filters in a bounded request; it must not decode the full catalog per field.
var streamContract = func() map[string][]string {
	result := map[string][]string{}
	for key, value := range logrules.Inventory().StreamContract {
		rows, ok := value.([]any)
		if !ok {
			continue
		}
		for _, row := range rows {
			if text, ok := row.(string); ok {
				result[key] = append(result[key], text)
			}
		}
	}
	return result
}()

func streamContractStrings(key string) []string { return streamContract[key] }
func streamObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var out map[string]json.RawMessage
	if json.Unmarshal(raw, &out) != nil || out == nil {
		return nil, errLogStreamInvalid
	}
	return out, nil
}
func streamDecode(raw json.RawMessage, out any) error {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errLogStreamInvalid
	}
	if json.Unmarshal(raw, out) != nil {
		return errLogStreamInvalid
	}
	return nil
}

// Configure validates and applies a candidate using the frozen sink inventory.
// Callers supply existing private fields for updates and seal them only after
// successful validation. The candidate and private map must be detached copies.
func Configure(s *store.LogStream, raw map[string]json.RawMessage, create, allowHTTP bool, private map[string]any) error {
	fields := "patch_fields"
	if create {
		fields = "create_fields"
	}
	for key, v := range raw {
		if !slices.Contains(streamContractStrings(fields), key) || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return errLogStreamInvalid
		}
	}
	schema, ok := logrules.SinkSchema(s.Type)
	if !ok {
		return errLogStreamInvalid
	}
	if v, ok := raw["name"]; ok {
		if streamDecode(v, &s.Name) != nil {
			return errLogStreamInvalid
		}
	}
	if v, ok := raw["isPriority"]; ok {
		if streamDecode(v, &s.IsPriority) != nil {
			return errLogStreamInvalid
		}
	}
	if v, ok := raw["status"]; ok {
		if streamDecode(v, &s.Status) != nil || !slices.Contains([]string{"active", "paused", "suspended"}, s.Status) {
			return errLogStreamInvalid
		}
	}
	if !schema.Delivered {
		if create {
			s.Status = "suspended"
		} else if s.Status != "suspended" {
			return errLogStreamInvalid
		}
	}
	if v, ok := raw["startFrom"]; ok {
		var text string
		if streamDecode(v, &text) != nil || !streamRFC3339.MatchString(text) {
			return errLogStreamInvalid
		}
		start, err := time.Parse(time.RFC3339Nano, text)
		if err != nil || start.IsZero() || store.ValidateLogTimes(start) != nil {
			return errLogStreamInvalid
		}
		s.StartFrom = start.UTC()
	}
	if v, ok := raw["filters"]; ok {
		var rows []json.RawMessage
		if streamDecode(v, &rows) != nil {
			return errLogStreamInvalid
		}
		filters := make([]store.LogStreamFilter, 0, len(rows))
		for _, row := range rows {
			obj, err := streamObject(row)
			if err != nil || len(obj) != 2 {
				return errLogStreamInvalid
			}
			var f store.LogStreamFilter
			if streamDecode(obj["type"], &f.Type) != nil || streamDecode(obj["name"], &f.Name) != nil || !slices.Contains(streamContractStrings("filter_type"), f.Type) || !slices.Contains(streamContractStrings("filter_names"), f.Name) {
				return errLogStreamInvalid
			}
			filters = append(filters, f)
		}
		s.Filters = filters
	}
	if v, ok := raw["pii_config"]; ok {
		obj, err := streamObject(v)
		if err != nil {
			return errLogStreamInvalid
		}
		for k := range obj {
			if !slices.Contains([]string{"log_fields", "method", "algorithm"}, k) {
				return errLogStreamInvalid
			}
		}
		pii := &store.LogStreamPII{Method: "mask", Algorithm: "xxhash"}
		if streamDecode(obj["log_fields"], &pii.LogFields) != nil || len(pii.LogFields) == 0 {
			return errLogStreamInvalid
		}
		seen := map[string]bool{}
		for _, f := range pii.LogFields {
			if seen[f] || !slices.Contains(streamContractStrings("pii_fields"), f) {
				return errLogStreamInvalid
			}
			seen[f] = true
		}
		if v, ok := obj["method"]; ok {
			if streamDecode(v, &pii.Method) != nil {
				return errLogStreamInvalid
			}
		}
		if v, ok := obj["algorithm"]; ok {
			if streamDecode(v, &pii.Algorithm) != nil {
				return errLogStreamInvalid
			}
		}
		if !slices.Contains(streamContractStrings("pii_methods"), pii.Method) || !slices.Contains(streamContractStrings("pii_algorithms"), pii.Algorithm) {
			return errLogStreamInvalid
		}
		s.PII = pii
	}
	var err error
	incoming := map[string]json.RawMessage{}
	if v, ok := raw["sink"]; ok {
		incoming, err = streamObject(v)
		if err != nil {
			return err
		}
	} else if create {
		return errLogStreamInvalid
	}
	for k := range incoming {
		if !slices.ContainsFunc(schema.Fields, func(f logrules.SinkField) bool { return f.Name == k }) {
			return errLogStreamInvalid
		}
	}
	for _, f := range schema.Fields {
		if rawValue, ok := incoming[f.Name]; ok {
			var marker string
			if f.Secret && json.Unmarshal(rawValue, &marker) == nil && marker == logrules.Marker {
				if _, exists := private[f.Name]; create || !exists {
					return errLogStreamInvalid
				}
				continue
			}
			value, err := validateStreamSinkField(f, rawValue, allowHTTP)
			if err != nil {
				return err
			}
			if f.Secret {
				private[f.Name] = value
			} else {
				s.Sink[f.Name] = value
			}
		}
		if f.Required {
			_, exists := s.Sink[f.Name]
			if f.Secret {
				_, exists = private[f.Name]
			}
			if !exists {
				return errLogStreamInvalid
			}
		}
	}
	// Validate the complete merged sink, so changes remain atomic and omitted
	// credentials are checked under the same deployment rules as new ones.
	for _, f := range schema.Fields {
		v, exists := s.Sink[f.Name]
		if f.Secret {
			v, exists = private[f.Name]
		}
		if exists {
			rawValue, _ := json.Marshal(v)
			if _, err = validateStreamSinkField(f, rawValue, allowHTTP); err != nil {
				return err
			}
		}
	}
	return nil
}
func validateStreamSinkField(f logrules.SinkField, raw json.RawMessage, allowHTTP bool) (any, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errLogStreamInvalid
	}
	switch f.Type {
	case "string":
		var v string
		if streamDecode(raw, &v) != nil || f.Required && strings.TrimSpace(v) == "" || f.Secret && v == logrules.Marker {
			return nil, errLogStreamInvalid
		}
		if len(f.Values) > 0 && !slices.Contains(f.Values, v) {
			return nil, errLogStreamInvalid
		}
		if f.Pattern != "" {
			ok, err := regexp.MatchString(f.Pattern, v)
			if err != nil || !ok {
				return nil, errLogStreamInvalid
			}
		}
		switch f.Name {
		case "httpEndpoint", "sumoSourceAddress":
			if !streamURL(v, allowHTTP) {
				return nil, errLogStreamInvalid
			}
		case "splunkDomain":
			if !streamURL("https://"+v, false) || strings.ContainsAny(v, "/?#@") {
				return nil, errLogStreamInvalid
			}
			u, _ := url.Parse("https://" + v)
			if u.Port() != "" {
				return nil, errLogStreamInvalid
			}
		case "splunkPort":
			port, err := strconv.Atoi(v)
			if err != nil || port < 1 || port > 65535 {
				return nil, errLogStreamInvalid
			}
		case "httpAuthorization":
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, errLogStreamInvalid
			}
		case "httpContentType":
			if _, _, err := mime.ParseMediaType(v); err != nil || !httpguts.ValidHeaderFieldValue(v) {
				return nil, errLogStreamInvalid
			}
		}
		return v, nil
	case "boolean":
		var v bool
		if streamDecode(raw, &v) != nil {
			return nil, errLogStreamInvalid
		}
		return v, nil
	case "array":
		var rows []json.RawMessage
		if streamDecode(raw, &rows) != nil {
			return nil, errLogStreamInvalid
		}
		out := make([]any, 0, len(rows))
		for _, row := range rows {
			obj, err := streamObject(row)
			if err != nil || len(obj) != 2 {
				return nil, errLogStreamInvalid
			}
			var header, value string
			if streamDecode(obj["header"], &header) != nil || streamDecode(obj["value"], &value) != nil || !httpguts.ValidHeaderFieldName(header) || !httpguts.ValidHeaderFieldValue(value) {
				return nil, errLogStreamInvalid
			}
			out = append(out, map[string]any{"header": header, "value": value})
		}
		return out, nil
	}
	return nil, errLogStreamInvalid
}
func streamURL(value string, allowHTTP bool) bool {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Scheme != "https" && (!allowHTTP || u.Scheme != "http") {
		return false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return !strings.ContainsAny(u.Host, "\r\n\t ")
}
