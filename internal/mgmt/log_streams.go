package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/logstream"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"golang.org/x/net/http/httpguts"
)

var errLogStreamInvalid = badBody("invalid log stream configuration")
var streamRFC3339 = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

var errLogStreamConflict = &Error{Status: 409, Code: "conflict", Message: "The log stream changed concurrently"}

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
func (h *Handlers) streamError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrInvalid):
		Fail(w, errLogStreamInvalid)
	case errors.Is(err, store.ErrConflict):
		Fail(w, errLogStreamConflict)
	case errors.Is(err, store.ErrNotFound):
		Fail(w, &Error{Status: 404, Code: "not_found", Message: "Log stream not found"})
	default:
		h.logError(w, r, err)
	}
}

func (h *Handlers) streamView(s *store.LogStream) (map[string]any, error) {
	private, err := logstream.OpenSecrets(h.Wrapper, s)
	if err != nil {
		return nil, err
	}
	sink := map[string]any{}
	schema, ok := logrules.SinkSchema(s.Type)
	if !ok {
		return nil, store.ErrInvalid
	}
	for _, f := range schema.Fields {
		if f.Secret {
			if _, ok := private[f.Name]; ok {
				sink[f.Name] = logrules.Marker
			}
		} else if v, ok := s.Sink[f.Name]; ok {
			sink[f.Name] = v
		}
	}
	filters := make([]map[string]string, 0, len(s.Filters))
	for _, f := range s.Filters {
		filters = append(filters, map[string]string{"type": f.Type, "name": f.Name})
	}
	out := map[string]any{"id": s.ID, "name": s.Name, "type": s.Type, "status": s.Status, "sink": sink, "filters": filters, "isPriority": s.IsPriority}
	if s.PII != nil {
		out["pii_config"] = map[string]any{"log_fields": s.PII.LogFields, "method": s.PII.Method, "algorithm": s.PII.Algorithm}
	}
	return out, nil
}
func (h *Handlers) writeStream(w http.ResponseWriter, r *http.Request, s *store.LogStream, status int) {
	view, err := h.streamView(s)
	if err != nil {
		h.streamError(w, r, err)
		return
	}
	writeJSON(w, status, view)
}
func (h *Handlers) ListLogStreams(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	rows, err := repo.ListLogStreams(r.Context(), resolved(r).ID)
	if err != nil {
		h.streamError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for i := range rows {
		view, err := h.streamView(&rows[i])
		if err != nil {
			h.streamError(w, r, err)
			return
		}
		out = append(out, view)
	}
	writeJSON(w, 200, out)
}
func (h *Handlers) GetLogStream(w http.ResponseWriter, r *http.Request, id string) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	s, err := repo.GetLogStream(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.streamError(w, r, err)
		return
	}
	h.writeStream(w, r, s, 200)
}
func (h *Handlers) CreateLogStream(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	raw, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	s := &store.LogStream{TenantID: resolved(r).ID, ID: "lst_" + secrets.RandomString(24), Status: "active", Sink: map[string]any{}}
	if err = streamDecode(raw["type"], &s.Type); err != nil {
		Fail(w, errLogStreamInvalid)
		return
	}
	if err = h.applyStream(s, raw, true); err != nil {
		h.streamError(w, r, err)
		return
	}
	if err = repo.CreateLogStream(r.Context(), s); err != nil {
		h.streamError(w, r, err)
		return
	}
	logDetails(r, "create log stream", "id", s.ID, "type", s.Type)
	h.writeStream(w, r, s, 201)
}
func (h *Handlers) UpdateLogStream(w http.ResponseWriter, r *http.Request, id string) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	raw, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		s, err := repo.GetLogStream(r.Context(), resolved(r).ID, id)
		if err != nil {
			h.streamError(w, r, err)
			return
		}
		if err = h.applyStream(s, raw, false); err != nil {
			h.streamError(w, r, err)
			return
		}
		if err = repo.UpdateLogStream(r.Context(), s, s.Version); errors.Is(err, store.ErrConflict) {
			continue
		} else if err != nil {
			h.streamError(w, r, err)
			return
		}
		logDetails(r, "update log stream", "id", s.ID, "type", s.Type)
		h.writeStream(w, r, s, 200)
		return
	}
	Fail(w, errLogStreamConflict)
}
func (h *Handlers) DeleteLogStream(w http.ResponseWriter, r *http.Request, id string) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	if err := repo.DeleteLogStream(r.Context(), resolved(r).ID, id); err != nil {
		h.streamError(w, r, err)
		return
	}
	logDetails(r, "delete log stream", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// applyStream validates a complete candidate before any write. Retrying a
// version conflict always rebuilds it from a fresh tenant-scoped snapshot.
func (h *Handlers) applyStream(s *store.LogStream, raw map[string]json.RawMessage, create bool) error {
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
	private, err := logstream.OpenSecrets(h.Wrapper, s)
	if err != nil {
		return err
	}
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
			value, err := h.validateStreamSinkField(f, rawValue)
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
			if _, err = h.validateStreamSinkField(f, rawValue); err != nil {
				return err
			}
		}
	}
	sealed, err := logstream.SealSecrets(h.Wrapper, s, private)
	if err != nil {
		return err
	}
	s.SealedSecrets = sealed
	return nil
}
func (h *Handlers) validateStreamSinkField(f logrules.SinkField, raw json.RawMessage) (any, error) {
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
			if !streamURL(v, h.LogsConfig.Streams.AllowInsecureHTTP) {
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
