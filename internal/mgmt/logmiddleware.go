package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const managementCaptureLimit = 64 << 10

// LogMiddleware is the router boundary, installed after Auth's token and live
// operator-grant checks, before per-operation scope checks.
func (h *Handlers) LogMiddleware(next http.Handler) http.Handler { return h.logMiddleware(next) }

func (h *Handlers) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Streaming responses must reach the network directly, without capture.
		if r.Method == http.MethodGet && r.URL.Path == "/api/v2/events" {
			next.ServeHTTP(w, r)
			return
		}
		caller, authenticated := CallerFrom(r.Context())
		if !authenticated {
			next.ServeHTTP(w, r)
			return
		}
		ctx := events.WithContext(r.Context(), events.FromRequest(r))
		// Caller comes from Auth, never a client_id in a mutation body.
		if caller.Kind == M2M && caller.ClientID != "" {
			attribution := events.FromRequest(r)
			attribution.ClientID, attribution.ClientName, attribution.ClientMetadata = caller.ClientID, "", map[string]string{}
			ctx = events.WithContext(ctx, attribution)
			if res, ok := tenant.FromContext(ctx); ok {
				client, err := h.Store.Clients().Get(ctx, res.Tenant.ID, caller.ClientID)
				if err == nil {
					ctx = events.Enrich(ctx, client, nil)
				} else if !errors.Is(err, store.ErrNotFound) {
					Fail(w, err)
					return
				}
			}
		}
		for key, values := range r.Header {
			if logscrub.SensitiveKey(key) || strings.EqualFold(key, "Cookie") {
				for _, value := range values {
					ctx = logscrub.WithCredentials(ctx, value)
					if strings.EqualFold(key, "Authorization") {
						_, token, _ := strings.Cut(value, " ")
						ctx = logscrub.WithCredentials(ctx, token)
					}
				}
			}
		}
		for key, values := range r.URL.Query() {
			if logscrub.SensitiveKey(key) {
				ctx = logscrub.WithCredentials(ctx, values...)
			}
		}
		resource := managementResource(r.URL.Path)
		requestBody, complete := captureManagementRequest(r)
		if complete {
			ctx = registerManagementCredentials(ctx, requestBody, false)
		}
		ctx = logs.WithRecorder(ctx, h.Recorder)
		hints := &managementHints{}
		ctx = context.WithValue(ctx, managementHintsKey{}, hints)
		r = r.WithContext(ctx)
		writer := &managementWriter{ResponseWriter: w, resource: resource}
		next.ServeHTTP(wrapManagementWriter(writer), r)
		ctx = r.Context()
		status := writer.status
		if status == 0 {
			status = 200
		}
		responseBody, responseComplete := writer.capture.value()
		if responseComplete {
			ctx = registerManagementCredentials(ctx, responseBody, false)
		}
		write := r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete
		typ := ""
		switch {
		case write && status >= 200 && status < 300:
			typ = "sapi"
		case write && status >= 400:
			typ = "fapi"
		case r.Method == http.MethodGet && status >= 200 && status < 300 && (writer.secretRead || responseComplete && managementSecretRead(resource, responseBody)):
			typ = "mgmt_api_read"
		}
		if typ == "" && status != http.StatusTooManyRequests {
			return
		}
		auth := map[string]any{"strategy": "client_credentials", "client_id": caller.ClientID}
		event := logs.FromRequest(r)
		if caller.Kind == Operator {
			auth = map[string]any{"strategy": "operator", "user_id": caller.UserID}
			event.UserID = caller.UserID
		} else {
			event.ClientID = caller.ClientID
		}
		requestLogged := any(logscrub.Marker)
		if complete {
			requestLogged = managementAllowBody(requestBody, logrules.BodyAllowlist(resource), "")
		}
		responseLogged := any(logscrub.Marker)
		if complete && responseComplete {
			responseLogged = managementAllowBody(responseBody, logrules.BodyAllowlist(resource), "")
		}
		event.Details = map[string]any{"request": map[string]any{"method": r.Method, "path": r.URL.Path, "query": managementQuery(r), "body": requestLogged, "auth": auth}, "response": map[string]any{"statusCode": status, "body": responseLogged}}
		if hints.action != "" {
			event.Details["operation"] = hints.action
			event.Details["resource"] = hints.details
		}
		event.Details = logscrub.ScrubValueContext(ctx, event.Details).(map[string]any)
		if typ != "" {
			event.Type = typ
			if strings.HasPrefix(r.URL.Path, "/api/v2/") {
				logs.RecordEvent(ctx, h.Recorder, event)
			}
			// Only pre-scrubbed copies reach a plain server logger, too.
			h.log().InfoContext(ctx, "management API operation", "type", typ, "tenant_id", logscrub.MaskText(ctx, event.TenantID), "details", event.Details)
		}
		if status == http.StatusTooManyRequests {
			event.Type = "api_limit"
			if strings.HasPrefix(r.URL.Path, "/api/v2/") {
				logs.RecordEvent(ctx, h.Recorder, event)
			}
		}
	})
}

type managementHintsKey struct{}
type managementHints struct {
	action  string
	details map[string]any
}

// logDetails retains resource information already resolved by handlers, without
// another store read or a per-handler sink.
func logDetails(r *http.Request, action string, args ...any) {
	if hints, ok := r.Context().Value(managementHintsKey{}).(*managementHints); ok {
		hints.action = action
		hints.details = map[string]any{}
		for i := 0; i+1 < len(args); i += 2 {
			if key, ok := args[i].(string); ok {
				hints.details[key] = args[i+1]
			}
		}
	}
}

type managementCapture struct {
	data     []byte
	overflow bool
}

func (c *managementCapture) Write(p []byte) (int, error) {
	n := len(p)
	remaining := managementCaptureLimit - len(c.data)
	if n > remaining {
		c.overflow = true
	}
	c.data = append(c.data, p[:min(n, remaining)]...)
	return n, nil
}
func (c *managementCapture) value() (any, bool) {
	if c.overflow {
		return nil, false
	}
	if len(c.data) == 0 {
		return nil, true
	}
	return decodeManagementCapture(c.data)
}
func decodeManagementCapture(body []byte) (any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil, false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, false
	}
	return value, true
}

type managementReplayBody struct {
	io.Reader
	original io.ReadCloser
}

func (r *managementReplayBody) Close() error { return r.original.Close() }

type managementReadError struct{ err error }

func (r *managementReadError) Read([]byte) (int, error) { err := r.err; r.err = io.EOF; return 0, err }

// Replay every byte and the original read error. The public decoder still owns
// limits, strict validation and errors; ContentLength and GetBody are untouched.
func captureManagementRequest(r *http.Request) (any, bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, true
	}
	original := r.Body
	body, err := io.ReadAll(io.LimitReader(original, managementCaptureLimit+1))
	readers := []io.Reader{bytes.NewReader(body)}
	if err != nil {
		readers = append(readers, &managementReadError{err: err})
	}
	readers = append(readers, original)
	r.Body = &managementReplayBody{Reader: io.MultiReader(readers...), original: original}
	if err != nil || len(body) > managementCaptureLimit {
		return nil, false
	}
	if len(body) == 0 {
		return nil, true
	}
	return decodeManagementCapture(body)
}
func managementResource(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/api/v2/"), "/")
	if !strings.HasPrefix(path, "/api/v2/") || len(parts) == 0 {
		return "default"
	}
	if parts[0] == "emails" && len(parts) > 1 && parts[1] == "templates" {
		return "email-templates"
	}
	return parts[0]
}
func managementQuery(r *http.Request) map[string]any {
	result := map[string]any{}
	for key, values := range r.URL.Query() {
		switch key {
		case "page", "per_page", "include_totals", "sort", "fields", "include_fields":
			result[key] = values
		default:
			result[key] = logscrub.Marker
		}
	}
	return result
}
func managementAllowBody(value any, paths []string, path string) any {
	allowed := func(p string) bool {
		for _, candidate := range paths {
			if candidate == p {
				return true
			}
		}
		return false
	}
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, value := range v {
			p := key
			if path != "" {
				p = path + "." + key
			}
			if logscrub.SensitiveKey(key) || !allowed(p) {
				out[key] = logscrub.Marker
			} else {
				out[key] = managementAllowBody(value, paths, p)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, value := range v {
			p := path
			if _, ok := value.(map[string]any); ok {
				p += "[]"
			}
			out[i] = managementAllowBody(value, paths, p)
		}
		return out
	case string:
		if _, credentialURL := managementURLCredentials(v); credentialURL {
			return logscrub.Marker
		}
		if decoded, ok := decodeManagementCapture([]byte(v)); ok {
			switch decoded.(type) {
			case map[string]any, []any:
				b, err := json.Marshal(managementAllowBody(decoded, paths, path))
				if err != nil {
					return logscrub.Marker
				}
				return string(b)
			}
		}
		if path == "" {
			return logscrub.Marker
		}
		return v
	default:
		if path == "" && value != nil {
			return logscrub.Marker
		}
		return value
	}
}
func registerManagementCredentials(ctx context.Context, value any, sensitive bool) context.Context {
	switch v := value.(type) {
	case map[string]any:
		for key, value := range v {
			ctx = registerManagementCredentials(ctx, value, sensitive || key == "sink" || key == "options" || logscrub.SensitiveKey(key) || strings.Contains(strings.ToLower(key), "hash"))
		}
	case []any:
		for _, value := range v {
			ctx = registerManagementCredentials(ctx, value, sensitive)
		}
	case string:
		if credentials, _ := managementURLCredentials(v); len(credentials) > 0 {
			ctx = logscrub.WithCredentials(ctx, credentials...)
		}
		if sensitive {
			ctx = logscrub.WithCredentials(ctx, v)
		}
		if decoded, ok := decodeManagementCapture([]byte(v)); ok {
			switch decoded.(type) {
			case map[string]any, []any:
				ctx = registerManagementCredentials(ctx, decoded, sensitive)
			}
		}
	}
	return ctx
}

// Secret-read eligibility follows the frozen serializers, not arbitrary
// metadata keys that happen to use a credential name. Reflection visits typed
// page slices without marshaling another (potentially unbounded) body copy.
func managementSecretRead(resource string, value any) bool {
	var nonempty func(reflect.Value) bool
	unwrap := func(v reflect.Value) reflect.Value {
		for v.IsValid() && (v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer) {
			if v.IsNil() {
				return reflect.Value{}
			}
			v = v.Elem()
		}
		return v
	}
	nonempty = func(v reflect.Value) bool {
		v = unwrap(v)
		if !v.IsValid() {
			return false
		}
		switch v.Kind() {
		case reflect.String:
			return v.String() != "" && v.String() != logscrub.Marker
		case reflect.Map:
			for _, key := range v.MapKeys() {
				if nonempty(v.MapIndex(key)) {
					return true
				}
			}
		case reflect.Array, reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				if nonempty(v.Index(i)) {
					return true
				}
			}
		}
		return false
	}
	get := func(v reflect.Value, key string) reflect.Value {
		v = unwrap(v)
		if !v.IsValid() || v.Kind() != reflect.Map || v.Type().Key().Kind() != reflect.String {
			return reflect.Value{}
		}
		return v.MapIndex(reflect.ValueOf(key).Convert(v.Type().Key()))
	}
	var sensitiveOptions func(reflect.Value) bool
	sensitiveOptions = func(v reflect.Value) bool {
		v = unwrap(v)
		if !v.IsValid() {
			return false
		}
		switch v.Kind() {
		case reflect.Map:
			for _, key := range v.MapKeys() {
				child := v.MapIndex(key)
				if key.Kind() == reflect.String && logscrub.SensitiveKey(key.String()) && nonempty(child) {
					return true
				}
				if sensitiveOptions(child) {
					return true
				}
			}
		case reflect.Array, reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				if sensitiveOptions(v.Index(i)) {
					return true
				}
			}
		}
		return false
	}
	var visit func(reflect.Value) bool
	visit = func(v reflect.Value) bool {
		v = unwrap(v)
		if !v.IsValid() {
			return false
		}
		if v.Kind() == reflect.Slice || v.Kind() == reflect.Array {
			for i := 0; i < v.Len(); i++ {
				if visit(v.Index(i)) {
					return true
				}
			}
			return false
		}
		if v.Kind() != reflect.Map {
			return false
		}
		// List envelopes and raw arrays carry exactly the same serializer objects.
		if nested := get(v, resource); nested.IsValid() && visit(nested) {
			return true
		}
		switch resource {
		case "clients":
			return nonempty(get(v, "client_secret"))
		case "connections":
			return sensitiveOptions(get(v, "options"))
		case "emails":
			return nonempty(get(v, "credentials"))
		case "actions":
			secrets := unwrap(get(v, "secrets"))
			if secrets.IsValid() && (secrets.Kind() == reflect.Array || secrets.Kind() == reflect.Slice) {
				for i := 0; i < secrets.Len(); i++ {
					if nonempty(get(secrets.Index(i), "value")) {
						return true
					}
				}
			}
		case "users":
			identities := unwrap(get(v, "identities"))
			if identities.IsValid() && (identities.Kind() == reflect.Array || identities.Kind() == reflect.Slice) {
				for i := 0; i < identities.Len(); i++ {
					for _, key := range []string{"access_token", "refresh_token"} {
						if nonempty(get(identities.Index(i), key)) {
							return true
						}
					}
				}
			}
		case "keys":
			for _, key := range []string{"private_key", "privateKey", "d", "p", "q", "dp", "dq", "qi"} {
				if nonempty(get(v, key)) {
					return true
				}
			}
		}
		return false
	}
	return visit(reflect.ValueOf(value))
}

// URLs in otherwise public fields must not carry user-info or bearer query /
// fragment material into sinks. Hide the complete URL and register its values
// so an input cannot copy a URL credential into another allowlisted field.
func managementURLCredentials(value string) ([]string, bool) {
	if !strings.Contains(value, "://") {
		return nil, false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, true
	}
	var credentials []string
	secret := false
	if parsed.User != nil {
		secret = true
		credentials = append(credentials, parsed.User.Username())
		if password, ok := parsed.User.Password(); ok {
			credentials = append(credentials, password)
		}
	}
	for key, values := range parsed.Query() {
		if logscrub.SensitiveKey(key) {
			secret = true
			credentials = append(credentials, values...)
		}
	}
	if parsed.Fragment != "" {
		secret = true
		credentials = append(credentials, parsed.Fragment)
		if values, err := url.ParseQuery(parsed.Fragment); err == nil {
			for key, values := range values {
				if logscrub.SensitiveKey(key) {
					credentials = append(credentials, values...)
				}
			}
		}
	}
	return credentials, secret
}
