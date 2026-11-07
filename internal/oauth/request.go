// internal/oauth/request.go
package oauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
)

const maxTokenRequestBytes = 64 << 10

// parseTokenRequest reads the body of a token endpoint request. Auth0 SDKs
// send both form-encoded and JSON bodies, so both are accepted. JSON
// scalars become strings; authn_response and explicitly named native profile
// objects are reserialized while preserving their submitted member order. Query parameters
// are never read: credentials must not travel in URLs.
func parseTokenRequest(w http.ResponseWriter, r *http.Request, objectFields ...string) (form url.Values, failure *Error) {
	registerOAuthAuthorization(r)
	defer func() { registerOAuthForm(r, r.PostForm) }()
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBytes)
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, invalidRequest("Content-Type must be application/x-www-form-urlencoded or application/json")
	}
	switch mediaType {
	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return nil, invalidRequest("malformed or oversized form body")
		}
		for k, vs := range r.PostForm {
			if len(vs) > 1 {
				return nil, repeatedParam(k)
			}
		}
		return r.PostForm, nil
	case "application/json":
		dec := json.NewDecoder(r.Body)
		dec.UseNumber()
		bad := invalidRequest("malformed or oversized JSON body")
		if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
			return nil, bad
		}
		form, seen := url.Values{}, map[string]bool{}
		for dec.More() {
			keyTok, err := dec.Token()
			key, ok := keyTok.(string)
			if err != nil || !ok {
				return nil, bad
			}
			if seen[key] {
				return nil, repeatedParam(key)
			}
			seen[key] = true
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return nil, bad
			}
			var v any
			valueDecoder := json.NewDecoder(bytes.NewReader(raw))
			valueDecoder.UseNumber()
			if err := valueDecoder.Decode(&v); err != nil {
				return nil, bad
			}
			if slices.Contains(objectFields, key) {
				if _, ok := v.(map[string]any); !ok {
					return nil, invalidRequest(fmt.Sprintf("parameter %q must be an object", key))
				}
			}
			if key == "organization" || key == "invitation" {
				if _, ok := v.(string); !ok {
					return nil, invalidRequest(fmt.Sprintf("parameter %q must be a string", key))
				}
			}
			if _, ok := v.(map[string]any); ok && (key == "authn_response" || slices.Contains(objectFields, key)) {
				// Preserve field order and duplicate/case semantics for the same
				// credential JSON submitted as a form string. RawMessage reserialization
				// compacts the object without rebuilding its untrusted members.
				encoded, err := json.Marshal(raw)
				if err != nil {
					return nil, bad
				}
				form.Set(key, string(encoded))
				registerOAuthForm(r, url.Values{key: form[key]})
				continue
			}
			switch x := v.(type) {
			case string:
				form.Set(key, x)
			case json.Number:
				form.Set(key, x.String())
			case bool:
				form.Set(key, strconv.FormatBool(x))
			case nil:
				// null is treated as absent
			default:
				return nil, invalidRequest(fmt.Sprintf("parameter %q must be a string", key))
			}
			registerOAuthForm(r, url.Values{key: form[key]})
		}
		if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
			return nil, bad
		}
		if _, err := dec.Token(); err != io.EOF {
			return nil, invalidRequest("unexpected data after the JSON object")
		}
		return form, nil
	default:
		return nil, invalidRequest("Content-Type must be application/x-www-form-urlencoded or application/json")
	}
}

// Register at ingress, before authentication or validation can log a failure.
// Parsers cap form/JSON bytes; Basic fields come from the bounded HTTP header.
func registerOAuthAuthorization(r *http.Request) {
	header := r.Header.Get("Authorization")
	values := []string{header}
	if parts := strings.SplitN(header, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "Basic") {
		values = append(values, parts[1])
		if decoded, err := base64.StdEncoding.DecodeString(parts[1]); err == nil {
			values = append(values, string(decoded))
		}
	}
	if _, secret, ok := r.BasicAuth(); ok {
		values = append(values, secret)
		if decoded, err := url.QueryUnescape(secret); err == nil {
			values = append(values, decoded)
		}
	}
	*r = *r.WithContext(logscrub.WithCredentials(r.Context(), values...))
}
func registerOAuthForm(r *http.Request, form url.Values) {
	var values []string
	for key, value := range form {
		if logscrub.SensitiveKey(key) || key == "otp" || key == "code" || key == "ticket" {
			values = append(values, value...)
		}
	}
	*r = *r.WithContext(logscrub.WithCredentials(r.Context(), values...))
}
