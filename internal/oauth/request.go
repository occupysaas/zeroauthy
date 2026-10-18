// internal/oauth/request.go
package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
)

const maxTokenRequestBytes = 64 << 10

// parseTokenRequest reads the body of a token endpoint request. Auth0 SDKs
// send both form-encoded and JSON bodies, so both are accepted. JSON
// values must be scalars and are converted to strings. Query parameters
// are never read: credentials must not travel in URLs.
func parseTokenRequest(w http.ResponseWriter, r *http.Request) (url.Values, *Error) {
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
			var v any
			if err := dec.Decode(&v); err != nil {
				return nil, bad
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
