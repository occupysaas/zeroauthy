// internal/oauth/request.go
package oauth

import (
	"encoding/json"
	"fmt"
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
				return nil, invalidRequest(fmt.Sprintf("parameter %q is repeated", k))
			}
		}
		return r.PostForm, nil
	case "application/json":
		var raw map[string]any
		dec := json.NewDecoder(r.Body)
		dec.UseNumber()
		if err := dec.Decode(&raw); err != nil {
			return nil, invalidRequest("malformed or oversized JSON body")
		}
		form := url.Values{}
		for k, v := range raw {
			switch x := v.(type) {
			case string:
				form.Set(k, x)
			case json.Number:
				form.Set(k, x.String())
			case bool:
				form.Set(k, strconv.FormatBool(x))
			case nil:
				// null is treated as absent
			default:
				return nil, invalidRequest(fmt.Sprintf("parameter %q must be a string", k))
			}
		}
		return form, nil
	default:
		return nil, invalidRequest("Content-Type must be application/x-www-form-urlencoded or application/json")
	}
}
