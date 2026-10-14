// internal/authz/response.go
package authz

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// writeResponse delivers an authorization response (code or error) to the
// client using the request's response_mode.
func writeResponse(w http.ResponseWriter, r *http.Request, req Request, params url.Values) {
	switch req.ResponseMode {
	case "form_post":
		l := i18n.Default()
		if res, ok := tenant.FromContext(r.Context()); ok {
			l = i18n.ForRequest(res.Tenant, r, req.UILocales)
		}
		ui.RenderFormPost(w, l, req.RedirectURI, params)
	case "web_message":
		resp := map[string]string{}
		for k := range params {
			resp[k] = params.Get(k)
		}
		ui.RenderWebMessage(w, originOf(req.RedirectURI), resp)
	case "fragment":
		redirect(w, r, strings.SplitN(req.RedirectURI, "#", 2)[0]+"#"+params.Encode())
	default:
		u, _ := url.Parse(req.RedirectURI) // validated by callbackAllowed
		q := u.Query()
		for k, vs := range params {
			q[k] = vs
		}
		u.RawQuery = q.Encode()
		redirect(w, r, u.String())
	}
}

func redirect(w http.ResponseWriter, r *http.Request, to string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, to, http.StatusFound)
}

func errorParams(e *Error, state string) url.Values {
	v := url.Values{"error": {e.Code}, "error_description": {e.Description}}
	if state != "" {
		v.Set("state", state)
	}
	return v
}
