package authz

import (
	"errors"
	"mime"
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Continue resumes a suspended post-login flow on its original tenant origin.
// The single-use state and the browser's active session jointly authorize it.
func (h *Handlers) Continue(w http.ResponseWriter, r *http.Request) {
	invalid := func() { httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid continuation state") }
	res, ok := tenant.FromContext(r.Context())
	if !ok || h.Actions == nil {
		invalid()
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		invalid()
		return
	}
	body := url.Values{}
	if r.Method == http.MethodPost {
		ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if ct != "application/x-www-form-urlencoded" {
			invalid()
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAuthorizeFormBytes)
		if err = r.ParseForm(); err != nil {
			invalid()
			return
		}
		body = r.PostForm
	}
	for _, p := range []url.Values{query, body} {
		for _, vs := range p {
			if len(vs) != 1 {
				invalid()
				return
			}
		}
	}
	state := query.Get("state")
	if body.Has("state") {
		if state != "" && body.Get("state") != state {
			invalid()
			return
		}
		state = body.Get("state")
	}
	sess, err := h.ActiveSession(r.Context(), r, res)
	if err != nil || sess == nil {
		invalid()
		return
	}
	info := actions.RequestInfo{IP: httpx.ClientIP(r, h.TrustProxyHeaders), Hostname: res.Host, Origin: res.Origin(), Method: r.Method, UserAgent: r.UserAgent(), Language: firstLanguage(r.Header.Get("Accept-Language")), Query: map[string]any{}, Body: map[string]any{}}
	for k, v := range query {
		info.Query[k] = v[0]
	}
	for k, v := range body {
		info.Body[k] = v[0]
	}
	result, err := h.Actions.ContinuePostLogin(r.Context(), res.Tenant.ID, state, sess, info)
	if errors.Is(err, actions.ErrInvalidContinue) {
		invalid()
		return
	}
	continuation := map[string]string(nil)
	if result != nil {
		continuation = result.Continuation
	}
	if err != nil {
		var fe *actions.ErrFlow
		if errors.As(err, &fe) {
			continuation = fe.Continuation
		}
	}
	if continuation == nil {
		h.flowError(w, r, res, flowReq{}, errServer())
		return
	}
	fr := flowFromParams(continuation)
	client, verr, _ := h.validateFlow(r.Context(), res, &fr)
	if verr != nil {
		h.flowError(w, r, res, fr, verr)
		return
	}
	disabled, connErr := h.connectionDisabled(r.Context(), res, client, sess)
	if connErr != nil || disabled {
		invalid()
		return
	}
	eff, ok := h.postLoginResult(w, r, res, client, fr, result, err)
	if !ok {
		return
	}
	h.finish(w, r, res, client, fr, sess, eff, false, result.Continuation["za_screen_shown"] == "true")
}
