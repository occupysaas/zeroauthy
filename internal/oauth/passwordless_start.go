package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/passwordless"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
)

const maxStartBytes = 64 << 10

// startBody reads a /passwordless/start body. Unknown members are accepted
// and ignored, as Auth0 does for the extra options auth0.js forwards.
func startBody(w http.ResponseWriter, r *http.Request) (map[string]string, url.Values, *Error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxStartBytes)
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	fields := map[string]string{}
	params := url.Values{}
	if mediaType == "application/x-www-form-urlencoded" {
		if err := r.ParseForm(); err != nil {
			return nil, nil, invalidRequest("malformed or oversized form body")
		}
		for k := range r.PostForm {
			fields[k] = r.PostForm.Get(k)
		}
		return fields, params, nil
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil || raw == nil {
		return nil, nil, invalidRequest("malformed or oversized JSON body")
	}
	for k, v := range raw {
		if k == "authParams" {
			var ap map[string]any
			if json.Unmarshal(v, &ap) != nil {
				return nil, nil, invalidRequest("authParams must be an object")
			}
			for pk, pv := range ap {
				switch x := pv.(type) {
				case string:
					params.Set(pk, x)
				case float64, bool:
					params.Set(pk, fmt.Sprint(x))
				}
			}
			continue
		}
		var s string
		if json.Unmarshal(v, &s) == nil {
			fields[k] = s
		}
	}
	return fields, params, nil
}

// PasswordlessStart implements POST /passwordless/start: client
// authentication per enforce_client_authentication_on_passwordless_start,
// then the passwordless service.
func (h *Handlers) PasswordlessStart(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok || h.Passwordless == nil {
		writeError(w, serverError())
		return
	}
	ctx := logs.WithRecorder(r.Context(), h.Recorder)
	*r = *r.WithContext(ctx)
	fields, params, oerr := startBody(w, r)
	if oerr != nil {
		writeError(w, oerr)
		return
	}
	ctx = logscrub.WithCredentials(ctx, fields["client_secret"], fields["client_assertion"])
	*r = *r.WithContext(ctx)
	clientID := fields["client_id"]
	_, _, hasBasic := r.BasicAuth()
	if clientID == "" && !hasBasic {
		writeError(w, invalidRequest("client_id is required"))
		return
	}
	if fields["client_assertion"] != "" {
		// Private key JWT is not served by this token endpoint either.
		writeError(w, invalidClient(authFailed, false))
		return
	}
	var client *store.Client
	authenticated := hasBasic || fields["client_secret"] != ""
	if authenticated {
		form := url.Values{}
		if clientID != "" {
			form.Set("client_id", clientID)
		}
		if s := fields["client_secret"]; s != "" {
			form.Set("client_secret", s)
		}
		client, oerr = h.authenticateClient(ctx, r, form, res.Tenant.ID)
		if oerr != nil {
			writeError(w, oerr)
			return
		}
	} else {
		c, err := h.Store.Clients().Get(ctx, res.Tenant.ID, clientID)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, invalidClient(authFailed, false))
			return
		}
		if err != nil {
			writeError(w, serverError())
			return
		}
		client = c
		if client.TokenEndpointAuthMethod != store.AuthMethodNone {
			if tenantrules.PhoneSettingsOf(res.Tenant).EnforceClientAuthOnPasswordlessStart {
				writeError(w, invalidClient("client authentication is required", false))
				return
			}
			e := logs.FromRequest(r)
			e.Type, e.ClientID, e.ClientName = "depnote", client.ClientID, client.Name
			e.Description = "unauthenticated /passwordless/start by a confidential client"
			logs.RecordEvent(ctx, h.Recorder, e)
		}
	}
	// auth0-forwarded-for is honoured only for authenticated confidential clients.
	ip := httpx.ClientIP(r, h.TrustProxyHeaders)
	if authenticated {
		ip = h.endUserIP(r, client)
	}
	ctx = passwordless.WithRequest(ctx, passwordless.RequestInfo{IP: ip, Hostname: r.Host, Method: r.Method, UserAgent: r.UserAgent(), Language: r.Header.Get("x-request-language"), Origin: res.Origin()})
	result, err := h.Passwordless.Start(ctx, passwordless.StartInput{
		TenantID: res.Tenant.ID, ClientID: client.ClientID, Connection: fields["connection"], Email: fields["email"], PhoneNumber: fields["phone_number"],
		Send: fields["send"], AuthParams: params, IP: ip, UserAgent: r.UserAgent(), Locale: r.Header.Get("x-request-language"), Origin: res.Origin(),
	})
	var pe *passwordless.Error
	switch {
	case errors.As(err, &pe):
		if pe.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(pe.RetryAfter))
		}
		writeError(w, &Error{Status: pe.Status, Code: pe.Code, Description: pe.Description})
		return
	case errors.Is(err, store.ErrPhoneUnavailable):
		writeError(w, &Error{Status: http.StatusNotImplemented, Code: "phone_unavailable", Description: "passwordless authentication is not available with this storage plugin"})
		return
	case err != nil:
		h.log().ErrorContext(ctx, "passwordless start", "tenant", res.Tenant.ID, "err", err)
		writeError(w, serverError())
		return
	}
	body := map[string]any{"_id": result.ID}
	if result.PhoneNumber != "" {
		body["phone_number"], body["phone_verified"] = result.PhoneNumber, result.Verified
	} else {
		body["email"], body["email_verified"] = result.Email, result.Verified
	}
	noStore(w)
	httpx.WriteJSON(w, http.StatusOK, body)
}
