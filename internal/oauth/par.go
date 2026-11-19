package oauth

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/dpop"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// maxPARRequestBytes is Auth0's documented limit for a pushed request.
const maxPARRequestBytes = 10 << 10

type parResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

// OauthPar implements POST /oauth/par (RFC 9126, D-0028).
func (h *Handlers) OauthPar(w http.ResponseWriter, r *http.Request) {
	registerOAuthAuthorization(r)
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		writeError(w, serverError())
		return
	}
	out, oerr := h.par(w, r, res)
	if oerr != nil {
		e := logs.FromRequest(r)
		e.Type = "fpar"
		e.ClientID = r.PostForm.Get("client_id")
		logs.RecordEvent(r.Context(), h.Recorder, e)
		writeError(w, oerr)
		return
	}
	noStore(w)
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (h *Handlers) par(w http.ResponseWriter, r *http.Request, res tenant.Resolved) (*parResponse, *Error) {
	form, oerr := parsePARRequest(w, r)
	if oerr != nil {
		return nil, oerr
	}
	ctx := r.Context()
	t := res.Tenant
	if !t.PushedAuthorizationRequestsSupported {
		return nil, invalidRequest("pushed authorization requests are not enabled for this tenant") // P6b
	}
	c, oerr := h.authenticateClient(ctx, r, form, t.ID)
	if oerr != nil {
		return nil, oerr
	}
	ctx = logs.WithEvent(ctx, logs.Event{ClientID: c.ClientID, ClientName: c.Name})
	*r = *r.WithContext(ctx)
	if c.TokenEndpointAuthMethod == store.AuthMethodNone {
		return nil, invalidRequest("only confidential applications may push authorization requests") // P3b
	}
	if !c.IsFirstParty {
		return nil, invalidRequest("pushed authorization requests are not available to third-party applications") // P9
	}
	if form.Has("request_uri") {
		return nil, invalidRequest("request_uri is not allowed in a pushed authorization request") // P6a
	}
	req := authz.ParseRequest(form)
	req.ClientID, req.Pushed = c.ClientID, true
	// A signed request object is verified and merged first, whatever method
	// authenticated the client (spec §4).
	if verr := authz.ApplyRequestObject(ctx, h.Store, t, res.Issuer(), h.now(), h.log(), &req); verr != nil {
		return nil, parError(verr)
	}
	if req.Signed && req.Invitation != "" {
		// An invitation ticket carried only inside the signed object is not
		// in the form, so registerOAuthForm did not mask it.
		ctx = logscrub.WithCredentials(ctx, req.Invitation)
		*r = *r.WithContext(ctx)
	}
	if len(r.Header.Values("DPoP")) > 0 {
		service := h.DPoP
		if service == nil {
			service = &dpop.Service{Store: h.Store, Wrapper: h.Wrapper, Now: h.Now}
		}
		p, e := service.Verify(ctx, r, res, dpop.AuthorizationServer, false, "", req.DPoPJKT)
		if e != nil {
			if e.Internal {
				return nil, serverError()
			}
			return nil, &Error{Status: 400, Code: e.Code, Description: "the proof could not be accepted"}
		}
		req.DPoPJKT = p.JKT
	}
	if len(req.Ext) > authz.MaxExtParams {
		return nil, invalidRequest(fmt.Sprintf("at most %d ext- parameters are allowed", authz.MaxExtParams)) // P2c
	}
	if _, verr, _ := authz.ValidateRequest(ctx, h.Store, t, &req); verr != nil {
		return nil, parError(verr) // P2
	}

	id := secrets.RandomString(64)
	now := h.now().UTC()
	if err := h.Store.PushedAuthRequests().Create(ctx, &store.PushedAuthRequest{
		Origin: res.Origin(), TenantID: t.ID, IDHash: secrets.HashToken(id), ClientID: c.ClientID, Params: req.Params(),
		Signed: req.Signed, ExpiresAt: now.Add(authz.PARLifetime), CreatedAt: now,
	}); err != nil {
		h.log().ErrorContext(ctx, "store pushed request", "tenant", t.ID, "client_id", c.ClientID, "err", err)
		return nil, serverError()
	}
	return &parResponse{RequestURI: authz.RequestURIPrefix + id, ExpiresIn: int(authz.PARLifetime.Seconds())}, nil
}

// parError is an /authorize error as /oauth/par answers it.
func parError(e *authz.Error) *Error {
	if e.Code == "server_error" {
		return serverError()
	}
	return &Error{Status: parStatus(e.Code), Code: e.Code, Description: e.Description}
}

// parStatus is the HTTP status Auth0 uses at /oauth/par for each
// /authorize error code (D-0028).
func parStatus(code string) int {
	switch code {
	case "unauthorized_client", "access_denied":
		return http.StatusForbidden
	case "unsupported_response_type":
		return http.StatusNotImplemented
	default:
		return http.StatusBadRequest
	}
}

// parsePARRequest reads a form-encoded body of at most 10 KB with no
// repeated parameters (P2d, P2e). An oversized body is 413
// payload_too_large, as on Auth0.
func parsePARRequest(w http.ResponseWriter, r *http.Request) (url.Values, *Error) {
	registerOAuthAuthorization(r)
	defer func() { registerOAuthForm(r, r.PostForm) }()
	r.Body = http.MaxBytesReader(w, r.Body, maxPARRequestBytes)
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return nil, invalidRequest("Content-Type must be application/x-www-form-urlencoded")
	}
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, &Error{Status: http.StatusRequestEntityTooLarge, Code: "payload_too_large", Description: "the request body exceeds 10 KB"}
		}
		return nil, invalidRequest("malformed form body")
	}
	for k, vs := range r.PostForm {
		if len(vs) > 1 {
			return nil, invalidRequest(fmt.Sprintf("parameter %q is repeated", k))
		}
	}
	return r.PostForm, nil
}
