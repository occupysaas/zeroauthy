package oauth

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
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
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		writeError(w, serverError())
		return
	}
	out, oerr := h.par(w, r, res)
	if oerr != nil {
		writeError(w, oerr)
		return
	}
	noStore(w)
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (h *Handlers) par(w http.ResponseWriter, r *http.Request, res tenant.Resolved) (*parResponse, *Error) {
	ctx := r.Context()
	t := res.Tenant
	if !t.PushedAuthorizationRequestsSupported {
		return nil, invalidRequest("pushed authorization requests are not enabled for this tenant") // P6b
	}
	form, oerr := parsePARRequest(w, r)
	if oerr != nil {
		return nil, oerr
	}
	c, oerr := h.authenticateClient(ctx, r, form, t.ID)
	if oerr != nil {
		return nil, oerr
	}
	if c.TokenEndpointAuthMethod == store.AuthMethodNone {
		return nil, invalidRequest("only confidential applications may push authorization requests") // P3b
	}
	if !c.IsFirstParty {
		return nil, invalidRequest("pushed authorization requests are not available to third-party applications") // P9
	}
	if form.Has("request_uri") {
		return nil, invalidRequest("request_uri is not allowed in a pushed authorization request") // P6a
	}
	ext := 0
	for k := range form {
		if strings.HasPrefix(k, authz.ExtPrefix) {
			ext++
		}
	}
	if ext > authz.MaxExtParams {
		return nil, invalidRequest(fmt.Sprintf("at most %d ext- parameters are allowed", authz.MaxExtParams)) // P2c
	}

	req := authz.ParseRequest(form)
	req.ClientID, req.Pushed = c.ClientID, true
	if _, verr, _ := authz.ValidateRequest(ctx, h.Store, t, &req); verr != nil {
		if verr.Code == "server_error" {
			return nil, serverError()
		}
		return nil, &Error{Status: parStatus(verr.Code), Code: verr.Code, Description: verr.Description} // P2
	}

	id := secrets.RandomString(64)
	now := h.now().UTC()
	if err := h.Store.PushedAuthRequests().Create(ctx, &store.PushedAuthRequest{
		Origin: res.Origin(), TenantID: t.ID, IDHash: secrets.HashToken(id), ClientID: c.ClientID, Params: req.Params(),
		ExpiresAt: now.Add(authz.PARLifetime), CreatedAt: now,
	}); err != nil {
		h.log().ErrorContext(ctx, "store pushed request", "tenant", t.ID, "client_id", c.ClientID, "err", err)
		return nil, serverError()
	}
	return &parResponse{RequestURI: authz.RequestURIPrefix + id, ExpiresIn: int(authz.PARLifetime.Seconds())}, nil
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
