package authz

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// Transaction keys that are not request parameters: Request.Params and
// RequestFromParams ignore them.
const (
	ParamFlow     = store.TxnParamFlow
	FlowDevice    = store.TxnFlowDevice
	ParamDevice   = "za_device"    // device code hash
	ParamUserCode = "za_user_code" // the formatted user code, for display
	// ParamStage marks a transaction that is past login: the consent page,
	// or the device entry and confirmation pages.
	ParamStage         = "za_stage"
	StageDeviceEntry   = "device-entry"
	StageDeviceConfirm = "device-confirm"

	stageConsent = "consent"
	// sessionKey holds the ID of the session the consent transaction was
	// created for.
	sessionKey = "za_session"
	// cookiePathKey holds the za_txn cookie's path when it is not "/u".
	cookiePathKey = "za_cookie_path"
)

// deviceGrant is the device authorization grant type. It is spelled out
// here because internal/oauth imports authz.
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

// flowReq is a request on its way through login and consent: an
// /authorize request, or a device authorization (DeviceCodeHash set).
type flowReq struct {
	Request
	DeviceCodeHash string
}

func (f flowReq) device() bool { return f.DeviceCodeHash != "" }

// params is Request.Params plus ParamFlow and ParamDevice for the device flow.
func (f flowReq) params() map[string]string {
	p := f.Request.Params()
	if f.device() {
		p[ParamFlow], p[ParamDevice] = FlowDevice, f.DeviceCodeHash
	}
	return p
}

func flowFromParams(p map[string]string) flowReq {
	f := flowReq{Request: RequestFromParams(p)}
	if p[ParamFlow] == FlowDevice {
		f.DeviceCodeHash = p[ParamDevice]
	}
	return f
}

// errCodeNotPending is a device flow whose code was decided, expired or
// removed since the page was shown.
var errCodeNotPending = errInvalidRequest("the device code is no longer pending")

// validateFlow checks that fr may still complete. /authorize requests are
// validated again; a device flow needs its client to still hold the device
// grant and its code to be pending and unexpired. Device failures are never
// redirectable.
func (h *Handlers) validateFlow(ctx context.Context, res tenant.Resolved, fr *flowReq) (*store.Client, *Error, bool) {
	if !fr.device() {
		return ValidateRequest(ctx, h.Store, res.Tenant, &fr.Request)
	}
	client, err := h.Store.Clients().Get(ctx, res.Tenant.ID, fr.ClientID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errInvalidRequest("unknown client"), false
	case err != nil:
		h.log().ErrorContext(ctx, "load client", "tenant", res.Tenant.ID, "err", err)
		return nil, errServer(), false
	case !slices.Contains(client.GrantTypes, deviceGrant):
		return nil, errUnauthorizedClient("the client is not allowed to use the device authorization flow"), false
	}
	dc, err := h.Store.DeviceCodes().Get(ctx, res.Tenant.ID, fr.DeviceCodeHash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errCodeNotPending, false
	case err != nil:
		h.log().ErrorContext(ctx, "load device code", "tenant", res.Tenant.ID, "err", err)
		return nil, errServer(), false
	case dc.ClientID != client.ClientID || dc.Status != store.DeviceCodePending || !h.now().Before(dc.ExpiresAt) || res.CheckOrigin(dc.Origin) != nil:
		return nil, errCodeNotPending, false
	}
	return client, nil, false
}

// flowError shows a request that can no longer complete on the generic
// error page. A device code that is no longer pending reads as an expired
// session: the user starts over on the device page.
func (h *Handlers) flowError(w http.ResponseWriter, r *http.Request, res tenant.Resolved, fr flowReq, e *Error) {
	view := ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, fr.UILocales))
	status, title, detail := http.StatusBadRequest, i18n.KeyErrInvalidRequest, e.Description
	switch {
	case e == errCodeNotPending:
		detail = view.L.T(i18n.KeyErrSessionExpired)
	case e.Code == "server_error":
		status, title, detail = http.StatusInternalServerError, i18n.KeyErrServer, ""
	}
	ui.RenderErrorDetail(w, status, view, view.L.T(title), detail)
}

// approve completes fr for sess with scopes: an authorization code for
// /authorize, an approved device code for the device flow.
func (h *Handlers) approve(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, sess *store.LoginSession, scopes []string) {
	if !fr.device() {
		h.issueCode(w, r, res, client, fr.Request, sess, scopes)
		return
	}
	// Device tokens are not bound to the session, so it does not record
	// the client.
	h.decideDevice(w, r, res, fr, store.DeviceDecision{Status: store.DeviceCodeApproved, UserID: sess.UserID, GrantedScopes: scopes}, "/device/success")
}

// refuse ends fr with e: an authorization error for /authorize, a denied
// device code for the device flow. A server error leaves a device code
// pending.
func (h *Handlers) refuse(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, e *Error) {
	switch {
	case !fr.device():
		h.deny(w, r, res, client, fr.Request, e)
	case e.Code == "server_error":
		h.flowError(w, r, res, fr, e)
	default:
		h.decideDevice(w, r, res, fr, store.DeviceDecision{Status: store.DeviceCodeDenied}, "/device/denied")
	}
}

// decideDevice records dec and redirects to page. A code decided, expired
// or removed meanwhile keeps its state and shows the error page.
func (h *Handlers) decideDevice(w http.ResponseWriter, r *http.Request, res tenant.Resolved, fr flowReq, dec store.DeviceDecision, page string) {
	ctx := r.Context()
	_, err := h.Store.DeviceCodes().Decide(ctx, res.Tenant.ID, fr.DeviceCodeHash, dec)
	switch {
	case errors.Is(err, store.ErrAlreadyUsed) || errors.Is(err, store.ErrNotFound):
		h.flowError(w, r, res, fr, errCodeNotPending)
		return
	case err != nil:
		h.log().ErrorContext(ctx, "decide device code", "tenant", res.Tenant.ID, "err", err)
		h.flowError(w, r, res, fr, errServer())
		return
	}
	redirect(w, r, page)
}
