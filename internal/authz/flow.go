package authz

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
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
		return ValidateRequestOn(ctx, h.Store, res, &fr.Request)
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
// eff are the post-login flow's effects, sealed onto the code or approval
// for the token endpoint.
func (h *Handlers) approve(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, sess *store.LoginSession, scopes []string, eff *actions.Effects) {
	if h.requireMFA(w, r, res, client, fr, sess, eff) {
		return
	}
	staged := cookieHeaders{header: make(http.Header)}
	var code string
	var policyError *Error
	err := orglogin.WithMembershipEvents(r.Context(), h.Store, func(ctx context.Context, tx store.Store) error {
		local := *h
		local.Store = tx
		sm := *h.Sessions
		sm.Store = tx
		local.Sessions = &sm
		request := r.WithContext(ctx)
		if hosted, e := local.organizationSession(&staged, request, res, client, &fr, sess); e != nil {
			policyError = e
			return store.ErrPrecondition
		} else if hosted {
			policyError = errAccessDenied("an organization must be selected before issuing a code")
			return store.ErrPrecondition
		}
		if e := local.commitLogin(&staged, request, res, fr, sess, eff); e != nil {
			return e
		}
		if fr.invitationBinding[orglogin.InvitationIDParam] != "" && eff != nil && eff.RBAC != nil {
			snapshot, e := store.OrganizationAuthorizationSnapshot(ctx, tx, res.Tenant.ID, sess.UserID, fr.OrgID, eff.RBAC.Audience)
			if e != nil {
				return e
			}
			if snapshot == nil {
				return store.ErrPrecondition
			}
			copied := *eff
			copied.RBAC = &actions.RBACSnapshot{Audience: eff.RBAC.Audience, Permissions: append([]string{}, snapshot.Permissions...)}
			eff = &copied
		}
		if fr.SAML != "" {
			// A SAML response is built after the commit; no code is issued.
			return nil
		}
		if !fr.device() {
			var e error
			code, e = local.createCode(ctx, res, client, fr.Request, sess, scopes, eff)
			return e
		}
		sealed, e := local.sealFor(res.Tenant.ID, actions.SealDevice, fr.DeviceCodeHash, eff)
		if e != nil {
			return e
		}
		_, e = tx.DeviceCodes().Decide(ctx, res.Tenant.ID, fr.DeviceCodeHash, store.DeviceDecision{Status: store.DeviceCodeApproved, UserID: sess.UserID, GrantedScopes: scopes, ActionEffects: sealed})
		return e
	})
	if err != nil {
		if policyError != nil {
			h.refuse(w, r, res, client, fr, policyError)
			return
		}
		if fr.device() && (errors.Is(err, store.ErrAlreadyUsed) || errors.Is(err, store.ErrNotFound)) {
			h.flowError(w, r, res, fr, errCodeNotPending)
			return
		}
		h.log().ErrorContext(r.Context(), "commit login authorization", "tenant", res.Tenant.ID, "err", err)
		if errors.Is(err, orglogin.ErrInvitationIdentity) {
			h.refuse(w, r, res, client, fr, errAccessDenied(orglogin.ErrInvitationIdentity.Error()))
		} else {
			h.refuse(w, r, res, client, fr, errServer())
		}
		return
	}
	for _, cookie := range staged.Header().Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", cookie)
	}
	h.loginSucceeded(w, r, res, client, fr, sess)
	if fr.SAML != "" {
		if h.SAML == nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		h.SAML.Respond(w, r, res, client, fr.SAML, fr.OrgID, sess, eff)
		return
	}
	if fr.device() {
		redirect(w, r, "/device/success")
		return
	}
	params := url.Values{"code": {code}}
	if fr.State != "" {
		params.Set("state", fr.State)
	}
	writeResponse(w, r, fr.Request, params)
}

// refuse ends fr with e: an authorization error for /authorize, a denied
// device code for the device flow. A server error leaves a device code
// pending.
func (h *Handlers) refuse(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, e *Error) {
	if e.Code != "server_error" {
		if err := h.retirePending(w, r, res); err != nil {
			e = errServer()
		}
	}

	if txn, ok := r.Context().Value(completionTxnKey{}).(*store.AuthTransaction); ok && e.Code != "server_error" {
		h.EndTxn(w, r, res, txn)
	}
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
	if dec.Status == store.DeviceCodeApproved {
		h.loginSucceeded(w, r, res, &store.Client{ClientID: fr.ClientID}, fr, &store.LoginSession{UserID: dec.UserID})
	}
	redirect(w, r, page)
}

// loginSucceeded records only a committed authorization, after Actions, access
// policy, consent and final organization checks. Signup's ss describes the
// separate user-creation outcome; this event counts its completed login once.
func (h *Handlers) loginSucceeded(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, sess *store.LoginSession) {
	// Record confidence only for a committed login while the confidence-score
	// policy is active, and reuse a still-valid device cookie rather than
	// inserting a row per authorization. Unsupported old plugins retain their
	// pre-MFA behavior; a cookie failure cannot undo issuance.
	if err := h.recordKnownDevice(w, r, res, sess); err != nil && !errors.Is(err, store.ErrMFAUnavailable) {
		h.log().ErrorContext(r.Context(), "record MFA browser", "tenant", res.Tenant.ID)
	}
	if outcome, ok := r.Context().Value(silentAuthorizationKey{}).(*silentAuthorizationOutcome); ok {
		outcome.completed = true
	}

	e := logs.FromRequest(r)
	e.TenantID, e.ClientID, e.ClientName = res.Tenant.ID, client.ClientID, client.Name
	e.UserID, e.Connection, e.OrganizationID = sess.UserID, sess.Connection, fr.OrgID
	e.Audience, e.Scope = fr.Audience, fr.Scope
	e.Type = "s"
	if slices.ContainsFunc(sess.AuthMethods, func(m store.AuthMethod) bool { return m.Name == "passkey" }) {
		e.Details = map[string]any{"prompts": []map[string]any{{"name": "login-id", "performed_amr": []string{"phr"}}}}
	}
	if slices.Contains(fr.Prompts(), "none") {
		e.Type = "ssa"
	}
	logs.RecordEvent(r.Context(), logs.RecorderFromContext(r.Context()), e)
}

func (h *Handlers) recordKnownDevice(w http.ResponseWriter, r *http.Request, res tenant.Resolved, sess *store.LoginSession) error {
	g, err := h.Store.MFA().GetGuardian(r.Context(), res.Tenant.ID)
	if err != nil {
		return err
	}
	if !slices.Contains(g.Policies, "confidence-score") {
		return nil
	}
	u, err := h.Store.Users().Get(r.Context(), res.Tenant.ID, sess.UserID)
	if err != nil {
		return err
	}
	known, err := h.Sessions.MFABrowserValid(r.Context(), r, u, "device")
	if err != nil || known {
		return err
	}
	return h.Sessions.SetMFABrowser(r.Context(), w, u, "device")
}

// Only cookie headers are staged until the enclosing store commit succeeds.
type cookieHeaders struct{ header http.Header }

func (w *cookieHeaders) Header() http.Header         { return w.header }
func (w *cookieHeaders) Write(p []byte) (int, error) { return len(p), nil }
func (w *cookieHeaders) WriteHeader(int)             {}
