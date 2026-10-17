package login

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/devicecode"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// The device pages live outside /u (paths observed on Auth0), so their
// transactions' za_txn cookies use Path=/.
const deviceCookiePath = "/"

// Activate serves GET /activate: the code entry form, or, with
// ?user_code=, the same check as ActivateSubmit (D1).
func (h *Handlers) Activate(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		h.fail(w, r, errTxn, nil)
		return
	}
	q := r.URL.Query()
	f, err := h.newEntry(w, r, res, q.Get("ui_locales"))
	if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	if !q.Has("user_code") {
		ui.RenderDeviceCode(w, http.StatusOK, f.view, ui.DeviceCodeData{State: f.txn.ID, CSRF: f.txn.CSRFToken})
		return
	}
	h.checkCode(w, r, f, q.Get("user_code"))
}

// ActivateSubmit serves POST /activate (form: state, csrf, code).
func (h *Handlers) ActivateSubmit(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedStage(w, r, authz.StageDeviceEntry)
	if !ok {
		return
	}
	h.checkCode(w, r, f, r.PostForm.Get("code"))
}

// newEntry stores a code entry transaction. It has no client.
func (h *Handlers) newEntry(w http.ResponseWriter, r *http.Request, res tenant.Resolved, uiLocales string) (*flow, error) {
	txn, err := h.Authz.CreateTxn(w, r, res, "", map[string]string{
		authz.ParamFlow: authz.FlowDevice, authz.ParamStage: authz.StageDeviceEntry, "ui_locales": uiLocales,
	}, deviceCookiePath)
	if err != nil {
		return nil, err
	}
	l := i18n.ForRequest(res.Tenant, r, uiLocales)
	return &flow{res: res, view: ui.TenantView(res.Tenant, l), txn: txn}, nil
}

// checkCode looks up the code typed on the entry transaction f, within
// the tenant, IP and transaction limits, and redirects to the
// confirmation page when the code is pending.
func (h *Handlers) checkCode(w http.ResponseWriter, r *http.Request, f *flow, code string) {
	ctx := r.Context()
	tenantID := f.res.Tenant.ID
	data := ui.DeviceCodeData{State: f.txn.ID, CSRF: f.txn.CSRFToken, UserCode: code}
	norm := devicecode.Normalize(code)
	if norm == "" {
		// Not a guess: it touches no limit, so it adds no throttle entry.
		data.ErrorKey = i18n.KeyDeviceNoCode
		ui.RenderDeviceCode(w, http.StatusBadRequest, f.view, data)
		return
	}
	// IPv6 sources are bucketed by /64, so rotating addresses within one
	// host's prefix does not escape the IP limit.
	ipKey := identity.IPThrottleKey(tenantID, httpx.IPBucket(httpx.ClientIP(r, h.TrustProxyHeaders)))
	// Attempt counts the try up front; a code that is found refunds it.
	tenantOK := h.DeviceTenantThrottle.Attempt(tenantID)
	ipOK := tenantOK && h.DeviceIPThrottle.Attempt(ipKey)
	if !ipOK {
		if tenantOK {
			// A locked IP's requests must not wear down the tenant limit.
			h.DeviceTenantThrottle.Refund(tenantID)
		}
		data.ErrorKey = i18n.KeyTooManyAttempts
		ui.RenderDeviceCode(w, http.StatusTooManyRequests, f.view, data)
		return
	}
	refund := func() {
		h.DeviceTenantThrottle.Refund(tenantID)
		h.DeviceIPThrottle.Refund(ipKey)
	}
	if !h.DeviceTxnThrottle.Attempt(f.txn.ID) {
		// No lookup happens, so the tenant and IP are not charged; the
		// transaction ends, so its throttle entry goes too.
		refund()
		h.DeviceTxnThrottle.Success(f.txn.ID)
		h.Authz.EndTxn(w, r, f.res, f.txn)
		h.fail(w, r, errTxn, f)
		return
	}
	dc, err := h.Store.DeviceCodes().GetByUserCode(ctx, tenantID, secrets.HashToken(norm))
	switch {
	case err != nil && !errors.Is(err, store.ErrNotFound):
		h.fail(w, r, err, f)
		return
	case err != nil || !h.usable(dc):
		data.ErrorKey = i18n.KeyDeviceInvalidExpiredCode
		ui.RenderDeviceCode(w, http.StatusBadRequest, f.view, data)
		return
	}
	refund()
	// The entry transaction ends here; drop its throttle entry with it.
	h.DeviceTxnThrottle.Success(f.txn.ID)
	h.Authz.EndTxn(w, r, f.res, f.txn)

	_, mask := devicecode.Settings(f.res.Tenant)
	txn, err := h.Authz.CreateTxn(w, r, f.res, dc.ClientID, map[string]string{
		authz.ParamFlow: authz.FlowDevice, authz.ParamStage: authz.StageDeviceConfirm,
		authz.ParamDevice: dc.DeviceCodeHash, authz.ParamUserCode: devicecode.Format(norm, mask),
		"ui_locales": f.txn.Params["ui_locales"],
	}, deviceCookiePath)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	http.Redirect(w, r, "/device/confirmation?"+url.Values{"state": {txn.ID}}.Encode(), http.StatusFound)
}

// usable reports whether dc can still be confirmed.
func (h *Handlers) usable(dc *store.DeviceCode) bool {
	return dc.Status == store.DeviceCodePending && h.now().Before(dc.ExpiresAt)
}

// stageTxn is loadTxn for a device transaction at stage.
func (h *Handlers) stageTxn(r *http.Request, state, stage string) (*flow, error) {
	f, err := h.loadTxn(r, state)
	if err != nil {
		return f, err
	}
	if f.txn.Params[authz.ParamStage] != stage {
		return f, errTxn
	}
	return f, nil
}

// postedStage is postedTxn for a device transaction at stage.
func (h *Handlers) postedStage(w http.ResponseWriter, r *http.Request, stage string) (*flow, bool) {
	f, ok := h.postedTxn(w, r)
	if !ok {
		return nil, false
	}
	if f.txn.Params[authz.ParamStage] != stage {
		h.fail(w, r, errTxn, f)
		return nil, false
	}
	return f, true
}

// DeviceConfirmPage serves GET /device/confirmation?state=.
func (h *Handlers) DeviceConfirmPage(w http.ResponseWriter, r *http.Request) {
	f, err := h.stageTxn(r, r.URL.Query().Get("state"), authz.StageDeviceConfirm)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	ui.RenderDeviceConfirm(w, f.view, ui.DeviceConfirmData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken, UserCode: f.txn.Params[authz.ParamUserCode], ClientName: f.clientName,
	})
}

// DeviceConfirmSubmit serves POST /device/confirmation (form: state, csrf,
// action=confirm|cancel).
func (h *Handlers) DeviceConfirmSubmit(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedStage(w, r, authz.StageDeviceConfirm)
	if !ok {
		return
	}
	action := r.PostForm.Get("action")
	if action != "confirm" && action != "cancel" {
		h.fail(w, r, errTxn, f)
		return
	}
	ctx := r.Context()
	uiLocales := f.txn.Params["ui_locales"]
	dc, err := h.Store.DeviceCodes().Get(ctx, f.res.Tenant.ID, f.txn.Params[authz.ParamDevice])
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.fail(w, r, err, f)
		return
	}
	h.Authz.EndTxn(w, r, f.res, f.txn)
	if err != nil || !h.usable(dc) || dc.ClientID != f.txn.ClientID {
		// Decided, expired or removed since the page was shown: start over.
		entry, err := h.newEntry(w, r, f.res, uiLocales)
		if err != nil {
			h.fail(w, r, err, f)
			return
		}
		ui.RenderDeviceCode(w, http.StatusBadRequest, entry.view, ui.DeviceCodeData{
			State: entry.txn.ID, CSRF: entry.txn.CSRFToken, ErrorKey: i18n.KeyDeviceInvalidExpiredCode,
		})
		return
	}
	if action == "confirm" {
		h.Authz.ContinueDevice(w, r, f.res, dc, uiLocales)
		return
	}
	h.Authz.DenyDevice(w, r, f.res, dc, uiLocales)
}

// DeviceSuccess serves GET /device/success.
func (h *Handlers) DeviceSuccess(w http.ResponseWriter, r *http.Request) { h.deviceResult(w, r, true) }

// DeviceDenied serves GET /device/denied.
func (h *Handlers) DeviceDenied(w http.ResponseWriter, r *http.Request) { h.deviceResult(w, r, false) }

func (h *Handlers) deviceResult(w http.ResponseWriter, r *http.Request, allowed bool) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		h.fail(w, r, errTxn, nil)
		return
	}
	ui.RenderDeviceResult(w, ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, "")), allowed)
}
