package login

import (
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// CIBA approval pages (Plan 41c, D-0100), at Auth0's path /bc-verify. They
// live outside /u, so their transactions' cookies use Path=/.

// cibaRequest returns the pending, delivered, unexpired request of this
// origin, or nil.
func (h *Handlers) cibaRequest(r *http.Request, res tenant.Resolved, get func(store.CIBAStore) (*store.CIBARequest, error)) (*store.CIBARequest, error) {
	repo, err := store.CIBA(r.Context(), h.Store)
	if err != nil {
		return nil, err
	}
	req, err := get(repo)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if req.Status != store.CIBAPending || req.UserID == "" || !h.now().Before(req.ExpiresAt) || res.CheckOrigin(req.Origin) != nil {
		return nil, nil
	}
	return req, nil
}

func (h *Handlers) cibaExpired(w http.ResponseWriter, r *http.Request, res tenant.Resolved) {
	view := ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
	ui.RenderErrorDetail(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrInvalidRequest), view.L.T(i18n.KeyCIBAExpired))
}

// CIBAVerify serves GET /bc-verify?consent=: the approval page of the
// request the emailed link names. The link value is single use: it works
// until the request is decided or expires.
func (h *Handlers) CIBAVerify(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		h.fail(w, r, errTxn, nil)
		return
	}
	ticket := r.URL.Query().Get("consent")
	*r = *r.WithContext(logscrub.WithCredentials(r.Context(), ticket))
	if ticket == "" {
		h.cibaExpired(w, r, res)
		return
	}
	req, err := h.cibaRequest(r, res, func(repo store.CIBAStore) (*store.CIBARequest, error) {
		return repo.GetCIBARequestByTicket(r.Context(), res.Tenant.ID, secrets.HashToken(ticket))
	})
	if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	if req == nil {
		h.cibaExpired(w, r, res)
		return
	}
	uiLocales := r.URL.Query().Get("ui_locales")
	txn, err := h.Authz.CreateTxn(w, r, res, req.ClientID, map[string]string{
		authz.ParamFlow: authz.FlowCIBA, authz.ParamStage: authz.StageCIBAConfirm, authz.ParamCIBA: req.IDHash, "ui_locales": uiLocales,
	}, deviceCookiePath)
	if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	name := req.ClientID
	if c, err := h.Store.Clients().Get(r.Context(), res.Tenant.ID, req.ClientID); err == nil && c.Name != "" {
		name = c.Name
	}
	view := ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, uiLocales))
	ui.RenderCIBAConfirm(w, view, ui.CIBAConfirmData{State: txn.ID, CSRF: txn.CSRFToken, ClientName: name, BindingMessage: req.BindingMessage, Scopes: req.Scopes})
}

// CIBAVerifySubmit serves POST /bc-verify (form: state, csrf,
// action=approve|deny). Approve signs in as the request's user; deny
// records the denial.
func (h *Handlers) CIBAVerifySubmit(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedStage(w, r, authz.StageCIBAConfirm)
	if !ok {
		return
	}
	action := r.PostForm.Get("action")
	if action != "approve" && action != "deny" {
		h.fail(w, r, errTxn, f)
		return
	}
	uiLocales := f.txn.Params["ui_locales"]
	req, err := h.cibaRequest(r, f.res, func(repo store.CIBAStore) (*store.CIBARequest, error) {
		return repo.GetCIBARequest(r.Context(), f.res.Tenant.ID, f.txn.Params[authz.ParamCIBA])
	})
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	h.Authz.EndTxn(w, r, f.res, f.txn)
	if req == nil || req.ClientID != f.txn.ClientID {
		h.cibaExpired(w, r, f.res)
		return
	}
	if action == "deny" {
		h.Authz.DenyCIBA(w, r, f.res, req, uiLocales)
		return
	}
	hint := ""
	if u, err := h.Store.Users().Get(r.Context(), f.res.Tenant.ID, req.UserID); err == nil {
		hint = u.Email
	}
	h.Authz.ContinueCIBA(w, r, f.res, req, hint, uiLocales)
}

// CIBAApproved serves GET /bc-verify/approved.
func (h *Handlers) CIBAApproved(w http.ResponseWriter, r *http.Request) { h.cibaResult(w, r, true) }

// CIBADenied serves GET /bc-verify/denied.
func (h *Handlers) CIBADenied(w http.ResponseWriter, r *http.Request) { h.cibaResult(w, r, false) }

func (h *Handlers) cibaResult(w http.ResponseWriter, r *http.Request, approved bool) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		h.fail(w, r, errTxn, nil)
		return
	}
	ui.RenderCIBAResult(w, ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, "")), approved)
}
