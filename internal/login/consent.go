package login

import (
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// ConsentPage renders the consent or confirmation screen of a transaction
// started by /authorize after login.
func (h *Handlers) ConsentPage(w http.ResponseWriter, r *http.Request) {
	f, err := h.loadTxn(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	sess, err := h.Authz.ActiveSession(r.Context(), r, f.res)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if sess == nil {
		h.fail(w, r, errTxn, f)
		return
	}
	v, err := h.Authz.ConsentView(r.Context(), f.res, f.txn, sess)
	if err != nil {
		h.log().WarnContext(r.Context(), "consent page", "tenant", f.res.Tenant.ID, "err", err)
		h.fail(w, r, errTxn, f)
		return
	}
	ui.RenderConsent(w, http.StatusOK, f.view, ui.ConsentData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken, Confirmation: v.Confirmation, ThirdParty: v.ThirdParty,
		CallbackDomain: v.CallbackDomain, APIName: v.APIName, Scopes: v.Scopes, RedirectURI: v.RedirectURI,
	})
}

// ConsentSubmit handles the accept or decline button.
func (h *Handlers) ConsentSubmit(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedTxn(w, r)
	if !ok {
		return
	}
	sess, err := h.Authz.ActiveSession(r.Context(), r, f.res)
	switch {
	case err != nil:
		h.fail(w, r, err, f)
		return
	case sess == nil:
		h.fail(w, r, errTxn, f)
		return
	}
	switch r.PostForm.Get("action") {
	case "accept":
		h.Authz.Consent(w, r, f.res, f.txn, sess, true)
	case "decline":
		h.Authz.Consent(w, r, f.res, f.txn, sess, false)
	default:
		h.fail(w, r, errors.New("login: consent form without an action"), f)
	}
}
