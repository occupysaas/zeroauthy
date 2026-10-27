package login

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

func (h *Handlers) transitionHosted(r *http.Request, f *flow, next store.HostedLoginState) error {
	expected := f.txn.HostedState.Revision
	if err := h.Store.AuthTransactions().CompareAndSwapHosted(r.Context(), f.res.Tenant.ID, f.txn.ID, expected, next, h.now()); err != nil {
		return err
	}
	next.Revision = expected + 1
	f.txn.HostedState = next
	return nil
}
func postedHostedRevision(r *http.Request, f *flow) bool {
	values := r.PostForm["hosted_revision"]
	if len(values) != 1 {
		return false
	}
	revision, err := strconv.ParseInt(values[0], 10, 64)
	return err == nil && revision >= 0 && revision == f.txn.HostedState.Revision
}
func (h *Handlers) stageData(f *flow, login string) ui.LoginStageData {
	return ui.LoginStageData{LoginData: ui.LoginData{State: f.txn.ID, CSRF: f.txn.CSRFToken, Login: login, SignupURL: signupURL(f), ForgotURL: h.forgotURL(f), RedirectURI: f.txn.Params["redirect_uri"]}, Revision: f.txn.HostedState.Revision}
}
func passwordLocation(f *flow) string {
	return "/u/login/password?" + url.Values{"state": {f.txn.ID}}.Encode()
}

func (h *Handlers) LoginIdentifierPost(w http.ResponseWriter, r *http.Request) { h.LoginSubmit(w, r) }
func (h *Handlers) identifierPost(w http.ResponseWriter, r *http.Request, f *flow) {
	identifier := strings.TrimSpace(r.PostForm.Get("username"))
	if !h.guardHostedForm(w, r, f, "login-id", "login-id", func(status int, message string) {
		d := h.stageData(f, identifier)
		d.Error = message
		h.renderIdentifier(w, r, status, f, d)
	}) {
		return
	}
	if !utf8.ValidString(identifier) || len(identifier) > 320 || identifier == "" {
		d := h.stageData(f, identifier)
		d.Error = f.view.L.T(i18n.KeyInvalidIdentifier)
		h.renderIdentifier(w, r, http.StatusBadRequest, f, d)
		return
	}
	next := f.txn.HostedState.Clone()
	next.Step = "password"
	next.Identifier = identifier
	next.ConnectionID = f.conn.ID
	if err := h.transitionHosted(r, f, next); err != nil {
		h.fail(w, r, errTxn, f)
		return
	}
	http.Redirect(w, r, passwordLocation(f), http.StatusSeeOther)
}

func (h *Handlers) LoginPasswordGet(w http.ResponseWriter, r *http.Request) {
	f, err := h.load(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if f.txn.HostedState.Step != "password" || f.txn.HostedState.ConnectionID != f.conn.ID {
		h.fail(w, r, errTxn, f)
		return
	}
	if !h.captchaPage(w, r, f, "login") {
		return
	}
	h.renderLoginStage(w, r, http.StatusOK, f, h.stageData(f, f.txn.HostedState.Identifier).LoginData)
}
func (h *Handlers) LoginPasswordPost(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	if f.txn.HostedState.Step != "password" || f.txn.HostedState.ConnectionID != f.conn.ID {
		h.fail(w, r, errTxn, f)
		return
	}
	if !h.guardHostedForm(w, r, f, "login-password", "login-password", func(status int, message string) {
		data := h.stageData(f, f.txn.HostedState.Identifier).LoginData
		data.Error = message
		h.renderLoginStage(w, r, status, f, data)
	}) {
		return
	}
	next := f.txn.HostedState.Clone()
	next.Step = "authenticating"
	if err := h.transitionHosted(r, f, next); err != nil {
		h.fail(w, r, errTxn, f)
		return
	}
	// The stored identifier wins over every posted field. The state claim above
	// occurs before protection or an external database script can be invoked.
	h.authenticateLogin(w, r, f, next.Identifier)
}
func (h *Handlers) LoginIdentifierResetPost(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	if f.txn.HostedState.Step != "password" || !postedHostedRevision(r, f) {
		h.fail(w, r, errTxn, f)
		return
	}
	next := store.HostedLoginState{Step: "identifier"}
	if err := h.transitionHosted(r, f, next); err != nil {
		h.fail(w, r, errTxn, f)
		return
	}
	http.Redirect(w, r, "/u/login?"+url.Values{"state": {f.txn.ID}}.Encode(), http.StatusSeeOther)
}

// Ordinary authentication denials return the claimed password stage to a new
// revision. Infrastructure failures and crashes retain authenticating, requiring
// the browser to restart authorization instead of replaying an uncertain call.
func (h *Handlers) renderLoginStage(w http.ResponseWriter, r *http.Request, status int, f *flow, data ui.LoginData) {
	if data.Social == nil {
		data.Social = h.socialButtons(r, f)
	}
	if f.txn.HostedState.Step == "authenticating" {
		next := f.txn.HostedState.Clone()
		next.Step = "password"
		if err := h.transitionHosted(r, f, next); err != nil {
			h.fail(w, r, errTxn, f)
			return
		}
		data.Login = next.Identifier
	}
	if f.txn.HostedState.Step == "password" {
		if !h.prepareHostedForm(w, r, f, "login-password", "login-password") {
			return
		}
		ui.RenderLoginPassword(w, status, f.view, ui.LoginStageData{LoginData: data, Revision: f.txn.HostedState.Revision})
		return
	}
	if !h.prepareHostedForm(w, r, f, "login", "login") {
		return
	}
	data.HostedRevision = hostedRevision(f)
	ui.RenderLogin(w, status, f.view, data)
}
