package login

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// Only IDs, control flags and send time are retained in the bound envelope.
// Recovery codes are returned directly from the service to one response.
type mfaPageState struct {
	Factor, AuthenticatorID, ChallengeID      string
	SentAt                                    time.Time
	Proven, RecoveryPending, Remember, Manual bool
}
type mfaFlow struct {
	*flow
	pending *authz.MFAPending
	sess    *store.LoginSession
	page    mfaPageState
}

func (h *Handlers) mfaInvalid(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/authorize/resume?error=invalid_request", http.StatusSeeOther)
}
func (h *Handlers) loadMFA(w http.ResponseWriter, r *http.Request, post bool) *mfaFlow {
	h.maskRequest(r)
	var f *flow
	var err error
	if post {
		var ok bool
		f, ok = h.postedTxn(w, r)
		if !ok {
			return nil
		}
	} else {
		f, err = h.loadTxn(r, r.URL.Query().Get("state"))
		if err != nil {
			h.mfaInvalid(w, r)
			return nil
		}
	}
	if h.MFA == nil || h.Authz == nil || h.Sessions == nil {
		http.Error(w, "mfa_unavailable", http.StatusNotImplemented)
		return nil
	}
	var sess *store.LoginSession
	isolated := f.txn.ClientID == "" && (f.txn.Params["za_mfa_ticket"] == "1" || f.txn.Params["za_mfa_reset"] == "1")
	if !isolated {
		sess, err = h.Authz.ActiveSession(r.Context(), r, f.res)
		if err != nil {
			h.mfaInvalid(w, r)
			return nil
		}
	}
	pending, err := h.Authz.PendingMFA(r.Context(), r, f.res, f.txn, sess)
	if err != nil {
		h.mfaInvalid(w, r)
		return nil
	}
	if _, err = h.Store.MFA().GetGuardian(r.Context(), f.res.Tenant.ID); err != nil {
		if errors.Is(err, store.ErrMFAUnavailable) {
			http.Error(w, "mfa_unavailable", 501)
		} else {
			h.fail(w, r, err, f)
		}
		return nil
	}
	out := &mfaFlow{flow: f, pending: pending, sess: sess}
	if f.txn.HostedState.Step != "" {
		if f.txn.HostedState.Step != "mfa-page" {
			h.fail(w, r, errTxn, f)
			return nil
		}
		raw, e := base64.RawURLEncoding.DecodeString(f.txn.HostedState.Identifier)
		if e != nil {
			h.fail(w, r, errTxn, f)
			return nil
		}
		plain, e := keys.OpenBound(h.Authz.Wrapper, "hosted-mfa-page/v1", []string{f.res.Tenant.ID, f.txn.ID, pending.UserID}, raw)
		if e != nil || json.Unmarshal(plain, &out.page) != nil {
			h.fail(w, r, errTxn, f)
			return nil
		}
	}
	return out
}
func (h *Handlers) saveMFAPage(r *http.Request, f *mfaFlow, step string) error {
	plain, err := json.Marshal(f.page)
	if err != nil {
		return err
	}
	sealed, err := keys.SealBound(h.Authz.Wrapper, "hosted-mfa-page/v1", []string{f.res.Tenant.ID, f.txn.ID, f.pending.UserID}, plain)
	if err != nil {
		return err
	}
	next := f.txn.HostedState.Clone()
	next.Step = step
	next.Identifier = base64.RawURLEncoding.EncodeToString(sealed)
	return h.transitionHosted(r, f.flow, next)
}
func mfaURL(f *mfaFlow, path string) string {
	return path + "?" + url.Values{"state": {f.txn.ID}}.Encode()
}
func mfaPath(f *mfaFlow) string {
	switch f.page.Factor {
	case "otp":
		if f.pending.Requirement.Enroll {
			return "/u/mfa-otp-enrollment"
		}
		return "/u/mfa-otp-challenge"
	case "email":
		return "/u/mfa-email-challenge"
	case "recovery-code":
		return "/u/mfa-recovery-code-challenge"
	}
	return "/u/mfa"
}
func mfaPage(f *mfaFlow) string {
	if f.page.RecoveryPending {
		return "mfa_recovery_enroll"
	}
	switch f.page.Factor {
	case "otp":
		if f.pending.Requirement.Enroll {
			if f.page.Manual {
				return "mfa_otp_enroll_code"
			}
			return "mfa_otp_enroll"
		}
		return "mfa_otp_challenge"
	case "email":
		return "mfa_email_challenge"
	case "recovery-code":
		return "mfa_recovery_challenge"
	}
	if f.pending.Requirement.Enroll {
		return "mfa_enroll_options"
	}
	return "mfa_options"
}
func (h *Handlers) renderMFA(w http.ResponseWriter, r *http.Request, status int, f *mfaFlow, recovery, message string) {
	page := mfaPage(f)
	prompt, screen := ui.MFAScreen(page)
	if !h.prepareHostedForm(w, r, f.flow, prompt, screen) {
		return
	}
	d := ui.MFAData{RedirectURI: f.txn.Params["redirect_uri"], State: f.txn.ID, CSRF: f.txn.CSRFToken, Revision: f.txn.HostedState.Revision, Action: mfaPath(f), Error: message, RecoveryCode: recovery, AllowRemember: f.pending.Requirement.AllowRemember, CodeScreen: f.page.Manual, Recovery: f.page.Factor == "recovery-code"}
	if f.page.RecoveryPending {
		d.Action = "/u/mfa-recovery-code-enrollment"
		d.AllowRemember = false
	}
	if f.page.Factor == "" {
		for _, factor := range f.pending.Requirement.Factors {
			if f.pending.Requirement.Enroll && factor == "recovery-code" {
				continue
			}
			d.Options = append(d.Options, ui.MFAOption{Factor: factor, Label: f.view.L.T(prompt + "." + screen + "." + factor + "Text")})
		}
	}
	if f.page.Factor != "" && !f.page.RecoveryPending {
		d.AnotherURL = mfaURL(f, "/u/mfa") + "&action=another"
	}
	if f.page.Factor == "otp" && f.pending.Requirement.Enroll && !f.page.Proven {
		e, err := h.MFA.EnrollmentDisplay(r.Context(), f.res.Tenant.ID, f.pending.UserID, f.page.AuthenticatorID)
		if err != nil {
			h.fail(w, r, err, f.flow)
			return
		}
		// QRSVG may decline an over-capacity issuer/account; manual entry remains usable.
		d.Secret = e.Secret
		d.QR = template.HTML(mfa.QRSVG(e.URI))
		*r = *r.WithContext(logscrub.WithCredentials(r.Context(), e.Secret, e.URI))
	}
	ui.RenderMFA(w, status, f.view, page, d)
}
func (h *Handlers) startMFAMethod(w http.ResponseWriter, r *http.Request, f *mfaFlow, factor string) bool {
	if !slices.Contains(f.pending.Requirement.Factors, factor) || factor != "otp" && factor != "email" && factor != "recovery-code" || f.pending.Requirement.Enroll && factor == "recovery-code" {
		h.fail(w, r, errTxn, f.flow)
		return false
	}
	if f.page.Proven || f.page.RecoveryPending {
		h.fail(w, r, errTxn, f.flow)
		return false
	}
	if f.page.Factor == factor && f.page.ChallengeID != "" {
		return true
	}
	// Claim the revision before sending an email or creating a method.
	if err := h.saveMFAPage(r, f, "mfa-busy"); err != nil {
		h.fail(w, r, errTxn, f.flow)
		return false
	}
	f.page = mfaPageState{Factor: factor, SentAt: h.now()}
	var err error
	if factor != "recovery-code" {
		if f.pending.Requirement.Enroll {
			var e *mfa.Enrollment
			svc := h.MFA
			if f.pending.Requirement.Reason == "action" {
				svc = svc.WithNewFactorEnrollment()
			}
			e, err = svc.BeginEnroll(r.Context(), f.res.Tenant.ID, f.pending.UserID, factor, r.Host)
			if err == nil {
				f.page.AuthenticatorID = e.AuthenticatorID
				f.page.ChallengeID = e.ChallengeID
				if factor == "email" {
					u, _ := h.Store.Users().Get(r.Context(), f.res.Tenant.ID, f.pending.UserID)
					h.event(r, f.flow, "gd_send_email_verification", u)
				}
			}
		} else {
			var aa []store.Authenticator
			var u *store.User
			var g *store.GuardianSettings
			aa, err = h.Store.MFA().ListAuthenticators(r.Context(), f.res.Tenant.ID, f.pending.UserID)
			if err == nil {
				u, err = h.Store.Users().Get(r.Context(), f.res.Tenant.ID, f.pending.UserID)
			}
			if err == nil {
				g, err = h.Store.MFA().GetGuardian(r.Context(), f.res.Tenant.ID)
			}
			if err == nil {
				typ := factor
				if typ == "otp" {
					typ = "totp"
				}
				for _, a := range aa {
					if a.Type == typ && mfa.UsableMethod(u, a, g.Factors) && (f.page.AuthenticatorID == "" || a.Preferred) {
						f.page.AuthenticatorID = a.ID
					}
				}
				if f.page.AuthenticatorID == "" {
					err = mfa.ErrNoFactor
				} else {
					var c *mfa.Challenge
					c, err = h.MFA.BeginChallenge(r.Context(), f.res.Tenant.ID, f.pending.UserID, f.page.AuthenticatorID, r.Host)
					if err == nil {
						f.page.ChallengeID = c.ID
					}
				}
			}
		}
	}
	if err != nil {
		f.page = mfaPageState{}
		_ = h.saveMFAPage(r, f, "mfa-page")
		h.fail(w, r, err, f.flow)
		return false
	}
	if err = h.saveMFAPage(r, f, "mfa-page"); err != nil {
		h.fail(w, r, errTxn, f.flow)
		return false
	}
	return true
}
func (h *Handlers) MFAPage(w http.ResponseWriter, r *http.Request) {
	f := h.loadMFA(w, r, false)
	if f == nil {
		return
	}
	if f.page.RecoveryPending {
		if r.URL.Path != "/u/mfa-recovery-code-enrollment" {
			http.Redirect(w, r, mfaURL(f, "/u/mfa-recovery-code-enrollment"), http.StatusSeeOther)
			return
		}
		h.renderMFA(w, r, 200, f, "", "")
		return
	}
	if r.URL.Path == "/u/mfa" {
		show, _ := f.res.Tenant.SettingsExtra["flags"].(map[string]any)
		flag, _ := f.res.Tenant.SettingsExtra["mfa_show_factor_list_on_enrollment"].(bool)
		if show != nil {
			v, _ := show["mfa_show_factor_list_on_enrollment"].(bool)
			flag = flag || v
		}
		if r.URL.Query().Get("action") == "another" || f.pending.Requirement.SelectFactor && len(f.pending.Requirement.Factors) > 1 || f.pending.Requirement.Enroll && f.pending.Requirement.Reason != "action" && (len(f.pending.Requirement.Factors) > 1 || flag) {
			f.page.Factor = ""
			h.renderMFA(w, r, 200, f, "", "")
			return
		}
		if f.page.Factor == "" {
			if len(f.pending.Requirement.Factors) == 0 {
				h.fail(w, r, errTxn, f.flow)
				return
			}
			if !h.startMFAMethod(w, r, f, f.pending.Requirement.Factors[0]) {
				return
			}
		}
		http.Redirect(w, r, mfaURL(f, mfaPath(f)), http.StatusSeeOther)
		return
	}
	factor := ""
	switch r.URL.Path {
	case "/u/mfa-otp-enrollment":
		if f.pending.Requirement.Enroll {
			factor = "otp"
		}
	case "/u/mfa-otp-challenge":
		if !f.pending.Requirement.Enroll {
			factor = "otp"
		}
	case "/u/mfa-email-challenge":
		factor = "email"
	case "/u/mfa-recovery-code-challenge":
		if !f.pending.Requirement.Enroll {
			factor = "recovery-code"
		}
	}
	if factor == "" {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	if !h.startMFAMethod(w, r, f, factor) {
		return
	}
	h.renderMFA(w, r, 200, f, "", "")
}
func (h *Handlers) MFASubmit(w http.ResponseWriter, r *http.Request) {
	f := h.loadMFA(w, r, true)
	if f == nil {
		return
	}
	if !postedHostedRevision(r, f.flow) {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	if r.URL.Path == "/u/mfa" {
		if f.page.Proven || f.page.RecoveryPending {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		options := "mfa_options"
		if f.pending.Requirement.Enroll {
			options = "mfa_enroll_options"
		}
		prompt, screen := ui.MFAScreen(options)
		if !h.guardHostedForm(w, r, f.flow, prompt, screen, func(status int, msg string) { f.page.Factor = ""; h.renderMFA(w, r, status, f, "", msg) }) {
			return
		}
		if !h.startMFAMethod(w, r, f, r.PostForm.Get("factor")) {
			return
		}
		http.Redirect(w, r, mfaURL(f, mfaPath(f)), http.StatusSeeOther)
		return
	}
	expected := mfaPath(f)
	if f.page.RecoveryPending {
		expected = "/u/mfa-recovery-code-enrollment"
	}
	if r.URL.Path != expected || f.page.Factor == "" || !slices.Contains(f.pending.Requirement.Factors, f.page.Factor) {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	page := mfaPage(f)
	prompt, screen := ui.MFAScreen(page)
	if !h.guardHostedForm(w, r, f.flow, prompt, screen, func(status int, msg string) { h.renderMFA(w, r, status, f, "", msg) }) {
		return
	}
	if f.page.RecoveryPending {
		if !f.page.Proven || r.PostForm.Get("ack") != "yes" {
			h.renderMFA(w, r, 400, f, "", f.view.L.T(prompt+"."+screen+".acknowledgeText"))
			return
		}
		if err := h.saveMFAPage(r, f, "mfa-busy"); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		h.finishMFA(w, r, f)
		return
	}
	if f.pending.Requirement.Enroll && f.page.Factor == "otp" && r.PostForm.Get("action") == "manual" {
		f.page.Manual = true
		if err := h.saveMFAPage(r, f, "mfa-page"); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		h.renderMFA(w, r, 200, f, "", "")
		return
	}
	if r.PostForm.Get("action") == "resend" {
		if f.page.Factor != "email" {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		if h.now().Before(f.page.SentAt.Add(30 * time.Second)) {
			h.renderMFA(w, r, 429, f, "", f.view.L.T(prompt+"."+screen+".tooManyAttempts"))
			return
		}
		if err := h.saveMFAPage(r, f, "mfa-busy"); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		c, err := h.MFA.BeginChallenge(r.Context(), f.res.Tenant.ID, f.pending.UserID, f.page.AuthenticatorID, r.Host)
		if err != nil {
			_ = h.saveMFAPage(r, f, "mfa-page")
			h.renderMFA(w, r, 429, f, "", f.view.L.T(prompt+"."+screen+".tooManyAttempts"))
			return
		}
		f.page.ChallengeID = c.ID
		f.page.SentAt = h.now()
		if err = h.saveMFAPage(r, f, "mfa-page"); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		if f.pending.Requirement.Enroll {
			u, _ := h.Store.Users().Get(r.Context(), f.res.Tenant.ID, f.pending.UserID)
			h.event(r, f.flow, "gd_send_email_verification", u)
		}
		h.renderMFA(w, r, 200, f, "", "")
		return
	}
	if err := h.saveMFAPage(r, f, "mfa-busy"); err != nil {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	var recovery string
	var err error
	if f.pending.Requirement.Enroll {
		var result *mfa.Confirmed
		svc := h.MFA
		if f.pending.Requirement.Reason == "action" {
			svc = svc.WithNewFactorEnrollment()
		}
		confirm := svc.ConfirmEnroll
		if f.pending.Requirement.Reason == "ticket" && !f.pending.TicketAllowMultiple {
			confirm = h.MFA.ConfirmFirstEnroll
		}
		result, err = confirm(r.Context(), f.res.Tenant.ID, f.pending.UserID, &mfa.Enrollment{AuthenticatorID: f.page.AuthenticatorID, ChallengeID: f.page.ChallengeID}, mfa.Proof{Code: r.PostForm.Get("code")})
		if err == nil {
			recovery = result.RecoveryCode
			if f.page.Factor == "email" {
				u, _ := h.Store.Users().Get(r.Context(), f.res.Tenant.ID, f.pending.UserID)
				h.event(r, f.flow, "gd_auth_email_verification", u)
			}
		}
	} else if f.page.Factor == "recovery-code" {
		recovery, err = h.MFA.Recover(r.Context(), f.res.Tenant.ID, f.pending.UserID, r.PostForm.Get("code"))
	} else {
		err = h.MFA.Verify(r.Context(), f.res.Tenant.ID, f.pending.UserID, &mfa.Challenge{ID: f.page.ChallengeID, AuthenticatorID: f.page.AuthenticatorID}, mfa.Proof{Code: r.PostForm.Get("code")})
	}
	if err != nil {
		if e := h.saveMFAPage(r, f, "mfa-page"); e != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		key := "invalidCode"
		status := 400
		if errors.Is(err, mfa.ErrThrottled) {
			key = "tooManyAttempts"
			status = 429
		}
		h.renderMFA(w, r, status, f, "", f.view.L.T(prompt+"."+screen+"."+key))
		return
	}
	f.page.Proven = true
	f.page.Remember = f.pending.Requirement.AllowRemember && r.PostForm.Get("remember") == "yes"
	if recovery != "" {
		f.page.RecoveryPending = true
		if err = h.saveMFAPage(r, f, "mfa-page"); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		*r = *r.WithContext(logscrub.WithCredentials(r.Context(), recovery))
		h.renderMFA(w, r, 200, f, recovery, "")
		return
	}
	h.finishMFA(w, r, f)
}
func (h *Handlers) finishMFA(w http.ResponseWriter, r *http.Request, f *mfaFlow) {
	if !f.page.Proven {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	if f.pending.Requirement.Reason == "reset" {
		if err := h.Authz.CompleteMFAReset(w, r, f.res, f.txn); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		cookie, err := r.Cookie("za_reset_mfa")
		if err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "za_reset_mfa_page", Value: "", Path: "/u", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: "za_reset_mfa", Value: "", Path: "/u", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, "/u/reset-password?"+url.Values{"ticket": {cookie.Value}}.Encode(), http.StatusSeeOther)
		return
	}
	if f.pending.Requirement.Reason != "ticket" {
		if err := h.Sessions.MarkMFA(r.Context(), f.sess); err != nil {
			h.fail(w, r, err, f.flow)
			return
		}
		if f.page.Remember && f.pending.Requirement.AllowRemember {
			u, err := h.Store.Users().Get(r.Context(), f.res.Tenant.ID, f.pending.UserID)
			if err != nil {
				h.fail(w, r, err, f.flow)
				return
			}
			if err = h.Sessions.SetMFABrowser(r.Context(), w, u, "remember"); err != nil {
				h.fail(w, r, err, f.flow)
				return
			}
		}
	}
	h.Authz.MFAComplete(w, r, f.res, f.txn, f.sess)
}
func (h *Handlers) MFATicket(w http.ResponseWriter, r *http.Request) {
	h.maskRequest(r)
	res, ok := tenant.FromContext(r.Context())
	if !ok || h.MFA == nil || h.Authz == nil || h.Sessions == nil {
		http.Error(w, "mfa_unavailable", 501)
		return
	}
	var user *store.User
	var factors []string
	var allowMultiple bool
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		ticket, e := tx.MFA().ConsumeTicket(r.Context(), res.Tenant.ID, secrets.HashToken(r.URL.Query().Get("ticket")), h.now())
		if e != nil {
			return e
		}
		allowMultiple = ticket.AllowMultiple
		user, e = tx.Users().Get(r.Context(), res.Tenant.ID, ticket.UserID)
		if e != nil {
			return e
		}
		if user.Blocked {
			return store.ErrNotFound
		}
		g, e := tx.MFA().GetGuardian(r.Context(), res.Tenant.ID)
		if e != nil {
			return e
		}
		aa, e := tx.MFA().ListAuthenticators(r.Context(), res.Tenant.ID, user.UserID)
		if e != nil {
			return e
		}
		if !ticket.AllowMultiple {
			for _, a := range aa {
				if mfa.UsableMethod(user, a, g.Factors) {
					return store.ErrInvalid
				}
			}
		}
		for _, factor := range []string{"otp", "email"} {
			if ticket.Factor != "" && ticket.Factor != factor {
				continue
			}
			if g.Factors[factor] && (factor != "email" || user.EmailVerified && user.Email != "") {
				factors = append(factors, factor)
			}
		}
		if len(factors) == 0 {
			return mfa.ErrNoFactor
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrMFAUnavailable) {
			http.Error(w, "mfa_unavailable", 501)
			return
		}
		ui.RenderError(w, 400, ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, "")), i18n.ForRequest(res.Tenant, r, "").T("mfa.mfa-enroll-result.invalidTicket"))
		return
	}
	if err = h.Authz.StartMFATicket(w, r, res, user, factors, allowMultiple); err != nil {
		h.fail(w, r, err, nil)
	}
}
