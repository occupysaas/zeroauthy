package login

import (
	"errors"
	"net/http"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/ui"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

func webAuthnMFAPath(path string) bool {
	return strings.HasPrefix(path, "/u/mfa-webauthn-") || path == "/u/mfa-detect-browser-capabilities"
}
func (h *Handlers) mfaRP(r *http.Request, f *mfaFlow) (rpid.Result, error) {
	if h.Passkeys == nil {
		return rpid.Result{}, mfa.ErrNoFactor
	}
	policy := h.Passkeys.RPID
	policy.Store = h.Store
	rp, err := policy.For(r.Context(), f.res)
	if err == nil && !rp.Valid {
		err = mfa.ErrNoFactor
	}
	return rp, err
}
func (h *Handlers) webAuthnMFAService(r *http.Request, f *mfaFlow) (*mfa.Service, rpid.Result, error) {
	rp, err := h.mfaRP(r, f)
	if err != nil {
		return nil, rp, err
	}
	realm := ""
	if f.sess != nil {
		realm = f.sess.Connection
	}
	b := passkey.Binding{RPID: rp.RPID, Origins: []string{rp.Origin}, TxnID: f.txn.ID, CookieHash: f.txn.CookieHash, ClientID: f.txn.ClientID, Realm: realm, Organization: f.txn.Params[store.TxnParamOrgID], UserID: f.pending.UserID}
	svc := h.MFA.WithWebAuthnBinding(b).WithWebAuthnBrowserError(r.PostForm.Get("webauthn_error"))
	if f.page.PlatformProof {
		svc = svc.WithPlatformEnrollmentProof()
	}
	if f.pending.Requirement.Reason == "action" && f.page.Factor != "webauthn-platform" {
		svc = svc.WithNewFactorEnrollment()
	}
	if f.page.Factor != "webauthn-platform" && (firstOnlyEnrollment(f.pending) || f.pending.Requirement.Reason == "ticket" && !f.pending.TicketAllowMultiple) {
		svc = svc.WithFirstWebAuthnEnrollment()
	}
	if f.pending.Requirement.Reason == "ticket" && (!f.pending.Requirement.PlatformAfterProof || f.page.Factor == "webauthn-platform") {
		svc = svc.WithProofCommit(func(tx store.Store) error {
			ticket, e := tx.MFA().ConsumeTicket(r.Context(), f.res.Tenant.ID, f.pending.TicketHash, h.now())
			if errors.Is(e, store.ErrNotFound) || e == nil && ticket.UserID != f.pending.UserID {
				return mfa.ErrInvalidCode
			}
			return e
		})
	}
	return svc, rp, nil
}
func (h *Handlers) detectMFARequirement(r *http.Request, f *mfaFlow) error {
	g, err := h.Store.MFA().GetGuardian(r.Context(), f.res.Tenant.ID)
	if err != nil {
		return err
	}
	u, err := h.Store.Users().Get(r.Context(), f.res.Tenant.ID, f.pending.UserID)
	if err != nil {
		return err
	}
	aa, err := h.Store.MFA().ListAuthenticators(r.Context(), f.res.Tenant.ID, f.pending.UserID)
	if err != nil {
		return err
	}
	methods, err := h.MFA.PhoneMethods(r.Context(), f.res.Tenant.ID)
	if err != nil {
		return err
	}
	customize, _ := f.res.Tenant.SettingsExtra["customize_mfa_in_postlogin_action"].(bool)
	req, err := mfa.Decide(mfa.DecideInput{Settings: g, User: u, Authenticators: aa, Effects: f.pending.Effects.MFA, CustomizeInActions: customize, PhoneEnroll: len(methods) > 0, WebAuthn: f.page.WebAuthn, MFAAPI: f.pending.Requirement.Reason == "mfa-api"})
	if f.pending.Requirement.Reason == "ticket" || f.pending.Requirement.Reason == "reset" {
		req = f.pending.Requirement
		req.DetectWebAuthn = false
		var factors []string
		for _, factor := range req.Factors {
			if !isWebAuthnMFA(factor) || f.page.WebAuthn.Available && (factor != "webauthn-platform" || f.page.WebAuthn.Platform && mfaPlatformDevicePresent(aa, f.page.WebAuthn)) {
				factors = append(factors, factor)
			}
		}
		req.Factors = factors
		err = nil
		if len(factors) == 0 {
			err = mfa.ErrNoFactor
		}
	}
	if req.PlatformAfterProof && (!f.page.WebAuthn.Available || !f.page.WebAuthn.Platform) {
		return mfa.ErrNoFactor
	}
	if err != nil {
		return err
	}
	req.PlatformAfterProof = req.PlatformAfterProof || f.pending.Requirement.PlatformAfterProof
	req.Reason = f.pending.Requirement.Reason
	req.AllowRemember = req.AllowRemember && f.pending.Requirement.AllowRemember
	f.pending.Requirement = req
	f.page.Switched = &req
	return nil
}
func webAuthnMFAScreen(f *mfaFlow) (string, string) {
	if f.page.WebAuthnUnavailable {
		return "mfa-webauthn", "mfa-webauthn-not-available-error"
	}
	if f.page.WebAuthnError {
		return "mfa-webauthn", "mfa-webauthn-error"
	}
	if f.page.WebAuthnStage != "" {
		return "mfa-webauthn", f.page.WebAuthnStage
	}
	if f.pending.Requirement.Enroll {
		return "mfa-webauthn", "mfa-" + f.page.Factor + "-enrollment"
	}
	if f.pending.Requirement.Reason == "reset" {
		return "reset-password", "reset-password-mfa-" + f.page.Factor + "-challenge"
	}
	return "mfa-webauthn", "mfa-" + f.page.Factor + "-challenge"
}
func (h *Handlers) renderWebAuthnMFA(w http.ResponseWriter, r *http.Request, status int, f *mfaFlow, message string) {
	page := "mfa_webauthn"
	prompt, screen := webAuthnMFAScreen(f)
	if r.URL.Path == "/u/mfa-detect-browser-capabilities" && !f.page.WebAuthnUnavailable {
		page = "mfa_detect"
		prompt = "mfa"
		screen = "mfa-detect-browser-capabilities"
	}
	if !h.prepareHostedForm(w, r, f.flow, prompt, screen) {
		return
	}
	d := ui.MFAData{State: f.txn.ID, CSRF: f.txn.CSRFToken, Revision: f.txn.HostedState.Revision, RedirectURI: f.txn.Params["redirect_uri"], Action: mfaPath(f), Error: message, AllowRemember: f.pending.Requirement.AllowRemember, AnotherURL: mfaURL(f, "/u/mfa") + "&action=another", WebAuthnScreen: screen, WebAuthnPrompt: prompt}
	if page == "mfa_detect" {
		d.Action = "/u/mfa-detect-browser-capabilities"
		d.Passkey = &ui.WebAuthnData{Operation: "detect", Mediation: "button", MFA: true}
	}
	if f.page.Factor == "webauthn-platform" && f.pending.Requirement.Enroll {
		d.AnotherURL = ""
	}
	if f.page.Factor == "webauthn-platform" {
		d.PlatformEnrollment = f.pending.Requirement.Enroll && f.page.WebAuthnStage == ""
		d.Name = platformDefaultName(f.page.WebAuthn.Device)
	}
	if f.page.WebAuthnStage == "mfa-webauthn-change-key-nickname" {
		d.Nickname = true
		d.AllowRemember = false
	}
	if f.page.WebAuthnStage == "mfa-webauthn-enrollment-success" {
		d.WebAuthnSuccess = true
		d.AllowRemember = false
		d.AnotherURL = ""
	}
	if page != "mfa_detect" && !d.Nickname && !d.WebAuthnSuccess && f.page.ChallengeID != "" {
		svc, _, err := h.webAuthnMFAService(r, f)
		if err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		creation, request, err := svc.WebAuthnOptions(r.Context(), f.res.Tenant.ID, f.pending.UserID, f.page.ChallengeID)
		if err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		var raw []byte
		operation := "get"
		if f.pending.Requirement.Enroll {
			raw, err = creation.JSON()
			operation = "create"
		} else {
			raw, err = request.JSON()
		}
		if err != nil {
			h.fail(w, r, err, f.flow)
			return
		}
		d.Passkey = &ui.WebAuthnData{Operation: operation, ChallengeID: f.page.ChallengeID, PublicKey: raw, Mediation: "button", MFA: true}
	}
	if f.page.WebAuthnUnavailable {
		d.WebAuthnUnavailable = true
		d.Passkey = nil
		d.Action = "/u/mfa"
		d.AllowRemember = false
	}
	ui.RenderMFA(w, status, f.view, page, d)
}
func (h *Handlers) startWebAuthnMFA(w http.ResponseWriter, r *http.Request, f *mfaFlow) bool {
	if !f.page.WebAuthn.Available {
		h.renderWebAuthnMFA(w, r, 400, f, f.view.L.T("mfa-webauthn.mfa-webauthn-not-available-error.description"))
		return false
	}
	svc, rp, err := h.webAuthnMFAService(r, f)
	if err != nil {
		h.fail(w, r, errTxn, f.flow)
		return false
	}
	if f.pending.Requirement.Enroll {
		var e *mfa.Enrollment
		e, _, err = svc.BeginWebAuthnEnroll(r.Context(), f.res.Tenant.ID, f.pending.UserID, f.page.Factor, rp, passkey.UserDisplay{})
		if err == nil {
			f.page.AuthenticatorID = e.AuthenticatorID
			f.page.ChallengeID = e.ChallengeID
		}
	} else {
		var c *mfa.Challenge
		c, _, err = svc.BeginWebAuthnChallenge(r.Context(), f.res.Tenant.ID, f.pending.UserID, f.page.Factor, rp, f.page.WebAuthn.Device)
		if err == nil {
			f.page.ChallengeID = c.ID
		}
	}
	if err != nil {
		h.fail(w, r, err, f.flow)
		return false
	}
	return true
}
func (h *Handlers) webAuthnMFAPage(w http.ResponseWriter, r *http.Request) {
	f := h.loadMFA(w, r, false)
	if f == nil {
		return
	}
	if r.URL.Path == "/u/mfa-detect-browser-capabilities" {
		if f.page.WebAuthnDetected {
			http.Redirect(w, r, mfaURL(f, "/u/mfa"), 303)
			return
		}
		h.renderWebAuthnMFA(w, r, 200, f, "")
		return
	}
	if f.pending.Requirement.DetectWebAuthn && !f.page.WebAuthnDetected {
		http.Redirect(w, r, mfaURL(f, "/u/mfa-detect-browser-capabilities"), 303)
		return
	}
	if !isWebAuthnMFA(f.page.Factor) || r.URL.Path != mfaPath(f) {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	h.renderWebAuthnMFA(w, r, 200, f, "")
}
func (h *Handlers) webAuthnMFASubmit(w http.ResponseWriter, r *http.Request) {
	f := h.loadMFA(w, r, true)
	if f == nil {
		return
	}
	if !postedHostedRevision(r, f.flow) {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	if r.URL.Path == "/u/mfa-detect-browser-capabilities" {
		if f.page.WebAuthnDetected || f.page.Proven {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		if !h.guardHostedForm(w, r, f.flow, "mfa", "mfa-detect-browser-capabilities", func(status int, msg string) { h.renderWebAuthnMFA(w, r, status, f, msg) }) {
			return
		}
		rp, err := h.mfaRP(r, f)
		available, e := h.MFA.WebAuthnAvailable(r.Context())
		if err != nil || e != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		f.page.WebAuthnDetected = true
		f.page.WebAuthn = mfa.WebAuthnCapabilities{Available: available && r.PostForm.Get("webauthn") == "1", Platform: available && r.PostForm.Get("platform") == "1", RPID: rp.RPID, Device: webauthn.DeviceOf(r.UserAgent())}
		if err = h.detectMFARequirement(r, f); err != nil {
			if !errors.Is(err, mfa.ErrNoFactor) {
				h.fail(w, r, err, f.flow)
				return
			}
			f.page.WebAuthnUnavailable = true
			// Persist the negative result; an ordinary form submission can never
			// loop back into detection or offer an unavailable WebAuthn factor.
			f.page.Switched = &mfa.Requirement{Required: true, Reason: f.pending.Requirement.Reason}
		}
		if err = h.saveMFAPage(r, f, "mfa-page"); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		if f.page.WebAuthnUnavailable {
			h.renderWebAuthnMFA(w, r, 400, f, f.view.L.T("mfa-webauthn.mfa-webauthn-not-available-error.description"))
			return
		}
		http.Redirect(w, r, mfaURL(f, "/u/mfa"), 303)
		return
	}
	if !isWebAuthnMFA(f.page.Factor) || r.URL.Path != mfaPath(f) || !f.page.WebAuthn.Available {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	prompt, screen := webAuthnMFAScreen(f)
	if !h.guardHostedForm(w, r, f.flow, prompt, screen, func(status int, msg string) { h.renderWebAuthnMFA(w, r, status, f, msg) }) {
		return
	}
	if f.page.Factor == "webauthn-platform" && f.pending.Requirement.Enroll && f.page.WebAuthnStage == "" && r.PostForm.Get("platform_choice") != "" {
		h.skipPlatformMFA(w, r, f, r.PostForm.Get("platform_choice"))
		return
	}
	if err := h.saveMFAPage(r, f, "mfa-busy"); err != nil {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	if f.page.WebAuthnStage == "mfa-webauthn-enrollment-success" {
		if !f.page.Proven {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		h.finishMFA(w, r, f)
		return
	}
	f.page.WebAuthnError = false
	svc, _, err := h.webAuthnMFAService(r, f)
	if err != nil {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	recovery := ""
	if f.pending.Requirement.Enroll {
		enrollment := &mfa.Enrollment{ChallengeID: f.page.ChallengeID, AuthenticatorID: f.page.AuthenticatorID}
		if f.page.WebAuthnStage == "mfa-webauthn-change-key-nickname" {
			var result *mfa.Confirmed
			result, err = svc.ConfirmWebAuthnEnroll(r.Context(), f.res.Tenant.ID, f.pending.UserID, enrollment, nil, r.PostForm.Get("name"), r.UserAgent())
			if err == nil {
				recovery = result.RecoveryCode
			}
		} else {
			// The sealed page chooses the challenge. A submitted ID cannot select
			// another transaction's row, even if the attacker knows it.
			raw := []byte(r.PostForm.Get("credential"))
			if r.PostForm.Get("challenge_id") != f.page.ChallengeID || r.PostForm.Get("webauthn_error") != "" {
				raw = nil
			}
			err = svc.StageWebAuthnEnroll(r.Context(), f.res.Tenant.ID, f.pending.UserID, enrollment, raw, r.UserAgent())
			if err == nil {
				f.page.WebAuthnStage = "mfa-webauthn-change-key-nickname"
				f.page.Remember = f.page.OtherRemember || f.pending.Requirement.AllowRemember && r.PostForm.Get("remember") == "yes"
			}
		}
	} else {
		raw := []byte(r.PostForm.Get("credential"))
		if r.PostForm.Get("challenge_id") != f.page.ChallengeID || r.PostForm.Get("webauthn_error") != "" {
			raw = nil
		}
		err = svc.VerifyWebAuthn(r.Context(), f.res.Tenant.ID, f.pending.UserID, &mfa.Challenge{ID: f.page.ChallengeID}, raw)
	}
	if err != nil {
		if errors.Is(err, mfa.ErrAlreadyEnrolled) && firstOnlyEnrollment(f.pending) {
			f.page = mfaPageState{WebAuthnDetected: f.page.WebAuthnDetected, WebAuthn: f.page.WebAuthn}
			h.restartSwitchedMFA(w, r, f)
			return
		}
		status := 400
		key := "mfa-webauthn.mfa-webauthn-error.description"
		if errors.Is(err, mfa.ErrThrottled) {
			status = 429
			key = "mfa-webauthn.mfa-webauthn-error.too-many-webauthn-challenge-attempts-error"
		}
		if errors.Is(err, mfa.ErrExpired) || webauthn.Reason(err) == "user_verified" {
			f.page.WebAuthnStage = ""
		}
		if f.page.WebAuthnStage != "mfa-webauthn-change-key-nickname" && !errors.Is(err, mfa.ErrThrottled) {
			if !h.startWebAuthnMFA(w, r, f) {
				return
			}
		}
		f.page.WebAuthnError = f.page.WebAuthnStage != "mfa-webauthn-change-key-nickname"
		if e := h.saveMFAPage(r, f, "mfa-page"); e != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		h.renderWebAuthnMFA(w, r, status, f, f.view.L.T(key))
		return
	}
	if f.page.WebAuthnStage == "mfa-webauthn-change-key-nickname" && screen != "mfa-webauthn-change-key-nickname" {
		if err = h.saveMFAPage(r, f, "mfa-page"); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		http.Redirect(w, r, mfaURL(f, mfaPath(f)), 303)
		return
	}
	f.page.Proven = true
	if !f.pending.Requirement.Enroll {
		f.page.Remember = f.page.OtherRemember || f.pending.Requirement.AllowRemember && r.PostForm.Get("remember") == "yes"
	}
	if recovery != "" {
		f.page.RecoveryPending = true
		if err = h.saveMFAPage(r, f, "mfa-page"); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		h.renderMFA(w, r, 200, f, recovery, "")
		return
	}
	if f.pending.Requirement.Enroll {
		f.page.WebAuthnStage = "mfa-webauthn-enrollment-success"
		if err = h.saveMFAPage(r, f, "mfa-page"); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		http.Redirect(w, r, mfaURL(f, mfaPath(f)), 303)
		return
	}
	h.finishMFA(w, r, f)
}
