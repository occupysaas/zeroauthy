package login

import (
	"context"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/ui"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

func (h *Handlers) enrollmentFlow(w http.ResponseWriter, r *http.Request, post bool) (*flow, *store.LoginSession, string, bool) {
	var f *flow
	var err error
	if post {
		var ok bool
		f, ok = h.postedTxn(w, r)
		if !ok {
			return nil, nil, "", false
		}
	} else {
		f, err = h.loadTxn(r, r.URL.Query().Get("state"))
	}
	if err != nil || f == nil || h.Passkeys == nil {
		h.fail(w, r, errTxn, f)
		return nil, nil, "", false
	}
	sess, err := h.Authz.ActiveSession(r.Context(), r, f.res)
	if err != nil || sess == nil {
		h.fail(w, r, errTxn, f)
		return nil, nil, "", false
	}
	kind, err := h.Authz.PendingPasskeyPrompt(r, f.res, f.txn, sess)
	expected := "/u/passkey-enrollment"
	if kind == "local" {
		expected += "-local"
	}
	if err != nil || r.URL.Path != expected {
		h.fail(w, r, errTxn, f)
		return nil, nil, "", false
	}
	if kind == "local" {
		c, e := r.Cookie(authz.PasskeyDeviceCookie)
		if e != nil || c.Value == "" {
			h.fail(w, r, errTxn, f)
			return nil, nil, "", false
		}
	}
	f.conn, err = h.Store.Connections().GetByName(r.Context(), f.res.Tenant.ID, sess.Connection)
	if err != nil {
		h.fail(w, r, errTxn, f)
		return nil, nil, "", false
	}
	return f, sess, kind, true
}
func enrollmentBinding(f *flow, sess *store.LoginSession, rpID, origin, kind string) passkey.Binding {
	b := passkeyBinding(f, rpID, origin)
	b.UserID = sess.UserID
	b.Purpose = passkey.PasskeyProgressiveRegister
	if kind == "local" {
		b.Purpose = passkey.PasskeyLocalRegister
	}
	return b
}

// PasskeyEnrollmentPage renders only an existing, browser-bound post-MFA prompt.
func (h *Handlers) PasskeyEnrollmentPage(w http.ResponseWriter, r *http.Request) {
	f, sess, kind, ok := h.enrollmentFlow(w, r, false)
	if !ok {
		return
	}
	h.renderEnrollment(w, r, 200, f, sess, kind, "")
}
func (h *Handlers) renderEnrollment(w http.ResponseWriter, r *http.Request, status int, f *flow, sess *store.LoginSession, kind, message string) {
	_, rp, effective, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, f.conn)
	if err != nil || !effective {
		h.fail(w, r, errTxn, f)
		return
	}
	u, err := h.Store.Users().Get(r.Context(), f.res.Tenant.ID, sess.UserID)
	if err != nil || u.Blocked {
		h.fail(w, r, errTxn, f)
		return
	}
	stage := "passkey-enrollment"
	enrollKind := passkey.Progressive
	if kind == "local" {
		stage += "-local"
		enrollKind = passkey.Local
	}
	if !h.captchaPage(w, r, f, "login") {
		return
	}
	if !h.prepareHostedForm(w, r, f, "passkeys", stage) {
		return
	}
	issued, err := h.Passkeys.Issue(r.Context(), f.res.Tenant.ID, enrollmentBinding(f, sess, rp.RPID, rp.Origin, kind), hostedPasskeyLifetime)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	display := passkey.UserDisplay{}
	identityID := ""
	for _, id := range u.Identities {
		if id.Connection == f.conn.Name && id.Provider == store.StrategyDatabase {
			identityID = id.UserID
			break
		}
	}
	if identityID == "" {
		h.fail(w, r, errTxn, f)
		return
	}
	opts, err := h.Passkeys.CreationOptions(r.Context(), f.res.Tenant.ID, u, display, rp.RPID, enrollKind, issued.Challenge, issued.UserHandle, hostedPasskeyLifetime)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	raw, err := opts.JSON()
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	d := ui.SignupData{State: f.txn.ID, CSRF: f.txn.CSRFToken, Error: message, HostedRevision: hostedRevision(f), RedirectURI: f.txn.Params["redirect_uri"], EnrollmentKind: kind, EnrollmentAction: "/u/" + stage, Passkey: &ui.WebAuthnData{Operation: "create", ChallengeID: issued.ID, PublicKey: raw, Mediation: "button", Enrollment: kind}}
	ui.RenderSignupStage(w, status, stage, f.view, d)
}

// PasskeyEnrollmentPost answers the prompt once, optionally adding a credential.
func (h *Handlers) PasskeyEnrollmentPost(w http.ResponseWriter, r *http.Request) {
	f, sess, kind, ok := h.enrollmentFlow(w, r, true)
	if !ok {
		return
	}
	stage := "passkey-enrollment"
	if kind == "local" {
		stage += "-local"
	}
	retry := func(status int, message string) { h.renderEnrollment(w, r, status, f, sess, kind, message) }
	if !h.guardHostedForm(w, r, f, "passkeys", stage, retry) {
		return
	}
	var enroll func(context.Context, store.Store) error
	if r.PostForm.Get("skip") != "1" {
		_, rp, effective, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, f.conn)
		if err != nil || !effective {
			h.fail(w, r, errTxn, f)
			return
		}
		taken, err := h.Passkeys.Take(r.Context(), f.res.Tenant.ID, r.PostForm.Get("challenge_id"), enrollmentBinding(f, sess, rp.RPID, rp.Origin, kind))
		if err != nil || r.PostForm.Get("webauthn_error") != "" {
			h.enrollmentFailure(w, r, f, sess, kind, webauthn.Reason(err))
			return
		}
		if err := h.submitCaptcha(r, f.res, &f.view, "login", f.txn.ID, secrets.RandomString(32)); err != nil {
			status, key := captchaFailure(err)
			retry(status, f.view.L.T(key))
			return
		}
		enroll = func(ctx context.Context, tx store.Store) error {
			u, err := tx.Users().Get(ctx, f.res.Tenant.ID, sess.UserID)
			if err != nil {
				return err
			}
			identityID := ""
			for _, id := range u.Identities {
				if id.Provider == store.StrategyDatabase && id.Connection == f.conn.Name {
					identityID = id.UserID
					break
				}
			}
			svc := *h.Passkeys
			svc.Store = tx
			_, err = svc.Enroll(ctx, f.res.Tenant.ID, u, identityID, []byte(r.PostForm.Get("credential")), taken, r.UserAgent())
			return err
		}
	}
	err := h.Authz.CompletePasskeyPrompt(w, r, f.res, f.txn, sess, r.PostForm.Get("skip") == "1" && r.PostForm.Get("snooze") == "1", enroll)
	if err != nil {
		if enroll != nil {
			h.enrollmentFailure(w, r, f, sess, kind, webauthn.Reason(err))
		} else {
			h.fail(w, r, errTxn, f)
		}
		return
	}
	if enroll != nil {
		e := logs.FromRequest(r)
		e.TenantID = f.res.Tenant.ID
		e.UserID = sess.UserID
		e.Type = "gd_enrollment_complete"
		e.Details = map[string]any{"authenticator": map[string]any{"type": "passkey"}}
		logs.RecordEvent(r.Context(), h.Recorder, e)
	}
}
func (h *Handlers) enrollmentFailure(w http.ResponseWriter, r *http.Request, f *flow, sess *store.LoginSession, kind, reason string) {
	if reason == "" {
		reason = "UnknownError"
	}
	e := logs.FromRequest(r)
	e.TenantID = f.res.Tenant.ID
	e.UserID = sess.UserID
	e.Type = "gd_webauthn_enrollment_failed"
	e.Details = map[string]any{"authentication_methods": []string{"passkey"}, "failure_details": map[string]any{"errorCode": reason}}
	logs.RecordEvent(r.Context(), h.Recorder, e)
	if _, err := h.Authz.PendingPasskeyPrompt(r, f.res, f.txn, sess); err != nil {
		h.fail(w, r, errTxn, f)
		return
	}
	if err := h.protectionService().RecordFailure(r.Context(), h.captchaAttempt(r, f.res, "login"), secrets.RandomString(32)); err != nil {
		h.fail(w, r, err, f)
		return
	}
	h.renderEnrollment(w, r, 400, f, sess, kind, f.view.L.T(i18n.KeyPasskeyEnrollmentFailure))
}
