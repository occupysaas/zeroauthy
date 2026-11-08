package login

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/ui"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

const signupIDStep = "signup-id"
const signupEnrollStep = "passkey-enrollment"
const signupPasswordStep = "signup-password"
const signupFailureKey = i18n.KeyPasskeyEnrollmentFailure

// signupProfileFields are the hosted signup identifiers a passkey signup draft
// carries. Hosted signup takes no root profile attributes (name, picture and
// the like) from the form, as before passkeys; extra fields reach the user
// only through the ulp- prompt fields.
var signupProfileFields = []string{"email", "username", "phone_number"}

type signupDraft struct {
	Purpose                               string
	Transaction, CookieHash, ConnectionID string
	Profile                               map[string]string
	User                                  store.User
}

func signupPrompt(f *flow) string {
	if f.txn.HostedState.Step == signupPasswordStep {
		return signupPasswordStep
	}
	return "signup"
}
func signupLocation(f *flow, stage string) string {
	return "/u/signup/" + stage + "?" + url.Values{"state": {f.txn.ID}}.Encode()
}
func (h *Handlers) splitSignup(r *http.Request, f *flow) (bool, error) {
	if h.Passkeys == nil || f.txn.Params[orglogin.InvitationIDParam] != "" {
		return false, nil
	}
	policy, rp, effective, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, f.conn)
	if err == nil && policy.Effective && !rp.Valid {
		return false, errTxn
	}
	return effective, err
}
func (h *Handlers) signupAllowed(w http.ResponseWriter, r *http.Request, f *flow) bool {
	if f.conn.DisableSignup || !organizationSignupAllowed(f) {
		ui.RenderError(w, 403, f.view, f.view.L.T(i18n.KeyErrSignupDisabled))
		return false
	}
	return true
}

// signupStagePage returns whether it owns the request, including refused steps.
func (h *Handlers) signupStagePage(w http.ResponseWriter, r *http.Request, f *flow) bool {
	effective, err := h.splitSignup(r, f)
	if err != nil {
		h.fail(w, r, err, f)
		return true
	}
	staged := strings.HasPrefix(f.txn.HostedState.Step, "signup-") || f.txn.HostedState.Step == signupEnrollStep
	if !effective && !staged && r.URL.Path == "/u/signup" {
		return false
	}
	if !h.signupAllowed(w, r, f) {
		return true
	}
	if !effective {
		h.fail(w, r, errTxn, f)
		return true
	}
	if r.URL.Path == "/u/signup" {
		if f.txn.HostedState.Step == "signup-authenticating" {
			h.fail(w, r, errTxn, f)
			return true
		}
		next := f.txn.HostedState.Clone()
		next.Step = signupIDStep
		next.Identifier = ""
		next.ConnectionID = f.conn.ID
		if err := h.transitionHosted(r, f, next); err != nil {
			h.fail(w, r, errTxn, f)
			return true
		}
		http.Redirect(w, r, signupLocation(f, "identifier"), 303)
		return true
	}
	switch r.URL.Path {
	case "/u/signup/identifier":
		if f.txn.HostedState.Step != signupIDStep {
			h.fail(w, r, errTxn, f)
			return true
		}
		h.renderSignupID(w, r, 200, f, "")
	case "/u/signup/passkey":
		if f.txn.HostedState.Step != signupEnrollStep {
			h.fail(w, r, errTxn, f)
			return true
		}
		h.renderSignupEnrollment(w, r, 200, f, "")
	case "/u/signup/password":
		if f.txn.HostedState.Step != signupPasswordStep {
			h.fail(w, r, errTxn, f)
			return true
		}
		draft, err := h.loadSignupDraft(r, f)
		if err != nil {
			h.fail(w, r, errTxn, f)
			return true
		}
		h.applySignupProfile(r, draft)
		if !h.captchaPage(w, r, f, "signup") {
			return true
		}
		h.renderSignup(w, r, 200, f, h.signupData(f, draft.Profile))
	default:
		h.fail(w, r, errTxn, f)
	}
	return true
}
func (h *Handlers) signupData(f *flow, p map[string]string) ui.SignupData {
	return ui.SignupData{State: f.txn.ID, CSRF: f.txn.CSRFToken, Email: p["email"], Username: p["username"], PhoneNumber: p["phone_number"], RequiresUsername: f.conn.RequiresUsername, PhoneEnabled: store.PhoneIdentifierActive(f.conn) && store.PhoneSignupStatus(f.conn) != "not_allowed", LoginURL: "/u/login?" + url.Values{"state": {f.txn.ID}}.Encode(), RedirectURI: f.txn.Params["redirect_uri"], Profile: p}
}
func (h *Handlers) renderSignupID(w http.ResponseWriter, r *http.Request, status int, f *flow, message string) {
	if !h.captchaPage(w, r, f, "signup") || !h.prepareHostedForm(w, r, f, signupIDStep, signupIDStep) {
		return
	}
	p := map[string]string{}
	for _, key := range signupProfileFields {
		p[key] = r.PostForm.Get(key)
	}
	if p["email"] == "" {
		p["email"] = f.txn.Params["login_hint"]
	}
	data := h.signupData(f, p)
	data.Error = message
	data.HostedRevision = hostedRevision(f)
	data.EmailCodeEnabled = h.codeTemplateEnabled(r.Context(), f.res.Tenant.ID, "verify_email_by_code")
	ui.RenderSignupStage(w, status, signupIDStep, f.view, data)
}
func (h *Handlers) loadSignupDraft(r *http.Request, f *flow) (*signupDraft, error) {
	state := f.txn.HostedState
	if state.ConnectionID != f.conn.ID || !strings.HasPrefix(state.Identifier, "signup-draft:") {
		return nil, errTxn
	}
	row, err := h.Store.MFA().GetChallenge(r.Context(), f.res.Tenant.ID, state.Identifier, h.now())
	if err != nil {
		return nil, errTxn
	}
	logs.AddCredentials(r.Context(), string(row.Binding))
	var d signupDraft
	if row.Kind != "webauthn" || json.Unmarshal(row.Binding, &d) != nil || d.Purpose != "signup-draft" || d.Transaction != f.txn.ID || d.CookieHash != f.txn.CookieHash || d.ConnectionID != f.conn.ID || d.User.TenantID != f.res.Tenant.ID || !row.ExpiresAt.Equal(f.txn.ExpiresAt) {
		return nil, errTxn
	}
	// Configuration can change while the browser holds registration options.
	// Revalidate the saved profile and required proofs against the current policy.
	_, _, err = identity.CheckSignupProfile(f.conn, identity.SignupInput{Email: d.User.Email, Username: d.User.Username, PhoneNumber: d.User.PhoneNumber, GivenName: d.Profile["given_name"], FamilyName: d.Profile["family_name"], Name: d.Profile["name"], Nickname: d.Profile["nickname"], Picture: d.Profile["picture"]})
	if err != nil {
		return nil, errTxn
	}
	if d.User.PhoneNumber != "" && store.PhoneSignupVerification(f.conn) && !d.User.PhoneVerified {
		return nil, errTxn
	}
	if d.User.Email != "" && h.codeTemplateEnabled(r.Context(), f.res.Tenant.ID, "verify_email_by_code") && !d.User.EmailVerified {
		return nil, errTxn
	}
	return &d, nil
}
func (h *Handlers) applySignupProfile(r *http.Request, d *signupDraft) {
	if r.PostForm == nil {
		r.PostForm = url.Values{}
	}
	for _, key := range signupProfileFields {
		r.PostForm.Set(key, d.Profile[key])
	}
}
func (h *Handlers) signupPosted(w http.ResponseWriter, r *http.Request, step string) (*flow, bool) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return nil, false
	}
	h.withFlowEvent(r, f)
	effective, err := h.splitSignup(r, f)
	if err != nil {
		h.fail(w, r, err, f)
		return nil, false
	}
	if !h.signupAllowed(w, r, f) {
		return nil, false
	}
	if !effective || f.txn.HostedState.Step != step || f.txn.HostedState.ConnectionID != f.conn.ID {
		h.fail(w, r, errTxn, f)
		return nil, false
	}
	return f, true
}

// SignupIdentifierPost spends the registration budget before any existence lookup.
func (h *Handlers) SignupIdentifierPost(w http.ResponseWriter, r *http.Request) {
	f, ok := h.signupPosted(w, r, signupIDStep)
	if !ok {
		return
	}
	redisplay := func(status int, message string) { h.renderSignupID(w, r, status, f, message) }
	if !h.guardHostedForm(w, r, f, signupIDStep, signupIDStep, redisplay) {
		return
	}
	in := identity.SignupInput{Email: r.PostForm.Get("email"), Username: r.PostForm.Get("username"), PhoneNumber: r.PostForm.Get("phone_number")}
	email, username, err := identity.CheckSignupProfile(f.conn, in)
	if err != nil {
		var pe *identity.PolicyError
		if errors.As(err, &pe) {
			redisplay(400, policyMessage(f.view.L, pe))
		} else {
			h.fail(w, r, err, f)
		}
		return
	}
	if in.PhoneNumber != "" {
		in.PhoneNumber, _ = phone.NormalizeE164(in.PhoneNumber, "")
		r.PostForm.Set("phone_number", in.PhoneNumber)
	}
	svc := h.protectionService()
	dec, err := svc.Begin(r.Context(), protection.Attempt{Tenant: f.res.Tenant, Connection: f.conn, Identifier: email, IP: httpx.ClientIP(r, h.TrustProxyHeaders), Flow: "signup"})
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !dec.Allowed {
		redisplay(429, f.view.L.T(i18n.KeyTooManyAttempts))
		return
	}
	attemptID := secrets.RandomString(32)
	if err := h.submitCaptcha(r, f.res, &f.view, "signup", f.txn.ID, attemptID); err != nil {
		if e := svc.Finish(r.Context(), dec.Receipt, "refund"); e != nil {
			h.fail(w, r, e, f)
			return
		}
		status, key := captchaFailure(err)
		redisplay(status, f.view.L.T(key))
		return
	}
	if err := svc.Finish(r.Context(), dec.Receipt, "failure"); err != nil {
		h.fail(w, r, err, f)
		return
	}
	for _, value := range []string{email, username, in.PhoneNumber} {
		if value == "" {
			continue
		}
		_, err := h.Store.Users().FindByLogin(r.Context(), f.res.Tenant.ID, f.conn.Name, value)
		if err == nil {
			if riskErr := h.recordFailure(r, f.res, "signup", attemptID, identity.ErrUserExists); riskErr != nil {
				h.fail(w, r, riskErr, f)
				return
			}
			redisplay(400, f.view.L.T(i18n.KeyEmailInUse))
			return
		}
		if !errors.Is(err, store.ErrNotFound) {
			h.fail(w, r, err, f)
			return
		}
	}
	// The same identifier proofs as password signup must complete before options.
	verifiedEmail, verifiedPhone, ready := h.signupIdentifierProofs(w, r, f, email, in.PhoneNumber, redisplay)
	if !ready {
		return
	}
	id := secrets.RandomHex(12)
	name, nickname := identity.DefaultNames(in.Name, in.Nickname, email, username)
	picture := in.Picture
	if picture == "" {
		picture = identity.DefaultPicture(email)
	}
	d := signupDraft{Purpose: "signup-draft", Transaction: f.txn.ID, CookieHash: f.txn.CookieHash, ConnectionID: f.conn.ID, Profile: map[string]string{}, User: store.User{TenantID: f.res.Tenant.ID, UserID: "auth0|" + id, Email: email, Username: username, PhoneNumber: in.PhoneNumber, EmailVerified: verifiedEmail, PhoneVerified: verifiedPhone, Name: name, Nickname: nickname, GivenName: in.GivenName, FamilyName: in.FamilyName, Picture: picture, CreatedAt: h.now(), UpdatedAt: h.now(), Identities: []store.Identity{{Provider: store.StrategyDatabase, Connection: f.conn.Name, UserID: id}}}}
	for _, key := range signupProfileFields {
		d.Profile[key] = r.PostForm.Get(key)
	}
	d.Profile["email"] = email
	d.Profile["username"] = username
	raw, err := json.Marshal(d)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	logs.AddCredentials(r.Context(), string(raw))
	draftID := "signup-draft:" + secrets.RandomString(32)
	if err := h.Store.MFA().CreateChallenge(r.Context(), &store.MFAChallenge{TenantID: f.res.Tenant.ID, ID: draftID, Kind: "webauthn", Binding: raw, ExpiresAt: f.txn.ExpiresAt}); err != nil {
		h.fail(w, r, err, f)
		return
	}
	credit, err := h.newSignupAdmission(r, f, draftID)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if err := h.Store.MFA().CreateChallenge(r.Context(), credit); err != nil {
		h.fail(w, r, err, f)
		return
	}
	next := f.txn.HostedState.Clone()
	next.Step = signupEnrollStep
	next.Identifier = draftID
	if err := h.transitionHosted(r, f, next); err != nil {
		h.fail(w, r, errTxn, f)
		return
	}
	http.Redirect(w, r, signupLocation(f, "passkey"), 303)
}
func signupRegistrationBinding(f *flow, d *signupDraft, rpID, origin string) passkey.Binding {
	b := passkeyBinding(f, rpID, origin)
	b.Purpose = passkey.PasskeyRegister
	b.UserID = d.User.UserID
	return b
}
func (h *Handlers) renderSignupEnrollment(w http.ResponseWriter, r *http.Request, status int, f *flow, message string) {
	d, err := h.loadSignupDraft(r, f)
	if err != nil {
		h.fail(w, r, errTxn, f)
		return
	}
	_, rp, effective, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, f.conn)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !effective {
		h.fail(w, r, errTxn, f)
		return
	}
	if !h.captchaPage(w, r, f, "signup") {
		return
	}
	if !h.prepareHostedForm(w, r, f, "passkeys", signupEnrollStep) {
		return
	}
	issued, err := h.Passkeys.Issue(r.Context(), f.res.Tenant.ID, signupRegistrationBinding(f, d, rp.RPID, rp.Origin), hostedPasskeyLifetime)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	opts, err := h.Passkeys.CreationOptions(r.Context(), f.res.Tenant.ID, &d.User, passkey.UserDisplay{}, rp.RPID, passkey.Signup, issued.Challenge, issued.UserHandle, hostedPasskeyLifetime)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	raw, err := opts.JSON()
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	data := h.signupData(f, d.Profile)
	data.Error = message
	data.HostedRevision = hostedRevision(f)
	data.Passkey = &ui.WebAuthnData{ChallengeID: issued.ID, PublicKey: raw, Mediation: "button", Operation: "create"}
	ui.RenderSignupStage(w, status, signupEnrollStep, f.view, data)
}
func (h *Handlers) signupEnrollmentFailure(w http.ResponseWriter, r *http.Request, f *flow, reason string) {
	if reason == "" {
		reason = "UnknownError"
	}
	e := logs.FromRequest(r)
	e.Type = "gd_webauthn_enrollment_failed"
	e.TenantID = f.res.Tenant.ID
	e.Details = map[string]any{"first_factor": true, "failure_details": map[string]any{"errorCode": reason}}
	logs.RecordEvent(r.Context(), h.Recorder, e)
	if err := h.protectionService().RecordFailure(r.Context(), h.captchaAttempt(r, f.res, "signup"), secrets.RandomString(32)); err != nil {
		h.fail(w, r, err, f)
		return
	}
	h.renderSignupEnrollment(w, r, 400, f, f.view.L.T(signupFailureKey))
}
func (h *Handlers) SignupPasskeyPost(w http.ResponseWriter, r *http.Request) {
	f, ok := h.signupPosted(w, r, signupEnrollStep)
	if !ok {
		return
	}
	d, err := h.loadSignupDraft(r, f)
	if err != nil {
		h.fail(w, r, errTxn, f)
		return
	}
	_, rp, _, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, f.conn)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	taken, err := h.Passkeys.Take(r.Context(), f.res.Tenant.ID, r.PostForm.Get("challenge_id"), signupRegistrationBinding(f, d, rp.RPID, rp.Origin))
	if err != nil {
		h.signupEnrollmentFailure(w, r, f, webauthn.Reason(err))
		return
	}
	if !h.guardHostedForm(w, r, f, "passkeys", signupEnrollStep, func(status int, message string) { h.renderSignupEnrollment(w, r, status, f, message) }) {
		return
	}
	if name := r.PostForm.Get("webauthn_error"); name != "" {
		h.signupEnrollmentFailure(w, r, f, webAuthnErrorName(name))
		return
	}
	if err := h.submitCaptcha(r, f.res, &f.view, "signup", f.txn.ID, secrets.RandomString(32)); err != nil {
		status, key := captchaFailure(err)
		h.renderSignupEnrollment(w, r, status, f, f.view.L.T(key))
		return
	}
	credit, err := h.peekSignupAdmission(r, f)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	admitted, err := h.consumeSignupAdmission(r, f, credit)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	svc := h.protectionService()
	dec, err := svc.Begin(r.Context(), protection.Attempt{Tenant: f.res.Tenant, Connection: f.conn, Identifier: d.User.Email, IP: httpx.ClientIP(r, h.TrustProxyHeaders), Flow: "signup", RegistrationAdmitted: admitted})
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !dec.Allowed {
		h.renderSignupEnrollment(w, r, 429, f, f.view.L.T(i18n.KeyTooManyAttempts))
		return
	}
	if err := svc.Finish(r.Context(), dec.Receipt, "failure"); err != nil {
		h.fail(w, r, err, f)
		return
	}
	h.applySignupProfile(r, d)
	callbacks, ok := h.signupCallbacks(w, r, f)
	if !ok {
		return
	}
	// Claim before invoking Actions, so concurrent page challenges cannot run
	// pre-registration effects or create two users for this transaction.
	next := f.txn.HostedState.Clone()
	next.Step = "signup-authenticating"
	if err := h.transitionHosted(r, f, next); err != nil {
		h.fail(w, r, errTxn, f)
		return
	}
	var user *store.User
	err = h.Database.CreateWithCredential(r.Context(), f.conn, callbacks, &d.User, func(ctx context.Context, tx store.Store, u *store.User) error {
		// Recheck current organization policy through the existing commit callback;
		// service connection checks and signup enablement run against this transaction.
		current, err := tx.Connections().Get(ctx, f.res.Tenant.ID, f.conn.ID)
		if err != nil {
			return err
		}
		if _, _, err := identity.CheckSignupProfile(current, identity.SignupInput{Email: u.Email, Username: u.Username, PhoneNumber: u.PhoneNumber, GivenName: d.Profile["given_name"], FamilyName: d.Profile["family_name"], Name: d.Profile["name"], Nickname: d.Profile["nickname"], Picture: d.Profile["picture"]}); err != nil {
			return identity.ErrSignupDisabled
		}
		if u.PhoneNumber != "" && store.PhoneSignupVerification(current) && !u.PhoneVerified {
			return identity.ErrSignupDisabled
		}
		bound := *h.Passkeys
		bound.Store = tx
		user, _, err = bound.Signup(ctx, f.res.Tenant.ID, u, []byte(r.PostForm.Get("credential")), taken, r.UserAgent())
		return err
	})
	if err != nil {
		next := f.txn.HostedState.Clone()
		next.Step = signupEnrollStep
		if e := h.transitionHosted(r, f, next); e != nil {
			h.fail(w, r, errTxn, f)
			return
		}
		h.event(r, f, "fs", nil)
		var denied *identity.ErrSignupDenied
		var failed *identity.ErrSignupActionFailed
		switch {
		case errors.As(err, &denied):
			h.renderSignupEnrollment(w, r, 400, f, denied.Description)
		case errors.As(err, &failed):
			ui.RenderErrorReference(w, 400, f.view, f.view.L.T(i18n.KeyErrServer), failed.ExecutionID)
		case errors.Is(err, identity.ErrUserExists):
			// A storage uniqueness conflict can belong to the credential rather than
			// the identifier. Only a canonical identifier race has a user-exists answer.
			exists := false
			for _, value := range []string{d.User.Email, d.User.Username, d.User.PhoneNumber} {
				if value == "" {
					continue
				}
				_, lookupErr := h.Store.Users().FindByLogin(r.Context(), f.res.Tenant.ID, f.conn.Name, value)
				if lookupErr == nil {
					exists = true
					break
				}
				if !errors.Is(lookupErr, store.ErrNotFound) {
					h.fail(w, r, lookupErr, f)
					return
				}
			}
			if exists {
				h.renderSignupEnrollment(w, r, 400, f, f.view.L.T(i18n.KeyEmailInUse))
			} else {
				h.signupEnrollmentFailure(w, r, f, "key")
			}

		case errors.Is(err, identity.ErrSignupDisabled):
			ui.RenderError(w, 403, f.view, f.view.L.T(i18n.KeyErrSignupDisabled))
		case errors.Is(err, passkey.ErrCeremony):
			h.signupEnrollmentFailure(w, r, f, webauthn.Reason(err))
		default:
			h.fail(w, r, err, f)
		}
		return
	}
	h.event(r, f, "ss", user, "passkey")
	h.sendSignupVerification(f, user)
	h.completeWithMethods(w, r, f, user, store.AuthMethod{Name: "passkey"})
}

// signupPasswordGate admits only the plain fallback form and restores the
// immutable server profile before entering the existing password signup rules.
func (h *Handlers) signupPasswordGate(w http.ResponseWriter, r *http.Request, f *flow) bool {
	effective, err := h.splitSignup(r, f)
	if err != nil {
		h.fail(w, r, err, f)
		return false
	}
	staged := strings.HasPrefix(f.txn.HostedState.Step, "signup-") || f.txn.HostedState.Step == signupEnrollStep
	if !effective && !staged && r.URL.Path == "/u/signup" {
		return true
	}
	if !h.signupAllowed(w, r, f) {
		return false
	}
	if !effective || r.URL.Path != "/u/signup/password" {
		h.fail(w, r, errTxn, f)
		return false
	}
	d, err := h.loadSignupDraft(r, f)
	if err != nil {
		h.fail(w, r, errTxn, f)
		return false
	}
	if f.txn.HostedState.Step == signupEnrollStep {
		// A password value on the selection step cannot skip the password form.
		if r.PostForm.Get("password") != "" {
			h.fail(w, r, errTxn, f)
			return false
		}
		if !h.guardHostedForm(w, r, f, "passkeys", signupEnrollStep, func(status int, message string) { h.renderSignupEnrollment(w, r, status, f, message) }) {
			return false
		}
		next := f.txn.HostedState.Clone()
		next.Step = signupPasswordStep
		if err := h.transitionHosted(r, f, next); err != nil {
			h.fail(w, r, errTxn, f)
			return false
		}
		http.Redirect(w, r, signupLocation(f, "password"), 303)
		return false
	}
	if f.txn.HostedState.Step != signupPasswordStep {
		h.fail(w, r, errTxn, f)
		return false
	}
	h.applySignupProfile(r, d)
	return true
}
func (h *Handlers) signupIdentifierProofs(w http.ResponseWriter, r *http.Request, f *flow, email, phone string, redisplay func(int, string)) (bool, bool, bool) {
	type proof struct{ identifier, field string }
	var proofs []proof
	if email != "" && h.codeTemplateEnabled(r.Context(), f.res.Tenant.ID, "verify_email_by_code") {
		proofs = append(proofs, proof{email, "email_code"})
	}
	if store.PhoneIdentifierActive(f.conn) && store.PhoneSignupVerification(f.conn) && phone != "" {
		proofs = append(proofs, proof{phone, "phone_code"})
	}
	missing := false
	for _, p := range proofs {
		if r.PostForm.Get(p.field) == "" {
			missing = true
			if err := h.sendIdentifierCode(r.Context(), f.res.Tenant.ID, f.conn.ID, p.identifier, "signup", ""); err != nil {
				h.fail(w, r, err, f)
				return false, false, false
			}
		}
	}
	if missing {
		redisplay(200, f.view.L.T(i18n.KeyPhoneEnterCodes))
		return false, false, false
	}
	emailOK, phoneOK := false, false
	for _, p := range proofs {
		if _, err := h.consumeIdentifierCode(r.Context(), f.res.Tenant.ID, f.conn.ID, p.identifier, "signup", r.PostForm.Get(p.field)); err != nil {
			redisplay(400, f.view.L.T(i18n.KeyPhoneInvalidCode))
			return false, false, false
		}
		if p.field == "email_code" {
			emailOK = true
		} else {
			phoneOK = true
		}
	}
	return emailOK, phoneOK, true
}

// A draft's admission is distinct from its immutable profile and from ceremony
// challenges. Only the conditional delete winner can spend the prepaid attempt.
type signupAdmission struct{ Purpose, Transaction, CookieHash, DraftID, ConnectionID, IP string }

func signupAdmissionID(draftID string) string {
	return "signup-admission:" + secrets.HashToken(draftID)
}
func (h *Handlers) newSignupAdmission(r *http.Request, f *flow, draftID string) (*store.MFAChallenge, error) {
	binding := signupAdmission{Purpose: "signup-admission", Transaction: f.txn.ID, CookieHash: f.txn.CookieHash, DraftID: draftID, ConnectionID: f.conn.ID, IP: httpx.ClientIP(r, h.TrustProxyHeaders)}
	raw, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	logs.AddCredentials(r.Context(), string(raw))
	return &store.MFAChallenge{TenantID: f.res.Tenant.ID, ID: signupAdmissionID(draftID), Kind: "webauthn", Binding: raw, ExpiresAt: f.txn.ExpiresAt}, nil
}
func (h *Handlers) peekSignupAdmission(r *http.Request, f *flow) (*store.MFAChallenge, error) {
	expected, err := h.newSignupAdmission(r, f, f.txn.HostedState.Identifier)
	if err != nil {
		return nil, err
	}
	row, err := h.Store.MFA().GetChallenge(r.Context(), f.res.Tenant.ID, expected.ID, h.now())
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	logs.AddCredentials(r.Context(), string(row.Binding))
	var got, want signupAdmission
	if row.Kind != "webauthn" || !row.ExpiresAt.Equal(expected.ExpiresAt) || json.Unmarshal(row.Binding, &got) != nil || json.Unmarshal(expected.Binding, &want) != nil {
		return nil, errTxn
	}
	ip := got.IP
	got.IP = want.IP
	if got != want {
		return nil, errTxn
	}
	if ip != want.IP {
		// Changing networks cannot transfer the original IP's admission. Discard
		// that credit; the caller must reserve the new IP's current budget.
		_, err := h.consumeSignupAdmission(r, f, row)
		return nil, err
	}
	return row, nil
}
func (h *Handlers) consumeSignupAdmission(r *http.Request, f *flow, row *store.MFAChallenge) (bool, error) {
	if row == nil {
		return false, nil
	}
	err := h.Store.MFA().ConsumeChallenge(r.Context(), f.res.Tenant.ID, row.ID, h.now())
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrPrecondition) {
		return false, nil
	}
	return err == nil, err
}
