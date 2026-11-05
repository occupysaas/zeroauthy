package login

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

const hostedPasskeyLifetime = 5 * time.Minute
const passkeyFailureKey = i18n.KeyPasskeyAuthenticationFailed

func passkeyBinding(f *flow, rpID, origin string) passkey.Binding {
	return passkey.Binding{Purpose: passkey.PasskeyLogin, RPID: rpID, Origins: []string{origin}, TxnID: f.txn.ID, CookieHash: f.txn.CookieHash, ClientID: f.txn.ClientID, Realm: f.conn.Name, Organization: f.txn.Params[store.TxnParamOrgID]}
}
func (h *Handlers) preparePasskey(r *http.Request, f *flow, data *ui.LoginStageData) error {
	if h.Passkeys == nil || f.conn == nil {
		return nil
	}
	p, rp, effective, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, f.conn)
	if err != nil {
		return err
	}
	if !effective {
		return nil
	}
	issued, err := h.Passkeys.Issue(r.Context(), f.res.Tenant.ID, passkeyBinding(f, rp.RPID, rp.Origin), hostedPasskeyLifetime)
	if err != nil {
		return err
	}
	options, err := h.Passkeys.RequestOptions(rp.RPID, issued.Challenge, hostedPasskeyLifetime).JSON()
	if err != nil {
		return err
	}
	data.Passkey = &ui.WebAuthnData{ChallengeID: issued.ID, PublicKey: json.RawMessage(options), Mediation: p.ChallengeUI}
	return nil
}

// webAuthnErrorName is an allowlist, never text supplied by the browser.
func webAuthnErrorName(name string) string {
	switch name {
	case "NotAllowedError", "InvalidStateError", "NotSupportedError", "SecurityError", "AbortError", "ConstraintError", "UnknownError":
		return name
	}
	return "UnknownError"
}
func (h *Handlers) passkeyRetry(w http.ResponseWriter, r *http.Request, f *flow, status int, key string) {
	// A replay loser may outlive the winning authorization's transaction. Give
	// every retry its own bound transaction, copying only trusted server state.
	// Its deadline never extends the original authorization's lifetime.
	token := secrets.RandomString(43)
	next := *f.txn
	next.ID, next.CSRFToken = secrets.RandomString(24), secrets.RandomString(32)
	next.CookieHash = secrets.HashToken(token)
	next.Params = maps.Clone(f.txn.Params)
	next.HostedState = f.txn.HostedState.Clone()
	next.HostedState.Step, next.HostedState.Revision = "identifier", 0
	if !h.now().Before(next.ExpiresAt) {
		h.fail(w, r, errTxn, f)
		return
	}
	if err := h.Store.AuthTransactions().Create(r.Context(), &next); err != nil {
		h.fail(w, r, err, f)
		return
	}
	cookiePath := next.Params["za_cookie_path"]
	if cookiePath == "" {
		cookiePath = "/u"
	}
	http.SetCookie(w, &http.Cookie{Name: authz.TxnCookiePrefix + f.txn.ID, Value: "", Path: cookiePath, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: authz.TxnCookiePrefix + next.ID, Value: token, Path: cookiePath, Expires: next.ExpiresAt, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	fresh := *f
	fresh.txn = &next
	data := h.stageData(&fresh, "")
	if key != "" {
		data.Error = fresh.view.L.T(key)
	}
	h.renderIdentifier(w, r, status, &fresh, data)
}
func (h *Handlers) passkeyFailure(w http.ResponseWriter, r *http.Request, f *flow, reason string) {
	if reason == "" {
		reason = "UnknownError"
	}
	e := logs.FromRequest(r)
	e.Type = "gd_webauthn_challenge_failed"
	e.TenantID = f.res.Tenant.ID
	e.Details = map[string]any{"first_factor": true, "failure_details": map[string]any{"errorCode": reason}}
	logs.RecordEvent(r.Context(), h.Recorder, e)
	svc := h.protectionService()
	attempt := protection.Attempt{Tenant: f.res.Tenant, Connection: f.conn, IP: httpx.ClientIP(r, h.TrustProxyHeaders), Flow: "passkey-login-failure"}
	// Unknown credentials must spend only the IP budget, without guessing an
	// identity. The failure flow uses the login budget without a user lookup.
	decision, err := svc.Begin(r.Context(), attempt)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if decision.Allowed {
		if err := svc.Finish(r.Context(), decision.Receipt, "failure"); err != nil {
			h.fail(w, r, err, f)
			return
		}
	}
	if err := svc.RecordFailure(r.Context(), h.captchaAttempt(r, f.res, "login"), secrets.RandomString(32)); err != nil {
		h.fail(w, r, err, f)
		return
	}
	h.passkeyRetry(w, r, f, http.StatusUnauthorized, passkeyFailureKey)
}
func (h *Handlers) LoginPasskeyPost(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedPasskeyTxn(w, r)
	if !ok {
		return
	}
	if h.Passkeys == nil {
		h.fail(w, r, errTxn, f)
		return
	}
	// Resolve the transaction's selected connection even when it has just become
	// unavailable. That produces the same generic credential refusal on recheck.
	conn, err := h.connection(r.Context(), f.res.Tenant.ID, f.txn)
	if err != nil {
		if r.PostForm.Get("challenge_id") != "" {
			conns, _, e := h.Store.Connections().List(r.Context(), f.res.Tenant.ID, store.ConnectionFilter{}, store.Page{})
			if e == nil {
				for _, c := range conns {
					if c.Strategy == store.StrategyDatabase && (f.txn.Params["connection"] == "" || c.Name == f.txn.Params["connection"]) {
						conn = c
						break
					}
				}
			}
		}
		if conn == nil {
			h.fail(w, r, err, f)
			return
		}
	}
	f.conn = conn
	h.withFlowEvent(r, f)
	_, rp, _, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, f.conn)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !rp.Valid {
		h.fail(w, r, errTxn, f)
		return
	}
	taken, err := h.Passkeys.Take(r.Context(), f.res.Tenant.ID, r.PostForm.Get("challenge_id"), passkeyBinding(f, rp.RPID, rp.Origin))
	if err != nil {
		h.passkeyFailure(w, r, f, webauthn.Reason(err))
		return
	}
	if f.txn.HostedState.Step != "identifier" {
		h.passkeyFailure(w, r, f, "challenge")
		return
	}
	if !h.guardHostedForm(w, r, f, "login-id", "login-id", func(status int, message string) { h.passkeyRetry(w, r, f, status, passkeyFailureKey) }) {
		return
	}
	if name := r.PostForm.Get("webauthn_error"); name != "" {
		name = webAuthnErrorName(name)
		if name == "NotAllowedError" {
			h.passkeyRetry(w, r, f, http.StatusOK, "")
			return
		}
		h.passkeyFailure(w, r, f, name)
		return
	}
	attemptID := secrets.RandomString(32)
	if err := h.submitCaptcha(r, f.res, &f.view, "login", f.txn.ID, attemptID); err != nil {
		status, key := captchaFailure(err)
		h.passkeyRetry(w, r, f, status, key)
		return
	}
	result, err := h.Passkeys.Login(r.Context(), f.res.Tenant.ID, []byte(r.PostForm.Get("credential")), taken.Challenge, taken.Binding)
	if errors.Is(err, identity.ErrUserBlocked) {
		h.event(r, f, "f", nil)
		h.passkeyRetry(w, r, f, http.StatusForbidden, "login.login.user-blocked")
		return
	}
	if err != nil {
		h.passkeyFailure(w, r, f, webauthn.Reason(err))
		return
	}
	var credentialIdentity struct {
		UserID string `json:"identity_user_id"`
	}
	if err := json.Unmarshal(result.Method.PublicData, &credentialIdentity); err != nil {
		h.passkeyFailure(w, r, f, "key")
		return
	}
	identifier := ""
	for i := range result.User.Identities {
		id := &result.User.Identities[i]
		if id.UserID == credentialIdentity.UserID && id.Connection == f.conn.Name && id.Provider == store.StrategyDatabase {
			identifier = protection.IdentityIdentifier(result.User, id)
			break
		}
	}
	svc := h.protectionService()
	decision, err := svc.Begin(r.Context(), protection.Attempt{Tenant: f.res.Tenant, Connection: f.conn, Identifier: identifier, IP: httpx.ClientIP(r, h.TrustProxyHeaders), Flow: "login"})
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !decision.Allowed {
		h.passkeyRetry(w, r, f, http.StatusTooManyRequests, i18n.KeyTooManyAttempts)
		return
	}
	if err := svc.Finish(r.Context(), decision.Receipt, "success"); err != nil {
		h.fail(w, r, err, f)
		return
	}
	// Taking the challenge prevents its replay; claiming the transaction prevents
	// two separately issued page challenges from creating two sessions.
	next := f.txn.HostedState.Clone()
	next.Step = "authenticating"
	if err := h.transitionHosted(r, f, next); err != nil {
		h.passkeyFailure(w, r, f, "challenge")
		return
	}
	h.completeWithMethods(w, r, f, result.User, store.AuthMethod{Name: "passkey"})
}

// A rejected browser/tenant/transaction binding reveals no credential state.
func (h *Handlers) postedPasskeyTxn(w http.ResponseWriter, r *http.Request) (*flow, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	err := r.ParseForm()
	h.maskRequest(r)
	var f *flow
	if err == nil {
		f, err = h.loadTxn(r, r.PostForm.Get("state"))
	}
	if err == nil && subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(f.txn.CSRFToken)) != 1 {
		err = errTxn
	}
	if err != nil {
		view := ui.Tenant{}
		if f != nil {
			view = f.view
		} else if res, ok := tenant.FromContext(r.Context()); ok {
			view = ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
		}
		ui.RenderError(w, http.StatusUnauthorized, view, view.L.T(passkeyFailureKey))
		return nil, false
	}
	return f, true
}
