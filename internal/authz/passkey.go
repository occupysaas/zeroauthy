package authz

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const StagePasskeyPrompt = "passkey-prompt"
const PasskeyPromptParam = "za_pk_prompt"
const PasskeyDeviceCookie = "za_pk_device"

type passkeyLoginKey struct{}
type passkeyAnsweredKey struct{}

// PasskeyLoginHint contains verified assertion metadata plus the browser's
// capability report. It is carried through required MFA, never sent to Actions.
type PasskeyLoginHint struct {
	Fresh      bool
	Attachment string
	Platform   bool
}

// WithPasskeyLogin records only the attachment from a verified assertion.
func WithPasskeyLogin(ctx context.Context, attachment string, platform bool) context.Context {
	return context.WithValue(ctx, passkeyLoginKey{}, PasskeyLoginHint{Fresh: true, Attachment: attachment, Platform: platform})
}

type passkeyPending struct {
	GuardianVersion                int
	CustomizeMFA                   bool
	Kind                           string
	At                             time.Time
	SessionID, UserID, RPID, Scope string
	Hint                           PasskeyLoginHint
	MFAAt                          time.Time
	Effects                        actions.Effects `json:"-"`
}

// PasskeyPrompt rechecks a durable post-MFA enrollment decision. Page access
// cannot create one. The request layer separately verifies its browser cookie.
func (h *Handlers) PasskeyPrompt(ctx context.Context, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession) (string, error) {
	p, err := h.passkeyPending(ctx, res, txn, sess)
	if err != nil {
		return "", err
	}
	return p.Kind, nil
}

// PendingPasskeyPrompt additionally checks the current browser and MFA proof.
func (h *Handlers) PendingPasskeyPrompt(r *http.Request, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession) (string, error) {
	p, err := h.passkeyPending(r.Context(), res, txn, sess)
	if err != nil {
		return "", err
	}
	cookie, err := r.Cookie(TxnCookiePrefix + txn.ID)
	if err != nil || secrets.HashToken(cookie.Value) != txn.CookieHash {
		return "", store.ErrInvalid
	}
	if p.Kind == "local" {
		device, err := r.Cookie(PasskeyDeviceCookie)
		if err != nil || secrets.HashToken(device.Value) != p.Scope {
			return "", store.ErrInvalid
		}
	}
	check := r
	if !sess.MFAAt.IsZero() {
		check = r.WithContext(context.WithValue(r.Context(), mfaCompletedKey{}, sess.ID))
	}
	req, err := h.mfaDecision(check, res, flowFromParams(txn.Params), sess, &p.Effects)
	if err != nil || req.Required {
		return "", store.ErrInvalid
	}
	return p.Kind, nil
}

func (h *Handlers) passkeyPending(ctx context.Context, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession) (*passkeyPending, error) {
	if h.Passkeys == nil || txn == nil || sess == nil {
		return nil, store.ErrInvalid
	}
	stored, err := h.Store.AuthTransactions().Get(ctx, res.Tenant.ID, txn.ID)
	if err != nil {
		return nil, err
	}
	var p passkeyPending
	if stored.Params[ParamStage] != StagePasskeyPrompt || !h.now().Before(stored.ExpiresAt) || res.CheckOrigin(stored.Origin) != nil || json.Unmarshal([]byte(stored.Params[PasskeyPromptParam]), &p) != nil || p.SessionID != sess.ID || p.UserID != sess.UserID || p.At.IsZero() || !p.MFAAt.Equal(sess.MFAAt) {
		return nil, store.ErrInvalid
	}
	g, err := h.Store.MFA().GetGuardian(ctx, res.Tenant.ID)
	if err != nil {
		return nil, err
	}
	customize, _ := res.Tenant.SettingsExtra["customize_mfa_in_postlogin_action"].(bool)
	if g.Version != p.GuardianVersion || customize != p.CustomizeMFA {
		return nil, store.ErrInvalid
	}
	if _, err = h.Store.MFA().GetChallenge(ctx, res.Tenant.ID, passkeyAnswerID(stored.ID), h.now()); err != nil {
		return nil, err
	}
	p.Effects = actions.Effects{}
	eff, e := h.consentEffects(res.Tenant.ID, stored)
	if e != nil {
		return nil, e
	}
	if eff != nil {
		p.Effects = *eff
	}
	u, err := h.Store.Users().Get(ctx, res.Tenant.ID, sess.UserID)
	if err != nil {
		return nil, err
	}
	if u.Blocked {
		return nil, store.ErrInvalid
	}
	c, err := h.Store.Connections().GetByName(ctx, res.Tenant.ID, sess.Connection)
	if err != nil {
		return nil, err
	}
	policy, rp, effective, err := h.Passkeys.Effective(ctx, res.Tenant.ID, res, c)
	if err != nil {
		return nil, err
	}
	if !effective || rp.RPID != p.RPID || !slices.Contains(c.EnabledClients, stored.ClientID) || (p.Kind == "progressive" && !policy.Progressive) || (p.Kind == "local" && (!policy.Local || p.Hint.Attachment != "cross-platform" || !p.Hint.Platform)) || (p.Kind != "local" && p.Kind != "progressive") {
		return nil, store.ErrInvalid
	}

	return &p, nil
}
func passkeyAnswerID(id string) string { return "passkey-prompt-answer:" + id }

func (h *Handlers) requirePasskeyPrompt(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, sess *store.LoginSession, eff *actions.Effects) bool {
	if h.Passkeys == nil || r.Context().Value(passkeyAnsweredKey{}) != nil || slices.Contains(fr.Prompts(), "none") {
		return false
	}
	hint, _ := r.Context().Value(passkeyLoginKey{}).(PasskeyLoginHint)
	if !hint.Fresh {
		return false
	}
	c, err := h.Store.Connections().GetByName(r.Context(), res.Tenant.ID, sess.Connection)
	if err != nil {
		h.refuse(w, r, res, client, fr, errServer())
		return true
	}
	policy, rp, effective, err := h.Passkeys.Effective(r.Context(), res.Tenant.ID, res, c)
	if err != nil {
		h.refuse(w, r, res, client, fr, errServer())
		return true
	}
	if !effective {
		return false
	}
	aa, err := h.Store.MFA().ListAuthenticators(r.Context(), res.Tenant.ID, sess.UserID)
	if err != nil {
		h.refuse(w, r, res, client, fr, errServer())
		return true
	}
	count, has := 0, false
	for _, a := range aa {
		if a.Type == "passkey" {
			count++
			if a.RPID == rp.RPID {
				has = true
			}
		}
	}
	if count >= 20 {
		return false
	}
	first := ""
	if len(sess.AuthMethods) > 0 {
		first = sess.AuthMethods[0].Name
	}
	kind, scope := "", rp.RPID
	if first == "pwd" && policy.Progressive && !has {
		kind = "progressive"
	}
	if first == "passkey" && policy.Local && hint.Attachment == "cross-platform" && hint.Platform {
		kind = "local"
		cookie, e := r.Cookie(PasskeyDeviceCookie)
		if e != nil || len(cookie.Value) < 32 {
			token := secrets.RandomString(43)
			cookie = &http.Cookie{Name: PasskeyDeviceCookie, Value: token, Path: "/", MaxAge: 365 * 24 * 60 * 60, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}
			http.SetCookie(w, cookie)
		}
		scope = secrets.HashToken(cookie.Value)
	}
	if kind == "" {
		return false
	}
	_, err = h.Store.WebAuthn().GetSnooze(r.Context(), res.Tenant.ID, sess.UserID, "passkey-"+kind, scope, h.now())
	if err == nil {
		return false
	}
	if !errors.Is(err, store.ErrNotFound) {
		h.refuse(w, r, res, client, fr, errServer())
		return true
	}
	g, err := h.Store.MFA().GetGuardian(r.Context(), res.Tenant.ID)
	if err != nil {
		h.refuse(w, r, res, client, fr, errServer())
		return true
	}
	customize, _ := res.Tenant.SettingsExtra["customize_mfa_in_postlogin_action"].(bool)
	p := passkeyPending{GuardianVersion: g.Version, CustomizeMFA: customize, Kind: kind, At: h.now(), SessionID: sess.ID, UserID: sess.UserID, RPID: rp.RPID, Scope: scope, Hint: hint, MFAAt: sess.MFAAt}
	if eff != nil {
		p.Effects = *eff
	}
	raw, err := json.Marshal(p)
	if err != nil {
		h.refuse(w, r, res, client, fr, errServer())
		return true
	}
	params := fr.params()
	params[ParamStage] = StagePasskeyPrompt
	params[sessionKey] = sess.ID
	params[PasskeyPromptParam] = string(raw)
	page := "/u/passkey-enrollment"
	if kind == "local" {
		page += "-local"
	}
	h.startTxnWith(w, r, res, client, fr, params, page, func(id string, saved map[string]string) error {
		sealed, e := h.sealConsent(res.Tenant.ID, id, sess.ID, client.ClientID, &p.Effects)
		if e != nil {
			return e
		}
		saved[effectsKey] = sealed
		return h.Store.MFA().CreateChallenge(r.Context(), &store.MFAChallenge{TenantID: res.Tenant.ID, ID: passkeyAnswerID(id), Kind: "webauthn", ExpiresAt: h.now().Add(TxnLifetime)})
	})
	return true
}

// CompletePasskeyPrompt atomically consumes the answer gate with optional
// enrollment. Every final write rechecks the active session and policy.
func (h *Handlers) CompletePasskeyPrompt(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession, snooze bool, enroll func(context.Context, store.Store) error) error {
	var pending *passkeyPending
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		local := *h
		local.Store = tx
		sessions := *h.Sessions
		sessions.Store = tx
		local.Sessions = &sessions
		svc := *h.Passkeys
		svc.Store = tx
		local.Passkeys = &svc
		if _, err := tx.Users().GetForUpdate(r.Context(), res.Tenant.ID, sess.UserID); err != nil {
			return err
		}
		current, err := local.ActiveSession(r.Context(), r, res)
		if err != nil || current == nil || current.ID != sess.ID {
			return store.ErrInvalid
		}
		fr := flowFromParams(txn.Params)
		client, verr, _ := local.validateFlow(r.Context(), res, &fr)
		if verr != nil {
			return store.ErrInvalid
		}
		hosted, orgerr := local.organizationSession(w, r, res, client, &fr, current)
		if orgerr != nil || hosted {
			return store.ErrInvalid
		}
		cookie, e := r.Cookie(TxnCookiePrefix + txn.ID)
		if e != nil || secrets.HashToken(cookie.Value) != txn.CookieHash {
			return store.ErrInvalid
		}
		pending, err = local.passkeyPending(r.Context(), res, txn, current)
		if err != nil {
			return err
		}
		if pending.Kind == "local" {
			device, e := r.Cookie(PasskeyDeviceCookie)
			if e != nil || secrets.HashToken(device.Value) != pending.Scope {
				return store.ErrInvalid
			}
		}
		check := r
		if !current.MFAAt.IsZero() {
			check = r.WithContext(context.WithValue(r.Context(), mfaCompletedKey{}, current.ID))
		}
		req, e := local.mfaDecision(check, res, flowFromParams(txn.Params), current, &pending.Effects)
		if e != nil || req.Required {
			return store.ErrInvalid
		}
		if err = tx.MFA().ConsumeChallenge(r.Context(), res.Tenant.ID, passkeyAnswerID(txn.ID), h.now()); err != nil {
			return err
		}
		if enroll != nil {
			if err = enroll(r.Context(), tx); err != nil {
				return err
			}
		}
		if snooze {
			if err = tx.WebAuthn().PutSnooze(r.Context(), &store.WebAuthnSnooze{TenantID: res.Tenant.ID, UserID: sess.UserID, Kind: "passkey-" + pending.Kind, ScopeKey: pending.Scope, Until: h.now().Add(30 * 24 * time.Hour)}); err != nil {
				return err
			}
		}
		return tx.AuthTransactions().Delete(r.Context(), res.Tenant.ID, txn.ID)
	})
	if err != nil {
		return err
	}
	h.clearTxnCookie(w, txn)
	fr := flowFromParams(txn.Params)
	client, verr, _ := h.validateFlow(r.Context(), res, &fr)
	if verr != nil {
		return store.ErrInvalid
	}
	ctx := context.WithValue(r.Context(), passkeyAnsweredKey{}, true)
	if !sess.MFAAt.IsZero() {
		ctx = context.WithValue(ctx, mfaCompletedKey{}, sess.ID)
	}
	h.finish(w, r.WithContext(ctx), res, client, fr, sess, &pending.Effects, false, true)
	return nil
}
