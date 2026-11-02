package authz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const StageMFA = "mfa"
const mfaPendingKey = "za_mfa_pending"

// MFAPending is authenticated, sealed state for Task 8's pages. Only IDs and
// requirements belong here; enrollment secrets/codes must never be persisted.
// A page must accept proof only for Requirement.Factors, then MarkMFA and call
// MFAComplete. MFAComplete reloads this state rather than trusting caller edits.
type MFAPending struct {
	Requirement       mfa.Requirement
	Effects           actions.Effects
	SessionID, UserID string
	PreviousMFAAt     time.Time
	RememberEpoch     int
}

type mfaCompletedKey struct{}

func (h *Handlers) mfaDecision(r *http.Request, res tenant.Resolved, sess *store.LoginSession, eff *actions.Effects) (mfa.Requirement, error) {
	var effects *actions.MFAEffects
	if eff != nil {
		effects = eff.MFA
	}
	g, err := h.Store.MFA().GetGuardian(r.Context(), res.Tenant.ID)
	if errors.Is(err, store.ErrMFAUnavailable) {
		// Older plugins have no policy. An explicit Action request still cannot
		// be fulfilled, except for its explicit skip instruction.
		if effects != nil && (effects.Mode != "" || effects.Provider != "" && effects.Provider != "none") {
			return mfa.Requirement{}, mfa.ErrNoFactor
		}
		return mfa.Requirement{}, nil
	}
	if err != nil {
		return mfa.Requirement{}, err
	}
	u, err := h.Store.Users().Get(r.Context(), res.Tenant.ID, sess.UserID)
	if err != nil {
		return mfa.Requirement{}, err
	}
	if u.Blocked {
		return mfa.Requirement{}, store.ErrNotFound
	}
	aa, err := h.Store.MFA().ListAuthenticators(r.Context(), res.Tenant.ID, sess.UserID)
	if err != nil {
		return mfa.Requirement{}, err
	}
	remember, err := h.Sessions.MFABrowserValid(r.Context(), r, u, "remember")
	if err != nil {
		return mfa.Requirement{}, err
	}
	known, err := h.Sessions.MFABrowserValid(r.Context(), r, u, "device")
	if err != nil {
		return mfa.Requirement{}, err
	}
	customize, _ := res.Tenant.SettingsExtra["customize_mfa_in_postlogin_action"].(bool)
	in := mfa.DecideInput{Settings: g, Effects: effects, Authenticators: aa, SessionMFAAt: sess.MFAAt, RememberValid: remember, KnownDevice: known, CustomizeInActions: customize}
	// Validate the original Action factor restrictions before satisfying its
	// forced prompt. Disabling its chosen factor must still fail closed.
	req, err := mfa.Decide(in)
	if err == nil && !sess.MFAAt.IsZero() {
		if completed, ok := r.Context().Value(mfaCompletedKey{}).(string); ok && completed == sess.ID {
			req.Required = false
			req.Enroll = false
		}
	}
	return req, err
}

func (h *Handlers) requireMFA(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, sess *store.LoginSession, eff *actions.Effects) bool {
	req, err := h.mfaDecision(r, res, sess, eff)
	if err != nil {
		if errors.Is(err, mfa.ErrNoFactor) {
			h.refuse(w, r, res, client, fr, errAccessDenied("MFA is required but no factor is enabled"))
		} else {
			h.refuse(w, r, res, client, fr, errServer())
		}
		return true
	}
	if !req.Required {
		return false
	}
	if slices.Contains(fr.Prompts(), "none") {
		h.refuse(w, r, res, client, fr, &Error{Code: "interaction_required", Description: "MFA requires interaction"})
		return true
	}
	u, err := h.Store.Users().Get(r.Context(), res.Tenant.ID, sess.UserID)
	if err != nil {
		h.refuse(w, r, res, client, fr, errServer())
		return true
	}
	pending := MFAPending{Requirement: req, SessionID: sess.ID, UserID: sess.UserID, PreviousMFAAt: sess.MFAAt, RememberEpoch: u.RememberBrowserEpoch}
	if eff != nil {
		pending.Effects = *eff
	}
	params := fr.params()
	params[ParamStage] = StageMFA
	params[sessionKey] = sess.ID
	h.startTxnWith(w, r, res, client, fr, params, "/u/mfa", func(id string, p map[string]string) error {
		plain, err := json.Marshal(pending)
		if err != nil {
			return err
		}
		sealed, err := keys.SealBound(h.Wrapper, "hosted-mfa/v1", []string{res.Tenant.ID, id, sess.ID, client.ClientID, res.Origin()}, plain)
		if err == nil {
			p[mfaPendingKey] = base64.RawURLEncoding.EncodeToString(sealed)
		}
		return err
	})
	return true
}

// PendingMFA validates the stored transaction, browser binding, origin and
// current active session before opening its sealed requirement. It is suitable
// for every MFA page request; it does not consume the transaction.
func (h *Handlers) PendingMFA(ctx context.Context, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession) (*MFAPending, error) {
	invalid := errors.New("authz: invalid MFA transaction")
	if txn == nil || sess == nil || h.Wrapper == nil {
		return nil, invalid
	}
	stored, err := h.Store.AuthTransactions().Get(ctx, res.Tenant.ID, txn.ID)
	if err != nil {
		return nil, err
	}
	if stored.TenantID != res.Tenant.ID || stored.Params[ParamStage] != StageMFA || !h.now().Before(stored.ExpiresAt) || res.CheckOrigin(stored.Origin) != nil {
		return nil, invalid
	}
	cookie, err := r.Cookie(TxnCookiePrefix + stored.ID)
	if err != nil || secrets.HashToken(cookie.Value) != stored.CookieHash {
		return nil, invalid
	}
	current, err := h.ActiveSession(ctx, r, res)
	if err != nil {
		return nil, err
	}
	if current == nil || current.ID != sess.ID || current.ID != stored.Params[sessionKey] {
		return nil, invalid
	}
	sealed, err := base64.RawURLEncoding.DecodeString(stored.Params[mfaPendingKey])
	if err != nil {
		return nil, invalid
	}
	plain, err := keys.OpenBound(h.Wrapper, "hosted-mfa/v1", []string{res.Tenant.ID, stored.ID, current.ID, stored.ClientID, res.Origin()}, sealed)
	if err != nil {
		return nil, invalid
	}
	var pending MFAPending
	if json.Unmarshal(plain, &pending) != nil || !pending.Requirement.Required || pending.SessionID != current.ID || pending.UserID != current.UserID {
		return nil, invalid
	}
	u, err := h.Store.Users().Get(ctx, res.Tenant.ID, current.UserID)
	if err != nil {
		return nil, err
	}
	if u.RememberBrowserEpoch != pending.RememberEpoch {
		return nil, invalid
	}
	return &pending, nil
}

// MFAComplete resumes only after a fresh proof marked the bound active session.
// Consuming the transaction is single-use; Actions are carried and never rerun.
func (h *Handlers) MFAComplete(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession) {
	pending, err := h.PendingMFA(r.Context(), r, res, txn, sess)
	if err != nil {
		h.invalidMFA(w, r, res)
		return
	}
	stored, err := h.Store.AuthTransactions().Get(r.Context(), res.Tenant.ID, txn.ID)
	if err != nil {
		h.invalidMFA(w, r, res)
		return
	}
	current, err := h.ActiveSession(r.Context(), r, res)
	if err != nil || current == nil || current.MFAAt.IsZero() || current.MFAAt.Equal(pending.PreviousMFAAt) || current.MFAAt.Before(stored.CreatedAt) {
		h.invalidMFA(w, r, res)
		return
	}
	fr := flowFromParams(stored.Params)
	client, verr, redirectable := h.validateFlow(r.Context(), res, &fr)
	if verr != nil {
		if redirectable {
			h.refuse(w, r, res, client, fr, verr)
		} else {
			h.flowError(w, r, res, fr, verr)
		}
		return
	}
	disabled, err := h.connectionDisabled(r, res, client, current)
	if err != nil || disabled {
		h.invalidMFA(w, r, res)
		return
	}
	if err = h.Store.AuthTransactions().Delete(r.Context(), res.Tenant.ID, stored.ID); err != nil {
		h.invalidMFA(w, r, res)
		return
	}
	h.clearTxnCookie(w, stored)
	*r = *r.WithContext(context.WithValue(r.Context(), mfaCompletedKey{}, current.ID))
	h.finish(w, r, res, client, fr, current, &pending.Effects, true, true)
}
func (h *Handlers) invalidMFA(w http.ResponseWriter, r *http.Request, res tenant.Resolved) {
	h.invalidTxn(w, r, res, &store.AuthTransaction{Params: map[string]string{}})
}
