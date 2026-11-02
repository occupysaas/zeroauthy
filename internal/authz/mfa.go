package authz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

const StageMFA = "mfa"
const mfaPendingKey = "za_mfa_pending"

// MFAPending is authenticated, sealed state for Task 8's pages. Only IDs and
// requirements belong here; enrollment secrets/codes must never be persisted.
// Pages accept proof only for Requirement.Factors. Login-purpose completion
// marks its session then calls MFAComplete; reset and ticket purposes never do.
// Completion reloads this state rather than trusting caller edits.
type MFAPending struct {
	Requirement                                                mfa.Requirement
	Effects                                                    actions.Effects
	SessionID, UserID                                          string
	PreviousMFAAt                                              time.Time
	RememberEpoch                                              int
	TicketAllowMultiple                                        bool
	ResetTicketHash, ResetPageHash, ResetResultURL, ResetEmail string
	ResetUserVersion                                           int64
	ResetEmailVerified                                         bool
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
	logs.RecordEvent(r.Context(), logs.RecorderFromContext(r.Context()), logs.Event{TenantID: res.Tenant.ID, UserID: sess.UserID, Type: "mfar", Date: h.now()})
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
	if txn == nil || h.Wrapper == nil {
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
	ticket := stored.ClientID == "" && stored.Params["za_mfa_ticket"] == "1"
	reset := stored.ClientID == "" && stored.Params["za_mfa_reset"] == "1"
	if ticket && reset {
		return nil, invalid
	}
	sid := ""
	var current *store.LoginSession
	if !ticket && !reset {
		current, err = h.ActiveSession(ctx, r, res)
		if err != nil {
			return nil, err
		}
		if sess == nil || current == nil || current.ID != sess.ID || current.ID != stored.Params[sessionKey] {
			return nil, invalid
		}
		sid = current.ID
	}
	sealed, err := base64.RawURLEncoding.DecodeString(stored.Params[mfaPendingKey])
	if err != nil {
		return nil, invalid
	}
	plain, err := keys.OpenBound(h.Wrapper, "hosted-mfa/v1", []string{res.Tenant.ID, stored.ID, sid, stored.ClientID, res.Origin()}, sealed)
	if err != nil {
		return nil, invalid
	}
	var pending MFAPending
	if json.Unmarshal(plain, &pending) != nil || !pending.Requirement.Required || pending.SessionID != sid || (!ticket && !reset && pending.UserID != current.UserID) || (ticket && pending.Requirement.Reason != "ticket") || (reset && (pending.Requirement.Reason != "reset" || pending.Requirement.Enroll || pending.Requirement.AllowRemember)) || (!reset && pending.Requirement.Reason == "reset") {
		return nil, invalid
	}
	u, err := h.Store.Users().Get(ctx, res.Tenant.ID, pending.UserID)
	if err != nil {
		return nil, err
	}
	if u.Blocked || u.RememberBrowserEpoch != pending.RememberEpoch {
		return nil, invalid
	}
	if reset {
		if pending.ResetTicketHash == "" || u.Version != pending.ResetUserVersion || u.Email != pending.ResetEmail || u.EmailVerified != pending.ResetEmailVerified {
			return nil, invalid
		}
		page, e := r.Cookie("za_reset_mfa_page")
		bearer, b := r.Cookie("za_reset_mfa")
		if e != nil || b != nil || secrets.HashToken(page.Value) != pending.ResetPageHash || secrets.HashToken(bearer.Value) != pending.ResetTicketHash {
			return nil, invalid
		}
		tk, e := h.Store.PasswordResetTickets().GetByTokenHash(ctx, res.Tenant.ID, pending.ResetTicketHash)
		if e != nil || tk.UserID != pending.UserID || tk.UsedAt != nil || tk.ChallengePassedAt != nil || !h.now().Before(tk.ExpiresAt) {
			return nil, invalid
		}
		conn, e := h.Store.Connections().GetByName(ctx, res.Tenant.ID, tk.Connection)
		if e != nil || conn.Strategy != store.StrategyDatabase {
			return nil, invalid
		}
		if _, e = orglogin.PasswordResetContext(ctx, h.Store, res.Tenant.ID, tk.OrganizationID, tk.ClientID, conn); e != nil {
			return nil, invalid
		}
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
	if pending.Requirement.Reason == "reset" {
		h.invalidMFA(w, r, res)
		return
	}
	if pending.Requirement.Reason == "ticket" {
		if err := h.Store.AuthTransactions().Delete(r.Context(), res.Tenant.ID, txn.ID); err != nil {
			h.invalidMFA(w, r, res)
			return
		}
		h.clearTxnCookie(w, txn)
		h.mfaTicketResult(w, r, res)

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

// StartMFATicket establishes enrollment-only authority, without an SSO session.
func (h *Handlers) StartMFATicket(w http.ResponseWriter, r *http.Request, res tenant.Resolved, u *store.User, factors []string, allowMultiple bool) error {
	p := map[string]string{ParamStage: StageMFA, "za_mfa_ticket": "1"}
	pending := MFAPending{Requirement: mfa.Requirement{Required: true, Enroll: true, Factors: factors, Reason: "ticket"}, UserID: u.UserID, RememberEpoch: u.RememberBrowserEpoch, TicketAllowMultiple: allowMultiple}
	txn, err := h.createTxn(w, r, res, "", p, "/u", func(id string, p map[string]string) error {
		plain, e := json.Marshal(pending)
		if e != nil {
			return e
		}
		sealed, e := keys.SealBound(h.Wrapper, "hosted-mfa/v1", []string{res.Tenant.ID, id, "", "", res.Origin()}, plain)
		if e == nil {
			p[mfaPendingKey] = base64.RawURLEncoding.EncodeToString(sealed)
		}
		return e
	})
	if err != nil {
		return err
	}
	http.Redirect(w, r, "/u/mfa?"+url.Values{"state": {txn.ID}}.Encode(), http.StatusSeeOther)
	return nil
}

func (h *Handlers) mfaTicketResult(w http.ResponseWriter, r *http.Request, res tenant.Resolved) {
	config, err := (hostedlogin.Service{Store: h.Store}).Load(r.Context(), res.Tenant.ID)
	if err != nil {
		h.invalidMFA(w, r, res)
		return
	}
	t := hostedlogin.LocalizedTenant(res.Tenant, config)
	req := r.WithContext(hostedlogin.WithConfiguration(r.Context(), config))
	view := ui.RequestTenant(req, t, i18n.ForRequest(t, r, ""))
	out, err := hostedlogin.RenderPartials(r.Context(), config.Partials["mfa"]["mfa-enroll-result"], map[string]any{
		"tenant":      map[string]any{"name": view.Name, "support_url": view.SupportURL, "support_email": view.SupportEmail},
		"application": map[string]any{"name": ""}, "locale": map[string]any{"language": view.L.Lang()},
		"prompt":   map[string]any{"name": "mfa", "screen": map[string]any{"name": "mfa-enroll-result", "text": view.L.ScreenText("mfa", "mfa-enroll-result")}},
		"branding": map[string]any{"logo_url": view.LogoURL, "primary_color": view.PrimaryColor},
	}, nil, "")
	if err == nil {
		ui.ApplyPartials(&view, out)
	}
	ui.RenderMFA(w, http.StatusOK, view, "mfa_result", ui.MFAData{})
}

// StartMFAReset creates proof-only authority for an existing unspent password
// reset ticket. It never creates a login session or accepts enrollment proof.
// The bearer stays in an HttpOnly browser cookie, only its hash enters storage.
func (h *Handlers) StartMFAReset(w http.ResponseWriter, r *http.Request, res tenant.Resolved, u *store.User, tk *store.PasswordResetTicket, page string, req mfa.Requirement, resultURL string) error {
	if u == nil || tk == nil || u.TenantID != res.Tenant.ID || tk.TenantID != res.Tenant.ID || !req.Required || req.Enroll || tk.UserID != u.UserID || page == "" {
		return store.ErrInvalid
	}
	req.Reason, req.AllowRemember = "reset", false
	pending := MFAPending{Requirement: req, UserID: u.UserID, RememberEpoch: u.RememberBrowserEpoch, ResetTicketHash: tk.TokenHash, ResetPageHash: secrets.HashToken(page), ResetResultURL: resultURL, ResetUserVersion: u.Version, ResetEmail: u.Email, ResetEmailVerified: u.EmailVerified}
	p := map[string]string{ParamStage: StageMFA, "za_mfa_reset": "1"}
	txn, err := h.createTxn(w, r, res, "", p, "/u", func(id string, p map[string]string) error {
		plain, e := json.Marshal(pending)
		if e != nil {
			return e
		}
		sealed, e := keys.SealBound(h.Wrapper, "hosted-mfa/v1", []string{res.Tenant.ID, id, "", "", res.Origin()}, plain)
		if e == nil {
			p[mfaPendingKey] = base64.RawURLEncoding.EncodeToString(sealed)
		}
		return e
	})
	if err != nil {
		return err
	}
	http.Redirect(w, r, "/u/mfa?"+url.Values{"state": {txn.ID}}.Encode(), http.StatusSeeOther)
	return nil
}

// CompleteMFAReset is called only by the hosted pages after successful service
// proof (and recovery acknowledgement). It consumes the browser-bound reset
// authority and marks the ticket's challenge pass in one user-locked transaction.
// Ordinary MFAComplete rejects reset authority, so no OAuth/SSO path is reachable.
func (h *Handlers) CompleteMFAReset(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction) error {
	pending, err := h.PendingMFA(r.Context(), r, res, txn, nil)
	if err != nil || pending.Requirement.Reason != "reset" {
		return store.ErrInvalid
	}
	browser := secrets.RandomString(43)
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		// Lock before every transactional authority read; this also avoids a
		// stale repeatable-read snapshot after a concurrent password change.
		if _, e := tx.Users().GetForUpdate(r.Context(), res.Tenant.ID, pending.UserID); e != nil {
			return e
		}
		local := *h
		local.Store = tx
		current, e := local.PendingMFA(r.Context(), r, res, txn, nil)
		if e != nil {
			return e
		}
		pending = current
		if e = h.storeMFAResetPass(r.Context(), tx, res, txn, pending, browser); e != nil {
			return e
		}
		return tx.AuthTransactions().Delete(r.Context(), res.Tenant.ID, txn.ID)
	})
	if err == nil {
		h.clearTxnCookie(w, txn)
		http.SetCookie(w, &http.Cookie{Name: ResetMFAPassCookie, Value: browser, Path: "/u/reset-password", MaxAge: int(txn.ExpiresAt.Sub(h.now()).Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	}
	return err
}
