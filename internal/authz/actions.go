package authz

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// effectsKey holds a consent transaction's sealed post-login effects, so
// accepting consent issues the code without running the flow again.
const effectsKey = "za_action_effects"

// postLogin runs the tenant's post-login flow for an authenticated request,
// before consent (D-0053). in carries the API the request names. It returns
// the flow's effects; on a denial or failure the response has been written
// and ok is false. Without an engine no Action runs and the effects are nil.
func (h *Handlers) postLogin(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, sess *store.LoginSession, in access.Input, screenShown bool) (*actions.Effects, bool) {
	*r = *r.WithContext(events.WithContext(r.Context(), events.FromRequest(r)))
	event := logs.FromRequest(r)
	event.TenantID = res.Tenant.ID
	event.ClientID = client.ClientID
	event.ClientName = client.Name
	event.UserID = sess.UserID
	event.Connection = sess.Connection
	*r = *r.WithContext(logs.WithEvent(r.Context(), event))
	if h.Actions == nil {
		return nil, true
	}
	ctx := r.Context()
	query := map[string]any{}
	for k, v := range fr.Request.Params() {
		if !strings.HasPrefix(k, "za_") { // zeroauthy's own transaction keys
			query[k] = v
		}
	}
	protocol := actionProtocol(fr)
	locale := ""
	if l := strings.Fields(fr.UILocales); len(l) > 0 {
		locale = l[0]
	}
	continuation := fr.params()
	if screenShown {
		continuation["za_screen_shown"] = "true"
	}
	result, err := h.Actions.PostLogin(ctx, actions.PostLoginInput{
		OrganizationID: fr.OrgID, Tenant: res, Client: client, Session: sess, Continuation: continuation,
		// Loaded only when Actions are bound: a tenant without post-login
		// Actions pays only the bindings read.
		Prepare: func(ctx context.Context, in *actions.PostLoginInput) error {
			user, err := h.Store.Users().Get(ctx, res.Tenant.ID, sess.UserID)
			if err != nil {
				return err
			}
			conn, err := h.Store.Connections().GetByName(ctx, res.Tenant.ID, sess.Connection)
			if errors.Is(err, store.ErrNotFound) {
				conn, err = nil, nil
			}
			if fr.OrgID != "" {
				member, e := h.Store.Organizations().IsMember(ctx, res.Tenant.ID, fr.OrgID, sess.UserID)
				if e != nil {
					return e
				}
				in.PendingMembership = !member
			}
			in.User, in.Connection = h.prospectiveUser(r, res, sess, user), conn
			if h.Sessions != nil {
				in.Risk.KnownDevice, err = h.Sessions.MFABrowserValid(ctx, r, user, "device")
				if err != nil {
					return err
				}
			}
			if fr.invitationBinding[orglogin.InvitationIDParam] != "" {
				txn, e := h.completionTransaction(ctx, r, res)
				if e != nil {
					return e
				}
				inv, e := orglogin.PreviewInvitation(ctx, h.Store, txn, sess, h.now())
				if e != nil {
					return e
				}
				in.User = orglogin.InvitationUserView(in.User, inv)
				in.PendingInvitationRoleIDs = append([]string{}, inv.Roles...)
			}
			return err
		},
		// The login form's body (with the password) is never passed on.
		Request: actions.RequestInfo{
			SecurityContext: actions.SecurityContextFrom(ctx), CorrelationID: actions.CorrelationID(r),
			IP: httpx.ClientIP(r, h.TrustProxyHeaders), Hostname: r.Host, Origin: res.Origin(), Method: r.Method,
			UserAgent: r.UserAgent(), Language: firstLanguage(r.Header.Get("Accept-Language")),
			Query: query, Body: map[string]any{},
		},
		Transaction:     actions.TransactionInfo{ACRValues: fr.Request.ACRValues, RedirectURI: fr.RedirectURI, State: fr.State, Locale: locale},
		Protocol:        protocol,
		RequestedScopes: fr.Scopes(),
		TargetScopes:    fr.Scopes(),
		ResourceServer:  in.API,
		// A device approval cannot redirect.
		CanRedirect: !fr.backchannel() && !slices.Contains(fr.Prompts(), "none"),
	})
	return h.postLoginResult(w, r, res, client, fr, sess, result, err)
}

func (h *Handlers) postLoginResult(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, sess *store.LoginSession, result *actions.Result, err error) (*actions.Effects, bool) {
	event := logs.FromRequest(r)
	event.TenantID = res.Tenant.ID
	event.ClientID = client.ClientID
	event.Type = "f"
	if result != nil {
		logs.AddExecution(r.Context(), result.ExecutionID)
	}
	var fe *actions.ErrFlow
	switch {
	case errors.Is(err, actions.ErrRedirectNotAllowed) && slices.Contains(fr.Prompts(), "none"):
		h.refuse(w, r, res, client, fr, &Error{Code: "interaction_required", Description: "the Action requires interaction"})
		return nil, false
	case errors.As(err, &fe):
		logs.AddExecution(r.Context(), fe.ExecutionID)
		logs.RecordEvent(r.Context(), logs.RecorderFromContext(r.Context()), event)
		h.actionsFailed(w, r, res, client, fr, fe.ExecutionID)
		return nil, false
	case err != nil:
		logs.RecordEvent(r.Context(), logs.RecorderFromContext(r.Context()), event)
		h.log().ErrorContext(r.Context(), "run post-login Actions", "tenant", res.Tenant.ID, "err", err)
		h.actionsFailed(w, r, res, client, fr, "")
		return nil, false
	case result.Denied != nil:
		event.Description = result.Denied.Reason
		logs.RecordEvent(r.Context(), logs.RecorderFromContext(r.Context()), event)
		h.refuse(w, r, res, client, fr, &Error{Code: result.Denied.Code, Description: result.Denied.Reason})
		return nil, false
	}
	// api.session.revoke ends the session and the login even when a later
	// Action redirected (Review Focus 3): no code or token follows.
	if se := result.Effects.Session; se != nil && se.Revoke != nil {
		if e := h.revokeSession(r.Context(), w, res, sess, se.Revoke.PreserveRefreshTokens); e != nil {
			h.log().ErrorContext(r.Context(), "revoke session from Action", "tenant", res.Tenant.ID, "err", e)
			h.actionsFailed(w, r, res, client, fr, result.ExecutionID)
			return nil, false
		}
		reason := se.Revoke.Reason
		if reason == "" {
			reason = "the session was revoked"
		}
		event.Description = reason
		logs.RecordEvent(r.Context(), logs.RecorderFromContext(r.Context()), event)
		h.refuse(w, r, res, client, fr, &Error{Code: "access_denied", Description: reason})
		return nil, false
	}
	if result.Redirect != nil {
		if p, _ := r.Context().Value(pendingLoginKey{}).(*pendingLogin); p != nil {
			target, e := url.Parse(result.Redirect.URL)
			if e != nil {
				h.actionsFailed(w, r, res, client, fr, result.ExecutionID)
				return nil, false
			}
			state := target.Query().Get("state")
			// This is only a selector. The original pending credential and the sealed
			// Action state's session/tenant/origin binding still authorize continuation.
			http.SetCookie(w, &http.Cookie{Name: continueSelectorCookie(state), Value: p.Transaction.ID, Path: "/continue", MaxAge: int(p.Transaction.ExpiresAt.Sub(h.now()).Seconds()), Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode})
		}
		redirect(w, r, result.Redirect.URL)
		return nil, false
	}
	return &result.Effects, true
}

// actionsFailed ends fr after a failed post-login flow: server_error with a
// generic description, and the hosted error page with the execution
// reference when the error is shown rather than redirected (D-0053). The
// reference never reaches error_description.
func (h *Handlers) actionsFailed(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, executionID string) {
	if fr.backchannel() || access.ShowErrorPage(client) {
		view := ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, fr.UILocales))
		ui.RenderErrorReference(w, http.StatusInternalServerError, view, view.L.T(i18n.KeyErrServer), executionID)
		return
	}
	writeResponse(w, r, fr.Request, errorParams(errServer(), fr.State))
}

// firstLanguage is the first tag of an Accept-Language header.
func firstLanguage(h string) string {
	tag, _, _ := strings.Cut(h, ",")
	tag, _, _ = strings.Cut(tag, ";")
	return strings.TrimSpace(tag)
}

// ranEmpty marks a consent transaction whose post-login flow ran without
// token or scope effects; nothing needs sealing.
const ranEmpty = "-"

// sealConsent seals eff for consent transaction txnID of sessionID and
// client; a flow without effects is only marked as run.
func (h *Handlers) sealConsent(tenantID, txnID, sessionID, clientID string, eff *actions.Effects) (string, error) {
	if !eff.HasTokenEffects() && eff.Target == nil && eff.MFA == nil && !hasMetadataDeletion(eff) {
		return ranEmpty, nil
	}
	b, err := actions.SealEffects(h.Wrapper, tenantID, actions.SealConsent, eff, txnID, sessionID, clientID)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// consentEffects opens the post-login effects carried by a consent
// transaction. nil without an error means the flow has not run (no engine
// when the transaction began).
func (h *Handlers) consentEffects(tenantID string, txn *store.AuthTransaction) (*actions.Effects, error) {
	raw, ok := txn.Params[effectsKey]
	switch {
	case !ok:
		return nil, nil
	case raw == ranEmpty:
		return &actions.Effects{}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	return actions.OpenEffects(h.Wrapper, tenantID, actions.SealConsent, b, txn.ID, txn.Params[sessionKey], txn.ClientID)
}

// sealFor seals eff's token effects for a code or device code bound to
// hash; nil when there are none.
func (h *Handlers) sealFor(tenantID, purpose, hash string, eff *actions.Effects) ([]byte, error) {
	if !eff.HasTokenEffects() {
		return nil, nil
	}
	return actions.SealEffects(h.Wrapper, tenantID, purpose, eff, hash)
}

func continueSelectorCookie(state string) string { return "za_continue_" + secrets.HashToken(state) }

func hasMetadataDeletion(eff *actions.Effects) bool {
	for _, patch := range []map[string]any{eff.AppMetadata, eff.UserMetadata} {
		for _, v := range patch {
			if v == nil {
				return true
			}
		}
	}
	return false
}

// actionProtocol is event.transaction.protocol for a flow.
func actionProtocol(fr flowReq) string {
	switch {
	case IsWSFedBinding(fr.SAML):
		return actions.ProtocolWSFed
	case fr.SAML != "":
		return actions.ProtocolSAMLP
	case fr.device():
		return actions.ProtocolDeviceCode
	case fr.ciba():
		return actions.ProtocolCIBA
	}
	return actions.ProtocolOIDCBasicProfile
}

// revokeSession ends a stored session for api.session.revoke (Plan 40): its
// refresh tokens are revoked unless preserved, the owners' versions bump,
// the row is deleted and back-channel logout is queued (session-revoked)
// in one transaction; the cookie is cleared. A pending login has no stored
// session, so nothing is written.
func (h *Handlers) revokeSession(ctx context.Context, w http.ResponseWriter, res tenant.Resolved, sess *store.LoginSession, preserve bool) error {
	if sess == nil {
		return nil
	}
	tid := res.Tenant.ID
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		if _, err := tx.Tenants().Get(ctx, tid); err != nil {
			return err
		}
		current, err := tx.Sessions().GetForUpdate(ctx, tid, sess.ID)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Users().GetForUpdate(ctx, tid, current.UserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if !preserve {
			if _, err := tx.RefreshTokens().RevokeBySession(ctx, tid, current.ID, h.now()); err != nil {
				return err
			}
		}
		if _, err := tx.Users().BumpVersion(ctx, tid, current.UserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := tx.Sessions().Delete(ctx, tid, current.ID); err != nil {
			return err
		}
		if h.Sessions != nil && h.Sessions.OnEnd != nil {
			return h.Sessions.OnEnd(ctx, tx, current)
		}
		return nil
	})
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: session.CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode})
	return nil
}

// capSessionLimits applies an Action's session expiry and cookie-mode calls
// to s: the setters only shorten (LR40-3), idle never passes absolute.
func capSessionLimits(s *store.LoginSession, se *actions.SessionEffects) {
	if se.ExpiresAt != nil && se.ExpiresAt.Before(s.ExpiresAt) {
		s.ExpiresAt = *se.ExpiresAt
	}
	if se.IdleExpiresAt != nil && se.IdleExpiresAt.Before(s.IdleExpiresAt) {
		s.IdleExpiresAt = *se.IdleExpiresAt
	}
	if s.IdleExpiresAt.After(s.ExpiresAt) {
		s.IdleExpiresAt = s.ExpiresAt
	}
	if se.CookieMode != "" {
		s.CookieMode = se.CookieMode
	}
}
