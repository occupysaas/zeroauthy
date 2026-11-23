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
		CanRedirect: !fr.device() && !slices.Contains(fr.Prompts(), "none"),
	})
	return h.postLoginResult(w, r, res, client, fr, result, err)
}

func (h *Handlers) postLoginResult(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, result *actions.Result, err error) (*actions.Effects, bool) {
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
	if fr.device() || access.ShowErrorPage(client) {
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
	}
	return actions.ProtocolOIDCBasicProfile
}
