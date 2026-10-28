package authz

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
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
	protocol := actions.ProtocolOIDCBasicProfile
	if fr.device() {
		protocol = actions.ProtocolDeviceCode
	}
	locale := ""
	if l := strings.Fields(fr.UILocales); len(l) > 0 {
		locale = l[0]
	}
	continuation := fr.params()
	if screenShown {
		continuation["za_screen_shown"] = "true"
	}
	result, err := h.Actions.PostLogin(ctx, actions.PostLoginInput{
		Tenant: res, Client: client, Session: sess, Continuation: continuation,
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
			in.User, in.Connection = user, conn
			return err
		},
		// The login form's body (with the password) is never passed on.
		Request: actions.RequestInfo{
			IP: httpx.ClientIP(r, h.TrustProxyHeaders), Hostname: r.Host, Origin: res.Origin(), Method: r.Method,
			UserAgent: r.UserAgent(), Language: firstLanguage(r.Header.Get("Accept-Language")),
			Query: query, Body: map[string]any{},
		},
		Transaction:     actions.TransactionInfo{RedirectURI: fr.RedirectURI, State: fr.State, Locale: locale},
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
	var fe *actions.ErrFlow
	switch {
	case errors.Is(err, actions.ErrRedirectNotAllowed) && slices.Contains(fr.Prompts(), "none"):
		h.refuse(w, r, res, client, fr, &Error{Code: "interaction_required", Description: "the Action requires interaction"})
		return nil, false
	case errors.As(err, &fe):
		h.actionsFailed(w, r, res, client, fr, fe.ExecutionID)
		return nil, false
	case err != nil:
		h.log().ErrorContext(r.Context(), "run post-login Actions", "tenant", res.Tenant.ID, "err", err)
		h.actionsFailed(w, r, res, client, fr, "")
		return nil, false
	case result.Denied != nil:
		h.refuse(w, r, res, client, fr, &Error{Code: result.Denied.Code, Description: result.Denied.Reason})
		return nil, false
	}
	if result.Redirect != nil {
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
	if !eff.HasTokenEffects() && eff.Target == nil {
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
