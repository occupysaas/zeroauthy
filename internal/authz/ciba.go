package authz

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// CIBA approval through the emailed link (Plan 41c, D-0100): /bc-verify
// shows the request, then login as the hinted user (or that user's
// session), MFA and post-login Actions run, and the decision is recorded
// on the request instead of issuing a code.

var (
	// errCIBANotPending is a request decided, expired or removed meanwhile.
	errCIBANotPending = errInvalidRequest("the request is no longer pending")
	// errCIBAWrongUser is a sign-in as someone else than the hinted user.
	errCIBAWrongUser = errAccessDenied("sign in as the user this request is for")
)

func cibaFlow(req *store.CIBARequest, uiLocales string) flowReq {
	return flowReq{
		Request:  Request{ClientID: req.ClientID, Scope: strings.Join(req.Scopes, " "), Audience: req.Audience, UILocales: uiLocales},
		CIBAHash: req.IDHash, CIBAUserID: req.UserID,
	}
}

// validateCIBA checks that fr may still complete: the client keeps the
// CIBA grant, and the request is pending, unexpired, delivered and from
// this origin. Failures are never redirectable.
func (h *Handlers) validateCIBA(ctx context.Context, res tenant.Resolved, fr *flowReq) (*store.Client, *Error, bool) {
	client, err := h.Store.Clients().Get(ctx, res.Tenant.ID, fr.ClientID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errInvalidRequest("unknown client"), false
	case err != nil:
		return nil, errServer(), false
	case !slices.Contains(client.GrantTypes, clientrules.GrantCIBA) || !client.IsFirstParty:
		return nil, errUnauthorizedClient("the client is not allowed to use the CIBA grant"), false
	}
	repo, err := store.CIBA(ctx, h.Store)
	if err != nil {
		return nil, errServer(), false
	}
	req, err := repo.GetCIBARequest(ctx, res.Tenant.ID, fr.CIBAHash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errCIBANotPending, false
	case err != nil:
		return nil, errServer(), false
	case req.ClientID != client.ClientID || req.Status != store.CIBAPending || req.UserID == "" || req.UserID != fr.CIBAUserID ||
		!h.now().Before(req.ExpiresAt) || res.CheckOrigin(req.Origin) != nil:
		return nil, errCIBANotPending, false
	}
	return client, nil, false
}

// ContinueCIBA runs login (or reuses the hinted user's session) and the
// access decision for an approved CIBA request. A session of another user
// starts a new login: the request can only be decided by its user.
func (h *Handlers) ContinueCIBA(w http.ResponseWriter, r *http.Request, res tenant.Resolved, req *store.CIBARequest, loginHint, uiLocales string) {
	ctx := r.Context()
	fr := cibaFlow(req, uiLocales)
	client, verr, _ := h.validateFlow(ctx, res, &fr)
	if verr != nil {
		h.flowError(w, r, res, fr, verr)
		return
	}
	sess, err := h.ActiveSession(ctx, r, res)
	if err != nil {
		h.log().ErrorContext(ctx, "load session", "tenant", res.Tenant.ID, "err", err)
		h.flowError(w, r, res, fr, errServer())
		return
	}
	login := sess == nil || sess.UserID != req.UserID
	if !login {
		if login, err = h.connectionDisabled(r, res, client, sess); err != nil {
			h.log().ErrorContext(ctx, "load session connection", "tenant", res.Tenant.ID, "err", err)
			h.flowError(w, r, res, fr, errServer())
			return
		}
	}
	if login {
		fr.LoginHint = loginHint
		if sess != nil {
			fr.Prompt = "login"
		}
		h.startLogin(w, r, res, client, fr)
		return
	}
	h.finish(w, r, res, client, fr, sess, nil, true, true)
}

// DenyCIBA marks a pending request denied and shows the denied page.
func (h *Handlers) DenyCIBA(w http.ResponseWriter, r *http.Request, res tenant.Resolved, req *store.CIBARequest, uiLocales string) {
	fr := cibaFlow(req, uiLocales)
	if _, verr, _ := h.validateFlow(r.Context(), res, &fr); verr != nil {
		h.flowError(w, r, res, fr, verr)
		return
	}
	h.decideCIBA(w, r, res, fr, store.CIBADecision{Status: store.CIBADenied})
}

// decideCIBA records dec and shows the result. A request decided,
// expired or removed meanwhile keeps its state and shows the error page.
func (h *Handlers) decideCIBA(w http.ResponseWriter, r *http.Request, res tenant.Resolved, fr flowReq, dec store.CIBADecision) {
	ctx := r.Context()
	repo, err := store.CIBA(ctx, h.Store)
	if err == nil {
		_, err = repo.DecideCIBARequest(ctx, res.Tenant.ID, fr.CIBAHash, dec)
	}
	switch {
	case errors.Is(err, store.ErrAlreadyUsed) || errors.Is(err, store.ErrNotFound):
		h.flowError(w, r, res, fr, errCIBANotPending)
	case err != nil:
		h.log().ErrorContext(ctx, "decide CIBA request", "tenant", res.Tenant.ID, "err", err)
		h.flowError(w, r, res, fr, errServer())
	case dec.Status == store.CIBAApproved:
		redirect(w, r, "/bc-verify/approved")
	default:
		redirect(w, r, "/bc-verify/denied")
	}
}
