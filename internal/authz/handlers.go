// internal/authz/handlers.go
package authz

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

const (
	// TxnCookiePrefix + transaction ID names the cookie binding a login
	// transaction to the browser that started it.
	TxnCookiePrefix = "za_txn_"
	TxnLifetime     = 15 * time.Minute
	CodeLifetime    = 60 * time.Second
)

type Handlers struct {
	Store    store.Store
	Sessions *session.Manager
	Log      *slog.Logger
	Now      func() time.Time
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// Authorize implements GET /authorize.
func (h *Handlers) Authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, r.URL.Query().Get("ui_locales")))
	req := ParseRequest(r.URL.Query())
	client, verr, redirectable := validate(ctx, h.Store, res.Tenant, &req)
	if verr != nil {
		if !redirectable {
			ui.RenderErrorDetail(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrInvalidRequest), verr.Description)
			return
		}
		writeResponse(w, r, req, errorParams(verr, req.State))
		return
	}

	sess, err := h.Sessions.Current(ctx, r, res.Tenant)
	if err != nil {
		h.log().ErrorContext(ctx, "load session", "tenant", res.Tenant.ID, "err", err)
		writeResponse(w, r, req, errorParams(errServer(), req.State))
		return
	}
	if sess != nil {
		// A session outlives its user: a blocked or deleted user must log in
		// again (and be refused there) rather than receive a code.
		u, err := h.Store.Users().Get(ctx, res.Tenant.ID, sess.UserID)
		switch {
		case errors.Is(err, store.ErrNotFound) || (err == nil && u.Blocked):
			sess = nil
		case err != nil:
			h.log().ErrorContext(ctx, "load session user", "tenant", res.Tenant.ID, "err", err)
			writeResponse(w, r, req, errorParams(errServer(), req.State))
			return
		}
	}
	login := h.needsLogin(req, sess)
	if !login {
		login, err = h.connectionDisabled(ctx, res, client, sess)
		if err != nil {
			h.log().ErrorContext(ctx, "load session connection", "tenant", res.Tenant.ID, "err", err)
			writeResponse(w, r, req, errorParams(errServer(), req.State))
			return
		}
	}
	if login {
		if slices.Contains(req.Prompts(), "none") {
			writeResponse(w, r, req, errorParams(errLoginRequired(), req.State))
			return
		}
		h.startLogin(w, r, res, client, req)
		return
	}
	h.issueCode(w, r, res, client, req, sess)
}

func (h *Handlers) needsLogin(req Request, sess *store.LoginSession) bool {
	if sess == nil || slices.Contains(req.Prompts(), "login") {
		return true
	}
	if req.Connection != "" && sess.Connection != req.Connection {
		return true
	}
	if maxAge, ok := req.MaxAgeSeconds(); ok && (maxAge == 0 || h.now().Sub(sess.AuthenticatedAt) > time.Duration(maxAge)*time.Second) {
		return true
	}
	return false
}

// connectionDisabled reports whether the session's connection is missing or
// not enabled for the client, in which case the session must not be reused.
func (h *Handlers) connectionDisabled(ctx context.Context, res tenant.Resolved, client *store.Client, sess *store.LoginSession) (bool, error) {
	conn, err := h.Store.Connections().GetByName(ctx, res.Tenant.ID, sess.Connection)
	if errors.Is(err, store.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return !slices.Contains(conn.EnabledClients, client.ClientID), nil
}

// startLogin stores the request in a transaction bound to this browser and
// sends the user to the hosted login (or signup) page.
func (h *Handlers) startLogin(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req Request) {
	ctx := r.Context()
	now := h.now()
	cookieValue := secrets.RandomString(43)
	params := req.Params()
	delete(params, "prompt") // prompt=login is satisfied by this login
	txn := &store.AuthTransaction{
		TenantID:   res.Tenant.ID,
		ID:         secrets.RandomString(24),
		CookieHash: secrets.HashToken(cookieValue),
		CSRFToken:  secrets.RandomString(32),
		ClientID:   client.ClientID,
		Params:     params,
		ExpiresAt:  now.Add(TxnLifetime),
		CreatedAt:  now,
	}
	if err := h.Store.AuthTransactions().Create(ctx, txn); err != nil {
		h.log().ErrorContext(ctx, "create login transaction", "tenant", res.Tenant.ID, "err", err)
		writeResponse(w, r, req, errorParams(errServer(), req.State))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: TxnCookiePrefix + txn.ID, Value: cookieValue, Path: "/u",
		MaxAge: int(TxnLifetime / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	page := "/u/login"
	if req.ScreenHint == "signup" {
		page = "/u/signup"
	}
	redirect(w, r, page+"?"+url.Values{"state": {txn.ID}}.Encode())
}

// Resume finishes a login transaction for an authenticated session. The
// login pages call it after a successful login or signup.
func (h *Handlers) Resume(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession) {
	ctx := r.Context()
	if err := h.Store.AuthTransactions().Delete(ctx, res.Tenant.ID, txn.ID); err != nil {
		h.log().WarnContext(ctx, "delete login transaction", "tenant", res.Tenant.ID, "err", err)
	}
	http.SetCookie(w, &http.Cookie{Name: TxnCookiePrefix + txn.ID, Value: "", Path: "/u", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})

	req := RequestFromParams(txn.Params)
	client, verr, redirectable := validate(ctx, h.Store, res.Tenant, &req)
	if verr != nil {
		// The application changed while the user was logging in.
		if !redirectable {
			view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, txn.Params["ui_locales"]))
			ui.RenderErrorDetail(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrInvalidRequest), verr.Description)
			return
		}
		writeResponse(w, r, req, errorParams(verr, req.State))
		return
	}
	h.issueCode(w, r, res, client, req, sess)
}

func (h *Handlers) issueCode(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req Request, sess *store.LoginSession) {
	ctx := r.Context()
	code, err := h.createCode(ctx, res, client, req, sess)
	if err != nil {
		h.log().ErrorContext(ctx, "issue authorization code", "tenant", res.Tenant.ID, "err", err)
		writeResponse(w, r, req, errorParams(errServer(), req.State))
		return
	}
	params := url.Values{"code": {code}}
	if req.State != "" {
		params.Set("state", req.State)
	}
	writeResponse(w, r, req, params)
}

func (h *Handlers) createCode(ctx context.Context, res tenant.Resolved, client *store.Client, req Request, sess *store.LoginSession) (string, error) {
	now := h.now()
	code := secrets.RandomString(43)
	ac := &store.AuthCode{
		TenantID:            res.Tenant.ID,
		CodeHash:            secrets.HashToken(code),
		ClientID:            client.ClientID,
		RedirectURI:         req.RedirectURI,
		UserID:              sess.UserID,
		SessionID:           sess.ID,
		Scopes:              req.Scopes(),
		Audience:            req.Audience,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		AuthTime:            sess.AuthenticatedAt,
		ExpiresAt:           now.Add(CodeLifetime),
		CreatedAt:           now,
	}
	if err := h.Store.AuthCodes().Create(ctx, ac); err != nil {
		return "", err
	}
	if err := h.Sessions.AddClient(ctx, sess, client.ClientID); err != nil {
		return "", err
	}
	return code, nil
}
