// internal/authz/handlers.go
package authz

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
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

// ConsentView describes the consent page of a transaction.
type ConsentView struct {
	Confirmation   bool     // the confirmation variant; otherwise consent
	ThirdParty     bool     // show the external-application notice
	CallbackDomain string   // host of redirect_uri, or its scheme for custom schemes
	APIName        string   // the API's name (identifier when unnamed); empty without an audience
	Scopes         []string // labels: scope names, or descriptions per use_scope_descriptions_for_consent
	RedirectURI    string
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
		h.deny(w, r, res, client, req, verr)
		return
	}

	sess, err := h.ActiveSession(ctx, r, res)
	if err != nil {
		h.log().ErrorContext(ctx, "load session", "tenant", res.Tenant.ID, "err", err)
		h.deny(w, r, res, client, req, errServer())
		return
	}
	login := h.needsLogin(req, sess)
	if !login {
		login, err = h.connectionDisabled(ctx, res, client, sess)
		if err != nil {
			h.log().ErrorContext(ctx, "load session connection", "tenant", res.Tenant.ID, "err", err)
			h.deny(w, r, res, client, req, errServer())
			return
		}
	}
	if login {
		if slices.Contains(req.Prompts(), "none") {
			h.deny(w, r, res, client, req, errLoginRequired())
			return
		}
		h.startLogin(w, r, res, client, req)
		return
	}
	h.finish(w, r, res, client, req, sess, false, false)
}

// ActiveSession returns the browser's session for res, or nil when there is
// none or its user is missing or blocked.
func (h *Handlers) ActiveSession(ctx context.Context, r *http.Request, res tenant.Resolved) (*store.LoginSession, error) {
	sess, err := h.Sessions.Current(ctx, r, res.Tenant)
	if err != nil || sess == nil {
		return nil, err
	}
	// A session outlives its user: a blocked or deleted user must log in
	// again (and be refused there) rather than receive a code.
	u, err := h.Store.Users().Get(ctx, res.Tenant.ID, sess.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound) || (err == nil && u.Blocked):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return sess, nil
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
	return !access.ConnectionUsable(client, conn), nil
}

// startLogin stores the request in a transaction bound to this browser and
// sends the user to the hosted login (or signup) page.
func (h *Handlers) startLogin(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req Request) {
	params := req.Params()
	var kept []string
	for _, p := range req.Prompts() {
		if p != "login" { // satisfied by this login
			kept = append(kept, p)
		}
	}
	if len(kept) > 0 {
		params["prompt"] = strings.Join(kept, " ")
	} else {
		delete(params, "prompt")
	}
	page := "/u/login"
	if req.ScreenHint == "signup" {
		page = "/u/signup"
	}
	h.startTxn(w, r, res, client, req, params, page)
}

// stageKey marks a consent transaction in its Params. It is not a request
// parameter: Params and RequestFromParams ignore it.
const (
	stageKey     = "za_stage"
	stageConsent = "consent"
)

// startConsent sends an authenticated user to the consent page.
func (h *Handlers) startConsent(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req Request) {
	params := req.Params()
	params[stageKey] = stageConsent
	h.startTxn(w, r, res, client, req, params, "/u/consent")
}

// invalidTxn shows the generic error page for a transaction used at the
// wrong step.
func (h *Handlers) invalidTxn(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction) {
	view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, txn.Params["ui_locales"]))
	ui.RenderErrorDetail(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrInvalidRequest), view.L.T(i18n.KeyErrSessionExpired))
}

// startTxn stores params in a transaction bound to this browser and
// redirects to page.
func (h *Handlers) startTxn(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req Request, params map[string]string, page string) {
	ctx := r.Context()
	now := h.now()
	cookieValue := secrets.RandomString(43)
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
		h.deny(w, r, res, client, req, errServer())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: TxnCookiePrefix + txn.ID, Value: cookieValue, Path: "/u",
		MaxAge: int(TxnLifetime / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	redirect(w, r, page+"?"+url.Values{"state": {txn.ID}}.Encode())
}

// Resume finishes a login transaction for an authenticated session. The
// login pages call it after a successful login or signup.
func (h *Handlers) Resume(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession) {
	ctx := r.Context()
	if txn.Params[stageKey] == stageConsent {
		h.invalidTxn(w, r, res, txn)
		return
	}
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
		h.deny(w, r, res, client, req, verr)
		return
	}
	// The login or signup page was just shown, so no confirmation (D-0027).
	h.finish(w, r, res, client, req, sess, false, true)
}

func (h *Handlers) issueCode(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req Request, sess *store.LoginSession, scopes []string) {
	ctx := r.Context()
	code, err := h.createCode(ctx, res, client, req, sess, scopes)
	if err != nil {
		h.log().ErrorContext(ctx, "issue authorization code", "tenant", res.Tenant.ID, "err", err)
		h.deny(w, r, res, client, req, errServer())
		return
	}
	params := url.Values{"code": {code}}
	if req.State != "" {
		params.Set("state", req.State)
	}
	writeResponse(w, r, req, params)
}

func (h *Handlers) createCode(ctx context.Context, res tenant.Resolved, client *store.Client, req Request, sess *store.LoginSession, scopes []string) (string, error) {
	now := h.now()
	code := secrets.RandomString(43)
	ac := &store.AuthCode{
		TenantID:            res.Tenant.ID,
		CodeHash:            secrets.HashToken(code),
		ClientID:            client.ClientID,
		RedirectURI:         req.RedirectURI,
		UserID:              sess.UserID,
		SessionID:           sess.ID,
		Scopes:              scopes,
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

// deny delivers an authorization error, or shows it on an error page when
// the client's redirection_policy protects it (D-0027).
func (h *Handlers) deny(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req Request, e *Error) {
	if access.ShowErrorPage(client) {
		view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, req.UILocales))
		ui.RenderErrorDetail(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrAccessDenied), e.Description)
		return
	}
	writeResponse(w, r, req, errorParams(e, req.State))
}

// accessInput loads what access.Decide needs for an interactive request.
// audienceKey is the audience a user grant is stored under.
func (h *Handlers) accessInput(ctx context.Context, res tenant.Resolved, client *store.Client, req Request, userID string) (access.Input, string, error) {
	in := access.Input{
		Flow: access.Interactive, Client: client, Scopes: req.Scopes(), Prompts: req.Prompts(),
		RedirectURI: req.RedirectURI, TenantSkipConfirmation: res.Tenant.SkipNonVerifiableCallbackURIConfirmationPrompt,
	}
	audienceKey := res.Issuer() + "userinfo" // O2
	if req.Audience != "" {
		rs, err := h.Store.ResourceServers().GetByIdentifier(ctx, res.Tenant.ID, req.Audience)
		if err != nil {
			return in, "", err
		}
		in.API, audienceKey = rs, rs.Identifier
		g, err := h.Store.ClientGrants().Find(ctx, res.Tenant.ID, client.ClientID, rs.Identifier, store.SubjectTypeUser)
		switch {
		case err == nil:
			in.ClientGrant = g
		case !errors.Is(err, store.ErrNotFound):
			return in, "", err
		}
	}
	ug, err := h.Store.UserGrants().Find(ctx, res.Tenant.ID, client.ClientID, userID, audienceKey)
	switch {
	case err == nil:
		in.UserGrant = ug
	case !errors.Is(err, store.ErrNotFound):
		return in, "", err
	}
	return in, audienceKey, nil
}

// finish runs the access decision for an authenticated request: it issues
// the code, sends the browser to the consent page, or delivers an error.
// accepted means the user just accepted the consent page for this request;
// screenShown means a login or signup page was shown in this transaction.
func (h *Handlers) finish(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req Request, sess *store.LoginSession, accepted, screenShown bool) {
	ctx := r.Context()
	in, audienceKey, err := h.accessInput(ctx, res, client, req, sess.UserID)
	if err != nil {
		h.log().ErrorContext(ctx, "load access decision input", "tenant", res.Tenant.ID, "err", err)
		h.deny(w, r, res, client, req, errServer())
		return
	}
	in.ScreenShown = screenShown || accepted
	d := access.Decide(in)
	switch {
	case d.Err != nil:
		h.deny(w, r, res, client, req, &Error{d.Err.Code, d.Err.Description})
		return
	case (d.Consent || d.Confirmation) && !accepted:
		h.startConsent(w, r, res, client, req)
		return
	case d.Consent: // accepted
		now := h.now()
		existing := []string(nil)
		if in.UserGrant != nil {
			existing = in.UserGrant.Scopes
		}
		if _, err := h.Store.UserGrants().Upsert(ctx, &store.UserGrant{
			TenantID: res.Tenant.ID, ID: "ugr_" + secrets.RandomString(24), ClientID: client.ClientID, UserID: sess.UserID,
			Audience: audienceKey, Scopes: access.GrantScopes(existing, d.Scopes), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			h.log().ErrorContext(ctx, "store user grant", "tenant", res.Tenant.ID, "err", err)
			h.deny(w, r, res, client, req, errServer())
			return
		}
	}
	h.issueCode(w, r, res, client, req, sess, d.Scopes)
}

// Consent finishes a consent-page transaction. Declining is access_denied.
func (h *Handlers) Consent(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession, accepted bool) {
	ctx := r.Context()
	if txn.Params[stageKey] != stageConsent {
		h.invalidTxn(w, r, res, txn)
		return
	}
	if err := h.Store.AuthTransactions().Delete(ctx, res.Tenant.ID, txn.ID); err != nil {
		h.log().WarnContext(ctx, "delete consent transaction", "tenant", res.Tenant.ID, "err", err)
	}
	http.SetCookie(w, &http.Cookie{Name: TxnCookiePrefix + txn.ID, Value: "", Path: "/u", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	req := RequestFromParams(txn.Params)
	client, verr, redirectable := validate(ctx, h.Store, res.Tenant, &req)
	if verr != nil {
		if !redirectable {
			view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, txn.Params["ui_locales"]))
			ui.RenderErrorDetail(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrInvalidRequest), verr.Description)
			return
		}
		h.deny(w, r, res, client, req, verr)
		return
	}
	if !accepted {
		h.deny(w, r, res, client, req, errUserDeclined())
		return
	}
	// The session may have changed since the page was shown. prompt=login was
	// satisfied before this transaction began.
	check := req
	check.Prompt = strings.Join(slices.DeleteFunc(req.Prompts(), func(p string) bool { return p == "login" }), " ")
	login := h.needsLogin(check, sess)
	if !login {
		var err error
		if login, err = h.connectionDisabled(ctx, res, client, sess); err != nil {
			h.log().ErrorContext(ctx, "load session connection", "tenant", res.Tenant.ID, "err", err)
			h.deny(w, r, res, client, req, errServer())
			return
		}
	}
	if login {
		h.startLogin(w, r, res, client, req)
		return
	}
	h.finish(w, r, res, client, req, sess, true, true)
}

// ConsentView describes the page for txn. It returns an error when the
// request is no longer valid; the caller shows the generic error page.
func (h *Handlers) ConsentView(ctx context.Context, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession) (*ConsentView, error) {
	if txn.Params[stageKey] != stageConsent {
		return nil, errors.New("not a consent transaction")
	}
	req := RequestFromParams(txn.Params)
	client, verr, _ := validate(ctx, h.Store, res.Tenant, &req)
	if verr != nil {
		return nil, errors.New(verr.Description)
	}
	in, _, err := h.accessInput(ctx, res, client, req, sess.UserID)
	if err != nil {
		return nil, err
	}
	d := access.Decide(in)
	if d.Err != nil {
		return nil, errors.New(d.Err.Description)
	}
	v := &ConsentView{Confirmation: !d.Consent, ThirdParty: !client.IsFirstParty, RedirectURI: req.RedirectURI}
	if u, err := url.Parse(req.RedirectURI); err == nil {
		v.CallbackDomain = u.Hostname()
		if v.CallbackDomain == "" {
			v.CallbackDomain = u.Scheme + ":"
		}
	}
	if in.API != nil {
		v.APIName = in.API.Name
		if v.APIName == "" {
			v.APIName = in.API.Identifier
		}
	}
	for _, s := range d.Scopes {
		label := s
		if res.Tenant.UseScopeDescriptionsForConsent && in.API != nil {
			if i := slices.IndexFunc(in.API.Scopes, func(d store.Scope) bool { return d.Value == s }); i >= 0 && in.API.Scopes[i].Description != "" {
				label = in.API.Scopes[i].Description
			}
		}
		v.Scopes = append(v.Scopes, label)
	}
	return v, nil
}
