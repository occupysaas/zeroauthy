// internal/authz/handlers.go
package authz

import (
	"context"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
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
	Device         bool // a device authorization; CallbackDomain and RedirectURI are empty
}

// renderPageError shows e on the error page of an /authorize request that
// cannot be redirected: a store failure is a 500 page, anything else a 400
// invalid-request page.
func renderPageError(w http.ResponseWriter, view ui.Tenant, e *Error) {
	if e.Code == "server_error" {
		ui.RenderErrorDetail(w, http.StatusInternalServerError, view, view.L.T(i18n.KeyErrServer), "")
		return
	}
	ui.RenderErrorDetail(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrInvalidRequest), e.Description)
}

// Authorize implements GET and POST /authorize.
func (h *Handlers) Authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	q, ok := authorizeParams(w, r)
	if !ok {
		return
	}
	view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, q.Get("ui_locales")))
	req := ParseRequest(q)
	if q.Has("request_uri") {
		pushed, perr := h.resolvePushed(ctx, res.Tenant, q)
		if perr != nil {
			renderPageError(w, view, perr)
			return
		}
		if pushed != nil {
			req = *pushed
			view = ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, req.UILocales))
		}
	}
	client, verr, redirectable := ValidateRequest(ctx, h.Store, res.Tenant, &req)
	if verr != nil {
		if !redirectable {
			renderPageError(w, view, verr)
			return
		}
		h.deny(w, r, res, client, req, verr)
		return
	}
	fr := flowReq{Request: req}

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
		h.startLogin(w, r, res, client, fr)
		return
	}
	h.finish(w, r, res, client, fr, sess, false, false)
}

// maxAuthorizeFormBytes bounds a POST /authorize body.
const maxAuthorizeFormBytes = 64 << 10

// authorizeParams returns the authorization request parameters: the query
// of a GET, or the form-encoded body of a POST (OpenID Connect Core
// §3.1.2.1; the query of a POST is not read). For GET the generated
// wrapper has already refused repeated parameters; for POST the same rule
// is applied here. On failure the JSON error has been written.
func authorizeParams(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	if r.Method != http.MethodPost {
		return r.URL.Query(), true
	}
	fail := func(d string) (url.Values, bool) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", d)
		return nil, false
	}
	if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct != "application/x-www-form-urlencoded" {
		return fail("Content-Type must be application/x-www-form-urlencoded")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthorizeFormBytes)
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			httpx.WriteError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "the request body exceeds 64 KB")
			return nil, false
		}
		return fail("malformed form body")
	}
	for _, name := range append([]string{"request_uri", "request"}, paramNames...) {
		if len(r.PostForm[name]) > 1 {
			return fail("parameter " + strconv.Quote(name) + " is repeated")
		}
	}
	return r.PostForm, true
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
func (h *Handlers) startLogin(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq) {
	params := fr.params()
	var kept []string
	for _, p := range fr.Prompts() {
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
	if fr.ScreenHint == "signup" {
		page = "/u/signup"
	}
	h.startTxn(w, r, res, client, fr, params, page)
}

// startConsent sends an authenticated user to the consent page.
func (h *Handlers) startConsent(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, sess *store.LoginSession) {
	params := fr.params()
	params[ParamStage] = stageConsent
	params[sessionKey] = sess.ID
	h.startTxn(w, r, res, client, fr, params, "/u/consent")
}

// invalidTxn shows the generic error page for a transaction used at the
// wrong step.
func (h *Handlers) invalidTxn(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction) {
	view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, txn.Params["ui_locales"]))
	ui.RenderErrorDetail(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrInvalidRequest), view.L.T(i18n.KeyErrSessionExpired))
}

// startTxn stores params in a transaction bound to this browser and
// redirects to page.
func (h *Handlers) startTxn(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, params map[string]string, page string) {
	txn, err := h.CreateTxn(w, r, res, client.ClientID, params, "/u")
	if err != nil {
		h.log().ErrorContext(r.Context(), "create login transaction", "tenant", res.Tenant.ID, "err", err)
		h.refuse(w, r, res, client, fr, errServer())
		return
	}
	redirect(w, r, page+"?"+url.Values{"state": {txn.ID}}.Encode())
}

// Resume finishes a login transaction for an authenticated session. The
// login pages call it after a successful login or signup.
func (h *Handlers) Resume(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession) {
	// Only a login transaction resumes: consent and the device pages have
	// their own steps.
	if txn.Params[ParamStage] != "" {
		h.invalidTxn(w, r, res, txn)
		return
	}
	h.EndTxn(w, r, res, txn)
	fr := flowFromParams(txn.Params)
	client, verr, redirectable := h.validateFlow(r.Context(), res, &fr)
	if verr != nil {
		// The application (or the device code) changed while the user was
		// logging in.
		if !redirectable {
			h.flowError(w, r, res, fr, verr)
			return
		}
		h.refuse(w, r, res, client, fr, verr)
		return
	}
	// The login or signup page was just shown, so no confirmation (D-0027).
	h.finish(w, r, res, client, fr, sess, false, true)
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

// deny delivers an /authorize error, or shows it on an error page when
// the client's redirection_policy protects it (D-0027). Flows that may be
// device flows use refuse.
func (h *Handlers) deny(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, req Request, e *Error) {
	if access.ShowErrorPage(client) {
		view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, req.UILocales))
		if e.Code == "server_error" {
			renderPageError(w, view, e)
			return
		}
		ui.RenderErrorDetail(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrAccessDenied), e.Description)
		return
	}
	writeResponse(w, r, req, errorParams(e, req.State))
}

// accessInput loads what access.Decide needs for an interactive or device request.
// audienceKey is the audience a user grant is stored under.
func (h *Handlers) accessInput(ctx context.Context, res tenant.Resolved, client *store.Client, fr flowReq, userID string) (access.Input, string, error) {
	req := fr.Request
	in := access.Input{
		Flow: access.Interactive, Client: client, Scopes: req.Scopes(), Prompts: req.Prompts(),
		RedirectURI: req.RedirectURI, TenantSkipConfirmation: res.Tenant.SkipNonVerifiableCallbackURIConfirmationPrompt,
	}
	if fr.device() {
		in.Flow = access.Device
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

// finish runs the access decision for an authenticated request: it
// approves it, sends the browser to the consent page, or refuses it.
// accepted means the user just accepted the consent page for this request;
// screenShown means a login or signup page was shown in this transaction.
func (h *Handlers) finish(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, sess *store.LoginSession, accepted, screenShown bool) {
	ctx := r.Context()
	in, audienceKey, err := h.accessInput(ctx, res, client, fr, sess.UserID)
	if err != nil {
		h.log().ErrorContext(ctx, "load access decision input", "tenant", res.Tenant.ID, "err", err)
		h.refuse(w, r, res, client, fr, errServer())
		return
	}
	in.ScreenShown = screenShown || accepted
	d := access.Decide(in)
	switch {
	case d.Err != nil:
		h.refuse(w, r, res, client, fr, &Error{d.Err.Code, d.Err.Description})
		return
	case (d.Consent || d.Confirmation) && !accepted:
		h.startConsent(w, r, res, client, fr, sess)
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
			h.refuse(w, r, res, client, fr, errServer())
			return
		}
	}
	h.approve(w, r, res, client, fr, sess, d.Scopes)
}

// Consent finishes a consent-page transaction. Declining is access_denied
// (a denied code for the device flow).
func (h *Handlers) Consent(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession, accepted bool) {
	ctx := r.Context()
	if txn.Params[ParamStage] != stageConsent {
		h.invalidTxn(w, r, res, txn)
		return
	}
	h.EndTxn(w, r, res, txn)
	fr := flowFromParams(txn.Params)
	client, verr, redirectable := h.validateFlow(ctx, res, &fr)
	if verr != nil {
		if !redirectable {
			h.flowError(w, r, res, fr, verr)
			return
		}
		h.refuse(w, r, res, client, fr, verr)
		return
	}
	if !accepted {
		h.refuse(w, r, res, client, fr, errUserDeclined())
		return
	}
	// Login freshness (prompt=login, max_age, connection) was settled before
	// this transaction began, so it is not checked again. The session must be
	// the one the page was shown for, and its connection must still be usable.
	login := sess.ID != txn.Params[sessionKey]
	if !login {
		var err error
		if login, err = h.connectionDisabled(ctx, res, client, sess); err != nil {
			h.log().ErrorContext(ctx, "load session connection", "tenant", res.Tenant.ID, "err", err)
			h.refuse(w, r, res, client, fr, errServer())
			return
		}
	}
	if login {
		h.startLogin(w, r, res, client, fr)
		return
	}
	h.finish(w, r, res, client, fr, sess, true, true)
}

// ConsentView describes the page for txn. It returns an error when the
// request is no longer valid; the caller shows the generic error page.
func (h *Handlers) ConsentView(ctx context.Context, res tenant.Resolved, txn *store.AuthTransaction, sess *store.LoginSession) (*ConsentView, error) {
	if txn.Params[ParamStage] != stageConsent {
		return nil, errors.New("not a consent transaction")
	}
	fr := flowFromParams(txn.Params)
	client, verr, _ := h.validateFlow(ctx, res, &fr)
	if verr != nil {
		return nil, errors.New(verr.Description)
	}
	in, _, err := h.accessInput(ctx, res, client, fr, sess.UserID)
	if err != nil {
		return nil, err
	}
	d := access.Decide(in)
	if d.Err != nil {
		return nil, errors.New(d.Err.Description)
	}
	v := &ConsentView{ThirdParty: !client.IsFirstParty, Device: fr.device()}
	if !v.Device { // the device flow has no confirmation variant and no callback
		v.Confirmation, v.RedirectURI = !d.Consent, fr.RedirectURI
		if u, err := url.Parse(fr.RedirectURI); err == nil {
			v.CallbackDomain = u.Hostname()
			if v.CallbackDomain == "" {
				v.CallbackDomain = u.Scheme + ":"
			}
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
