package login

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// resetCookie holds the CSRF token of the new-password form.
const resetCookie = "za_reset"

// resetContinueCookie carries "<ticket>.<za_reset value>" to /continue while a
// password-reset-post-challenge Action redirects. It is SameSite=None, like
// the session cookie, because the browser returns from another site, and it
// is scoped to /continue.
const resetContinueCookie = "za_reset_continue"

// errResetUnusable: the ticket's user or connection cannot be reset.
var errResetUnusable = errors.New("login: reset ticket is not usable")

func (h *Handlers) resetRequestData(f *flow, email string) ui.ResetRequestData {
	return ui.ResetRequestData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken, Email: email,
		LoginURL:    "/u/login?" + url.Values{"state": {f.txn.ID}}.Encode(),
		RedirectURI: f.txn.Params["redirect_uri"],
	}
}

// ResetRequestPage serves GET /u/reset-password/request: the email form
// (screen reset-password-request), in the login transaction's language.
func (h *Handlers) ResetRequestPage(w http.ResponseWriter, r *http.Request) {
	if h.Resets == nil {
		http.NotFound(w, r)
		return
	}
	f, err := h.load(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !h.captchaPage(w, r, f, "reset-send") {
		return
	}
	ui.RenderResetRequest(w, http.StatusOK, f.view, h.resetRequestData(f, f.txn.Params["login_hint"]))
}

// ResetRequestSubmit serves POST /u/reset-password/request. It always shows
// the same page, so the response does not reveal whether the address has an
// account; the link is emailed only to an existing, unblocked user within
// the send limit. Exhausted send budgets preserve the generic response.
func (h *Handlers) ResetRequestSubmit(w http.ResponseWriter, r *http.Request) {
	if h.Resets == nil {
		http.NotFound(w, r)
		return
	}
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	attemptID := secrets.RandomString(32)
	if err := h.submitCaptcha(r, f.res, &f.view, "reset-send", f.txn.ID, attemptID); err != nil {
		status, key := captchaFailure(err)
		data := h.resetRequestData(f, r.PostForm.Get("email"))
		data.Error = f.view.L.T(key)
		ui.RenderResetRequest(w, status, f.view, data)
		return
	}
	ctx := r.Context()
	user, err := h.Resets.FindByEmail(ctx, f.conn, r.PostForm.Get("email"))
	var ue *identity.UnauthorizedError
	switch {
	case err == nil:
		if err := h.Resets.RequestReset(f.res, f.conn, user, f.txn.ClientID, f.view.L.Lang()); err != nil {
			h.fail(w, r, err, f)
			return
		}
	case errors.As(err, &ue), errors.Is(err, store.ErrNotFound), errors.Is(err, identity.ErrScript):
		// Nothing to send; the page must not say so. identity has logged
		// a script failure.
	default:
		h.log().ErrorContext(ctx, "reset request: find user", "tenant", f.res.Tenant.ID, "err", err)
	}
	ui.RenderResetEmailSent(w, f.view)
}

// resetProblem names the reset-password-error screen variants.
type resetProblem int

const (
	resetInvalid resetProblem = iota
	resetExpired
	resetUsed
)

func (h *Handlers) renderResetError(w http.ResponseWriter, view ui.Tenant, p resetProblem) {
	title, desc := i18n.KeyResetErrGenericTitle, i18n.KeyResetErrGeneric
	switch p {
	case resetExpired:
		title, desc = i18n.KeyResetErrExpiredTitle, i18n.KeyResetErrExpired
	case resetUsed:
		title, desc = i18n.KeyResetErrUsedTitle, i18n.KeyResetErrUsed
	}
	ui.RenderResetError(w, http.StatusBadRequest, view, ui.ResetErrorData{Title: view.L.T(title), Description: view.L.T(desc)})
}

// resetTicket looks up the ticket without consuming it. On failure it
// returns the error screen to show, or err for a storage failure. view is
// in the ticket's language when the ticket exists, otherwise the request's.
func (h *Handlers) resetTicket(r *http.Request, res tenant.Resolved, raw string) (tk *store.PasswordResetTicket, view ui.Tenant, p resetProblem, err error) {
	view = ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
	if raw == "" {
		return nil, view, resetInvalid, nil
	}
	tk, err = h.Store.PasswordResetTickets().GetByTokenHash(r.Context(), res.Tenant.ID, secrets.HashToken(raw))
	if errors.Is(err, store.ErrNotFound) || err == nil && res.CheckOrigin(tk.Origin) != nil {
		// Another origin's link is invalid here, and is left unused.
		return nil, view, resetInvalid, nil
	}
	if err != nil {
		return nil, view, resetInvalid, err
	}
	view = ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, tk.Lang))
	switch {
	case tk.UsedAt != nil:
		return nil, view, resetUsed, nil
	case !h.now().Before(tk.ExpiresAt):
		return nil, view, resetExpired, nil
	}
	return tk, view, 0, nil
}

func setResetCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: resetCookie, Value: value, Path: "/u/reset-password", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// ResetPasswordPage serves GET /u/reset-password?ticket=…: the
// new-password form (screen reset-password), or the error screen for an
// unknown, used or expired ticket. Viewing the form does not use the ticket.
// A bound password-reset-post-challenge flow runs first, unless the ticket
// already passed it.
func (h *Handlers) ResetPasswordPage(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		h.fail(w, r, errTxn, nil)
		return
	}
	raw := r.URL.Query().Get("ticket")
	tk, view, p, err := h.resetTicket(r, res, raw)
	if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	if tk == nil {
		h.renderResetError(w, view, p)
		return
	}
	csrf := secrets.RandomString(32)
	setResetCookie(w, csrf, 900)
	if tk.ChallengePassedAt == nil && !h.resetChallenge(w, r, res, view, raw, tk, csrf) {
		return
	}
	h.showResetForm(w, r, res, view, raw, tk, csrf)
}

func (h *Handlers) showResetForm(w http.ResponseWriter, r *http.Request, res tenant.Resolved, view ui.Tenant, raw string, tk *store.PasswordResetTicket, csrf string) {
	// The challenge may have just stored its result URL. Read the committed
	// ticket so both the direct and continuation form admit its validated origin.
	fresh, err := h.Store.PasswordResetTickets().GetByTokenHash(r.Context(), res.Tenant.ID, secrets.HashToken(raw))
	if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	tk = fresh
	if _, err := h.prepareCaptcha(r, res, &view, "reset", tk.ID); err != nil {
		status, key := captchaFailure(err)
		ui.RenderError(w, status, view, view.L.T(key))
		return
	}
	ui.RenderResetForm(w, http.StatusOK, view, ui.ResetFormData{Ticket: raw, CSRF: csrf, RedirectURI: tk.ChallengeResultURL})
}

// resetChallengeBound reports whether password-reset-post-challenge has
// bindings now; POST reads it again, so bindings added after the page
// loaded still apply.
func (h *Handlers) resetChallengeBound(ctx context.Context, tenantID string) (bool, error) {
	bound, err := h.Store.Actions().Bindings(ctx, tenantID, actions.TriggerResetPostChallenge)
	return len(bound) > 0, err
}

// resetRequest is event.request for the reset page. The ticket, a bearer
// credential, is not shown to Actions.
func (h *Handlers) resetRequest(r *http.Request, res tenant.Resolved) actions.RequestInfo {
	q := map[string]any{}
	for k, v := range r.URL.Query() {
		if k != "ticket" && len(v) > 0 {
			q[k] = v[0]
		}
	}
	return actions.RequestInfo{IP: httpx.ClientIP(r, h.TrustProxyHeaders), Hostname: res.Host, Origin: res.Origin(), Method: r.Method,
		UserAgent: r.UserAgent(), Language: r.Header.Get("Accept-Language"), Query: q}
}

// resetChallenge runs the flow for an unpassed ticket. It reports whether
// the form may be shown; otherwise it has written the response.
func (h *Handlers) resetChallenge(w http.ResponseWriter, r *http.Request, res tenant.Resolved, view ui.Tenant, raw string, tk *store.PasswordResetTicket, csrf string) bool {
	ctx := r.Context()
	if h.Actions == nil {
		// Bound Actions without a runtime fail closed.
		bound, err := h.resetChallengeBound(ctx, res.Tenant.ID)
		if err != nil {
			h.fail(w, r, err, nil)
			return false
		}
		if bound {
			h.log().ErrorContext(ctx, "reset: password-reset-post-challenge is bound but the Actions runtime is unavailable", "tenant", res.Tenant.ID)
			ui.RenderError(w, http.StatusInternalServerError, view, view.L.T(i18n.KeyErrServer))
		}
		return !bound
	}
	in := actions.ResetChallengeInput{Tenant: res, Ticket: tk, Request: h.resetRequest(r, res), CanRedirect: true, PageCookie: csrf,
		Prepare: func(ctx context.Context, in *actions.ResetChallengeInput) error {
			user, err := h.Store.Users().Get(ctx, res.Tenant.ID, tk.UserID)
			if errors.Is(err, store.ErrNotFound) || err == nil && user.Blocked {
				return errResetUnusable
			} else if err != nil {
				return err
			}
			conn, err := h.Store.Connections().GetByName(ctx, res.Tenant.ID, tk.Connection)
			if errors.Is(err, store.ErrNotFound) || err == nil && conn.Strategy != store.StrategyDatabase {
				return errResetUnusable
			} else if err != nil {
				return err
			}
			in.User, in.Connection = user, conn
			if tk.ClientID != "" {
				client, err := h.Store.Clients().Get(ctx, res.Tenant.ID, tk.ClientID)
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					return err
				}
				in.Client = client
			}
			return nil
		}}
	result, err := h.Actions.ResetPostChallenge(ctx, in)
	return h.resetOutcome(w, r, res, view, raw, csrf, result, err)
}

// resetOutcome applies a challenge flow's result: deny, failure or redirect
// write the response and report false; a completed flow records the pass on
// the ticket. The ticket is never spent here.
func (h *Handlers) resetOutcome(w http.ResponseWriter, r *http.Request, res tenant.Resolved, view ui.Tenant, raw, page string, result *actions.Result, err error) bool {
	ctx := r.Context()
	var failed *actions.ErrFlow
	switch {
	case errors.Is(err, errResetUnusable):
		h.renderResetError(w, view, resetInvalid)
		return false
	case errors.As(err, &failed):
		ui.RenderErrorReference(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrServer), failed.ExecutionID)
		return false
	case err != nil:
		h.fail(w, r, err, nil)
		return false
	case result.Denied != nil:
		desc := result.Denied.Reason
		if desc == "" {
			desc = view.L.T(i18n.KeyResetErrGeneric)
		}
		ui.RenderResetError(w, http.StatusBadRequest, view, ui.ResetErrorData{Title: view.L.T(i18n.KeyResetErrGenericTitle), Description: desc})
		return false
	case result.Redirect != nil:
		http.SetCookie(w, &http.Cookie{Name: resetContinueCookie, Value: raw + "." + page, Path: "/continue", MaxAge: 900,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode})
		// The page URL holds the ticket; it must not leak as a referrer.
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, result.Redirect.URL, http.StatusFound)
		return false
	case result.ExecutionID == "":
		return true // nothing bound
	}
	err = h.Store.PasswordResetTickets().MarkChallengePassed(ctx, res.Tenant.ID, secrets.HashToken(raw), h.now(), result.ResultURL)
	switch {
	case errors.Is(err, store.ErrAlreadyUsed):
		h.renderResetError(w, view, resetUsed)
	case errors.Is(err, store.ErrNotFound):
		h.renderResetError(w, view, resetExpired)
	case err != nil:
		h.fail(w, r, err, nil)
	default:
		return true
	}
	return false
}

// ResetContinue resumes a reset page's suspended challenge flow from
// /continue. The state, the ticket and the page cookie must all match; a
// completed flow records the pass and shows the new-password form.
func (h *Handlers) ResetContinue(w http.ResponseWriter, r *http.Request, state string, req actions.RequestInfo) {
	invalid := func() { httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid continuation state") }
	res, ok := tenant.FromContext(r.Context())
	if !ok || h.Actions == nil {
		invalid()
		return
	}
	c, err := r.Cookie(resetContinueCookie)
	if err != nil {
		invalid()
		return
	}
	raw, page, ok := strings.Cut(c.Value, ".")
	if !ok || raw == "" || page == "" {
		invalid()
		return
	}
	tk, view, p, err := h.resetTicket(r, res, raw)
	if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	if tk == nil {
		h.renderResetError(w, view, p)
		return
	}
	result, err := h.Actions.ContinueResetChallenge(r.Context(), res.Tenant.ID, state, secrets.HashToken(raw), page, req)
	if errors.Is(err, actions.ErrInvalidContinue) {
		invalid()
		return
	}
	if err != nil || result.Redirect == nil {
		http.SetCookie(w, &http.Cookie{Name: resetContinueCookie, Value: "", Path: "/continue", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode})
	}
	if !h.resetOutcome(w, r, res, view, raw, page, result, err) {
		return
	}
	csrf := secrets.RandomString(32)
	setResetCookie(w, csrf, 900)
	h.showResetForm(w, r, res, view, raw, tk, csrf)
}

// ResetPasswordSubmit serves POST /u/reset-password. It ends every
// session, refresh token and other reset link of the user, sets the new
// password, clears any login lock on the user, and clears the caller's
// session cookie (D-0019).
func (h *Handlers) ResetPasswordSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok {
		h.fail(w, r, errTxn, nil)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		h.renderResetError(w, ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, "")), resetInvalid)
		return
	}
	// 1. CSRF: the form's token must match the za_reset cookie.
	csrf := r.PostForm.Get("csrf")
	c, cerr := r.Cookie(resetCookie)
	csrfOK := cerr == nil && c.Value != "" && subtle.ConstantTimeCompare([]byte(csrf), []byte(c.Value)) == 1

	attemptID := secrets.RandomString(32)
	// 2. The ticket. A forged or stale form still learns nothing beyond
	// what the ticket holder could see by opening the link; once the
	// ticket is used or expired that screen wins, otherwise a CSRF failure
	// shows the generic one.
	raw := r.PostForm.Get("ticket")
	tk, view, p, err := h.resetTicket(r, res, raw)
	if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	if tk == nil {
		if csrfOK {
			if err := h.protectionService().RecordFailure(ctx, h.captchaAttempt(r, res, "reset"), attemptID); err != nil {
				h.fail(w, r, err, nil)
				return
			}
		}
		h.renderResetError(w, view, p)
		return
	}
	if !csrfOK {
		h.renderResetError(w, view, resetInvalid)
		return
	}
	// A submit cannot skip a bound challenge, including one bound after the
	// page loaded. The ticket stays unused.
	if tk.ChallengePassedAt == nil {
		bound, err := h.resetChallengeBound(ctx, res.Tenant.ID)
		if err != nil {
			h.fail(w, r, err, nil)
			return
		}
		if bound {
			h.log().InfoContext(ctx, "reset refused: challenge not passed", "tenant", res.Tenant.ID, "user_id", tk.UserID)
			h.renderResetError(w, view, resetInvalid)
			return
		}
	}
	conn, err := h.Store.Connections().GetByName(ctx, res.Tenant.ID, tk.Connection)
	if errors.Is(err, store.ErrNotFound) || (err == nil && conn.Strategy != store.StrategyDatabase) {
		h.renderResetError(w, view, resetInvalid)
		return
	} else if err != nil {
		h.fail(w, r, err, nil)
		return
	}

	// 3. The new password; the ticket stays usable while it is rejected.
	pw := r.PostForm.Get("password")
	form := ui.ResetFormData{Ticket: raw, CSRF: csrf, RedirectURI: tk.ChallengeResultURL}
	if err := h.submitCaptcha(r, res, &view, "reset", tk.ID, attemptID); err != nil {
		status, key := captchaFailure(err)
		form.Error = view.L.T(key)
		ui.RenderResetForm(w, status, view, form)
		return
	}
	if pw != r.PostForm.Get("password_confirm") {
		form.Error = view.L.T(i18n.KeyResetPasswordMismatch)
		ui.RenderResetForm(w, http.StatusBadRequest, view, form)
		return
	}
	// 4. The user must still exist and not be blocked. The ticket is not
	// spent otherwise. The user is needed to check the password (history,
	// personal data), so this comes first.
	user, err := h.Store.Users().Get(ctx, res.Tenant.ID, tk.UserID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && user.Blocked) {
		h.renderResetError(w, view, resetInvalid)
		return
	} else if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	history, err := identity.LoadHistory(ctx, h.Store, conn, user.UserID)
	if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	var pe *identity.PolicyError
	if err := identity.CheckPassword(conn, identity.PersonOf(user), pw, history); errors.As(err, &pe) {
		if riskErr := h.recordFailure(r, res, "reset", attemptID, err); riskErr != nil {
			h.fail(w, r, riskErr, nil)
			return
		}

		if _, err := h.prepareCaptcha(r, res, &view, "reset", tk.ID); err != nil {
			status, key := captchaFailure(err)
			form.Error = view.L.T(key)
			ui.RenderResetForm(w, status, view, form)
			return
		}
		form.Error = policyMessage(view.L, pe)
		ui.RenderResetForm(w, http.StatusBadRequest, view, form)
		return
	} else if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	pw = identity.EffectivePassword(conn, pw)
	if err := h.protectionService().CheckPassword(ctx, res.Tenant, "pre-change-password", pw); err != nil {
		if riskErr := h.recordFailure(r, res, "reset", attemptID, err); riskErr != nil {
			h.fail(w, r, riskErr, nil)
			return
		}

		if _, err := h.prepareCaptcha(r, res, &view, "reset", tk.ID); err != nil {
			status, key := captchaFailure(err)
			form.Error = view.L.T(key)
			ui.RenderResetForm(w, status, view, form)
			return
		}
		status, key := breachFailure(err, http.StatusBadRequest)
		form.Error = view.L.T(key)
		ui.RenderResetForm(w, status, view, form)
		return
	}

	// 5. Hash outside the transaction for local credentials or legacy history.
	legacy := identity.IsLegacy(conn)
	var hash string
	if !legacy || (conn.PasswordOptions.History.Active && conn.PasswordOptions.History.Size > 0) {
		if hash, err = secrets.Hash(pw); err != nil {
			h.fail(w, r, err, nil)
			return
		}
	}

	// 6. Use the ticket. On a legacy connection this comes before the
	// change_password script (step 7), so two submits of one link run the
	// script at most once: the second gets the used-link page. A script
	// that then refuses or fails has spent the link; the form shows why,
	// and the user asks for a new link.
	now := h.now()
	tk, err = h.Store.PasswordResetTickets().Consume(ctx, res.Tenant.ID, secrets.HashToken(raw), now)
	switch {
	case errors.Is(err, store.ErrAlreadyUsed):
		h.renderResetError(w, view, resetUsed)
		return
	case errors.Is(err, store.ErrNotFound):
		h.renderResetError(w, view, resetInvalid)
		return
	case err != nil:
		h.fail(w, r, err, nil)
		return
	case !now.Before(tk.ExpiresAt):
		h.renderResetError(w, view, resetExpired)
		return
	}

	// 7. Set the password in the legacy store.
	if legacy {
		err := h.Database.ChangeLegacyPassword(ctx, conn, user, pw)
		var ue *identity.UnauthorizedError
		switch {
		case errors.As(err, &ue):
			form.Error = ue.Message
			ui.RenderResetForm(w, http.StatusBadRequest, view, form)
			return
		case errors.Is(err, identity.ErrPasswordNotChanged):
			form.Error = view.L.T(i18n.KeyResetNotChanged)
			ui.RenderResetForm(w, http.StatusBadRequest, view, form)
			return
		case err != nil:
			h.fail(w, r, err, nil)
			return
		}
	}

	// 8. In one transaction, log the user out everywhere, invalidate
	// their other reset links, record last_password_reset, queue
	// post-change-password and, on a local connection, set the password.
	// Either way the user's Version changes, so a grant that checked the
	// old password and has not minted yet is refused. A storage failure
	// rolls this step back, but the link is already spent (and on a legacy
	// connection the password has changed); the user should reset again.
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		// The first statement locks the user, so a grant minting for the
		// user runs wholly before this transaction (its tokens are revoked
		// below) or after it (its version check refuses it). A legacy
		// reset writes no local password, so it bumps the Version itself.
		if legacy {
			if _, err := tx.Users().BumpVersion(ctx, res.Tenant.ID, tk.UserID); err != nil {
				return err
			}
		}
		if err := recordPasswordReset(ctx, tx, res.Tenant.ID, tk.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Sessions().DeleteByUser(ctx, res.Tenant.ID, tk.UserID); err != nil {
			return err
		}
		if _, err := tx.RefreshTokens().RevokeByUser(ctx, res.Tenant.ID, tk.UserID, now); err != nil {
			return err
		}
		if _, err := tx.PasswordResetTickets().DeleteByUser(ctx, res.Tenant.ID, tk.UserID); err != nil {
			return err
		}
		if err := protection.ClearIdentity(ctx, tx, conn, user); err != nil {
			return err
		}
		if !legacy {
			if err := tx.Users().SetPasswordHash(ctx, res.Tenant.ID, tk.UserID, tk.Connection, hash, now); err != nil {
				return err
			}
		}
		if err := identity.RecordPassword(ctx, tx, conn, tk.UserID, hash); err != nil {
			return err
		}
		changed, err := tx.Users().Get(ctx, res.Tenant.ID, tk.UserID)
		if err != nil {
			return err
		}
		return actions.PasswordChanged(ctx, tx, h.Actions, res, changed, conn, actions.RequestInfo{IP: httpx.ClientIP(r, h.TrustProxyHeaders),
			Hostname: res.Host, Origin: res.Origin(), Method: r.Method, UserAgent: r.UserAgent(), Language: r.Header.Get("Accept-Language")})
	})
	if errors.Is(err, store.ErrNotFound) {
		h.renderResetError(w, view, resetInvalid)
		return
	} else if err != nil {
		h.fail(w, r, err, nil)
		return
	}
	h.log().InfoContext(ctx, "password reset", "tenant", res.Tenant.ID, "user_id", tk.UserID)
	// A Management API ticket with mark_email_as_verified also verifies
	// the email (U6). Its result_url is not used: Auth0's page shows the
	// success message and does not redirect. An Action's setResultUrl does
	// redirect (D-0054).
	if tk.MarkEmailVerified {
		if err := h.setEmailVerified(ctx, res.Tenant.ID, tk.UserID, now); err != nil {
			h.log().ErrorContext(ctx, "reset: mark email verified", "tenant", res.Tenant.ID, "user_id", tk.UserID, "err", err)
		}
	}

	// 10. Clear the form and session cookies.
	setResetCookie(w, "", -1)
	if _, err := h.Sessions.End(ctx, w, r, res.Tenant); err != nil {
		h.log().WarnContext(ctx, "reset: end session", "tenant", res.Tenant.ID, "err", err)
	}
	if tk.ChallengeResultURL != "" {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, tk.ChallengeResultURL, http.StatusFound)
		return
	}
	ui.RenderResetSuccess(w, view)
}

// recordPasswordReset locks the user and sets last_password_reset in tx.
func recordPasswordReset(ctx context.Context, tx store.Store, tenantID, userID string, at time.Time) error {
	u, err := tx.Users().GetForUpdate(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	u.LastPasswordReset, u.UpdatedAt = &at, at
	return tx.Users().Update(ctx, u)
}
