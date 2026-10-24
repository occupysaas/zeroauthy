package login

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"

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
	view = ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
	if raw == "" {
		return nil, view, resetInvalid, nil
	}
	tk, err = h.Store.PasswordResetTickets().GetByTokenHash(r.Context(), res.Tenant.ID, secrets.HashToken(raw))
	if errors.Is(err, store.ErrNotFound) {
		return nil, view, resetInvalid, nil
	}
	if err != nil {
		return nil, view, resetInvalid, err
	}
	view = ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, tk.Lang))
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
	if _, err := h.prepareCaptcha(r, res, &view, "reset", tk.ID); err != nil {
		status, key := captchaFailure(err)
		ui.RenderError(w, status, view, view.L.T(key))
		return
	}
	csrf := secrets.RandomString(32)
	setResetCookie(w, csrf, 900)
	ui.RenderResetForm(w, http.StatusOK, view, ui.ResetFormData{Ticket: raw, CSRF: csrf})
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
		h.renderResetError(w, ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, "")), resetInvalid)
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
	form := ui.ResetFormData{Ticket: raw, CSRF: csrf}
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
	// their other reset links and, on a local connection, set the password.
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
		} else if _, err := tx.Users().GetForUpdate(ctx, res.Tenant.ID, tk.UserID); err != nil {
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
		if legacy {
			return identity.RecordPassword(ctx, tx, conn, tk.UserID, hash)
		}
		if err := tx.Users().SetPasswordHash(ctx, res.Tenant.ID, tk.UserID, tk.Connection, hash, now); err != nil {
			return err
		}
		return identity.RecordPassword(ctx, tx, conn, tk.UserID, hash)
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
	// success message and does not redirect.
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
	ui.RenderResetSuccess(w, view)
}
