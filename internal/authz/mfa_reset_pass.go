package authz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const resetMFAPassPrefix = "za_mfa_pass:"
const ResetMFAPassCookie = "za_reset_mfa_pass"
const resetMFAPassStage = "reset-mfa-pass"

type resetMFAPass struct {
	State                      MFAPending
	BrowserHash                string
	ExpiresAt, TicketExpiresAt time.Time
}

// IsMFAResetPass recognizes an internal marker which Action result URLs cannot
// produce: setResultUrl accepts only absolute HTTPS/localhost URLs. Its presence
// requires a valid receipt, including when the receipt is missing or expired.
func IsMFAResetPass(tk *store.PasswordResetTicket) bool {
	return tk != nil && strings.HasPrefix(tk.ChallengeResultURL, resetMFAPassPrefix)
}

func (h *Handlers) storeMFAResetPass(ctx context.Context, tx store.Store, res tenant.Resolved, txn *store.AuthTransaction, pending *MFAPending, browser string) error {
	tk, err := tx.PasswordResetTickets().GetByTokenHash(ctx, res.Tenant.ID, pending.ResetTicketHash)
	if err != nil {
		return err
	}
	id := "reset_mfa_pass_" + pending.ResetTicketHash
	proofTxn, err := tx.AuthTransactions().Get(ctx, res.Tenant.ID, txn.ID)
	if err != nil {
		return err
	}
	pass := resetMFAPass{State: *pending, BrowserHash: secrets.HashToken(browser), ExpiresAt: proofTxn.ExpiresAt, TicketExpiresAt: tk.ExpiresAt}
	plain, err := json.Marshal(pass)
	if err != nil {
		return err
	}
	sealed, err := keys.SealBound(h.Wrapper, "hosted-reset-mfa-pass/v1", []string{res.Tenant.ID, id, res.Origin()}, plain)
	if err != nil {
		return err
	}
	// Keep the record until its ticket expires; the sealed proof deadline can
	// expire sooner. Natural cleanup therefore cannot remove an active marker.
	receipt := &store.AuthTransaction{TenantID: res.Tenant.ID, ID: id, Origin: res.Origin(), CookieHash: secrets.HashToken(secrets.RandomString(43)), Params: map[string]string{ParamStage: resetMFAPassStage, mfaPendingKey: base64.RawURLEncoding.EncodeToString(sealed)}, CreatedAt: h.now(), ExpiresAt: tk.ExpiresAt}
	if err = tx.AuthTransactions().Create(ctx, receipt); err != nil {
		return err
	}
	return tx.PasswordResetTickets().MarkChallengePassed(ctx, res.Tenant.ID, tk.TokenHash, h.now(), resetMFAPassPrefix+id)
}

// ValidateMFAResetPass opens the proof receipt and checks the current final-form
// browser/page and user authority. Final submit must call it using tx and a user
// loaded with GetForUpdate, before ticket consumption or password writes.
// Unmarked reset tickets retain the existing non-MFA semantics.
func (h *Handlers) ValidateMFAResetPass(ctx context.Context, r *http.Request, res tenant.Resolved, st store.Store, tk *store.PasswordResetTicket, u *store.User) (string, error) {
	if !IsMFAResetPass(tk) {
		return tk.ChallengeResultURL, nil
	}
	invalid := store.ErrInvalid
	id := "reset_mfa_pass_" + tk.TokenHash
	if tk.TenantID != res.Tenant.ID || tk.ChallengeResultURL != resetMFAPassPrefix+id || h.Wrapper == nil || tk.ChallengePassedAt == nil || !h.now().Before(tk.ExpiresAt) {
		return "", invalid
	}
	receipt, err := st.AuthTransactions().Get(ctx, res.Tenant.ID, id)
	if err != nil {
		return "", invalid
	}
	if receipt.Params[ParamStage] != resetMFAPassStage || receipt.ClientID != "" || receipt.Origin != res.Origin() {
		return "", invalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(receipt.Params[mfaPendingKey])
	if err != nil {
		return "", invalid
	}
	plain, err := keys.OpenBound(h.Wrapper, "hosted-reset-mfa-pass/v1", []string{res.Tenant.ID, id, res.Origin()}, raw)
	if err != nil {
		return "", invalid
	}
	var pass resetMFAPass
	if json.Unmarshal(plain, &pass) != nil || !h.now().Before(pass.ExpiresAt) || !pass.TicketExpiresAt.Equal(tk.ExpiresAt) {
		return "", invalid
	}
	p := pass.State
	if p.Requirement.Reason != "reset" || p.ResetTicketHash != tk.TokenHash || p.UserID != tk.UserID || u == nil || u.TenantID != res.Tenant.ID || u.UserID != p.UserID || u.Blocked || u.Version != p.ResetUserVersion || u.RememberBrowserEpoch != p.RememberEpoch || u.Email != p.ResetEmail || u.EmailVerified != p.ResetEmailVerified {
		return "", invalid
	}
	page, e := r.Cookie("za_reset")
	browser, b := r.Cookie(ResetMFAPassCookie)
	if e != nil || b != nil || page.Value == "" || browser.Value == "" || secrets.HashToken(page.Value) != p.ResetPageHash || secrets.HashToken(browser.Value) != pass.BrowserHash {
		return "", invalid
	}
	return p.ResetResultURL, nil
}
