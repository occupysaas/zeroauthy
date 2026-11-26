package myaccount

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/authmethods"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// otpSession is a started TOTP, email or phone enrollment.
type otpSession struct {
	Factor      string `json:"factor"`
	ChallengeID string `json:"challenge_id"`
}

// recoverySession is a generated, not yet saved recovery code.
type recoverySession struct {
	Hash string `json:"hash"`
}

// factorOn reports whether the Guardian factor named guardian is enabled.
func (h *Handlers) factorOn(ctx context.Context, tid, guardian string) (bool, error) {
	g, err := h.Store.MFA().GetGuardian(ctx, tid)
	if err != nil {
		return false, err
	}
	return g.Factors[guardian], nil
}

func (h *Handlers) startOTP(w http.ResponseWriter, r *http.Request, c *Caller, b createBody) {
	ctx := r.Context()
	svc := h.MFA.WithoutAutomaticRecovery()
	var e *mfa.Enrollment
	var err error
	switch b.Type {
	case "totp":
		e, err = svc.BeginEnroll(ctx, c.TenantID, c.UserID, "otp", "")
	case "email":
		on, ferr := h.factorOn(ctx, c.TenantID, "email")
		if ferr != nil || !on {
			h.mfaProblem(w, r, "start an email enrollment", errors.Join(ferr, mfa.ErrNoFactor))
			return
		}
		// LR42a-8: the user's own verified address only.
		if !c.User.EmailVerified || c.User.Email == "" || !strings.EqualFold(strings.TrimSpace(b.Email), c.User.Email) {
			writeProblem(w, r, badRequest("invalid_email", "email must be the user's verified email address.", ValidationError{Detail: "not the user's verified email", Field: "email", Source: "body"}))
			return
		}
		e, err = svc.BeginEnroll(ctx, c.TenantID, c.UserID, "email", "")
	case "phone":
		method := b.PreferredAuthenticationMethod
		if method == "" {
			method = "sms"
		}
		if method != "sms" && method != "voice" {
			writeProblem(w, r, badRequest("invalid_body", "preferred_authentication_method must be sms or voice.", ValidationError{Detail: "invalid", Field: "preferred_authentication_method", Source: "body"}))
			return
		}
		if b.PhoneNumber == "" {
			writeProblem(w, r, badRequest("invalid_body", "phone_number is required.", ValidationError{Detail: "required", Field: "phone_number", Source: "body"}))
			return
		}
		e, err = svc.BeginPhoneEnroll(ctx, c.TenantID, c.UserID, b.PhoneNumber, method)
	}
	if err != nil {
		h.mfaProblem(w, r, "start an enrollment", err)
		return
	}
	raw, err := h.newAuthSession(ctx, c, b.Type, e.AuthenticatorID, otpSession{Factor: e.Factor, ChallengeID: e.ChallengeID})
	if err != nil {
		h.fail(w, r, "store an enrollment", err)
		return
	}
	logs.AddCredentials(ctx, raw)
	out := map[string]any{"id": e.AuthenticatorID, "auth_session": raw}
	if b.Type == "totp" {
		out["barcode_uri"], out["manual_input_code"] = e.URI, e.Secret
	}
	w.Header().Set("Location", location(c, e.AuthenticatorID))
	writeJSON(w, r, http.StatusAccepted, out)
}

func (h *Handlers) verifyOTP(w http.ResponseWriter, r *http.Request, c *Caller, s *authSession, b verifyBody) {
	var os otpSession
	if err := json.Unmarshal(s.Data, &os); err != nil || os.ChallengeID == "" {
		writeProblem(w, r, errSession())
		return
	}
	if b.OTPCode == "" {
		writeProblem(w, r, badRequest("invalid_body", "otp_code is required.", ValidationError{Detail: "required", Field: "otp_code", Source: "body"}))
		return
	}
	e := &mfa.Enrollment{Factor: os.Factor, AuthenticatorID: s.MethodID, ChallengeID: os.ChallengeID}
	if _, err := h.MFA.WithoutAutomaticRecovery().ConfirmEnroll(r.Context(), c.TenantID, c.UserID, e, mfa.Proof{Code: b.OTPCode}); err != nil {
		h.mfaProblem(w, r, "confirm an enrollment", err)
		return
	}
	h.created(w, r, c, s.MethodID)
}

func (h *Handlers) startRecovery(w http.ResponseWriter, r *http.Request, c *Caller) {
	ctx := r.Context()
	if on, err := h.factorOn(ctx, c.TenantID, "recovery-code"); err != nil || !on {
		h.mfaProblem(w, r, "start a recovery code enrollment", errors.Join(err, mfa.ErrNoFactor))
		return
	}
	code := mfa.NewRecoveryCode()
	logs.AddCredentials(ctx, code)
	id := "recovery-code|dev_" + secrets.RandomString(20)
	raw, err := h.newAuthSession(ctx, c, "recovery-code", id, recoverySession{Hash: secrets.HashToken(code)})
	if err != nil {
		h.fail(w, r, "store an enrollment", err)
		return
	}
	logs.AddCredentials(ctx, raw)
	w.Header().Set("Location", location(c, id))
	writeJSON(w, r, http.StatusAccepted, map[string]any{"id": id, "auth_session": raw, "recovery_code": code})
}

// verifyRecovery saves the generated code, replacing any earlier one.
func (h *Handlers) verifyRecovery(w http.ResponseWriter, r *http.Request, c *Caller, s *authSession) {
	var rs recoverySession
	if err := json.Unmarshal(s.Data, &rs); err != nil || rs.Hash == "" {
		writeProblem(w, r, errSession())
		return
	}
	ctx := r.Context()
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		if _, err := tx.Users().GetForUpdate(ctx, c.TenantID, c.UserID); err != nil {
			return err
		}
		if on, err := factorOnIn(ctx, tx, c.TenantID, "recovery-code"); err != nil || !on {
			return errors.Join(err, mfa.ErrNoFactor)
		}
		if err := tx.MFA().DeleteUserAuthenticators(ctx, c.TenantID, c.UserID, []string{"recovery-code"}); err != nil {
			return err
		}
		return tx.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: c.TenantID, UserID: c.UserID, ID: s.MethodID, Type: "recovery-code", Confirmed: true, CodeHash: rs.Hash, LastStep: -1, CreatedAt: h.now()})
	})
	if err != nil {
		h.mfaProblem(w, r, "save a recovery code", err)
		return
	}
	logs.RecordEvent(ctx, logs.RecorderFromContext(ctx), logs.Event{TenantID: c.TenantID, UserID: c.UserID, ClientID: c.ClientID, Type: "gd_enrollment_complete", Date: h.now()})
	h.created(w, r, c, s.MethodID)
}

func factorOnIn(ctx context.Context, st store.Store, tid, guardian string) (bool, error) {
	g, err := st.MFA().GetGuardian(ctx, tid)
	if err != nil {
		return false, err
	}
	return g.Factors[guardian], nil
}

func findMethod(r *http.Request, h *Handlers, u *store.User, id string) (*authmethods.Method, error) {
	return authmethods.Find(r.Context(), h.Store, u, id)
}
