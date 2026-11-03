package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// The entire request is sealed: Action custom claims and their values may
// contain credentials. No raw token or unsealed Action material is persisted.
type mfaRequest struct {
	Audience, Origin string
	Scopes, Ceiling  []string
	Effects          *actions.Effects
	Requirement      mfa.Requirement
	AuthTime         time.Time
	UserVersion      int64
}
type mfaEnvelope struct {
	Sealed []byte `json:"sealed"`
}

func mfaBinding(t *store.MFAToken) []string {
	return []string{t.TenantID, t.Hash, t.ClientID, t.UserID, t.Connection}
}
func (h *Handlers) passwordMFA(ctx context.Context, res tenant.Resolved, c *store.Client, u *store.User, conn *store.Connection, aud string, scopes, ceiling []string, eff *actions.Effects, now time.Time) *Error {
	g, err := h.Store.MFA().GetGuardian(ctx, res.Tenant.ID)
	var effect *actions.MFAEffects
	if eff != nil {
		effect = eff.MFA
	}
	if errors.Is(err, store.ErrMFAUnavailable) {
		if effect == nil || effect.Provider == "none" {
			return nil
		}
		return mfaUnavailableError()
	}
	if err != nil {
		return serverError()
	}
	list, err := h.Store.MFA().ListAuthenticators(ctx, res.Tenant.ID, u.UserID)
	if err != nil {
		return mfaError(err)
	}
	customize, _ := res.Tenant.SettingsExtra["customize_mfa_in_postlogin_action"].(bool)
	req, err := mfa.Decide(mfa.DecideInput{Settings: g, Effects: effect, User: u, Authenticators: list, CustomizeInActions: customize, MFAAPI: aud != "" && h.isMFAAudience(ctx, res.Tenant.ID, aud)})
	if err != nil {
		return accessDenied("multifactor authentication is unavailable")
	}
	if !req.Required {
		return nil
	}
	if h.MFA == nil {
		return mfaUnavailableError()
	}
	raw := secrets.RandomString(48)
	t := &store.MFAToken{TenantID: res.Tenant.ID, Hash: secrets.HashToken(raw), ClientID: c.ClientID, UserID: u.UserID, Connection: conn.ID, ExpiresAt: now.Add(10 * time.Minute)}
	p, err := json.Marshal(mfaRequest{Audience: aud, Origin: res.Origin(), Scopes: scopes, Ceiling: ceiling, Effects: eff, Requirement: req, AuthTime: now, UserVersion: u.Version})
	if err != nil {
		return serverError()
	}
	sealed, err := keys.SealBound(h.Wrapper, "oauth-mfa-request/v1", mfaBinding(t), p)
	if err != nil {
		return serverError()
	}
	t.Request, err = json.Marshal(mfaEnvelope{Sealed: sealed})
	if err != nil {
		return serverError()
	}
	if err = h.Store.MFA().CreateMFAToken(ctx, t); err != nil {
		return mfaError(err)
	}
	logs.AddCredentials(ctx, raw)
	h.event(ctx, res, c, "mfar", conn, u.UserID)
	return &Error{Status: http.StatusForbidden, Code: "mfa_required", Description: "Multifactor authentication required", MFAToken: raw}
}
func (h *Handlers) pendingMFAToken(ctx context.Context, res tenant.Resolved, raw, clientID string) (*store.MFAToken, *mfaRequest, *Error) {
	if raw == "" {
		return nil, nil, invalidGrant("invalid MFA token")
	}
	t, err := h.Store.MFA().PeekMFAToken(ctx, res.Tenant.ID, secrets.HashToken(raw), h.now())
	if err != nil {
		if errors.Is(err, store.ErrMFAUnavailable) {
			return nil, nil, mfaUnavailableError()
		}
		return nil, nil, invalidGrant("invalid MFA token")
	}
	if clientID != "" && t.ClientID != clientID {
		return nil, nil, invalidGrant("invalid MFA token")
	}
	var env mfaEnvelope
	if json.Unmarshal(t.Request, &env) != nil {
		return nil, nil, invalidGrant("invalid MFA token")
	}
	plain, err := keys.OpenBound(h.Wrapper, "oauth-mfa-request/v1", mfaBinding(t), env.Sealed)
	if err != nil {
		return nil, nil, invalidGrant("invalid MFA token")
	}
	var p mfaRequest
	if json.Unmarshal(plain, &p) != nil || res.CheckOrigin(p.Origin) != nil {
		return nil, nil, invalidGrant("invalid MFA token")
	}
	u, e := h.activeUser(ctx, t.TenantID, t.UserID)
	if e != nil {
		return nil, nil, e
	}
	if u.Version != p.UserVersion {
		return nil, nil, invalidGrant("invalid MFA token")
	}
	conn, err := h.Store.Connections().Get(ctx, t.TenantID, t.Connection)
	if err != nil || !slices.Contains(conn.EnabledClients, t.ClientID) {
		return nil, nil, invalidGrant("invalid MFA token")
	}
	return t, &p, nil
}
func mfaUnavailableError() *Error {
	return &Error{Status: 501, Code: "mfa_unavailable", Description: "Multifactor authentication is unavailable"}
}
func mfaError(err error) *Error {
	switch {
	case errors.Is(err, store.ErrMFAUnavailable):
		return mfaUnavailableError()
	case errors.Is(err, mfa.ErrThrottled):
		return &Error{Status: 429, Code: "too_many_attempts", Description: "Too many failed attempts"}
	case errors.Is(err, mfa.ErrEmailDelivery):
		return &Error{Status: 503, Code: "temporarily_unavailable", Description: "Unable to deliver verification email"}
	case errors.Is(err, mfa.ErrInvalidCode), errors.Is(err, mfa.ErrExpired), errors.Is(err, mfa.ErrNoFactor), errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrPrecondition), errors.Is(err, errUserChanged):
		return invalidGrant("invalid MFA verification")
	default:
		return serverError()
	}
}
func (h *Handlers) mfaOTPGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	return h.mfaGrant(ctx, res, c, form, "otp", "feotpft")
}
func (h *Handlers) mfaOOBGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	return h.mfaGrant(ctx, res, c, form, "email", "feoobft")
}
func (h *Handlers) mfaRecoveryGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	return h.mfaGrant(ctx, res, c, form, "recovery-code", "fercft")
}
func (h *Handlers) mfaGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values, factor, failureCode string) (response *authapi.TokenResponse, failure *Error) {
	ctx = logscrub.WithCredentials(ctx, form.Get("mfa_token"), form.Get("otp"), form.Get("oob_code"), form.Get("binding_code"), form.Get("recovery_code"))
	var uid string
	defer func() {
		if failure != nil {
			h.event(ctx, res, c, failureCode, nil, uid)
		}
	}()
	if h.MFA == nil {
		return nil, mfaUnavailableError()
	}
	t, p, e := h.pendingMFAToken(ctx, res, form.Get("mfa_token"), c.ClientID)
	if e != nil {
		return nil, e
	}
	uid = t.UserID
	if !slices.Contains(p.Requirement.Factors, factor) {
		return nil, invalidGrant("invalid MFA verification")
	}
	u, e := h.activeUser(ctx, t.TenantID, uid)
	if e != nil {
		return nil, e
	}
	rs, lifetime, e := h.audienceFor(ctx, t.TenantID, p.Audience)
	if e != nil {
		return nil, e
	}
	d, e := h.decide(ctx, t.TenantID, access.Password, c, rs, p.Scopes)
	if e != nil {
		return nil, e
	}
	resp, write, e := h.preparePasswordTokens(ctx, res, c, u, rs, lifetime, p.Audience, d.Scopes, p.Ceiling, p.Effects, p.AuthTime, h.now())
	if e != nil {
		return nil, e
	}
	svc := h.MFA.WithProofCommit(func(tx store.Store) error {
		current, err := tx.Users().GetForUpdate(ctx, t.TenantID, uid)
		if err != nil {
			return err
		}
		if current.Blocked || current.Version != p.UserVersion {
			return errUserChanged
		}
		if _, err = tx.MFA().ConsumeMFAToken(ctx, t.TenantID, t.Hash, c.ClientID, h.now()); err != nil {
			return err
		}
		return write(tx)
	})
	var err error
	var next string
	switch factor {
	case "recovery-code":
		next, err = svc.Recover(ctx, t.TenantID, uid, form.Get("recovery_code"))
	default:
		var challenge *mfa.Challenge
		var a *store.Authenticator
		if factor == "email" {
			saved, x := h.Store.MFA().GetChallenge(ctx, t.TenantID, secrets.HashToken(form.Get("oob_code")), h.now())
			if x != nil || saved.UserID != uid || saved.Kind != "email" {
				return nil, invalidGrant("invalid MFA verification")
			}
			a, err = h.Store.MFA().GetAuthenticator(ctx, t.TenantID, uid, saved.AuthenticatorID)
			challenge = &mfa.Challenge{ID: form.Get("oob_code"), AuthenticatorID: saved.AuthenticatorID}
		} else {
			challenge, err = h.MFA.BeginOTPChallenge(ctx, t.TenantID, uid, form.Get("otp"), p.Requirement.Enroll)
			if err == nil {
				a, err = h.Store.MFA().GetAuthenticator(ctx, t.TenantID, uid, challenge.AuthenticatorID)
			}
		}
		if err == nil && a.Confirmed == p.Requirement.Enroll {
			return nil, invalidGrant("invalid MFA verification")
		}
		if err == nil {
			code := form.Get("otp")
			if factor == "email" {
				code = form.Get("binding_code")
			}
			if p.Requirement.Enroll {
				var confirmed *mfa.Confirmed
				enrollment := &mfa.Enrollment{AuthenticatorID: a.ID, ChallengeID: challenge.ID}
				// A primary-password enrollment continuation cannot survive
				// another flow establishing the user's first factor. Only an
				// explicit Action enroll request authorizes an additional one.
				explicitEnroll := p.Effects != nil && p.Effects.MFA != nil && p.Effects.MFA.Mode == "enroll"
				if explicitEnroll {
					confirmed, err = svc.WithNewFactorEnrollment().ConfirmEnroll(ctx, t.TenantID, uid, enrollment, mfa.Proof{Code: code})
				} else {
					confirmed, err = svc.ConfirmFirstEnroll(ctx, t.TenantID, uid, enrollment, mfa.Proof{Code: code})
				}
				if err == nil {
					next = confirmed.RecoveryCode
				}
			} else {
				err = svc.Verify(ctx, t.TenantID, uid, challenge, mfa.Proof{Code: code})
			}
		}
	}
	if err != nil {
		return nil, mfaError(err)
	}
	if next != "" {
		resp.RecoveryCode = &next
		logs.AddCredentials(ctx, next)
	}
	return resp, nil
}
