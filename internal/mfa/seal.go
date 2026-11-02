package mfa

import (
	"context"
	"encoding/base32"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// SealTOTPSecret seals enrollment or imported TOTP material under the master
// key, bound to its tenant, user and authenticator. Errors never include material.
func SealTOTPSecret(w keys.Wrapper, tid, uid, id, secret string) ([]byte, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) == 0 || tid == "" || uid == "" || id == "" {
		return nil, store.ErrInvalid
	}
	if w == nil {
		return nil, errSealing
	}
	sealed, err := w.Wrap([]byte(secret), totpAAD(tid, uid, id))
	if err != nil {
		return nil, errSealing
	}
	return sealed, nil
}

// EnrollmentDisplay reopens only an unconfirmed tenant/user-owned TOTP method
// for the hosted enrollment display; callers must not persist its return values.
func (s *Service) EnrollmentDisplay(ctx context.Context, tid, uid, id string) (*Enrollment, error) {
	a, err := s.st.MFA().GetAuthenticator(ctx, tid, uid, id)
	if err != nil {
		return nil, err
	}
	if a.Confirmed || a.Type != "totp" {
		return nil, store.ErrInvalid
	}
	if err = enabled(ctx, s.st, tid, a.Type); err != nil {
		return nil, err
	}
	if s.sealer == nil {
		return nil, errSealing
	}
	plain, err := s.sealer.Unwrap(a.SealedSecret, totpAAD(tid, uid, id))
	if err != nil {
		return nil, errSealing
	}
	u, err := s.st.Users().Get(ctx, tid, uid)
	if err != nil {
		return nil, err
	}
	t, err := s.st.Tenants().Get(ctx, tid)
	if err != nil {
		return nil, err
	}
	issuer := t.FriendlyName
	if issuer == "" {
		issuer = t.Name
	}
	return &Enrollment{Factor: "otp", AuthenticatorID: id, Secret: string(plain), URI: TOTPURI(issuer, u.Email, string(plain))}, nil
}
