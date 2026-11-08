package events

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (s *capture) WebAuthn() store.WebAuthn { return webauthn{WebAuthn: s.Store.WebAuthn(), s: s} }

type webauthn struct {
	store.WebAuthn
	s *capture
}

// Atomic passkey signup bypasses Users.Create on the decorating store, so
// capture its user creation in the same transaction as the credential.
func (r webauthn) CreateUserWithPasskey(ctx context.Context, u *store.User, a *store.Authenticator) error {
	return r.s.mutate(ctx, func(s *capture) error {
		if err := s.Store.WebAuthn().CreateUserWithPasskey(ctx, u, a); err != nil {
			return err
		}
		saved, err := s.Store.Users().Get(ctx, u.TenantID, u.UserID)
		if err != nil {
			return err
		}
		return s.emit(ctx, u.TenantID, "user.created", saved, nil)
	})
}
func (s *capture) CheckWebAuthnSupport(ctx context.Context) error {
	if p, ok := s.Store.(store.WebAuthnSupporter); ok {
		return p.CheckWebAuthnSupport(ctx)
	}
	if !s.WebAuthnSupported() {
		return store.ErrWebAuthnUnavailable
	}
	return nil
}
func (s *capture) WebAuthnSupported() bool {
	if p, ok := s.Store.(store.WebAuthnSupporter); ok {
		return p.WebAuthnSupported()
	}
	switch s.Store.WebAuthn().(type) {
	case store.UnimplementedWebAuthn, *store.UnimplementedWebAuthn:
		return false
	}
	return true
}
