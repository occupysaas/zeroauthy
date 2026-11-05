package sqlstore

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// WebAuthn is not stored in SQL until Plan 33b Task 5.
func (s *Store) WebAuthn() store.WebAuthn { return store.UnimplementedWebAuthn{} }

// CheckWebAuthnSupport reports the missing SQL schema until Task 5.
func (s *Store) CheckWebAuthnSupport(context.Context) error { return store.ErrWebAuthnUnavailable }

// WebAuthnSupported is false until Task 5.
func (s *Store) WebAuthnSupported() bool { return false }
