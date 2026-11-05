package store

import (
	"context"
	"errors"
	"time"
)

// ErrWebAuthnUnavailable means the driver lacks the webauthn.v1 capability.
var ErrWebAuthnUnavailable = errors.New("store: WebAuthn unavailable")

// WebAuthnSupporter is implemented by drivers that negotiate webauthn.v1
// (the gRPC plugin client); others support WebAuthn unconditionally.
type WebAuthnSupporter interface {
	CheckWebAuthnSupport(context.Context) error
	WebAuthnSupported() bool
}

// WebAuthnSnooze defers a passkey or platform enrollment prompt. Kind is
// passkey-progressive, passkey-local, platform-remind or platform-refuse;
// ScopeKey is an RP ID, browser ID or device key.
type WebAuthnSnooze struct {
	TenantID, UserID, Kind, ScopeKey string
	Until                            time.Time
}

// WebAuthn stores passkeys and WebAuthn ceremony state (Plan 33b). Passkeys
// are Authenticator rows with Type "passkey".
type WebAuthn interface {
	GetAuthenticatorByCredentialID(ctx context.Context, tid string, credID []byte) (*Authenticator, error) // ErrNotFound
	// CreatePasskey inserts a passkey. ErrConflict on a duplicate credential
	// ID in the tenant; ErrPrecondition when the user already has limit
	// passkeys; ErrNotFound when the user is missing.
	CreatePasskey(ctx context.Context, a *Authenticator, limit int) error
	CreateUserWithPasskey(ctx context.Context, u *User, a *Authenticator) error // one transaction; ErrConflict on user or credential
	// AcceptAssertion: ErrPrecondition unless count > stored or both are
	// zero; writes backed_up into PublicData and LastAuthAt. ErrNotFound if
	// the authenticator is missing or belongs to another user.
	AcceptAssertion(ctx context.Context, tid, uid, id string, count uint32, backedUp bool, at time.Time) error
	MovePasskeys(ctx context.Context, tid, fromUID, toUID, identityUserID string) error // "" = all of fromUID's passkeys
	PutSnooze(ctx context.Context, s *WebAuthnSnooze) error                            // upsert by (tid, uid, kind, scope)
	GetSnooze(ctx context.Context, tid, uid, kind, scope string, now time.Time) (*WebAuthnSnooze, error)
	// HostTenantsUnder returns distinct tenant IDs owning a host binding
	// equal to suffix or ending in "."+suffix.
	HostTenantsUnder(ctx context.Context, suffix string, limit int) ([]string, error)
	PurgeWebAuthn(ctx context.Context, before time.Time, limit int) (int, error) // expired snoozes
}

// UnimplementedWebAuthn answers ErrWebAuthnUnavailable for every method.
type UnimplementedWebAuthn struct{}

func (UnimplementedWebAuthn) GetAuthenticatorByCredentialID(context.Context, string, []byte) (*Authenticator, error) {
	return nil, ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) CreatePasskey(context.Context, *Authenticator, int) error {
	return ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) CreateUserWithPasskey(context.Context, *User, *Authenticator) error {
	return ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) AcceptAssertion(context.Context, string, string, string, uint32, bool, time.Time) error {
	return ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) MovePasskeys(context.Context, string, string, string, string) error {
	return ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) PutSnooze(context.Context, *WebAuthnSnooze) error {
	return ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) GetSnooze(context.Context, string, string, string, string, time.Time) (*WebAuthnSnooze, error) {
	return nil, ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) HostTenantsUnder(context.Context, string, int) ([]string, error) {
	return nil, ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) PurgeWebAuthn(context.Context, time.Time, int) (int, error) {
	return 0, ErrWebAuthnUnavailable
}

// AuthMethod records one authentication a session performed (Auth0's
// SessionAuthenticationSignal): Name is pwd, passkey, federated, email, sms
// or mfa; Type is the MFA factor for mfa.
type AuthMethod struct {
	Name, Type string
	At         time.Time
}

// ClientMobile holds a client's native app identities (Auth0 `mobile`),
// used for passkey association files (D-0039 addendum).
type ClientMobile struct {
	IOS     *ClientMobileIOS
	Android *ClientMobileAndroid
}
type ClientMobileIOS struct{ TeamID, AppBundleIdentifier string }
type ClientMobileAndroid struct {
	AppPackageName         string
	SHA256CertFingerprints []string
}

// Clone deep-copies m (nil stays nil).
func (m *ClientMobile) Clone() *ClientMobile {
	if m == nil {
		return nil
	}
	n := &ClientMobile{}
	if m.IOS != nil {
		ios := *m.IOS
		n.IOS = &ios
	}
	if m.Android != nil {
		a := *m.Android
		a.SHA256CertFingerprints = append([]string(nil), m.Android.SHA256CertFingerprints...)
		n.Android = &a
	}
	return n
}
