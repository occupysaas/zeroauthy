package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var ErrMFAUnavailable = errors.New("store: MFA unavailable")

type GuardianSettings struct {
	TenantID      string
	Factors       map[string]bool            // eight names from mfarules
	Policies      []string                   // [], ["all-applications"] or ["confidence-score"]
	Stored        map[string]json.RawMessage // route key → public JSON for §3 stored routes
	SealedSecrets map[string][]byte          // route key → sealed provider secret JSON
	Version       int
}
type Authenticator struct {
	TenantID, UserID, ID, Type, Name string // Type: totp|email|recovery-code|webauthn-roaming|webauthn-platform|phone
	Confirmed, Preferred             bool
	SealedSecret                     []byte // TOTP
	LastStep                         int64  // last accepted TOTP step
	CodeHash                         string // recovery code
	Email, Phone                     string
	CredentialID, PublicKey          []byte // WebAuthn; PublicKey is the COSE key
	RPID                             string
	SignCount                        uint32
	CreatedAt, LastAuthAt            time.Time
}
type MFAToken struct {
	TenantID, Hash, ClientID, UserID, Connection string
	Request                                      json.RawMessage // audience, scope, effects
	ExpiresAt                                    time.Time
}
type MFAChallenge struct {
	TenantID, ID, UserID, AuthenticatorID, Kind string // Kind: email|webauthn|oob
	CodeHash                                    string
	Challenge                                   []byte
	Attempts                                    int
	ExpiresAt                                   time.Time
}
type EnrollmentTicket struct {
	TenantID, Hash, UserID, Factor string
	AllowMultiple                  bool
	ExpiresAt                      time.Time
}
type MFABrowser struct {
	TenantID, Hash, UserID, Kind string // Kind: remember|device
	Epoch                        int
	ExpiresAt                    time.Time
}

type MFA interface {
	GetGuardian(ctx context.Context, tid string) (*GuardianSettings, error)  // defaults when none stored; ErrNotFound if tenant missing
	PutGuardian(ctx context.Context, s *GuardianSettings, version int) error // ErrConflict on version mismatch; ErrNotFound if tenant missing

	CreateAuthenticator(ctx context.Context, a *Authenticator) error // ErrConflict on duplicate WebAuthn credential ID in tenant or another recovery-code authenticator for the user
	GetAuthenticator(ctx context.Context, tid, uid, id string) (*Authenticator, error)
	ListAuthenticators(ctx context.Context, tid, uid string) ([]Authenticator, error)
	UpdateAuthenticator(ctx context.Context, a *Authenticator) error // name, preferred, confirmed
	DeleteAuthenticator(ctx context.Context, tid, uid, id string) error
	DeleteUserAuthenticators(ctx context.Context, tid, uid string, types []string) error     // nil = all
	AcceptTOTPStep(ctx context.Context, tid, uid, id string, step int64, at time.Time) error // ErrPrecondition unless step > LastStep
	// ReplaceRecoveryCode atomically replaces the existing recovery hash. An empty oldHash
	// means no recovery authenticator exists yet; in that case create a confirmed record
	// with ID recovery-code|dev_ plus 20 random alphanumerics and CreatedAt=at.
	// ErrPrecondition means the old hash does not match or the presence expectation failed;
	// ErrNotFound means the user is missing; ErrInvalid means newHash is empty.
	ReplaceRecoveryCode(ctx context.Context, tid, uid, oldHash, newHash string, at time.Time) error
	AcceptSignCount(ctx context.Context, tid, uid, id string, count uint32, at time.Time) error // ErrPrecondition unless increasing (both zero allowed)

	CreateMFAToken(ctx context.Context, t *MFAToken) error
	ConsumeMFAToken(ctx context.Context, tid, hash, clientID string, now time.Time) (*MFAToken, error) // ErrNotFound if missing, expired, consumed or other client
	PeekMFAToken(ctx context.Context, tid, hash string, now time.Time) (*MFAToken, error)

	CreateChallenge(ctx context.Context, c *MFAChallenge) error
	GetChallenge(ctx context.Context, tid, id string, now time.Time) (*MFAChallenge, error)
	FailChallenge(ctx context.Context, tid, id string) (attempts int, err error)
	ConsumeChallenge(ctx context.Context, tid, id string, now time.Time) error // ErrPrecondition if consumed or expired

	CreateTicket(ctx context.Context, t *EnrollmentTicket) error
	ConsumeTicket(ctx context.Context, tid, hash string, now time.Time) (*EnrollmentTicket, error)

	PutBrowser(ctx context.Context, b *MFABrowser) error
	GetBrowser(ctx context.Context, tid, hash string, now time.Time) (*MFABrowser, error)
	BumpRememberEpoch(ctx context.Context, tid, uid string) error // also on store.User.RememberBrowserEpoch

	PurgeMFA(ctx context.Context, before time.Time, limit int) (int, error) // expired tokens, challenges, tickets, browsers
	DeleteUserMFA(ctx context.Context, tid, uid string) error
	DeleteTenantMFA(ctx context.Context, tid string) error
}

type UnimplementedMFA struct{}

func (UnimplementedMFA) GetGuardian(ctx context.Context, tid string) (*GuardianSettings, error) {
	return nil, ErrMFAUnavailable
}
func (UnimplementedMFA) PutGuardian(ctx context.Context, s *GuardianSettings, version int) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) CreateAuthenticator(ctx context.Context, a *Authenticator) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) GetAuthenticator(ctx context.Context, tid, uid, id string) (*Authenticator, error) {
	return nil, ErrMFAUnavailable
}
func (UnimplementedMFA) ListAuthenticators(ctx context.Context, tid, uid string) ([]Authenticator, error) {
	return nil, ErrMFAUnavailable
}
func (UnimplementedMFA) UpdateAuthenticator(ctx context.Context, a *Authenticator) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) DeleteAuthenticator(ctx context.Context, tid, uid, id string) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) DeleteUserAuthenticators(ctx context.Context, tid, uid string, types []string) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) AcceptTOTPStep(ctx context.Context, tid, uid, id string, step int64, at time.Time) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) ReplaceRecoveryCode(ctx context.Context, tid, uid, oldHash, newHash string, at time.Time) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) AcceptSignCount(ctx context.Context, tid, uid, id string, count uint32, at time.Time) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) CreateMFAToken(ctx context.Context, t *MFAToken) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) ConsumeMFAToken(ctx context.Context, tid, hash, clientID string, now time.Time) (*MFAToken, error) {
	return nil, ErrMFAUnavailable
}
func (UnimplementedMFA) PeekMFAToken(ctx context.Context, tid, hash string, now time.Time) (*MFAToken, error) {
	return nil, ErrMFAUnavailable
}
func (UnimplementedMFA) CreateChallenge(ctx context.Context, c *MFAChallenge) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) GetChallenge(ctx context.Context, tid, id string, now time.Time) (*MFAChallenge, error) {
	return nil, ErrMFAUnavailable
}
func (UnimplementedMFA) FailChallenge(ctx context.Context, tid, id string) (attempts int, err error) {
	return 0, ErrMFAUnavailable
}
func (UnimplementedMFA) ConsumeChallenge(ctx context.Context, tid, id string, now time.Time) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) CreateTicket(ctx context.Context, t *EnrollmentTicket) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) ConsumeTicket(ctx context.Context, tid, hash string, now time.Time) (*EnrollmentTicket, error) {
	return nil, ErrMFAUnavailable
}
func (UnimplementedMFA) PutBrowser(ctx context.Context, b *MFABrowser) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) GetBrowser(ctx context.Context, tid, hash string, now time.Time) (*MFABrowser, error) {
	return nil, ErrMFAUnavailable
}
func (UnimplementedMFA) BumpRememberEpoch(ctx context.Context, tid, uid string) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) PurgeMFA(ctx context.Context, before time.Time, limit int) (int, error) {
	return 0, ErrMFAUnavailable
}
func (UnimplementedMFA) DeleteUserMFA(ctx context.Context, tid, uid string) error {
	return ErrMFAUnavailable
}
func (UnimplementedMFA) DeleteTenantMFA(ctx context.Context, tid string) error {
	return ErrMFAUnavailable
}
