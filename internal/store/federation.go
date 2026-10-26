package store

import (
	"context"
	"errors"
	"slices"
	"time"
)

// ErrFederationUnavailable is returned by a driver or plugin server that does
// not implement the federation repository. Social login stays unavailable
// rather than falling back to non-atomic behavior.
var ErrFederationUnavailable = errors.New("store: federation repository unavailable")

// Federation attempt states.
const (
	AttemptPending  = "pending"
	AttemptClaimed  = "claimed"
	AttemptFinished = "finished"
)

// FederatedIdentityKey names one upstream identity: the immutable connection
// ID and the provider subject, compared byte for byte (case-sensitive).
type FederatedIdentityKey struct {
	TenantID     string
	ConnectionID string
	Subject      string
}

// FederationEndpoints is the provider endpoint snapshot pinned when an
// attempt starts; the callback never rediscovers them.
type FederationEndpoints struct {
	AuthorizationURL string
	TokenURL         string
	JWKSURL          string
	UserInfoURL      string
	// TokenAuthMethod is client_secret_basic or client_secret_post.
	TokenAuthMethod string
}

// FederationAttempt is one upstream authorization attempt, single use. Only
// the hash of the upstream state is stored; SealedProof is the wrapped PKCE
// verifier and nonce.
type FederationAttempt struct {
	StateHash     string
	TenantID      string
	TransactionID string
	ConnectionID  string
	// Revision is the connection's FederationRevision at start; any effective
	// configuration change invalidates the attempt.
	Revision int64
	// IdentityEpoch is the tenant's IdentityEpoch at start; completion
	// requires it unchanged.
	IdentityEpoch int64
	CookieHash    string
	Origin        string
	CallbackURL   string
	Issuer        string
	Endpoints     FederationEndpoints
	SealedProof   []byte
	ExpiresAt     time.Time
	Status        string
	CreatedAt     time.Time
}

// Clone deep-copies a.
func (a *FederationAttempt) Clone() *FederationAttempt {
	if a == nil {
		return nil
	}
	out := *a
	out.SealedProof = slices.Clone(a.SealedProof)
	return &out
}

// Federation persists upstream attempts, the federated identity index, the
// tenant identity epoch and sealed upstream tokens. Every method obeys the
// store's transaction semantics; no method performs network I/O.
type Federation interface {
	// IdentityEpoch returns the tenant's durable identity epoch (zero until
	// first bumped). ErrNotFound if the tenant is absent.
	IdentityEpoch(ctx context.Context, tenantID string) (int64, error)
	// BumpIdentityEpoch adds one to the tenant's identity epoch. Callers bump
	// it in the same transaction as a user deletion or an identity removal
	// or ownership transfer.
	BumpIdentityEpoch(ctx context.Context, tenantID string) error
	// CreateAttempt stores a pending attempt and atomically invalidates the
	// preceding attempt of its transaction. ErrConflict on a duplicate state.
	CreateAttempt(ctx context.Context, a *FederationAttempt) error
	// GetAttempt returns a copy, or ErrNotFound.
	GetAttempt(ctx context.Context, tenantID, stateHash string) (*FederationAttempt, error)
	// ClaimAttempt moves a pending, unexpired (now before ExpiresAt) attempt
	// that is still its transaction's current one to claimed, if cookieHash
	// and origin match. It returns a copy. ErrNotFound if absent, superseded
	// or expired; ErrAlreadyUsed if already claimed or finished; ErrInvalid on
	// wrong bindings.
	ClaimAttempt(ctx context.Context, tenantID, stateHash, cookieHash, origin string, now time.Time) (*FederationAttempt, error)
	// FinishAttempt moves a claimed, current attempt to finished;
	// ErrAlreadyUsed otherwise, ErrNotFound if absent.
	FinishAttempt(ctx context.Context, tenantID, stateHash string) error
	// PutIdentity records userID as the owner of key. ErrConflict if another
	// user owns it.
	PutIdentity(ctx context.Context, key FederatedIdentityKey, userID string) error
	// DeleteIdentity removes key if expectedUserID owns it; ErrNotFound if
	// absent, ErrConflict if another user owns it.
	DeleteIdentity(ctx context.Context, key FederatedIdentityKey, expectedUserID string) error
	// GetTokens returns the opaque sealed token record, or ErrNotFound.
	GetTokens(ctx context.Context, key FederatedIdentityKey) ([]byte, error)
	PutTokens(ctx context.Context, key FederatedIdentityKey, sealed []byte) error
	// DeleteTokens removes the record; absent is not an error.
	DeleteTokens(ctx context.Context, key FederatedIdentityKey) error
	// DeleteExpired removes attempts that expired before the given time and
	// returns how many.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// UnimplementedFederation fails every call with ErrFederationUnavailable.
type UnimplementedFederation struct{}

func (UnimplementedFederation) IdentityEpoch(context.Context, string) (int64, error) {
	return 0, ErrFederationUnavailable
}
func (UnimplementedFederation) BumpIdentityEpoch(context.Context, string) error {
	return ErrFederationUnavailable
}
func (UnimplementedFederation) CreateAttempt(context.Context, *FederationAttempt) error {
	return ErrFederationUnavailable
}
func (UnimplementedFederation) GetAttempt(context.Context, string, string) (*FederationAttempt, error) {
	return nil, ErrFederationUnavailable
}
func (UnimplementedFederation) ClaimAttempt(context.Context, string, string, string, string, time.Time) (*FederationAttempt, error) {
	return nil, ErrFederationUnavailable
}
func (UnimplementedFederation) FinishAttempt(context.Context, string, string) error {
	return ErrFederationUnavailable
}
func (UnimplementedFederation) PutIdentity(context.Context, FederatedIdentityKey, string) error {
	return ErrFederationUnavailable
}
func (UnimplementedFederation) DeleteIdentity(context.Context, FederatedIdentityKey, string) error {
	return ErrFederationUnavailable
}
func (UnimplementedFederation) GetTokens(context.Context, FederatedIdentityKey) ([]byte, error) {
	return nil, ErrFederationUnavailable
}
func (UnimplementedFederation) PutTokens(context.Context, FederatedIdentityKey, []byte) error {
	return ErrFederationUnavailable
}
func (UnimplementedFederation) DeleteTokens(context.Context, FederatedIdentityKey) error {
	return ErrFederationUnavailable
}
func (UnimplementedFederation) DeleteExpired(context.Context, time.Time) (int, error) {
	return 0, ErrFederationUnavailable
}
