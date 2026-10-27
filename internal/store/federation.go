package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

// ErrFederationUnavailable is returned by a driver or plugin server that does
// not implement the federation repository. Social login stays unavailable
// rather than falling back to non-atomic behavior.
var ErrFederationUnavailable = errors.New("store: federation repository unavailable")

// MicrosoftFederationSupporter is an optional read-only capability probe. A
// driver must implement the Microsoft identity encoding and atomic index lifecycle.
type MicrosoftFederationSupporter interface {
	MicrosoftFederationSupported(context.Context) error
}

var canonicalMicrosoftGUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

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
	// Superseded is set when a later attempt started for the same
	// transaction; a superseded attempt can be neither claimed nor finished.
	Superseded bool
	CreatedAt  time.Time
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

// IsFederatedProvider reports whether an identity's Provider is a federated
// strategy whose identities the identity index owns.
func IsFederatedProvider(provider string) bool { return rules.IsFederated(provider) }

// FederatedSubject returns the upstream subject of a federated identity and
// true, or ("", false, nil) for any other identity. Google and personal
// Microsoft identities carry the raw subject in UserID; OAuth2, OIDC and Entra carry
// "<connection-name>|<subject>", and only that fixed prefix is stripped, so
// the subject may itself contain "|". A malformed identity is ErrInvalid.
func (id *Identity) FederatedSubject() (string, bool, error) {
	if !IsFederatedProvider(id.Provider) {
		return "", false, nil
	}
	sub := id.UserID
	if id.Provider != rules.Google && id.Provider != rules.WindowsLive {
		rest, ok := strings.CutPrefix(id.UserID, id.Connection+"|")
		if !ok || id.Connection == "" {
			return "", true, fmt.Errorf("%w: %s identity user_id must start with %q", ErrInvalid, id.Provider, id.Connection+"|")
		}
		sub = rest
	}
	if sub == "" || len(sub) > rules.MaxSubjectBytes || !utf8.ValidString(sub) || strings.ContainsRune(sub, 0) {
		return "", true, fmt.Errorf("%w: %s identity subject must be 1-%d bytes of UTF-8 without NUL", ErrInvalid, id.Provider, rules.MaxSubjectBytes)
	}
	return sub, true, nil
}

// FederatedPublicID returns the local public user ID of a federated identity:
// "google-oauth2|<sub>", "oauth2|<connection>|<sub>" or
// "oidc|<connection>|<sub>", "windowslive|<sub>" or "waad|<connection>|<subject>".
func FederatedPublicID(provider, connection, subject string) string {
	if provider == rules.Google || provider == rules.WindowsLive {
		return provider + "|" + subject
	}
	return provider + "|" + connection + "|" + subject
}

// ResolveFederatedKeys returns the index keys of u's federated identities,
// sorted and without duplicates. byName looks a connection up by name in the
// caller's transaction; an unknown connection or one whose strategy differs
// from the identity's provider is ErrInvalid, so an unresolved import cannot
// authenticate by accident.
func ResolveFederatedKeys(u *User, byName func(name string) (*Connection, error)) ([]FederatedIdentityKey, error) {
	var out []FederatedIdentityKey
	for i := range u.Identities {
		id := &u.Identities[i]
		sub, ok, err := id.FederatedSubject()
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		c, err := byName(id.Connection)
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("%w: identity connection %q does not exist", ErrInvalid, id.Connection)
		}
		if err != nil {
			return nil, err
		}
		if c.Strategy != id.Provider {
			return nil, fmt.Errorf("%w: identity provider %q does not match connection %q", ErrInvalid, id.Provider, id.Connection)
		}
		if c.Strategy == rules.WAAD {
			_, multi, err := rules.MicrosoftAuthority(c.Strategy, c.Extra)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid Microsoft identity connection policy", ErrInvalid)
			}
			oid := sub
			if multi {
				tid, rest, ok := strings.Cut(sub, ":")
				if !ok || !canonicalMicrosoftGUID.MatchString(tid) || tid == "9188040d-6c67-4c5b-b112-36a304b66dad" {
					return nil, fmt.Errorf("%w: invalid Microsoft identity tenant", ErrInvalid)
				}
				oid = rest
			}
			if !canonicalMicrosoftGUID.MatchString(oid) {
				return nil, fmt.Errorf("%w: invalid Microsoft identity object", ErrInvalid)
			}
		}
		out = append(out, FederatedIdentityKey{TenantID: u.TenantID, ConnectionID: c.ID, Subject: sub})
	}
	slices.SortFunc(out, CompareIdentityKeys)
	return slices.Compact(out), nil
}

// CompareIdentityKeys orders keys bytewise by tenant, connection, subject.
func CompareIdentityKeys(a, b FederatedIdentityKey) int {
	if c := strings.Compare(a.TenantID, b.TenantID); c != 0 {
		return c
	}
	if c := strings.Compare(a.ConnectionID, b.ConnectionID); c != 0 {
		return c
	}
	return strings.Compare(a.Subject, b.Subject)
}
