package store

import (
	"context"
	"errors"
	"time"
)

// ClientCredential is a public key or certificate registered on a client for
// private_key_jwt authentication or signed request objects.
type ClientCredential struct {
	TenantID, ClientID, ID, Type, Name, KID, Alg string // Type: "public_key" | "x509_cert"
	PublicKeyDER                                 []byte // PKIX SubjectPublicKeyInfo
	Thumbprint                                   string // base64url SHA-256 of the RFC 7638 JWK thumbprint input (thumbprint_sha256)
	ExpiresAt                                    *time.Time
	CreatedAt, UpdatedAt                         time.Time
}

// TokenExchangeProfile binds a subject_token_type to the Action that
// validates it (Auth0's custom token exchange profile).
type TokenExchangeProfile struct {
	TenantID, ID, Name, SubjectTokenType, ActionID, Type string
	CreatedAt, UpdatedAt                                 time.Time
}

// ErrClientCredentialsUnavailable means the driver lacks the
// client_credentials.v1 capability.
var ErrClientCredentialsUnavailable = errors.New("store: client credentials unavailable")

// ClientCredentialsSupporter is implemented by drivers that negotiate
// client_credentials.v1 (the gRPC plugin client); others support client
// credentials unconditionally.
type ClientCredentialsSupporter interface {
	CheckClientCredentialsSupport(context.Context) error
	ClientCredentialsSupported() bool
}

// ClientCredentialsAvailable reports whether s can store client credentials,
// assertion jtis and token exchange profiles. A store that implements
// ClientCredentialsSupporter answers through it; otherwise it is available
// unless its repository is UnimplementedClientCredentials.
func ClientCredentialsAvailable(ctx context.Context, s Store) bool {
	if cap, ok := s.(ClientCredentialsSupporter); ok {
		return cap.CheckClientCredentialsSupport(ctx) == nil && cap.ClientCredentialsSupported()
	}
	switch s.ClientCredentials().(type) {
	case UnimplementedClientCredentials, *UnimplementedClientCredentials:
		return false
	}
	return true
}

// ClientCredentials stores client public keys and certificates, the replay
// table of signed-JWT jtis and token exchange profiles (Plan 35).
type ClientCredentials interface {
	// Create inserts c. ErrNotFound when the client is missing; ErrConflict on
	// a duplicate id; ErrPrecondition when the client already has limit
	// credentials.
	Create(ctx context.Context, c *ClientCredential, limit int) error
	Get(ctx context.Context, tid, clientID, id string) (*ClientCredential, error) // ErrNotFound
	List(ctx context.Context, tid, clientID string) ([]*ClientCredential, error)  // ordered CreatedAt, ID
	UpdateExpiry(ctx context.Context, tid, clientID, id string, exp *time.Time) error
	// Delete removes the credential and its id from the client's
	// PrivateKeyJWTCredentials and SignedRequestObject.Credentials.
	Delete(ctx context.Context, tid, clientID, id string) error
	// UseJTI records (tid, clientID, sha256(jti)) until exp; ErrConflict if
	// it is already recorded and unexpired.
	UseJTI(ctx context.Context, tid, clientID, jti string, exp time.Time) error
	PurgeJTIs(ctx context.Context, before time.Time, limit int) (int, error) // rows with exp <= before
	// CreateProfile: ErrConflict on a duplicate id or subject_token_type;
	// ErrPrecondition when the tenant already has limit profiles.
	CreateProfile(ctx context.Context, p *TokenExchangeProfile, limit int) error
	GetProfile(ctx context.Context, tid, id string) (*TokenExchangeProfile, error)
	GetProfileByType(ctx context.Context, tid, subjectTokenType string) (*TokenExchangeProfile, error)
	// ListProfiles returns up to take profiles with id > from, in id order.
	// next is the last id when more profiles follow, else "".
	ListProfiles(ctx context.Context, tid, from string, take int) ([]*TokenExchangeProfile, string, error)
	// UpdateProfile replaces Name, SubjectTokenType and ActionID. ErrNotFound;
	// ErrConflict when the new subject_token_type belongs to another profile.
	UpdateProfile(ctx context.Context, p *TokenExchangeProfile) error
	DeleteProfile(ctx context.Context, tid, id string) error
	ProfilesForAction(ctx context.Context, tid, actionID string) (int, error)
}

// UnimplementedClientCredentials answers ErrClientCredentialsUnavailable for
// every method.
type UnimplementedClientCredentials struct{}

func (UnimplementedClientCredentials) Create(context.Context, *ClientCredential, int) error {
	return ErrClientCredentialsUnavailable
}
func (UnimplementedClientCredentials) Get(context.Context, string, string, string) (*ClientCredential, error) {
	return nil, ErrClientCredentialsUnavailable
}
func (UnimplementedClientCredentials) List(context.Context, string, string) ([]*ClientCredential, error) {
	return nil, ErrClientCredentialsUnavailable
}
func (UnimplementedClientCredentials) UpdateExpiry(context.Context, string, string, string, *time.Time) error {
	return ErrClientCredentialsUnavailable
}
func (UnimplementedClientCredentials) Delete(context.Context, string, string, string) error {
	return ErrClientCredentialsUnavailable
}
func (UnimplementedClientCredentials) UseJTI(context.Context, string, string, string, time.Time) error {
	return ErrClientCredentialsUnavailable
}
func (UnimplementedClientCredentials) PurgeJTIs(context.Context, time.Time, int) (int, error) {
	return 0, ErrClientCredentialsUnavailable
}
func (UnimplementedClientCredentials) CreateProfile(context.Context, *TokenExchangeProfile, int) error {
	return ErrClientCredentialsUnavailable
}
func (UnimplementedClientCredentials) GetProfile(context.Context, string, string) (*TokenExchangeProfile, error) {
	return nil, ErrClientCredentialsUnavailable
}
func (UnimplementedClientCredentials) GetProfileByType(context.Context, string, string) (*TokenExchangeProfile, error) {
	return nil, ErrClientCredentialsUnavailable
}
func (UnimplementedClientCredentials) ListProfiles(context.Context, string, string, int) ([]*TokenExchangeProfile, string, error) {
	return nil, "", ErrClientCredentialsUnavailable
}
func (UnimplementedClientCredentials) UpdateProfile(context.Context, *TokenExchangeProfile) error {
	return ErrClientCredentialsUnavailable
}
func (UnimplementedClientCredentials) DeleteProfile(context.Context, string, string) error {
	return ErrClientCredentialsUnavailable
}
func (UnimplementedClientCredentials) ProfilesForAction(context.Context, string, string) (int, error) {
	return 0, ErrClientCredentialsUnavailable
}
