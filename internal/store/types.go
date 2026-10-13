package store

import "time"

// Tenant is an isolated identity domain with its own clients, users,
// connections and signing keys.
type Tenant struct {
	ID string
	// Name is unique and also serves as the subdomain under
	// server.base_domain.
	Name         string
	FriendlyName string
	// Domains are normalized hosts that resolve to this tenant.
	Domains []string
	// DefaultAudience is used when a token request has no audience.
	DefaultAudience string
	CreatedAt       time.Time
}

// AppType is the kind of application a client represents.
type AppType string

const (
	AppTypeSPA            AppType = "spa"
	AppTypeRegularWeb     AppType = "regular_web"
	AppTypeNative         AppType = "native"
	AppTypeNonInteractive AppType = "non_interactive"
)

// Token endpoint client authentication methods (RFC 7591 names).
const (
	AuthMethodNone              = "none"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodClientSecretBasic = "client_secret_basic"
)

// ClientSecret is one credential of a confidential client. Several can be
// valid at once to allow rotation.
type ClientSecret struct {
	Hash      string // argon2id PHC string, see internal/secrets
	CreatedAt time.Time
	ExpiresAt *time.Time // nil means the secret does not expire
}

// Client is an application registered in a tenant.
type Client struct {
	TenantID                string
	ClientID                string
	Name                    string
	AppType                 AppType
	Secrets                 []ClientSecret
	TokenEndpointAuthMethod string
	GrantTypes              []string
	Callbacks               []string
	AllowedLogoutURLs       []string
	WebOrigins              []string
	AllowedOrigins          []string
	CreatedAt               time.Time
}

// Scope is a permission defined by a resource server.
type Scope struct {
	Value       string
	Description string
}

// ResourceServer is an API that access tokens are issued for. Identifier
// is the value of the audience parameter and aud claim.
type ResourceServer struct {
	TenantID           string
	ID                 string
	Identifier         string
	Name               string
	Scopes             []Scope
	SigningAlg         string
	TokenLifetime      int // seconds; 0 means the default
	AllowOfflineAccess bool
	CreatedAt          time.Time
}

// ClientGrant authorizes a client to obtain client_credentials tokens for
// an audience, limited to Scopes.
type ClientGrant struct {
	TenantID  string
	ID        string
	ClientID  string
	Audience  string
	Scopes    []string
	CreatedAt time.Time
}

// KeyStatus is a signing key's place in the rotation lifecycle:
// next → current → previous → revoked.
type KeyStatus string

const (
	KeyNext     KeyStatus = "next"     // published in JWKS, not yet signing
	KeyCurrent  KeyStatus = "current"  // signs new tokens
	KeyPrevious KeyStatus = "previous" // published so recent tokens still verify
	KeyRevoked  KeyStatus = "revoked"  // kept for audit, not published
)

// SigningKey is a tenant's token signing key pair.
type SigningKey struct {
	TenantID string
	KID      string
	Alg      string
	Status   KeyStatus
	// PrivateKey is the envelope-encrypted private key (see internal/keys).
	// Drivers store it opaquely and never see plaintext key material.
	PrivateKey []byte
	// PublicJWK is the public key as a JSON Web Key.
	PublicJWK []byte
	CreatedAt time.Time
}
