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
	// SessionLifetime and IdleSessionLifetime bound login sessions, in
	// seconds. Zero means the defaults (7 days and 3 days).
	SessionLifetime     int
	IdleSessionLifetime int
	Branding            Branding
	CreatedAt           time.Time
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
	// IDTokenLifetime in seconds; zero means the default (36000).
	IDTokenLifetime int
	CreatedAt       time.Time
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

// Branding customizes the hosted login pages.
type Branding struct {
	LogoURL      string // https URL, shown above the form
	PrimaryColor string // "#rrggbb"
}

// StrategyDatabase is the strategy of zeroauthy-managed username/password
// connections.
const StrategyDatabase = "auth0"

// PasswordPolicy constrains passwords on a database connection.
type PasswordPolicy struct {
	MinLength int // zero means 8
	// RequireCharacterClasses is how many of lowercase, uppercase, digits
	// and other characters a password must contain (0-4).
	RequireCharacterClasses int
}

// Connection is a source of user identities for a tenant.
type Connection struct {
	TenantID         string
	ID               string
	Name             string // unique per tenant, e.g. "Username-Password-Authentication"
	Strategy         string
	EnabledClients   []string
	DisableSignup    bool
	RequiresUsername bool
	PasswordPolicy   PasswordPolicy
	CreatedAt        time.Time
}

// Identity links a user to a connection.
type Identity struct {
	Connection   string
	Provider     string // the connection strategy, e.g. "auth0"
	UserID       string // ID within the provider (User.UserID without "provider|")
	PasswordHash string // argon2id PHC string; database connections only
}

// User is a person in a tenant. Email and Username are stored lowercase.
type User struct {
	TenantID      string
	UserID        string // "<provider>|<id>", e.g. "auth0|65f0c2..."
	Email         string
	EmailVerified bool
	Username      string
	Name          string
	Nickname      string
	Picture       string
	Blocked       bool
	Identities    []Identity
	LastLogin     *time.Time
	LoginsCount   int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// LoginSession is a browser's authenticated session with a tenant.
type LoginSession struct {
	TenantID        string
	ID              string // public identifier, used as the ID token "sid" claim
	TokenHash       string // secrets.HashToken of the session cookie value
	UserID          string
	Connection      string
	AuthenticatedAt time.Time
	ClientIDs       []string // clients that received tokens through this session
	ExpiresAt       time.Time
	IdleExpiresAt   time.Time
	CreatedAt       time.Time
}

// AuthTransaction holds an /authorize request while the user logs in.
type AuthTransaction struct {
	TenantID   string
	ID         string // the "state" of the hosted login pages
	CookieHash string // secrets.HashToken of the za_txn_<ID> cookie value
	CSRFToken  string
	ClientID   string
	Params     map[string]string // the validated authorize request
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// AuthCode is an issued authorization code.
type AuthCode struct {
	TenantID            string
	CodeHash            string // secrets.HashToken of the code
	ClientID            string
	RedirectURI         string
	UserID              string
	SessionID           string
	Scopes              []string
	Audience            string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            time.Time
	ExpiresAt           time.Time
	CreatedAt           time.Time
	UsedAt              *time.Time
}

// RefreshToken is an issued refresh token. A token and the tokens issued
// by rotating it form a family that shares FamilyID; reuse of a rotated
// token revokes the whole family.
type RefreshToken struct {
	TenantID  string
	ID        string // public identifier, used in logs
	TokenHash string // secrets.HashToken of the token
	FamilyID  string
	ClientID  string
	UserID    string
	SessionID string // the login session the family started in ("sid")
	Scopes    []string
	Audience  string    // API identifier; empty when the token is for /userinfo only
	AuthTime  time.Time // when the user authenticated; ID tokens carry it
	Rotating  bool
	// ExpiresAt is the family's absolute expiry. Zero means never.
	ExpiresAt time.Time
	// IdleExpiresAt is this token's inactivity expiry. Zero means never.
	IdleExpiresAt time.Time
	// RotatedAt is when the token was first exchanged for a successor.
	RotatedAt *time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}
