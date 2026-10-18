// Exported through pkg/store; add new names there too.

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
	// AllowedLogoutURLs are where /v2/logout may send a browser when the
	// request names no client.
	AllowedLogoutURLs []string
	// EnabledLocales are the languages hosted pages may use; the first is
	// the default. Empty means ["en"].
	EnabledLocales []string
	// CustomText overrides hosted-page text per language.
	CustomText CustomText
	// SessionLifetime and IdleSessionLifetime bound login sessions, in
	// seconds. Zero means the defaults (7 days and 3 days).
	SessionLifetime     int
	IdleSessionLifetime int
	Branding            Branding
	// DefaultDirectory is the name of the connection the password grant
	// authenticates against.
	DefaultDirectory string
	// SkipNonVerifiableCallbackURIConfirmationPrompt skips the confirmation
	// prompt for third-party apps with non-verifiable callback URIs.
	SkipNonVerifiableCallbackURIConfirmationPrompt bool
	// UseScopeDescriptionsForConsent shows scope descriptions on the consent prompt.
	UseScopeDescriptionsForConsent bool
	// PushedAuthorizationRequestsSupported allows /oauth/par and request_uri
	// at /authorize (RFC 9126).
	PushedAuthorizationRequestsSupported bool
	// DeviceFlowCharset ("base20" or "digits") and DeviceFlowMask shape the
	// user codes of the device flow. Empty means the defaults: base20 and
	// "****-****".
	DeviceFlowCharset string
	DeviceFlowMask    string
	// Reserved marks the tenant zeroauthy runs for itself (`system`, whose
	// users are the console operators). The store does not act on it.
	Reserved bool
	// Seeded marks a tenant defined by the seed file. The console shows a
	// banner on it: the next start overwrites edits to what the seed defines.
	Seeded bool
	// Origin is OriginAPI for a tenant created through the system API,
	// which the seed never touches; empty otherwise.
	Origin string

	CreatedAt time.Time
}

// OperatorAllTenants in Operator.Tenants grants every tenant.
const OperatorAllTenants = "*"

// Operator flags a user of the system tenant as a console operator.
type Operator struct {
	TenantID string // the system tenant's ID
	UserID   string
	// Tenants are the names of the tenants the operator manages;
	// ["*"] (OperatorAllTenants) means every tenant.
	Tenants   []string
	CreatedAt time.Time
	UpdatedAt time.Time
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
// valid at once to allow rotation. Exactly one of Hash and Sealed is set:
// Sealed is the current form (D-0038), Hash the legacy one, which keeps
// authenticating but cannot be revealed.
type ClientSecret struct {
	Hash      string // legacy argon2id PHC string, see internal/secrets
	Sealed    []byte // envelope from keys.SealClientSecret
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
	RefreshToken    RefreshTokenPolicy
	CreatedAt       time.Time

	// IsFirstParty is true for first-party applications.
	IsFirstParty bool
	// ThirdPartySecurityMode is SecurityModeStrict or SecurityModePermissive;
	// empty for first-party clients.
	ThirdPartySecurityMode string
	// RedirectionPolicy is a RedirectionPolicy* value; empty means the
	// default for the client's party.
	RedirectionPolicy string
	// SkipNonVerifiableCallbackURIConfirmationPrompt overrides the tenant's
	// value; nil means the tenant's value applies.
	SkipNonVerifiableCallbackURIConfirmationPrompt *bool
	// RequirePushedAuthorizationRequests refuses /authorize requests that
	// do not name a pushed request. Only for confidential clients of a
	// tenant that allows PAR.
	RequirePushedAuthorizationRequests bool
	// Origin records who created the client: OriginAPI for the Management
	// API (and the console), empty for the seed or zeroauthy itself. The
	// seed never touches API-created clients.
	Origin string
}

// OriginAPI marks a client, tenant, resource server or client grant created through the Management or
// system API.
const OriginAPI = "api"

// Scope is a permission defined by a resource server.
type Scope struct {
	Value       string
	Description string
}

// ResourceServer is an API that access tokens are issued for. Identifier
// is the value of the audience parameter and aud claim.
type ResourceServer struct {
	TenantID      string
	ID            string
	Identifier    string
	Name          string
	Scopes        []Scope
	SigningAlg    string
	TokenLifetime int // seconds; 0 means the default
	// TokenLifetimeForWeb is Auth0's lifetime for tokens issued by implicit
	// and hybrid flows. zeroauthy has neither, so it only stores and reports
	// it; 0 means the default.
	TokenLifetimeForWeb int
	AllowOfflineAccess  bool
	CreatedAt           time.Time

	// SkipConsentForVerifiableFirstPartyClients skips the consent prompt
	// for first-party clients with verifiable callback URIs.
	SkipConsentForVerifiableFirstPartyClients bool
	SubjectTypeAuthorization                  SubjectTypeAuthorization

	// IsSystem marks an API zeroauthy defines itself, such as a tenant's
	// Management API (Auth0's is_system). The store does not act on it.
	IsSystem bool
	// Origin records who created the API: OriginAPI for the Management API
	// (and the console), empty for the seed or zeroauthy itself. The seed
	// never touches API-created resource servers.
	Origin string
}

// Security modes of third-party applications.
const (
	SecurityModeStrict     = "strict"
	SecurityModePermissive = "permissive"
)

// Redirection policies of applications.
const (
	RedirectionPolicyOpenRedirectProtection = "open_redirect_protection"
	RedirectionPolicyAllowAlways            = "allow_always"
)

// API access policies.
const (
	PolicyAllowAll           = "allow_all"
	PolicyRequireClientGrant = "require_client_grant"
	PolicyDenyAll            = "deny_all"
)

// Subject types of client grants and access policies.
const (
	SubjectTypeUser   = "user"
	SubjectTypeClient = "client"
)

// WithDefaults returns a copy of g with an empty SubjectType read as a
// client grant. Drivers apply it in Create and Update.
func (g *ClientGrant) WithDefaults() *ClientGrant {
	out := *g
	if out.SubjectType == "" {
		out.SubjectType = SubjectTypeClient
	}
	return &out
}

// SubjectTypeAuthorization is an API's access policy for user flows and
// for client credentials (Auth0's subject_type_authorization). An empty
// policy means the default: allow_all for User, require_client_grant for
// Client.
type SubjectTypeAuthorization struct {
	User   string
	Client string
}

// ClientGrant authorizes a client to obtain tokens for an audience,
// limited to Scopes. SubjectType says whether it applies to user flows
// or to client credentials.
type ClientGrant struct {
	TenantID    string
	ID          string
	ClientID    string
	Audience    string
	Scopes      []string
	SubjectType string // SubjectTypeUser or SubjectTypeClient
	CreatedAt   time.Time
	// AllowAllScopes grants every scope the API defines when a token is
	// issued, so scopes added later are covered; Scopes is then empty
	// (Auth0's allow_all_scopes).
	AllowAllScopes bool
	// Origin records who created the grant: OriginAPI for the Management
	// API (and the console), empty for the seed or zeroauthy itself. The
	// seed never touches API-created grants.
	Origin string
}

// EffectiveScopes returns the scopes the grant allows for an API that
// defines defined: every defined scope for AllowAllScopes, else Scopes.
func (g *ClientGrant) EffectiveScopes(defined []Scope) []string {
	if !g.AllowAllScopes {
		return g.Scopes
	}
	out := make([]string, len(defined))
	for i, s := range defined {
		out[i] = s.Value
	}
	return out
}

// ClientGrantFilter narrows ClientGrants.List; an empty field matches all.
type ClientGrantFilter struct {
	ClientID    string
	Audience    string
	SubjectType string
	// ID keeps only the grant with this ID: a lookup by ID.
	ID string
	// AfterID keeps only grants whose ID sorts after it in byte order: the
	// cursor of checkpoint paging.
	AfterID string
}

// Page selects a window of an ordered list: Offset rows are skipped and at
// most Limit are returned. Limit 0 means no limit.
type Page struct {
	Offset int
	Limit  int
}

// UserGrant records the scopes a user consented to for a client and an
// audience (Auth0's user grants).
type UserGrant struct {
	TenantID  string
	ID        string
	ClientID  string
	UserID    string
	Audience  string // an API identifier, or https://{domain}/userinfo
	Scopes    []string
	CreatedAt time.Time
	UpdatedAt time.Time
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

	// EnabledDatabaseCustomization makes the connection use CustomScripts
	// (Auth0's custom database). ImportMode copies users into zeroauthy on
	// their first successful login.
	EnabledDatabaseCustomization bool
	ImportMode                   bool
	CustomScripts                map[string]string // ScriptNames -> JS source
	// ConfigurationSealed is the envelope-sealed JSON object of the
	// connection's configuration settings (keys.SealConnectionConfig).
	ConfigurationSealed   []byte
	SetUserRootAttributes string // RootAttributes*; empty means on_each_login
	// IsDomainConnection marks a domain-level connection (Auth0's
	// is_domain_connection).
	IsDomainConnection bool
}

// Custom database script names.
const (
	ScriptLogin          = "login"
	ScriptGetUser        = "get_user"
	ScriptCreate         = "create"
	ScriptVerify         = "verify"
	ScriptChangePassword = "change_password"
	ScriptDelete         = "delete"
	ScriptChangeEmail    = "change_email"
)

// ScriptNames lists every custom database script name Auth0 defines.
var ScriptNames = []string{ScriptLogin, ScriptGetUser, ScriptCreate, ScriptVerify,
	ScriptChangePassword, ScriptDelete, ScriptChangeEmail}

// Values for Connection.SetUserRootAttributes.
const (
	RootAttributesOnEachLogin  = "on_each_login" // default (empty means this)
	RootAttributesOnFirstLogin = "on_first_login"
)

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
	GivenName     string
	FamilyName    string
	// UserMetadata is free-form, user-editable JSON (maps, slices, scalars).
	UserMetadata map[string]any
	// AppMetadata is free-form JSON that users cannot edit.
	AppMetadata map[string]any
	Blocked     bool
	Identities  []Identity
	LastLogin   *time.Time
	LoginsCount int
	CreatedAt   time.Time
	UpdatedAt   time.Time
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
	ReplayedAt          *time.Time // first presentation after UsedAt; see AuthCodes.Consume
}

// PushedAuthRequest is an authorization request pushed to /oauth/par
// (RFC 9126). The /authorize request that names it uses it once.
type PushedAuthRequest struct {
	TenantID string
	// IDHash is secrets.HashToken of the opaque part of the request_uri.
	IDHash   string
	ClientID string
	// Params is the validated request, including kept ext-* parameters.
	Params    map[string]string
	ExpiresAt time.Time
	CreatedAt time.Time
	UsedAt    *time.Time
}

// DeviceCodeStatus is where a device authorization request is in its life.
type DeviceCodeStatus string

const (
	DeviceCodePending  DeviceCodeStatus = "pending"
	DeviceCodeApproved DeviceCodeStatus = "approved"
	DeviceCodeDenied   DeviceCodeStatus = "denied"
	DeviceCodeConsumed DeviceCodeStatus = "consumed"
)

// DeviceCode is a device authorization request (RFC 8628).
type DeviceCode struct {
	TenantID       string
	DeviceCodeHash string // secrets.HashToken(device_code)
	UserCodeHash   string // secrets.HashToken(devicecode.Normalize(user_code))
	ClientID       string
	Scopes         []string // requested
	Audience       string   // resolved audience; "" for none
	Status         DeviceCodeStatus
	UserID         string   // set by Decide(approved)
	GrantedScopes  []string // set by Decide(approved)
	// LastPolledAt is the last poll that was not answered slow_down.
	LastPolledAt      *time.Time
	ExpiredReportedAt *time.Time
	ExpiresAt         time.Time
	CreatedAt         time.Time
}

// DeviceDecision is the user's answer to a device code. Device tokens are
// not bound to the browser session: Auth0's device ID tokens carry no sid
// and no auth_time (observations/device-flow.md), so no session ID or auth
// time is recorded.
type DeviceDecision struct {
	Status        DeviceCodeStatus // DeviceCodeApproved or DeviceCodeDenied
	UserID        string
	GrantedScopes []string
}

// DevicePollOutcome is how the token endpoint answers one poll.
type DevicePollOutcome string

const (
	PollPending  DevicePollOutcome = "pending"   // authorization_pending
	PollSlowDown DevicePollOutcome = "slow_down" // too soon after the last accepted poll
	PollApproved DevicePollOutcome = "approved"  // this poll consumed an approved code: issue tokens
	PollDenied   DevicePollOutcome = "denied"    // this poll consumed a denied code: access_denied once
	PollExpired  DevicePollOutcome = "expired"   // first poll after expiry: expired_token
	PollInvalid  DevicePollOutcome = "invalid"   // consumed, or expired and already reported
)

// MinPollGap is the shortest gap between accepted polls (Auth0 never
// answered slow_down to polls 1 s apart).
const MinPollGap = time.Second

// DevicePoll is the outcome of one poll. Code is the record after the poll.
type DevicePoll struct {
	Code    *DeviceCode
	Outcome DevicePollOutcome
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

// RefreshTokenPolicy configures the refresh tokens issued to a client.
// Field meanings follow Auth0's public application settings.
type RefreshTokenPolicy struct {
	// Rotating issues a new refresh token on every exchange; presenting a
	// rotated token again (after Leeway) revokes its whole family.
	Rotating bool
	// Leeway is how many seconds after its first rotation a token may still
	// be exchanged, for clients that retry. Zero means no reuse at all.
	Leeway int
	// Expiring false means the tokens never expire.
	Expiring bool
	// TokenLifetime is the family's absolute lifetime in seconds; zero means
	// the default (31557600) when Expiring.
	TokenLifetime int
	// IdleTokenLifetime is the inactivity lifetime in seconds; zero means
	// the default (2592000) when Expiring.
	IdleTokenLifetime int
}

// CustomText holds a tenant's text overrides, shaped like Auth0's
// documented prompt custom text: prompt → language → screen → key → text.
type CustomText map[string]map[string]map[string]map[string]string

// PasswordResetTicket is an issued password-reset link. Only the hash of
// the ticket token is stored.
type PasswordResetTicket struct {
	TenantID   string
	ID         string
	TokenHash  string // secrets.HashToken of the ticket token
	UserID     string
	Connection string
	ClientID   string
	// Lang is the UI language chosen when the ticket was requested.
	Lang      string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}
