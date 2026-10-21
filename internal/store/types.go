// Exported through pkg/store; add new names there too.

package store

import (
	"maps"
	"slices"
	"strings"
	"time"
)

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

// Values of PasswordComplexity.CharacterTypes.
const (
	CharacterTypeUppercase = "uppercase"
	CharacterTypeLowercase = "lowercase"
	CharacterTypeNumber    = "number"
	CharacterTypeSpecial   = "special"
)

// CharacterTypes lists the four kinds of character a password can be
// required to contain.
var CharacterTypes = []string{CharacterTypeUppercase, CharacterTypeLowercase, CharacterTypeNumber, CharacterTypeSpecial}

// Values of PasswordComplexity.CharacterTypeRule.
const (
	CharacterTypeRuleAll         = "all"
	CharacterTypeRuleThreeOfFour = "three_of_four"
)

// Values of PasswordComplexity.IdenticalCharacters and SequentialCharacters.
const (
	PasswordAllow = "allow"
	PasswordBlock = "block"
)

// Values of PasswordComplexity.MaxLengthExceeded.
const (
	MaxLengthError    = "error"
	MaxLengthTruncate = "truncate"
)

// Values of PasswordDictionary.Default.
const (
	DictionaryEn10k  = "en_10k"
	DictionaryEn100k = "en_100k"
)

// PasswordComplexity is the complexity half of a connection's password
// options (Auth0's password_options.complexity). The zero value of every
// string field means the default named below; the store keeps what it is
// given.
type PasswordComplexity struct {
	MinLength int // zero means 8, zeroauthy's long-standing default
	// CharacterTypes lists the kinds a password must contain: any of
	// CharacterTypeUppercase, CharacterTypeLowercase, CharacterTypeNumber
	// and CharacterTypeSpecial.
	CharacterTypes []string
	// CharacterTypeRule is CharacterTypeRuleAll (every listed type; the
	// default) or CharacterTypeRuleThreeOfFour (at least three of the four
	// types, with all four listed).
	CharacterTypeRule string
	// IdenticalCharacters and SequentialCharacters are PasswordAllow (the
	// default) or PasswordBlock.
	IdenticalCharacters, SequentialCharacters string
	// MaxLengthExceeded is MaxLengthError (the default) or
	// MaxLengthTruncate.
	MaxLengthExceeded string
	// MinCharacterClasses is a zeroauthy extension that keeps the seed's
	// require_character_classes of 1 or 2: a password must contain at least
	// this many of the four kinds of character, whichever they are.
	// Auth0's model has no such rule. Zero means none; 3 and 4 are
	// expressed with CharacterTypes and CharacterTypeRule instead.
	MinCharacterClasses int
}

// LegacyComplexity converts the seed's password_policy (a minimum length and
// a number of required character classes, 0-4) into PasswordComplexity: 4
// classes are all four types, 3 are three of the four, 1 and 2 use
// MinCharacterClasses. Migration 0013 applies the same mapping to stored
// connections.
func LegacyComplexity(minLength, classes int) PasswordComplexity {
	c := PasswordComplexity{MinLength: minLength}
	switch {
	case classes >= 4:
		c.CharacterTypes = slices.Clone(CharacterTypes)
		c.CharacterTypeRule = CharacterTypeRuleAll
	case classes == 3:
		c.CharacterTypes = slices.Clone(CharacterTypes)
		c.CharacterTypeRule = CharacterTypeRuleThreeOfFour
	case classes > 0:
		c.MinCharacterClasses = classes
	}
	return c
}

// PasswordHistory is the history rule of a connection's password options:
// when Active, a new password must differ from the user's last Size.
type PasswordHistory struct {
	Active bool
	Size   int
}

// PasswordDictionary is the dictionary rule: when Active, a password found in
// the Default list (DictionaryEn10k or DictionaryEn100k) or in Custom is
// refused.
type PasswordDictionary struct {
	Active  bool
	Default string
	Custom  []string
}

// PasswordProfileData is the personal data rule: when Active, a password
// containing the value of one of BlockedFields is refused.
type PasswordProfileData struct {
	Active        bool
	BlockedFields []string
}

// PasswordOptions constrains passwords on a database connection (Auth0's
// password_options).
type PasswordOptions struct {
	Complexity  PasswordComplexity
	History     PasswordHistory
	Dictionary  PasswordDictionary
	ProfileData PasswordProfileData
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
	PasswordOptions  PasswordOptions
	// BruteForceProtection switches the login throttle for the connection.
	BruteForceProtection bool
	// UsernameMin and UsernameMax bound usernames on the connection
	// (Auth0's options.validation.username); zero means no limit was set.
	UsernameMin, UsernameMax int
	// Origin records who created the connection: OriginAPI for the
	// Management API (and the console), empty for the seed or zeroauthy
	// itself. The seed never touches API-created connections.
	Origin string
	// Extra holds the options zeroauthy stores but does not interpret
	// (Auth0's unknown option keys): a JSON object, any depth. Nil means
	// none. Numbers come back as float64.
	Extra     map[string]any
	CreatedAt time.Time

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

// ConnectionFilter narrows Connections.List. An empty Name matches all; Name
// is an exact, case-sensitive match. Strategies, when not empty, keeps the
// connections whose Strategy is any of them.
type ConnectionFilter struct {
	Name       string
	Strategies []string
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
	// ImportedHash is the canonical JSON of a passhash.Spec: a hash another
	// system made, imported with the user and upgraded to PasswordHash at
	// the first successful login. The store keeps it opaque. At most one of
	// PasswordHash and ImportedHash is non-empty.
	ImportedHash string `json:",omitempty"`
	// ProfileData is set on a linked (secondary) identity only, and nil on
	// the user's own: what the identity's user had when it was linked,
	// "email" (string) and "email_verified" (bool), and "username" when it
	// had one (D-0043). A linked identity logs in with these, not with the
	// user's root email and username.
	ProfileData map[string]any `json:",omitempty"`
}

// Linked reports whether id is a linked (secondary) identity.
func (id *Identity) Linked() bool { return id.ProfileData != nil }

// ProfileString returns ProfileData[k] when it is a string, or "".
func (id *Identity) ProfileString(k string) string {
	s, _ := id.ProfileData[k].(string)
	return s
}

// OwnIdentity returns u's own (not linked) identity: the one its UserID
// names, or else its first identity that is not linked; nil if none.
func (u *User) OwnIdentity() *Identity {
	var first *Identity
	for i := range u.Identities {
		id := &u.Identities[i]
		if id.Linked() {
			continue
		}
		if id.Provider+"|"+id.UserID == u.UserID {
			return id
		}
		if first == nil {
			first = id
		}
	}
	return first
}

// OwnIdentityOn returns u's own (not linked) identity on connection, or nil.
// Writes that name a connection (a password hash, an email change) target
// this identity; a linked identity on the connection is never chosen.
func (u *User) OwnIdentityOn(connection string) *Identity {
	for i := range u.Identities {
		if id := &u.Identities[i]; id.Connection == connection && !id.Linked() {
			return id
		}
	}
	return nil
}

// ConnectionDeleteEffect says what deleting connection does to u: delete
// is true when u's own identity is on it (the user goes, with everything
// that names it), and strip is true when only linked identities of u are on
// it (they are removed and the user stays, D-0043).
func (u *User) ConnectionDeleteEffect(connection string) (del, strip bool) {
	for i := range u.Identities {
		id := &u.Identities[i]
		if id.Connection != connection {
			continue
		}
		if !id.Linked() {
			return true, false
		}
		strip = true
	}
	return false, strip
}

// WithoutLinkedOn removes u's linked identities on connection.
func (u *User) WithoutLinkedOn(connection string) {
	u.Identities = slices.DeleteFunc(u.Identities, func(id Identity) bool { return id.Linked() && id.Connection == connection })
}

// LoginKey is one way a user is found at login: a value of kind "email" or
// "username" on a connection.
type LoginKey struct{ Connection, Kind, Value string }

// IdentityLogin returns the email and username that log in through id, one
// of u's identities: a linked identity's ProfileData values, otherwise u's
// own Email and Username.
func (u *User) IdentityLogin(id *Identity) (email, username string) {
	if id.Linked() {
		return id.ProfileString("email"), id.ProfileString("username")
	}
	return u.Email, u.Username
}

// LoginKeys returns every non-empty login of u's identities, sorted and
// without duplicates. Users.FindByLogin and the uniqueness rules of Create
// and Update work on these.
func (u *User) LoginKeys() []LoginKey {
	var out []LoginKey
	for i := range u.Identities {
		id := &u.Identities[i]
		email, username := u.IdentityLogin(id)
		for _, k := range [...]LoginKey{{id.Connection, "email", email}, {id.Connection, "username", username}} {
			if k.Value != "" {
				out = append(out, k)
			}
		}
	}
	slices.SortFunc(out, func(a, b LoginKey) int {
		if a.Connection != b.Connection {
			return strings.Compare(a.Connection, b.Connection)
		}
		if a.Kind != b.Kind {
			return strings.Compare(a.Kind, b.Kind)
		}
		return strings.Compare(a.Value, b.Value)
	})
	return slices.Compact(out)
}

// IdentityByLogin returns u's identity on connection that login (an email or
// username) logs in through, preferring u's own identity, or nil.
func (u *User) IdentityByLogin(connection, login string) *Identity {
	var found *Identity
	for i := range u.Identities {
		id := &u.Identities[i]
		if id.Connection != connection || login == "" {
			continue
		}
		if email, username := u.IdentityLogin(id); email == login || username == login {
			if !id.Linked() {
				return id
			}
			if found == nil {
				found = id
			}
		}
	}
	return found
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
	// PhoneNumber and PhoneVerified are profile fields, set through Update.
	PhoneNumber   string
	PhoneVerified bool
	LastLogin     *time.Time
	// LastIP is the client IP of the last login. Only RecordLogin sets it;
	// Update keeps the stored value.
	LastIP      string
	LoginsCount int
	// Version is store-maintained and starts at 0. Callers never set it:
	// Create stores 0 and Update keeps the stored value, except that Update
	// adds one when Blocked goes from false to true or Email changes.
	// SetPasswordHash, SetPasswordHashIfEmpty and BumpVersion add one too.
	// Tokens issued at one version stop being accepted once it moves on.
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
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
	// UpdatedAt and LastInteractedAt are the creation time until the
	// session is touched; Touch sets both to its time.
	UpdatedAt        time.Time
	LastInteractedAt time.Time
	// InitialIP and InitialUserAgent are those of the request that created
	// the session; LastIP and LastUserAgent those of the latest touch. There
	// is no ASN data (D-0043).
	InitialIP        string
	InitialUserAgent string
	LastIP           string
	LastUserAgent    string
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

// Clone returns a deep copy of ct; a nil map stays nil.
func (ct CustomText) Clone() CustomText {
	if ct == nil {
		return nil
	}
	out := make(CustomText, len(ct))
	for p, langs := range ct {
		out[p] = make(map[string]map[string]map[string]string, len(langs))
		for l, screens := range langs {
			out[p][l] = make(map[string]map[string]string, len(screens))
			for s, keys := range screens {
				out[p][l][s] = maps.Clone(keys)
			}
		}
	}
	return out
}

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
	Lang string
	// ResultURL, when set, is where the page sends the user after the
	// password is reset. IncludeEmailInRedirect adds the user's email to
	// that redirect. MarkEmailVerified sets email_verified when the ticket
	// is used.
	ResultURL              string
	IncludeEmailInRedirect bool
	MarkEmailVerified      bool
	ExpiresAt              time.Time
	UsedAt                 *time.Time
	CreatedAt              time.Time
}

// EmailVerificationTicket is an issued email verification link (Auth0's
// email verification ticket).
type EmailVerificationTicket struct {
	TenantID   string
	ID         string
	TokenHash  string // secrets.HashToken of the ticket token
	UserID     string
	Connection string
	ClientID   string
	// ResultURL, when set, is where the page sends the user afterwards;
	// IncludeEmailInRedirect adds the user's email to that redirect.
	ResultURL              string
	IncludeEmailInRedirect bool
	// Email is the user's email (lowercase) when the ticket was issued.
	// The ticket verifies only that address: if the user's email has
	// changed since, it no longer verifies anything.
	Email string
	// Lang is the UI language chosen when the ticket was requested.
	Lang      string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// UserGrantFilter narrows UserGrants.List. An empty field matches all; the
// fields are exact, case-sensitive matches.
type UserGrantFilter struct {
	UserID   string
	ClientID string
	Audience string
}

// ClientFilter narrows Clients.List. AppTypes, when not empty, keeps the
// clients whose AppType is any of them; IsFirstParty, when not nil, keeps
// the clients with that IsFirstParty.
type ClientFilter struct {
	AppTypes     []string
	IsFirstParty *bool
}

// JobType is the kind of a Management API job.
type JobType string

// The job types, as Auth0 names them.
const (
	JobUsersImport       JobType = "users_import"
	JobUsersExport       JobType = "users_export"
	JobVerificationEmail JobType = "verification_email"
)

// JobStatus is where a job is in its life.
type JobStatus string

// The job statuses, as Auth0 names them.
const (
	JobPending    JobStatus = "pending"
	JobProcessing JobStatus = "processing"
	JobCompleted  JobStatus = "completed"
	JobFailed     JobStatus = "failed"
)

// JobMaxAttempts is how many times a job is claimed: a job whose worker
// stopped (its lease ran out) is claimed again once, and failed when its
// second worker stops too.
const JobMaxAttempts = 2

// JobMaxChunk is the largest export file chunk AppendFile takes.
const JobMaxChunk = 1 << 20

// JobMaxRuntime is how long a job may run, from its first claim, before the
// sweeper fails it.
const JobMaxRuntime = 2 * time.Hour

// Status details the store gives the jobs it fails itself.
const (
	JobDetailTimedOut   = "Job timed out"
	JobDetailWorkerLost = "Job failed after its worker stopped twice"
)

// JobSummary counts the records of an import.
type JobSummary struct {
	Failed, Updated, Inserted, Total int
}

// Job is a Management API job: a bulk user import or export, or a
// verification email run. Workers claim jobs with a lease and renew it
// while they work.
type Job struct {
	TenantID, ID string
	Type         JobType
	Status       JobStatus
	// ConnectionID, Connection (the name) and ExternalID are as the
	// request gave them or the handler resolved them.
	ConnectionID, Connection, ExternalID string
	// Params are the request's options, as the handler stored them (JSON
	// values only).
	Params map[string]any
	// Input is the import file (at most 512000 bytes); nil for other types.
	// Finish clears it.
	Input []byte
	// Progress is the number of records committed so far.
	Progress      int
	Summary       JobSummary
	StatusDetails string
	// Attempts counts the claims; LeaseOwner and LeaseUntil name the
	// worker that holds the job and until when (empty and zero when none).
	// FirstClaimedAt is the first claim's time (zero before it).
	Attempts       int
	LeaseOwner     string
	LeaseUntil     time.Time
	FirstClaimedAt time.Time
	// UpdatedAt moves when the job is claimed and when it finishes.
	CreatedAt, UpdatedAt, ExpiresAt time.Time
	// FileSize is the number of bytes of the export file written so far.
	FileSize int64
}

// JobErrorItem is one problem with one record, as Auth0's job error
// details list them.
type JobErrorItem struct{ Code, Message, Path string }

// JobError is the failure of one record of an import. Index is the
// record's position in the file, starting at 0. User is the record with its
// secrets already masked.
type JobError struct {
	Index  int
	User   map[string]any
	Errors []JobErrorItem
}
