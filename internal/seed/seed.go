// Package seed applies a declarative YAML description of tenants, APIs,
// applications and grants to a store. Until the Management API exists,
// seeding is how zeroauthy is administered.
package seed

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/apirules"
	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"go.yaml.in/yaml/v3"
)

// Mode says how Apply treats what already exists.
type Mode string

const (
	// ModeApply (the default) makes the store match the seed: existing
	// entities the seed names are updated.
	ModeApply Mode = "apply"
	// ModeCreateOnly creates what the seed names and the store lacks, and
	// changes nothing that exists, so console edits survive a restart.
	ModeCreateOnly Mode = "create_only"
)

// Valid reports whether m is a mode ("" means ModeApply).
func (m Mode) Valid() bool { return m == "" || m == ModeApply || m == ModeCreateOnly }

type File struct {
	Tenants []Tenant `yaml:"tenants"`

	// Mode is set by the caller from the server's configuration; it is not
	// part of the seed file.
	Mode Mode `yaml:"-"`

	// Set by CheckManagementAPI: the server's base domain, which names each
	// tenant's Management API identifier.
	mgmtChecked bool
	baseDomain  string
}

type Tenant struct {
	PhoneProvider  *SeedPhoneProvider  `yaml:"phone_provider"`
	PhoneTemplates []SeedPhoneTemplate `yaml:"phone_templates"`
	Guardian       *Guardian           `yaml:"guardian"`
	// MyAccountAPI activates the My Account API (Plan 42a, LR42a-7).
	MyAccountAPI *MyAccountAPI `yaml:"my_account_api"`
	// MyOrganizationAPI activates the My Organization API (Plan 42b).
	MyOrganizationAPI *MyAccountAPI    `yaml:"my_organization_api"`
	EventStreams      []map[string]any `yaml:"event_streams"`
	LogStreams        []map[string]any `yaml:"log_streams"`
	Modules           []ActionModule   `yaml:"modules"`
	Actions           []Action         `yaml:"actions"`
	// TokenExchangeProfiles bind a subject_token_type to a custom token
	// exchange Action by name. They are applied after the Actions, so they
	// need ApplyWithActions.
	TokenExchangeProfiles []TokenExchangeProfile    `yaml:"token_exchange_profiles"`
	Triggers              map[string]Trigger        `yaml:"triggers"`
	AttackProtection      map[string]map[string]any `yaml:"attack_protection"`
	// Settings uses the public tenant settings inventory; legacy top-level durations remain seconds.
	Settings map[string]any `yaml:"settings"`
	// CIMDClients are Client ID Metadata Document URLs the deployment
	// registers once the server can fetch them (Plan 41b): a document that
	// cannot be fetched or is invalid is a warning, not a seed error.
	CIMDClients []string `yaml:"cimd_clients"`
	supplied    map[string]any

	Name         string   `yaml:"name"`
	FriendlyName string   `yaml:"friendly_name"`
	Domains      []string `yaml:"domains"`
	// DomainRPIDs contains optional per-alias RP IDs decoded from domains objects.
	DomainRPIDs         map[string]string `yaml:"-"`
	DefaultAudience     string            `yaml:"default_audience"`
	DefaultDirectory    string            `yaml:"default_directory"`
	AllowedLogoutURLs   []string          `yaml:"allowed_logout_urls"`
	ResourceServers     []ResourceServer  `yaml:"resource_servers"`
	Organizations       []Organization    `yaml:"organizations"`
	Roles               []Role            `yaml:"roles"`
	Clients             []Client          `yaml:"clients"`
	ClientGrants        []ClientGrant     `yaml:"client_grants"`
	SessionLifetime     int               `yaml:"session_lifetime"`
	IdleSessionLifetime int               `yaml:"idle_session_lifetime"`
	Branding            Branding          `yaml:"branding"`
	Connections         []Connection      `yaml:"connections"`
	Users               []User            `yaml:"users"`
	EnabledLocales      []string          `yaml:"enabled_locales"`
	CustomText          store.CustomText  `yaml:"custom_text"`

	DeviceFlow DeviceFlow `yaml:"device_flow"`

	SkipNonVerifiableCallbackURIConfirmationPrompt bool `yaml:"skip_non_verifiable_callback_uri_confirmation_prompt"`
	UseScopeDescriptionsForConsent                 bool `yaml:"use_scope_descriptions_for_consent"`
	PushedAuthorizationRequestsSupported           bool `yaml:"pushed_authorization_requests_supported"`

	// mgmtAudiences are client grant audiences that name a Management API
	// (https://<host>/api/v2/), which the seed does not define; checked
	// against the server configuration by CheckManagementAPI.
	mgmtAudiences []string
}

// Guardian patches tenant MFA configuration. Omitted factors and a nil policy
// list are preserved; an explicit empty policies list disables enforcement.
type Guardian struct {
	PhoneSettings         map[string]any            `yaml:"phone_settings"`
	PhoneSelectedProvider map[string]any            `yaml:"phone_selected_provider"`
	PhoneMessageTypes     map[string]any            `yaml:"phone_message_types"`
	PhoneProviders        map[string]map[string]any `yaml:"phone_providers"`
	PhoneTemplates        map[string]any            `yaml:"phone_templates"`
	Factors               map[string]bool           `yaml:"factors"`
	Policies              []string                  `yaml:"policies"`
	// WebAuthnRoaming is a zeroauthy extension: Auth0 sets security-key user
	// verification only in its Dashboard, so no Management API or Deploy CLI
	// handler carries it (LR33b-22). Omitted keeps the stored value.
	WebAuthnRoaming *GuardianWebAuthnRoaming `yaml:"webauthn_roaming"`
}

// GuardianWebAuthnRoaming is the security-key factor's user-verification
// setting: discouraged (the default, "Never"), preferred or required.
type GuardianWebAuthnRoaming struct {
	UserVerification string `yaml:"user_verification"`
}

// DeviceFlow shapes the user codes of the device authorization grant.
// Empty values select the defaults.
type DeviceFlow struct {
	Charset string `yaml:"charset"`
	Mask    string `yaml:"mask"`
}

type Role struct {
	Name        string           `yaml:"name"`
	Description string           `yaml:"description"`
	Permissions []RolePermission `yaml:"permissions"`
	// MyOrganizationVisible lets organization administrators assign the
	// role through the My Organization API (Plan 42b, LR42b-2).
	MyOrganizationVisible bool `yaml:"my_organization_visible"`
}
type RolePermission struct {
	ResourceServerIdentifier string `yaml:"resource_server_identifier"`
	PermissionName           string `yaml:"permission_name"`
}

type ResourceServer struct {
	ProofOfPossession *store.ProofOfPossession `yaml:"proof_of_possession"`
	EnforcePolicies   bool                     `yaml:"enforce_policies"`
	TokenDialect      string                   `yaml:"token_dialect"`
	Identifier        string                   `yaml:"identifier"`
	Name              string                   `yaml:"name"`
	Scopes            []Scope                  `yaml:"scopes"`
	// SigningAlg is RS256 (the default), HS256 or PS256. HS256 signs with
	// SigningSecret, plaintext in the seed and sealed when applied; an HS256
	// API without one keeps its stored secret, or gets a generated one.
	SigningAlg                             string `yaml:"signing_alg"`
	SigningSecret                          string `yaml:"signing_secret"`
	TokenLifetime                          int    `yaml:"token_lifetime"`
	AllowOfflineAccess                     bool   `yaml:"allow_offline_access"`
	AllowOnlineAccess                      bool   `yaml:"allow_online_access"`
	AllowOnlineAccessWithEphemeralSessions bool   `yaml:"allow_online_access_with_ephemeral_sessions"`

	SkipConsentForVerifiableFirstPartyClients *bool                    `yaml:"skip_consent_for_verifiable_first_party_clients"`
	SubjectTypeAuthorization                  SubjectTypeAuthorization `yaml:"subject_type_authorization"`

	// normalized is the API after apirules.Normalize, set by validate.
	normalized *apirules.Spec
}

// spec returns the API's settings for apirules.
func (rs *ResourceServer) spec() apirules.Spec {
	scopes := make([]store.Scope, len(rs.Scopes))
	for i, s := range rs.Scopes {
		scopes[i] = store.Scope{Value: s.Value, Description: s.Description}
	}
	return apirules.Spec{
		ProofOfPossession: rs.ProofOfPossession, Identifier: rs.Identifier, Name: rs.Name, Scopes: scopes, SigningAlg: rs.SigningAlg,
		TokenLifetime: rs.TokenLifetime, AllowOfflineAccess: rs.AllowOfflineAccess,
		AllowOnlineAccess: rs.AllowOnlineAccess, AllowOnlineAccessWithEphemeralSessions: rs.AllowOnlineAccessWithEphemeralSessions,
		EnforcePolicies: rs.EnforcePolicies, TokenDialect: rs.TokenDialect,
		SkipConsentForVerifiableFirstPartyClients: rs.SkipConsentForVerifiableFirstPartyClients,
		SubjectTypeAuthorization: store.SubjectTypeAuthorization{
			User: rs.SubjectTypeAuthorization.User.Policy, Client: rs.SubjectTypeAuthorization.Client.Policy,
		},
	}
}

// SubjectTypeAuthorization is Auth0's API access policy object.
type SubjectTypeAuthorization struct {
	User   AccessPolicy `yaml:"user"`
	Client AccessPolicy `yaml:"client"`
}

type AccessPolicy struct {
	Policy string `yaml:"policy"`
}

type Scope struct {
	Value       string `yaml:"value"`
	Description string `yaml:"description"`
}

type Client struct {
	// MyOrganizationConfiguration is my_organization_configuration (Plan 42b).
	MyOrganizationConfiguration map[string]any `yaml:"my_organization_configuration"`
	OIDCLogout                  map[string]any `yaml:"oidc_logout"`
	Addons                      map[string]any `yaml:"addons"`
	ClientAliases               []string       `yaml:"client_aliases"`
	// AsyncApprovalNotificationChannels are the CIBA channels (Plan 41c).
	AsyncApprovalNotificationChannels []string          `yaml:"async_approval_notification_channels"`
	FormTemplate                      string            `yaml:"form_template"`
	OIDCSupport                       map[string]any    `yaml:"oidc_support"`
	JWTConfiguration                  *JWTConfiguration `yaml:"jwt_configuration"`
	oidcLogout                        *store.OIDCLogout
	addons                            *store.ClientAddons
	oidcSupport                       *store.OIDCSupport
	TokenQuota                        map[string]any `yaml:"token_quota"`
	RequireProofOfPossession          bool           `yaml:"require_proof_of_possession"`
	ClientID                          string         `yaml:"client_id"`
	Name                              string         `yaml:"name"`
	AppType                           string         `yaml:"app_type"`
	// ClientSecret is plaintext in the seed file and sealed under the master
	// key when applied (D-0038). Protect seed files like any other credential
	// store. A confidential client may omit it once it exists: its stored
	// secret is then kept.
	ClientSecret            string       `yaml:"client_secret"`
	TokenEndpointAuthMethod string       `yaml:"token_endpoint_auth_method"`
	GrantTypes              []string     `yaml:"grant_types"`
	Callbacks               []string     `yaml:"callbacks"`
	AllowedLogoutURLs       []string     `yaml:"allowed_logout_urls"`
	WebOrigins              []string     `yaml:"web_origins"`
	AllowedOrigins          []string     `yaml:"allowed_origins"`
	IDTokenLifetime         int          `yaml:"id_token_lifetime"`
	RefreshToken            RefreshToken `yaml:"refresh_token"`

	OrganizationUsage            string   `yaml:"organization_usage"`
	OrganizationRequireBehavior  string   `yaml:"organization_require_behavior"`
	OrganizationDiscoveryMethods []string `yaml:"organization_discovery_methods"`

	IsFirstParty                                   *bool  `yaml:"is_first_party"`
	ThirdPartySecurityMode                         string `yaml:"third_party_security_mode"`
	RedirectionPolicy                              string `yaml:"redirection_policy"`
	SkipNonVerifiableCallbackURIConfirmationPrompt *bool  `yaml:"skip_non_verifiable_callback_uri_confirmation_prompt"`
	RequirePushedAuthorizationRequests             bool   `yaml:"require_pushed_authorization_requests"`

	// NativeSocialLogin stores the public apple/facebook/google enabled objects.
	// Shared rules validate its shape; omitted providers remain disabled.
	NativeSocialLogin any `yaml:"native_social_login"`
	nativeSocialLogin map[string]bool

	// Mobile is Auth0's client mobile object (ios.team_id,
	// ios.app_bundle_identifier, android.app_package_name,
	// android.sha256_cert_fingerprints), used for native passkeys and the
	// association files. It needs a store with webauthn.v1.
	Mobile map[string]any `yaml:"mobile"`
	mobile *store.ClientMobile

	// Credentials are the public keys of the client (at most two). The
	// three settings below name them by name; they need a store with
	// client_credentials.v1. private_key_jwt implies an omitted
	// token_endpoint_auth_method.
	Credentials                 []ClientCredential           `yaml:"credentials"`
	ClientAuthenticationMethods *ClientAuthenticationMethods `yaml:"client_authentication_methods"`
	SignedRequestObject         *SignedRequestObject         `yaml:"signed_request_object"`
	TokenExchange               *ClientTokenExchange         `yaml:"token_exchange"`
	parsedCredentials           []parsedCredential

	// normalized is the client after clientrules.Normalize, set by validate.
	tokenQuota *store.TokenQuota
	normalized *clientrules.Spec
}

// spec returns the client's settings for clientrules.
func (c *Client) spec() clientrules.Spec {
	alg := ""
	lifetime := c.IDTokenLifetime
	if c.JWTConfiguration != nil {
		alg = c.JWTConfiguration.Alg
		if c.JWTConfiguration.LifetimeInSeconds != nil {
			lifetime = *c.JWTConfiguration.LifetimeInSeconds
		}
	}
	method := c.TokenEndpointAuthMethod
	if c.usesPrivateKeyJWT() {
		// Normalize needs a confidential method; the stored one stays empty.
		method = store.AuthMethodClientSecretPost
	}
	return clientrules.Spec{
		TokenQuota: c.tokenQuota, Addons: c.addons.Clone(), ClientAliases: slices.Clone(c.ClientAliases), AsyncApprovalNotificationChannels: slices.Clone(c.AsyncApprovalNotificationChannels), FormTemplate: c.FormTemplate, OIDCLogout: c.oidcLogout.Clone(), OIDCSupport: c.oidcSupport.Clone(), IDTokenAlg: alg,
		Name: c.Name, AppType: c.AppType, TokenEndpointAuthMethod: method,
		OrganizationUsage: c.OrganizationUsage, OrganizationRequireBehavior: c.OrganizationRequireBehavior, OrganizationDiscoveryMethods: slices.Clone(c.OrganizationDiscoveryMethods),
		GrantTypes: c.GrantTypes, Callbacks: c.Callbacks, AllowedLogoutURLs: c.AllowedLogoutURLs,
		WebOrigins: c.WebOrigins, AllowedOrigins: c.AllowedOrigins, IDTokenLifetime: lifetime,
		RefreshToken: clientrules.RefreshToken{
			Policies:     c.RefreshToken.Policies,
			RotationType: c.RefreshToken.RotationType, ExpirationType: c.RefreshToken.ExpirationType,
			Leeway: c.RefreshToken.Leeway, TokenLifetime: c.RefreshToken.TokenLifetime,
			IdleTokenLifetime: c.RefreshToken.IdleTokenLifetime,
		},
		IsFirstParty: c.IsFirstParty, ThirdPartySecurityMode: c.ThirdPartySecurityMode,
		RedirectionPolicy: c.RedirectionPolicy,
		SkipNonVerifiableCallbackURIConfirmationPrompt: c.SkipNonVerifiableCallbackURIConfirmationPrompt,
		RequirePushedAuthorizationRequests:             c.RequirePushedAuthorizationRequests, RequireProofOfPossession: c.RequireProofOfPossession,
		Mobile:            c.mobile.Clone(),
		NativeSocialLogin: maps.Clone(c.nativeSocialLogin),
	}
}

// RefreshToken is a client's refresh-token policy. Values follow Auth0's
// public application settings; empty types take defaults in validate.
type RefreshToken struct {
	Policies          []store.MRRTPolicy `yaml:"policies"`
	RotationType      string             `yaml:"rotation_type"`   // rotating | non-rotating
	ExpirationType    string             `yaml:"expiration_type"` // expiring | non-expiring
	Leeway            int                `yaml:"leeway"`
	TokenLifetime     int                `yaml:"token_lifetime"`
	IdleTokenLifetime int                `yaml:"idle_token_lifetime"`
}

type ClientGrant struct {
	OrganizationUsage    string   `yaml:"organization_usage"`
	AllowAnyOrganization bool     `yaml:"allow_any_organization"`
	ClientID             string   `yaml:"client_id"`
	Audience             string   `yaml:"audience"`
	Scopes               []string `yaml:"scopes"`

	SubjectType string `yaml:"subject_type"`
}

// Load reads and validates a seed file.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	f, err := parse(data, filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("seed %s: %w", path, err)
	}
	return f, nil
}

// Parse decodes seed YAML, rejecting unknown fields, and validates it.
func Parse(data []byte) (*File, error) { return parse(data, "") }

func parse(data []byte, baseDir string) (*File, error) {
	normalized, domainRPIDs, err := decodeDomainAliases(data)
	if err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(normalized))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("seed: the file is empty; expected a tenants list")
		}
		return nil, fmt.Errorf("seed: %w", err)
	}
	var raw struct {
		Tenants []map[string]any `yaml:"tenants"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	for i := range f.Tenants {
		f.Tenants[i].supplied = raw.Tenants[i]
		if i < len(domainRPIDs) {
			f.Tenants[i].DomainRPIDs = domainRPIDs[i]
		}
	}
	if err := resolveAppleSecrets(&f, baseDir); err != nil {
		return nil, err
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// ValidateFile revalidates an in-memory seed after a trusted preparation step
// and refreshes its normalized shared-rule projections.
func ValidateFile(f *File) error {
	if f == nil {
		return errors.New("seed: nil file")
	}
	return f.validate()
}

type Branding struct {
	LogoURL      string `yaml:"logo_url"`
	PrimaryColor string `yaml:"primary_color"`
}

type Connection struct {
	Name             string         `yaml:"name"`
	Strategy         string         `yaml:"strategy"`
	EnabledClients   []string       `yaml:"enabled_clients"`
	DisableSignup    bool           `yaml:"disable_signup"`
	RequiresUsername bool           `yaml:"requires_username"`
	PasswordPolicy   PasswordPolicy `yaml:"password_policy"`
	// PasswordOptions is Auth0's password_options. It replaces
	// password_policy, which stays for existing seeds; naming both is an
	// error.
	PasswordOptions *connrules.PasswordOptions `yaml:"password_options"`

	// Custom database options keep Auth0's names.
	EnabledDatabaseCustomization bool              `yaml:"enabledDatabaseCustomization"`
	ImportMode                   bool              `yaml:"import_mode"`
	CustomScripts                map[string]string `yaml:"customScripts"`
	// Configuration is plaintext in the seed file and sealed when applied.
	Configuration         map[string]string `yaml:"configuration"`
	SetUserRootAttributes string            `yaml:"set_user_root_attributes"`

	IsDomainConnection bool `yaml:"is_domain_connection"`

	// Options are the options of a database, passwordless or federated strategy (google-oauth2,
	// oauth2, oidc, okta, windowslive, waad, apple) in Auth0's names. Apple app_secret
	// requires a file:// or env:// reference. Other options.client_secret is plaintext in
	// the seed file and sealed when applied; enterprise front-channel and
	// private_key_jwt connections do not require it. Keys are not seeded.
	Options      map[string]any `yaml:"options"`
	DisplayName  string         `yaml:"display_name"`
	ShowAsButton *bool          `yaml:"show_as_button"`

	// normalized is the connection after connrules.Normalize, set by
	// validate.
	normalized *connrules.Spec
}

// spec returns the connection's settings for connrules. It copies, so that
// Normalize leaves the parsed seed alone.
func (c *Connection) spec() connrules.Spec {
	s := connrules.Spec{
		Name: c.Name, Strategy: c.Strategy,
		EnabledClients:     slices.Clone(c.EnabledClients),
		IsDomainConnection: c.IsDomainConnection,
		Options: connrules.Options{
			DisableSignup: c.DisableSignup, RequiresUsername: c.RequiresUsername,
			EnabledDatabaseCustomization: c.EnabledDatabaseCustomization, ImportMode: c.ImportMode,
			CustomScripts:         maps.Clone(c.CustomScripts),
			SetUserRootAttributes: c.SetUserRootAttributes,
		},
	}
	if c.Options != nil {
		s.Options.Extra = cloneYAMLMap(c.Options)
		s.DisplayName, s.ShowAsButton = c.DisplayName, c.ShowAsButton
	}
	// Validate secret reference syntax separately; wire schema validation uses a
	// valid placeholder without reading the environment during Parse.
	if s.Passwordless() && s.Strategy == connrules.StrategySMS {
		if _, ok := s.Options.Extra["twilio_token"]; ok {
			s.Options.Extra["twilio_token"] = "00000000000000000000000000000000"
		}
		if ga, ok := s.Options.Extra["gateway_authentication"].(map[string]any); ok {
			if _, ok := ga["secret"]; ok {
				ga["secret"] = "seed-reference-placeholder"
			}
		}
	}
	if c.Configuration != nil {
		s.Options.Configuration = make(map[string]*string, len(c.Configuration))
		for k, v := range c.Configuration {
			s.Options.Configuration[k] = &v
		}
	}
	if po := c.PasswordOptions; po != nil {
		cp := connrules.PasswordOptions{}
		if po.Complexity != nil {
			v := *po.Complexity
			v.CharacterTypes = slices.Clone(v.CharacterTypes)
			cp.Complexity = &v
		}
		if po.History != nil {
			v := *po.History
			cp.History = &v
		}
		if po.Dictionary != nil {
			v := *po.Dictionary
			v.Custom = slices.Clone(v.Custom)
			cp.Dictionary = &v
		}
		if po.ProfileData != nil {
			v := *po.ProfileData
			v.BlockedFields = slices.Clone(v.BlockedFields)
			cp.ProfileData = &v
		}
		s.Options.PasswordOptions = &cp
		return s
	}
	if s.Federated() || s.Passwordless() {
		// No password model: a password_policy or password_options on a
		// federated connection is refused by validation.
		if c.PasswordPolicy != (PasswordPolicy{}) {
			s.Options.PasswordOptions = &connrules.PasswordOptions{}
		}
		return s
	}
	// The seed's own password policy owns the complexity half only.
	lc := store.LegacyComplexity(c.PasswordPolicy.MinLength, c.PasswordPolicy.RequireCharacterClasses)
	var minLength *int
	if lc.MinLength > 0 {
		minLength = &lc.MinLength
	}
	s.Options.PasswordOptions = &connrules.PasswordOptions{Complexity: &connrules.Complexity{
		MinLength: minLength, CharacterTypes: lc.CharacterTypes, CharacterTypeRule: lc.CharacterTypeRule,
		MinCharacterClasses: lc.MinCharacterClasses,
	}}
	return s
}

type PasswordPolicy struct {
	MinLength               int `yaml:"min_length"`
	RequireCharacterClasses int `yaml:"require_character_classes"`
}

type User struct {
	Connection string `yaml:"connection"`
	Email      string `yaml:"email"`
	Username   string `yaml:"username"`
	// Password is plaintext in the seed file and hashed when applied.
	Password      string `yaml:"password"`
	EmailVerified bool   `yaml:"email_verified"`
	Name          string `yaml:"name"`
	Nickname      string `yaml:"nickname"`
	GivenName     string `yaml:"given_name"`
	FamilyName    string `yaml:"family_name"`
	Picture       string `yaml:"picture"`
	Blocked       bool   `yaml:"blocked"`
}

// cloneYAMLMap deep-copies a decoded YAML mapping into JSON-shaped values.
func cloneYAMLMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneYAMLValue(v)
	}
	return out
}

func cloneYAMLValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneYAMLMap(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = cloneYAMLValue(e)
		}
		return out
	case int:
		return float64(x)
	}
	return v
}

// MyAccountAPI is the seed shorthand for the tenant's My Account API: active
// creates the system API https://{canonical host}/me/, false removes it.
type MyAccountAPI struct {
	Active bool `yaml:"active"`
}

// CIMDClients maps each tenant name to its cimd_clients URLs.
func (f *File) CIMDClients() map[string][]string {
	out := map[string][]string{}
	for _, t := range f.Tenants {
		if len(t.CIMDClients) > 0 {
			out[t.Name] = append([]string(nil), t.CIMDClients...)
		}
	}
	return out
}
