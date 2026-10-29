// Package clientrules holds the rules every application must follow,
// whoever writes it: the seed, the Management API and, through the API, the
// console. Spec is a client's settings in Auth0's terms; Normalize fills in
// the defaults and validates; Apply copies a Spec into a store.Client and
// FromClient reads one back.
package clientrules

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Grant types zeroauthy knows by name. Only some are served by its token
// endpoint; the others (implicit, the MFA grants) are accepted and stored
// so that tools which send Auth0's defaults keep working (D-0039).
const (
	GrantAuthorizationCode = "authorization_code"
	GrantImplicit          = "implicit"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
	GrantPassword          = "password"
	GrantPasswordRealm     = "http://auth0.com/oauth/grant-type/password-realm"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	GrantMFAOOB            = "http://auth0.com/oauth/grant-type/mfa-oob"
	GrantMFAOTP            = "http://auth0.com/oauth/grant-type/mfa-otp"
	GrantMFARecoveryCode   = "http://auth0.com/oauth/grant-type/mfa-recovery-code"
)

// GrantTypes lists every grant type a client may name.
var GrantTypes = []string{
	GrantAuthorizationCode, GrantImplicit, GrantRefreshToken, GrantClientCredentials,
	GrantPassword, GrantPasswordRealm, GrantDeviceCode,
	GrantMFAOOB, GrantMFAOTP, GrantMFARecoveryCode,
}

// AppTypes lists the application types.
var AppTypes = []string{
	string(store.AppTypeSPA), string(store.AppTypeRegularWeb),
	string(store.AppTypeNative), string(store.AppTypeNonInteractive),
}

// AuthMethods lists the token endpoint authentication methods.
var AuthMethods = []string{
	store.AuthMethodNone, store.AuthMethodClientSecretPost, store.AuthMethodClientSecretBasic,
}

// Refresh token rotation and expiration types (Auth0's names).
const (
	Rotating     = "rotating"
	NonRotating  = "non-rotating"
	Expiring     = "expiring"
	NonExpiring  = "non-expiring"
	DefaultIDTTL = 36000 // ID token lifetime, seconds
)

// strictGrantTypes are the only grant types a strict third-party
// application may use.
var strictGrantTypes = []string{GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials}

// Spec is a client's settings. Empty strings and nil pointers mean "the
// default", which Normalize fills in.
type Spec struct {
	Name                    string
	AppType                 string
	TokenEndpointAuthMethod string
	GrantTypes              []string
	Callbacks               []string
	AllowedLogoutURLs       []string
	WebOrigins              []string
	AllowedOrigins          []string
	// IDTokenLifetime in seconds; zero means the default (DefaultIDTTL).
	IDTokenLifetime int
	RefreshToken    RefreshToken

	IsFirstParty                                   *bool
	ThirdPartySecurityMode                         string
	RedirectionPolicy                              string
	SkipNonVerifiableCallbackURIConfirmationPrompt *bool
	RequirePushedAuthorizationRequests             bool

	// Organization settings (D-0055); empty and nil mean unset.
	OrganizationUsage            string
	OrganizationRequireBehavior  string
	OrganizationDiscoveryMethods []string
}

// RefreshToken is a client's refresh-token policy in Auth0's terms.
type RefreshToken struct {
	RotationType      string // Rotating | NonRotating
	ExpirationType    string // Expiring | NonExpiring
	Leeway            int
	TokenLifetime     int
	IdleTokenLifetime int
}

// DefaultAuthMethod is the method a client gets when it names none.
// Browser and native apps cannot keep secrets, so they are public clients.
func DefaultAuthMethod(appType string) string {
	switch store.AppType(appType) {
	case store.AppTypeSPA, store.AppTypeNative:
		return store.AuthMethodNone
	default:
		return store.AuthMethodClientSecretPost
	}
}

// DefaultGrantTypes are the grant types the Management API gives a new
// client that names none. Auth0 gives every type the same list
// (observations/management-clients.md, M1); zeroauthy leaves out implicit,
// which it does not serve, and client_credentials for public clients, which
// cannot use it.
func DefaultGrantTypes(authMethod string) []string {
	if authMethod == store.AuthMethodNone {
		return []string{GrantAuthorizationCode, GrantRefreshToken}
	}
	return []string{GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials}
}

// CheckURL reports why raw cannot be registered as a redirect target: it
// must parse, be absolute, have no fragment, and http(s) URLs need a host.
// Wildcard hosts (https://*.example.com/cb) parse like any other host.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return fmt.Errorf("%q is not a valid URL", raw)
	case u.Scheme == "":
		return fmt.Errorf("%q must be an absolute URL", raw)
	case strings.Contains(raw, "#"):
		return fmt.Errorf("%q must not contain a fragment", raw)
	case (u.Scheme == "http" || u.Scheme == "https") && u.Host == "":
		return fmt.Errorf("%q has no host", raw)
	}
	return nil
}

// checkOrigin reports why raw is not an origin: a scheme and a host, and
// nothing after them.
func checkOrigin(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q is not an origin (scheme://host[:port])", raw)
	}
	return nil
}

// Normalize fills in s's defaults and checks it. parSupported is the
// tenant's pushed_authorization_requests_supported. It returns every
// problem, each phrased without the client's name. The checks that span
// clients (connections, grants) are the caller's.
func Normalize(s *Spec, parSupported bool) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if !slices.Contains(AppTypes, s.AppType) {
		fail("app_type %q must be one of %v", s.AppType, AppTypes)
	}
	if s.TokenEndpointAuthMethod == "" {
		s.TokenEndpointAuthMethod = DefaultAuthMethod(s.AppType)
	}
	if !slices.Contains(AuthMethods, s.TokenEndpointAuthMethod) {
		fail("token_endpoint_auth_method %q must be one of %v", s.TokenEndpointAuthMethod, AuthMethods)
	}
	for _, cb := range s.Callbacks {
		if err := CheckURL(cb); err != nil {
			fail("callback %v", err)
			continue
		}
		if rest, ok := strings.CutPrefix(cb, "https://*."); ok {
			host := rest[:strings.IndexAny(rest+"/", "/:?")]
			if len(strings.Split(host, ".")) < 2 || slices.Contains(strings.Split(host, "."), "") {
				fail("wildcard callback %q must cover a domain of at least two labels", cb)
			}
		}
	}
	for _, u := range s.AllowedLogoutURLs {
		if err := CheckURL(u); err != nil {
			fail("allowed_logout_urls: %v", err)
		}
	}
	for _, o := range s.WebOrigins {
		if err := checkOrigin(o); err != nil {
			fail("web_origins: %v", err)
		}
	}
	for _, o := range s.AllowedOrigins {
		if err := checkOrigin(o); err != nil {
			fail("allowed_origins: %v", err)
		}
	}
	if s.IDTokenLifetime < 0 {
		fail("the ID token lifetime must not be negative")
	}
	public := s.TokenEndpointAuthMethod == store.AuthMethodNone

	firstParty := s.IsFirstParty == nil || *s.IsFirstParty
	s.IsFirstParty = &firstParty
	switch {
	case firstParty && s.ThirdPartySecurityMode != "":
		fail("third_party_security_mode is only for third-party applications")
	case !firstParty && s.ThirdPartySecurityMode == "":
		s.ThirdPartySecurityMode = store.SecurityModeStrict // O1c
	}
	if !firstParty && s.ThirdPartySecurityMode != store.SecurityModeStrict && s.ThirdPartySecurityMode != store.SecurityModePermissive {
		fail("third_party_security_mode %q must be strict or permissive", s.ThirdPartySecurityMode)
	}
	if s.RequirePushedAuthorizationRequests {
		switch {
		case !parSupported:
			fail("require_pushed_authorization_requests needs the tenant's pushed_authorization_requests_supported")
		case public:
			fail("require_pushed_authorization_requests is only for confidential applications")
		case !firstParty:
			fail("third-party applications cannot use pushed authorization requests") // P9, D-0028
		}
	}
	if s.RedirectionPolicy == "" {
		s.RedirectionPolicy = store.RedirectionPolicyAllowAlways // O1d
		if !firstParty {
			s.RedirectionPolicy = store.RedirectionPolicyOpenRedirectProtection
		}
	}
	if s.RedirectionPolicy != store.RedirectionPolicyAllowAlways && s.RedirectionPolicy != store.RedirectionPolicyOpenRedirectProtection {
		fail("redirection_policy %q must be %s or %s", s.RedirectionPolicy,
			store.RedirectionPolicyOpenRedirectProtection, store.RedirectionPolicyAllowAlways)
	}
	strict := !firstParty && s.ThirdPartySecurityMode == store.SecurityModeStrict
	for _, gt := range s.GrantTypes {
		switch {
		case !slices.Contains(GrantTypes, gt):
			fail("grant type %q is not supported", gt)
		case !firstParty && (gt == GrantPassword || gt == GrantPasswordRealm):
			fail("grant type %q is not available to third-party applications", gt)
		case strict && !slices.Contains(strictGrantTypes, gt):
			fail("grant type %q is not available to strict third-party applications", gt)
		}
	}
	if slices.Contains(s.GrantTypes, GrantDeviceCode) {
		// Observed on Auth0: the Management API accepts the device grant
		// only for first-party native public clients.
		if store.AppType(s.AppType) != store.AppTypeNative {
			fail("device grant requires app_type native")
		}
		if !public {
			fail("device grant requires token_endpoint_auth_method none")
		}
		if !firstParty {
			fail("device grant is not available to third-party applications")
		}
	}
	if strict && slices.Contains(s.GrantTypes, GrantClientCredentials) && public {
		fail("client_credentials requires a confidential client")
	}

	rt := &s.RefreshToken
	if strict && store.AppType(s.AppType) == store.AppTypeNative && rt.RotationType == "" {
		rt.RotationType = Rotating // strict default for native apps
	}
	if strict && rt.ExpirationType == "" {
		rt.ExpirationType = Expiring // Auth0 requires strict refresh tokens to expire
	}
	if rt.RotationType == "" {
		rt.RotationType = NonRotating
		if store.AppType(s.AppType) == store.AppTypeSPA {
			rt.RotationType = Rotating
		}
	}
	if rt.ExpirationType == "" {
		rt.ExpirationType = NonExpiring
		if rt.RotationType == Rotating {
			rt.ExpirationType = Expiring
		}
	}
	switch {
	case rt.RotationType != Rotating && rt.RotationType != NonRotating:
		fail("refresh_token.rotation_type %q must be rotating or non-rotating", rt.RotationType)
	case rt.ExpirationType != Expiring && rt.ExpirationType != NonExpiring:
		fail("refresh_token.expiration_type %q must be expiring or non-expiring", rt.ExpirationType)
	case rt.RotationType == Rotating && rt.ExpirationType != Expiring:
		fail("refresh_token rotation requires expiration_type expiring")
	case store.AppType(s.AppType) == store.AppTypeSPA && rt.ExpirationType != Expiring:
		fail("single-page applications require expiring refresh tokens")
	}
	if strict && rt.ExpirationType != Expiring {
		fail("strict third-party applications require expiring refresh tokens")
	}
	if rt.Leeway < 0 || rt.TokenLifetime < 0 || rt.IdleTokenLifetime < 0 {
		fail("refresh_token leeway and lifetimes must not be negative")
	}
	if rt.TokenLifetime > 0 && rt.IdleTokenLifetime > rt.TokenLifetime {
		fail("refresh_token.idle_token_lifetime must not exceed token_lifetime")
	}
	if err := ValidateOrganizationFields(s.OrganizationUsage, s.OrganizationRequireBehavior, s.OrganizationDiscoveryMethods); err != nil {
		errs = append(errs, err)
	} else if err := CheckOrganizationGrants(s.OrganizationUsage, s.GrantTypes); err != nil {
		errs = append(errs, err)
	}
	return errs
}

// ErrOrganizationRule marks a client organization setting that is well
// formed but conflicts with another setting. Auth0 reports these without an
// errorCode (observed, D-0055), unlike malformed values.
var ErrOrganizationRule = errors.New("organization setting conflict")

var (
	orgUsages    = []string{store.OrgUsageDeny, store.OrgUsageAllow, store.OrgUsageRequire}
	orgBehaviors = []string{store.OrgBehaviorNoPrompt, store.OrgBehaviorPreLoginPrompt, store.OrgBehaviorPostLoginPrompt}
	orgMethods   = []string{store.OrgDiscoveryEmail, store.OrgDiscoveryName}
	// orgRefusedGrants cannot be used by a require client: Organizations
	// do not support the password and device flows (D-0055).
	orgRefusedGrants = []string{GrantPassword, GrantPasswordRealm, GrantDeviceCode}
)

// ValidateOrganizationFields checks a client's organization settings, where
// "" and nil mean unset. pre_login_prompt is accepted with every usage
// (observed); discovery methods need at least one entry and are allowed
// only with pre_login_prompt, a conflict wrapping ErrOrganizationRule.
// post_login_prompt needs an OIDC-conformant client, which every zeroauthy
// client is.
func ValidateOrganizationFields(usage, behavior string, methods []string) error {
	switch {
	case usage != "" && !slices.Contains(orgUsages, usage):
		return fmt.Errorf("organization_usage %q must be one of %v", usage, orgUsages)
	case behavior != "" && !slices.Contains(orgBehaviors, behavior):
		return fmt.Errorf("organization_require_behavior %q must be one of %v", behavior, orgBehaviors)
	case methods != nil && len(methods) == 0:
		return errors.New("organization_discovery_methods needs at least one method")
	}
	for _, m := range methods {
		if !slices.Contains(orgMethods, m) {
			return fmt.Errorf("organization_discovery_methods: %q must be one of %v", m, orgMethods)
		}
	}
	if methods != nil && behavior != store.OrgBehaviorPreLoginPrompt {
		return fmt.Errorf("%w: organization_discovery_methods is only allowed with organization_require_behavior %s", ErrOrganizationRule, store.OrgBehaviorPreLoginPrompt)
	}
	return nil
}

// CheckOrganizationGrants refuses a require client holding the password,
// password-realm or device grants, whichever was configured first
// (observed, D-0055). The error wraps ErrOrganizationRule.
func CheckOrganizationGrants(usage string, grants []string) error {
	if usage != store.OrgUsageRequire {
		return nil
	}
	for _, g := range grants {
		if slices.Contains(orgRefusedGrants, g) {
			return fmt.Errorf("%w: organization_usage require cannot be used with grant type %q", ErrOrganizationRule, g)
		}
	}
	return nil
}

// CheckImmutable reports a change of party or security mode from the
// stored client c to the normalized s: both are fixed at creation.
func CheckImmutable(c *store.Client, s *Spec) error {
	if c.IsFirstParty != *s.IsFirstParty || c.ThirdPartySecurityMode != s.ThirdPartySecurityMode {
		return fmt.Errorf("is_first_party and third_party_security_mode cannot change after creation")
	}
	return nil
}

// Apply copies a normalized s into c. It leaves the identity (tenant,
// client ID, creation time, origin) and the secrets alone.
func Apply(c *store.Client, s *Spec) {
	c.Name, c.AppType = s.Name, store.AppType(s.AppType)
	c.TokenEndpointAuthMethod = s.TokenEndpointAuthMethod
	c.GrantTypes = slices.Clone(s.GrantTypes)
	c.Callbacks, c.AllowedLogoutURLs = slices.Clone(s.Callbacks), slices.Clone(s.AllowedLogoutURLs)
	c.WebOrigins, c.AllowedOrigins = slices.Clone(s.WebOrigins), slices.Clone(s.AllowedOrigins)
	c.IDTokenLifetime = s.IDTokenLifetime
	c.RefreshToken = store.RefreshTokenPolicy{
		Rotating:          s.RefreshToken.RotationType == Rotating,
		Leeway:            s.RefreshToken.Leeway,
		Expiring:          s.RefreshToken.ExpirationType == Expiring,
		TokenLifetime:     s.RefreshToken.TokenLifetime,
		IdleTokenLifetime: s.RefreshToken.IdleTokenLifetime,
	}
	c.IsFirstParty, c.ThirdPartySecurityMode = *s.IsFirstParty, s.ThirdPartySecurityMode
	c.RedirectionPolicy = s.RedirectionPolicy
	c.RequirePushedAuthorizationRequests = s.RequirePushedAuthorizationRequests
	c.OrganizationUsage, c.OrganizationRequireBehavior = s.OrganizationUsage, s.OrganizationRequireBehavior
	c.OrganizationDiscoveryMethods = slices.Clone(s.OrganizationDiscoveryMethods)
	c.SkipNonVerifiableCallbackURIConfirmationPrompt = nil
	if p := s.SkipNonVerifiableCallbackURIConfirmationPrompt; p != nil {
		v := *p
		c.SkipNonVerifiableCallbackURIConfirmationPrompt = &v
	}
}

// FromClient returns c's settings as a normalized Spec, the starting point
// of an update.
func FromClient(c *store.Client) Spec {
	firstParty := c.IsFirstParty
	s := Spec{
		Name: c.Name, AppType: string(c.AppType),
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		GrantTypes:              slices.Clone(c.GrantTypes),
		Callbacks:               slices.Clone(c.Callbacks), AllowedLogoutURLs: slices.Clone(c.AllowedLogoutURLs),
		WebOrigins: slices.Clone(c.WebOrigins), AllowedOrigins: slices.Clone(c.AllowedOrigins),
		IDTokenLifetime: c.IDTokenLifetime,
		RefreshToken: RefreshToken{
			RotationType: NonRotating, ExpirationType: NonExpiring,
			Leeway: c.RefreshToken.Leeway, TokenLifetime: c.RefreshToken.TokenLifetime,
			IdleTokenLifetime: c.RefreshToken.IdleTokenLifetime,
		},
		IsFirstParty: &firstParty, ThirdPartySecurityMode: c.ThirdPartySecurityMode,
		RedirectionPolicy:                  c.RedirectionPolicy,
		RequirePushedAuthorizationRequests: c.RequirePushedAuthorizationRequests,
		OrganizationUsage:                  c.OrganizationUsage,
		OrganizationRequireBehavior:        c.OrganizationRequireBehavior,
		OrganizationDiscoveryMethods:       slices.Clone(c.OrganizationDiscoveryMethods),
	}
	if c.RefreshToken.Rotating {
		s.RefreshToken.RotationType = Rotating
	}
	if c.RefreshToken.Expiring {
		s.RefreshToken.ExpirationType = Expiring
	}
	if p := c.SkipNonVerifiableCallbackURIConfirmationPrompt; p != nil {
		v := *p
		s.SkipNonVerifiableCallbackURIConfirmationPrompt = &v
	}
	return s
}
