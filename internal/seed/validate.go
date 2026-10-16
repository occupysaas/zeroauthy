package seed

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// checkURL reports why raw cannot be registered as a redirect target: it
// must parse, be absolute, have no fragment, and http(s) URLs need a host.
// Wildcard hosts (https://*.example.com/cb) parse like any other host.
func checkURL(raw string) error {
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

var configKey = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

const (
	maxScriptBytes   = 102400
	maxConfigKeys    = 64
	maxConfigValueBy = 4096
)

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

var appTypes = []string{
	string(store.AppTypeSPA), string(store.AppTypeRegularWeb),
	string(store.AppTypeNative), string(store.AppTypeNonInteractive),
}

var authMethods = []string{
	store.AuthMethodNone, store.AuthMethodClientSecretPost, store.AuthMethodClientSecretBasic,
}

// strictGrantTypes are the only grant types a strict third-party
// application may use.
var strictGrantTypes = []string{"authorization_code", "refresh_token", "client_credentials"}

// defaultAuthMethod picks a method when the seed omits one. Browser and
// native apps cannot keep secrets, so they are public clients.
func defaultAuthMethod(appType string) string {
	switch store.AppType(appType) {
	case store.AppTypeSPA, store.AppTypeNative:
		return store.AuthMethodNone
	default:
		return store.AuthMethodClientSecretPost
	}
}

func (f *File) validate() error {
	var errs []error
	seenTenants := map[string]bool{}
	domainOwner := map[string]string{}
	for i := range f.Tenants {
		t := &f.Tenants[i]
		if t.Name == "" {
			errs = append(errs, fmt.Errorf("seed: tenants[%d]: name is required", i))
			continue
		}
		if seenTenants[t.Name] {
			errs = append(errs, fmt.Errorf("seed: duplicate tenant %q", t.Name))
		}
		seenTenants[t.Name] = true
		if !dnsLabel.MatchString(t.Name) {
			errs = append(errs, fmt.Errorf("seed: tenant %q: name must be a valid DNS label (lowercase a-z, 0-9, '-', at most 63 characters)", t.Name))
		}
		errs = append(errs, t.validate()...)
		for _, d := range t.Domains {
			if strings.TrimSpace(d) == "" {
				errs = append(errs, fmt.Errorf("seed: tenant %q: empty domain", t.Name))
				continue
			}
			nd := tenant.NormalizeHost(d)
			if owner, dup := domainOwner[nd]; dup {
				if owner == t.Name {
					errs = append(errs, fmt.Errorf("seed: tenant %q: duplicate domain %q", t.Name, d))
				} else {
					errs = append(errs, fmt.Errorf("seed: tenant %q: domain %q is already used by tenant %q", t.Name, d, owner))
				}
				continue
			}
			domainOwner[nd] = t.Name
		}
	}
	return errors.Join(errs...)
}

func (t *Tenant) validate() []error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("seed: tenant %q: "+format, append([]any{t.Name}, args...)...))
	}
	for _, u := range t.AllowedLogoutURLs {
		if err := checkURL(u); err != nil {
			fail("allowed_logout_urls: %v", err)
		}
	}

	if err := i18n.ValidateLocales(t.EnabledLocales); err != nil {
		fail("enabled_locales: %v", err)
	}
	if err := i18n.ValidateCustomText(t.EnabledLocales, t.CustomText); err != nil {
		fail("%v", err)
	}

	apis := map[string]*ResourceServer{}
	for i := range t.ResourceServers {
		rs := &t.ResourceServers[i]
		if rs.Identifier == "" {
			fail("resource_servers[%d]: identifier is required", i)
			continue
		}
		if apis[rs.Identifier] != nil {
			fail("duplicate resource server %q", rs.Identifier)
		}
		apis[rs.Identifier] = rs
		if rs.SkipConsentForVerifiableFirstPartyClients == nil {
			skip := false // O1a: Auth0's default for new APIs (D-0026)
			rs.SkipConsentForVerifiableFirstPartyClients = &skip
		}
		sta := &rs.SubjectTypeAuthorization
		if sta.User.Policy == "" {
			sta.User.Policy = store.PolicyAllowAll
		}
		if sta.Client.Policy == "" {
			sta.Client.Policy = store.PolicyRequireClientGrant
		}
		if !slices.Contains([]string{store.PolicyAllowAll, store.PolicyRequireClientGrant, store.PolicyDenyAll}, sta.User.Policy) {
			fail("resource server %q: subject_type_authorization.user.policy %q must be allow_all, require_client_grant or deny_all", rs.Identifier, sta.User.Policy)
		}
		if !slices.Contains([]string{store.PolicyRequireClientGrant, store.PolicyDenyAll}, sta.Client.Policy) {
			fail("resource server %q: subject_type_authorization.client.policy %q must be require_client_grant or deny_all", rs.Identifier, sta.Client.Policy)
		}
	}

	clients := map[string]bool{}
	thirdParty := map[string]bool{}
	for i := range t.Clients {
		c := &t.Clients[i]
		if c.ClientID == "" {
			fail("clients[%d]: client_id is required", i)
			continue
		}
		if clients[c.ClientID] {
			fail("duplicate client %q", c.ClientID)
		}
		clients[c.ClientID] = true
		if !slices.Contains(appTypes, c.AppType) {
			fail("client %q: app_type %q must be one of %v", c.ClientID, c.AppType, appTypes)
		}
		if c.TokenEndpointAuthMethod == "" {
			c.TokenEndpointAuthMethod = defaultAuthMethod(c.AppType)
		}
		if !slices.Contains(authMethods, c.TokenEndpointAuthMethod) {
			fail("client %q: token_endpoint_auth_method %q must be one of %v", c.ClientID, c.TokenEndpointAuthMethod, authMethods)
		}
		for _, cb := range c.Callbacks {
			if err := checkURL(cb); err != nil {
				fail("client %q: callback %v", c.ClientID, err)
				continue
			}
			if rest, ok := strings.CutPrefix(cb, "https://*."); ok {
				host := rest[:strings.IndexAny(rest+"/", "/:?")]
				if len(strings.Split(host, ".")) < 2 || slices.Contains(strings.Split(host, "."), "") {
					fail("client %q: wildcard callback %q must cover a domain of at least two labels", c.ClientID, cb)
				}
			}
		}
		for _, u := range c.AllowedLogoutURLs {
			if err := checkURL(u); err != nil {
				fail("client %q: allowed_logout_urls: %v", c.ClientID, err)
			}
		}
		public := c.TokenEndpointAuthMethod == store.AuthMethodNone
		if public && c.ClientSecret != "" {
			fail("client %q: public clients must not have a client_secret", c.ClientID)
		}
		if !public && c.ClientSecret == "" {
			fail("client %q: client_secret is required for %s", c.ClientID, c.TokenEndpointAuthMethod)
		}
		firstParty := c.IsFirstParty == nil || *c.IsFirstParty
		c.IsFirstParty = &firstParty
		thirdParty[c.ClientID] = !firstParty
		switch {
		case firstParty && c.ThirdPartySecurityMode != "":
			fail("client %q: third_party_security_mode is only for third-party applications", c.ClientID)
		case !firstParty && c.ThirdPartySecurityMode == "":
			c.ThirdPartySecurityMode = store.SecurityModeStrict // O1c
		}
		if !firstParty && c.ThirdPartySecurityMode != store.SecurityModeStrict && c.ThirdPartySecurityMode != store.SecurityModePermissive {
			fail("client %q: third_party_security_mode %q must be strict or permissive", c.ClientID, c.ThirdPartySecurityMode)
		}
		if c.RedirectionPolicy == "" {
			c.RedirectionPolicy = store.RedirectionPolicyAllowAlways // O1d
			if !firstParty {
				c.RedirectionPolicy = store.RedirectionPolicyOpenRedirectProtection
			}
		}
		if c.RedirectionPolicy != store.RedirectionPolicyAllowAlways && c.RedirectionPolicy != store.RedirectionPolicyOpenRedirectProtection {
			fail("client %q: redirection_policy %q must be %s or %s", c.ClientID, c.RedirectionPolicy,
				store.RedirectionPolicyOpenRedirectProtection, store.RedirectionPolicyAllowAlways)
		}
		strict := !firstParty && c.ThirdPartySecurityMode == store.SecurityModeStrict
		for _, gt := range c.GrantTypes {
			switch {
			case !firstParty && (gt == "password" || gt == "http://auth0.com/oauth/grant-type/password-realm"):
				fail("client %q: grant type %q is not available to third-party applications", c.ClientID, gt)
			case strict && !slices.Contains(strictGrantTypes, gt):
				fail("client %q: grant type %q is not available to strict third-party applications", c.ClientID, gt)
			}
		}
		if strict && slices.Contains(c.GrantTypes, "client_credentials") && c.TokenEndpointAuthMethod == store.AuthMethodNone {
			fail("client %q: client_credentials requires a confidential client", c.ClientID)
		}
		if strict && store.AppType(c.AppType) == store.AppTypeNative && c.RefreshToken.RotationType == "" {
			c.RefreshToken.RotationType = "rotating" // strict default for native apps
		}
		rt := &c.RefreshToken
		if rt.RotationType == "" {
			rt.RotationType = "non-rotating"
			if store.AppType(c.AppType) == store.AppTypeSPA {
				rt.RotationType = "rotating"
			}
		}
		if rt.ExpirationType == "" {
			rt.ExpirationType = "non-expiring"
			if rt.RotationType == "rotating" {
				rt.ExpirationType = "expiring"
			}
		}
		switch {
		case rt.RotationType != "rotating" && rt.RotationType != "non-rotating":
			fail("client %q: refresh_token.rotation_type %q must be rotating or non-rotating", c.ClientID, rt.RotationType)
		case rt.ExpirationType != "expiring" && rt.ExpirationType != "non-expiring":
			fail("client %q: refresh_token.expiration_type %q must be expiring or non-expiring", c.ClientID, rt.ExpirationType)
		case rt.RotationType == "rotating" && rt.ExpirationType != "expiring":
			fail("client %q: refresh_token rotation requires expiration_type expiring", c.ClientID)
		case store.AppType(c.AppType) == store.AppTypeSPA && rt.ExpirationType != "expiring":
			fail("client %q: single-page applications require expiring refresh tokens", c.ClientID)
		}
		if strict && rt.ExpirationType != "expiring" {
			fail("client %q: strict third-party applications require expiring refresh tokens", c.ClientID)
		}
		if rt.Leeway < 0 || rt.TokenLifetime < 0 || rt.IdleTokenLifetime < 0 {
			fail("client %q: refresh_token leeway and lifetimes must not be negative", c.ClientID)
		}
		if rt.TokenLifetime > 0 && rt.IdleTokenLifetime > rt.TokenLifetime {
			fail("client %q: refresh_token.idle_token_lifetime must not exceed token_lifetime", c.ClientID)
		}
	}

	seenGrants := map[[3]string]bool{}
	for i := range t.ClientGrants {
		g := &t.ClientGrants[i]
		if g.SubjectType == "" {
			g.SubjectType = store.SubjectTypeClient // O1e
		}
		if g.SubjectType != store.SubjectTypeClient && g.SubjectType != store.SubjectTypeUser {
			fail("client grant %q → %q: subject_type %q must be client or user", g.ClientID, g.Audience, g.SubjectType)
		}
		if !clients[g.ClientID] {
			fail("client grant references unknown client %q", g.ClientID)
		}
		rs := apis[g.Audience]
		if rs == nil {
			fail("client grant references unknown audience %q", g.Audience)
			continue
		}
		k := [3]string{g.ClientID, g.Audience, g.SubjectType}
		if seenGrants[k] {
			fail("duplicate client grant %q → %q (%s)", g.ClientID, g.Audience, g.SubjectType)
		}
		seenGrants[k] = true
		for _, s := range g.Scopes {
			if !slices.ContainsFunc(rs.Scopes, func(d Scope) bool { return d.Value == s }) {
				fail("client grant %q → %q: scope %q is not defined by the resource server", g.ClientID, g.Audience, s)
			}
		}
	}

	if b := t.Branding; b.LogoURL != "" {
		if u, err := url.Parse(b.LogoURL); err != nil || u.Scheme != "https" || u.Host == "" {
			fail("branding.logo_url must be an https URL")
		}
	}
	if c := t.Branding.PrimaryColor; c != "" && !hexColor.MatchString(c) {
		fail("branding.primary_color must look like #1a73e8")
	}

	conns := map[string]*Connection{}
	for i := range t.Connections {
		c := &t.Connections[i]
		if c.Name == "" {
			fail("connections[%d]: name is required", i)
			continue
		}
		if conns[c.Name] != nil {
			fail("duplicate connection %q", c.Name)
		}
		conns[c.Name] = c
		if c.Strategy == "" {
			c.Strategy = store.StrategyDatabase
		}
		if c.Strategy != store.StrategyDatabase {
			fail("connection %q: strategy %q is not supported (only %q)", c.Name, c.Strategy, store.StrategyDatabase)
		}
		for _, id := range c.EnabledClients {
			switch {
			case !clients[id]:
				fail("connection %q: unknown client %q", c.Name, id)
			case thirdParty[id]:
				// Auth0 refuses this (observations/consent.md): third-party
				// applications reach connections only at the domain level.
				fail("connection %q: third-party application %q cannot be enabled on a connection; use is_domain_connection", c.Name, id)
			}
		}
		if p := c.PasswordPolicy; p.MinLength < 0 || p.RequireCharacterClasses < 0 || p.RequireCharacterClasses > 4 {
			fail("connection %q: password_policy.min_length must be >= 0 and require_character_classes 0-4", c.Name)
		}
		t.validateCustomDB(c, fail)
	}

	if d := t.DefaultDirectory; d != "" {
		if c := conns[d]; c == nil {
			fail("default_directory %q is not a connection of this tenant", d)
		} else if c.Strategy != store.StrategyDatabase {
			fail("default_directory %q must be a database connection", d)
		}
	}

	seenUsers := map[[2]string]bool{}
	seenUsernames := map[[2]string]bool{}
	for i := range t.Users {
		u := &t.Users[i]
		c := conns[u.Connection]
		if c == nil {
			fail("users[%d]: unknown connection %q", i, u.Connection)
			continue
		}
		if c.EnabledDatabaseCustomization && !c.ImportMode {
			fail("users[%d]: connection %q is a legacy custom database; users live in the legacy store", i, u.Connection)
			continue
		}
		u.Email = identity.NormalizeLogin(u.Email)
		u.Username = identity.NormalizeLogin(u.Username)
		if identity.CheckEmail(u.Email) != nil {
			fail("users[%d]: %q is not a valid email address", i, u.Email)
			continue
		}
		k := [2]string{u.Connection, u.Email}
		if seenUsers[k] {
			fail("duplicate user %q on connection %q", u.Email, u.Connection)
		}
		seenUsers[k] = true
		if c.RequiresUsername && u.Username == "" {
			fail("user %q: username is required by connection %q", u.Email, c.Name)
		}
		if u.Username != "" {
			if err := identity.CheckUsername(u.Username); err != nil {
				fail("user %q: %v", u.Email, err)
			}
			uk := [2]string{u.Connection, u.Username}
			if seenUsernames[uk] {
				fail("duplicate username %q on connection %q", u.Username, u.Connection)
			}
			seenUsernames[uk] = true
		}
		if err := identity.CheckPassword(store.PasswordPolicy{
			MinLength: c.PasswordPolicy.MinLength, RequireCharacterClasses: c.PasswordPolicy.RequireCharacterClasses,
		}, u.Password); err != nil {
			fail("user %q: %v", u.Email, err)
		}
	}
	return errs
}

// validateCustomDB checks a connection's custom database options.
func (t *Tenant) validateCustomDB(c *Connection, fail func(string, ...any)) {
	switch c.SetUserRootAttributes {
	case "", store.RootAttributesOnEachLogin, store.RootAttributesOnFirstLogin:
	default:
		fail("connection %q: set_user_root_attributes %q must be %s or %s", c.Name, c.SetUserRootAttributes,
			store.RootAttributesOnEachLogin, store.RootAttributesOnFirstLogin)
	}
	if !c.EnabledDatabaseCustomization {
		if len(c.CustomScripts) > 0 || len(c.Configuration) > 0 || c.ImportMode {
			fail("connection %q: customScripts, configuration and import_mode require enabledDatabaseCustomization", c.Name)
		}
		return
	}
	for _, name := range slices.Sorted(maps.Keys(c.CustomScripts)) {
		if !slices.Contains(store.ScriptNames, name) {
			fail("connection %q: unknown customScripts key %q", c.Name, name)
			continue
		}
		if len(c.CustomScripts[name]) > maxScriptBytes {
			fail("connection %q: customScripts.%s is larger than %d bytes", c.Name, name, maxScriptBytes)
		}
	}
	if strings.TrimSpace(c.CustomScripts[store.ScriptLogin]) == "" {
		fail("connection %q: enabledDatabaseCustomization requires a login script", c.Name)
	}
	if len(c.Configuration) > maxConfigKeys {
		fail("connection %q: configuration has %d keys, at most %d allowed", c.Name, len(c.Configuration), maxConfigKeys)
	}
	for _, k := range slices.Sorted(maps.Keys(c.Configuration)) {
		if !configKey.MatchString(k) {
			fail("connection %q: configuration key %q must be 1-128 characters of A-Za-z0-9_", c.Name, k)
		}
		if len(c.Configuration[k]) > maxConfigValueBy {
			fail("connection %q: configuration value for %q is larger than %d bytes", c.Name, k, maxConfigValueBy)
		}
	}
}
