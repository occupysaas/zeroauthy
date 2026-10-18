package seed

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/apirules"
	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/devicecode"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

var configKey = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

const (
	maxScriptBytes   = 102400
	maxConfigKeys    = 64
	maxConfigValueBy = 4096
)

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

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
		if t.Name == tenant.SystemName {
			errs = append(errs, fmt.Errorf("seed: tenant name %q is reserved for zeroauthy's own tenant", t.Name))
		}
		if !tenant.ValidName(t.Name) {
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

// isManagementAPIURL reports whether aud has the form of a Management API
// identifier, https://<host>/api/v2/.
func isManagementAPIURL(aud string) bool {
	u, err := url.Parse(aud)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Path == "/api/v2/" &&
		u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

// CheckManagementAPI checks the seed against each tenant's Management API
// identifier, which depends on the server's base domain
// (tenant.ManagementAPIIdentifier): no resource server may redefine it, and
// every client grant for a Management API must name the tenant's own. On
// success it records baseDomain, so that Apply creates each seeded
// tenant's Management API. Load cannot check this, since the base domain
// comes from the server configuration.
func (f *File) CheckManagementAPI(baseDomain string) error {
	var errs []error
	for i := range f.Tenants {
		t := &f.Tenants[i]
		id := tenant.ManagementAPIIdentifier(&store.Tenant{Name: t.Name, Domains: t.Domains}, baseDomain)
		for _, rs := range t.ResourceServers {
			if err := apirules.Reserved(rs.Identifier, id); err != nil {
				errs = append(errs, fmt.Errorf("seed: tenant %q: resource server: %w", t.Name, err))
			}
		}
		for _, aud := range t.mgmtAudiences {
			if aud != id {
				errs = append(errs, fmt.Errorf("seed: tenant %q: client grant audience %q is not a defined resource server or the tenant's Management API (%q)", t.Name, aud, id))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	f.mgmtChecked, f.baseDomain = true, baseDomain
	return nil
}

// CheckSystemHost reports a seeded tenant whose domains include host, the
// system tenant's host (tenant.SystemHost). Load cannot check this, since the
// host comes from the server configuration.
func (f *File) CheckSystemHost(host string) error {
	if host == "" {
		return nil
	}
	var errs []error
	for _, t := range f.Tenants {
		for _, d := range t.Domains {
			if tenant.NormalizeHost(d) == host {
				errs = append(errs, fmt.Errorf("seed: tenant %q: domain %q is the system host, reserved for zeroauthy's own tenant", t.Name, d))
			}
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
		if err := clientrules.CheckURL(u); err != nil {
			fail("allowed_logout_urls: %v", err)
		}
	}

	if err := i18n.ValidateLocales(t.EnabledLocales); err != nil {
		fail("enabled_locales: %v", err)
	}
	if err := i18n.ValidateCustomText(t.EnabledLocales, t.CustomText); err != nil {
		fail("%v", err)
	}

	if t.DeviceFlow.Charset != "" || t.DeviceFlow.Mask != "" {
		charset := t.DeviceFlow.Charset
		if charset == "" {
			charset = devicecode.CharsetBase20
		}
		if charset != devicecode.CharsetBase20 && charset != devicecode.CharsetDigits {
			fail("device_flow.charset %q must be base20 or digits", t.DeviceFlow.Charset)
		} else {
			mask := t.DeviceFlow.Mask
			if mask == "" {
				mask = devicecode.DefaultMask
				if charset == devicecode.CharsetDigits {
					mask = "***-***-***"
				}
			}
			if err := devicecode.ValidateMask(charset, mask); err != nil {
				fail("device_flow.mask %q: %v", t.DeviceFlow.Mask, err)
			}
		}
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
		if err := apirules.Reserved(rs.Identifier, ""); err != nil {
			fail("resource server: %v", err)
		}
		spec := rs.spec()
		for _, err := range apirules.Normalize(&spec) {
			fail("resource server %q: %v", rs.Identifier, err)
		}
		rs.normalized = &spec
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
		public := c.TokenEndpointAuthMethod == store.AuthMethodNone ||
			(c.TokenEndpointAuthMethod == "" && clientrules.DefaultAuthMethod(c.AppType) == store.AuthMethodNone)
		if public && c.ClientSecret != "" {
			fail("client %q: public clients must not have a client_secret", c.ClientID)
		}
		// A confidential client may omit client_secret: an existing client
		// then keeps its stored secret (Plan 13). Creating one without a
		// secret fails when the seed is applied.
		spec := c.spec()
		for _, err := range clientrules.Normalize(&spec, t.PushedAuthorizationRequestsSupported) {
			fail("client %q: %v", c.ClientID, err)
		}
		c.normalized = &spec
		thirdParty[c.ClientID] = !*spec.IsFirstParty
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
		mgmt := rs == nil && isManagementAPIURL(g.Audience)
		if rs == nil && !mgmt {
			fail("client grant references unknown audience %q", g.Audience)
			continue
		}
		k := [3]string{g.ClientID, g.Audience, g.SubjectType}
		if seenGrants[k] {
			fail("duplicate client grant %q → %q (%s)", g.ClientID, g.Audience, g.SubjectType)
		}
		seenGrants[k] = true
		if mgmt {
			if g.SubjectType != store.SubjectTypeClient {
				fail("client grant %q → %q: the Management API accepts machine-to-machine (client) grants only", g.ClientID, g.Audience)
			}
			if !slices.Contains(t.mgmtAudiences, g.Audience) {
				t.mgmtAudiences = append(t.mgmtAudiences, g.Audience)
			}
			for _, s := range g.Scopes {
				if !tenantsetup.IsManagementAPIScope(s) {
					fail("client grant %q → %q: scope %q is not a Management API scope", g.ClientID, g.Audience, s)
				}
			}
			continue
		}
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
