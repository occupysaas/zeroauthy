package seed

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/apirules"
	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/devicecode"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/rbacrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func (f *File) validate() error {
	var errs []error
	seenTenants := map[string]bool{}
	domainOwner := map[string]string{}
	for i := range f.Tenants {
		t := &f.Tenants[i]
		if err := validateActions(t); err != nil {
			errs = append(errs, fmt.Errorf("seed: tenant %q: Actions: %w", t.Name, err))
		}
		if err := validateTenantSettings(t); err != nil {
			errs = append(errs, err)
		}
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

	seenRoles := map[string]bool{}
	for _, role := range t.Roles {
		if seenRoles[role.Name] {
			fail("duplicate role %q", role.Name)
		}
		seenRoles[role.Name] = true
		for _, err := range rbacrules.NormalizeRole(&store.Role{Name: role.Name, Description: role.Description}) {
			fail("role %q: %v", role.Name, err)
		}
		for _, key := range role.Permissions {
			api := apis[key.ResourceServerIdentifier]
			if api == nil {
				fail("role %q: permission API %q is not defined", role.Name, key.ResourceServerIdentifier)
				continue
			}
			if !slices.ContainsFunc(api.Scopes, func(s Scope) bool { return s.Value == key.PermissionName }) {
				fail("role %q: permission %q is not defined", role.Name, key.PermissionName)
			}
			if key.PermissionName == "openid" || key.PermissionName == "profile" || key.PermissionName == "email" || key.PermissionName == "offline_access" {
				fail("role %q: protocol scopes cannot be assigned", role.Name)
			}
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
		if g.OrganizationUsage != "" && g.OrganizationUsage != "deny" && g.OrganizationUsage != "allow" && g.OrganizationUsage != "require" {
			fail("invalid grant organization_usage")
		}
		if g.SubjectType != store.SubjectTypeClient && (g.OrganizationUsage != "" && g.OrganizationUsage != "deny" || g.AllowAnyOrganization) {
			fail("user grant cannot activate organization policy")
		}
		if !clients[g.ClientID] {
			fail("client grant references unknown client %q", g.ClientID)
		}
		rs := apis[g.Audience]
		mgmt := rs == nil && apirules.IsManagementAPIIdentifier(g.Audience)
		if rs == nil && !mgmt {
			fail("client grant references unknown audience %q", g.Audience)
			continue
		}
		k := [3]string{g.ClientID, g.Audience, g.SubjectType}
		if seenGrants[k] {
			fail("duplicate client grant %q → %q (%s)", g.ClientID, g.Audience, g.SubjectType)
		}
		seenGrants[k] = true
		if mgmt && !slices.Contains(t.mgmtAudiences, g.Audience) {
			t.mgmtAudiences = append(t.mgmtAudiences, g.Audience)
		}
		defined := func(s string) bool {
			return rs != nil && slices.ContainsFunc(rs.Scopes, func(d Scope) bool { return d.Value == s })
		}
		for _, err := range apirules.CheckGrant(g.SubjectType, mgmt, g.Scopes, defined) {
			fail("client grant %q → %q: %v", g.ClientID, g.Audience, err)
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
		if p := c.PasswordPolicy; p.MinLength < 0 || p.MinLength > identity.MaxPasswordBytes || p.RequireCharacterClasses < 0 || p.RequireCharacterClasses > 4 {
			fail("connection %q: password_policy.min_length must be 0 to %d and require_character_classes 0-4", c.Name, identity.MaxPasswordBytes)
		} else if c.PasswordOptions != nil && p != (PasswordPolicy{}) {
			fail("connection %q: password_policy and password_options cannot both be set", c.Name)
		}
		spec := c.spec()
		if c.Options != nil && !spec.Federated() {
			fail("connection %q: options is only for the google-oauth2, oauth2, oidc, windowslive and waad strategies", c.Name)
		}
		if spec.Federated() {
			if _, named := c.Options["client_secret"]; !named {
				fail("connection %q: options.client_secret is required", c.Name)
			}
		}
		for _, err := range connrules.Normalize(&spec) {
			fail("connection %q: %v", c.Name, err)
		}
		c.normalized = &spec
		c.Strategy = spec.Strategy
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
		var stored store.Connection
		connrules.Apply(c.normalized, &stored)
		if u.Username != "" {
			if err := identity.CheckUsername(&stored, u.Username); err != nil {
				fail("user %q: %v", u.Email, err)
			}
			uk := [2]string{u.Connection, u.Username}
			if seenUsernames[uk] {
				fail("duplicate username %q on connection %q", u.Username, u.Connection)
			}
			seenUsernames[uk] = true
		}
		person := identity.Person{
			Email: u.Email, Username: u.Username, Name: u.Name, GivenName: u.GivenName,
			FamilyName: u.FamilyName, Nickname: u.Nickname,
		}
		if err := identity.CheckPassword(&stored, person, u.Password, nil); err != nil {
			fail("user %q: %v", u.Email, err)
		}
	}
	return errs
}
