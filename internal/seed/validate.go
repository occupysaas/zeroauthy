package seed

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strings"

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

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

var appTypes = []string{
	string(store.AppTypeSPA), string(store.AppTypeRegularWeb),
	string(store.AppTypeNative), string(store.AppTypeNonInteractive),
}

var authMethods = []string{
	store.AuthMethodNone, store.AuthMethodClientSecretPost, store.AuthMethodClientSecretBasic,
}

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
	}

	clients := map[string]bool{}
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
		if rt.Leeway < 0 || rt.TokenLifetime < 0 || rt.IdleTokenLifetime < 0 {
			fail("client %q: refresh_token leeway and lifetimes must not be negative", c.ClientID)
		}
		if rt.TokenLifetime > 0 && rt.IdleTokenLifetime > rt.TokenLifetime {
			fail("client %q: refresh_token.idle_token_lifetime must not exceed token_lifetime", c.ClientID)
		}
	}

	seenGrants := map[[2]string]bool{}
	for _, g := range t.ClientGrants {
		if !clients[g.ClientID] {
			fail("client grant references unknown client %q", g.ClientID)
		}
		rs := apis[g.Audience]
		if rs == nil {
			fail("client grant references unknown audience %q", g.Audience)
			continue
		}
		k := [2]string{g.ClientID, g.Audience}
		if seenGrants[k] {
			fail("duplicate client grant %q → %q", g.ClientID, g.Audience)
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
			if !clients[id] {
				fail("connection %q: unknown client %q", c.Name, id)
			}
		}
		if p := c.PasswordPolicy; p.MinLength < 0 || p.RequireCharacterClasses < 0 || p.RequireCharacterClasses > 4 {
			fail("connection %q: password_policy.min_length must be >= 0 and require_character_classes 0-4", c.Name)
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
		u.Email = identity.NormalizeLogin(u.Email)
		u.Username = identity.NormalizeLogin(u.Username)
		if addr, err := mail.ParseAddress(u.Email); err != nil || addr.Address != u.Email {
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
