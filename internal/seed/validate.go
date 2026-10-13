package seed

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

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
		public := c.TokenEndpointAuthMethod == store.AuthMethodNone
		if public && c.ClientSecret != "" {
			fail("client %q: public clients must not have a client_secret", c.ClientID)
		}
		if !public && c.ClientSecret == "" {
			fail("client %q: client_secret is required for %s", c.ClientID, c.TokenEndpointAuthMethod)
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
	return errs
}
