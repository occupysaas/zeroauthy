package tenant

import (
	"net/url"
	"regexp"
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidName reports whether name can name a tenant: a DNS label (lower-case
// letters, digits and hyphens, at most 63 characters), because it becomes
// the tenant's subdomain under the base domain.
func ValidName(name string) bool { return dnsLabel.MatchString(name) }

// ValidDomain reports whether d is a host, with an optional port, and
// nothing else. Callers normalize it first (NormalizeHost).
func ValidDomain(d string) bool {
	u, err := url.Parse("https://" + d)
	return err == nil && d != "" && u.Host == d && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}
