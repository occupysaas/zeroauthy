package federation

import (
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"golang.org/x/net/idna"
	"net/mail"
	"strings"
)

// MatchHomeRealm preserves the supplied eligible connection order. It routes
// only from an exact email domain and never reads a user repository.
func MatchHomeRealm(email string, conns []*store.Connection) *store.Connection {
	if len(email) > 320 {
		return nil
	}
	address, e := mail.ParseAddress(email)
	if e != nil || address.Address != email {
		return nil
	}
	i := strings.LastIndexByte(email, '@')
	if i < 1 {
		return nil
	}
	domain, e := idna.Lookup.ToASCII(strings.ToLower(email[i+1:]))
	if e != nil || domain == "" {
		return nil
	}
	for _, c := range conns {
		if c == nil || !rules.IsEnterprise(c.Strategy) {
			continue
		}
		spec := connrules.FromConnection(c)
		if active, ok := spec.Authentication["active"].(bool); ok && !active {
			continue
		}
		aliases, e := rules.ParseDomainAliases(c.Extra["domain_aliases"])
		if e != nil {
			continue
		}
		for _, alias := range aliases {
			candidate, e := idna.Lookup.ToASCII(alias)
			if e == nil && strings.EqualFold(domain, candidate) {
				return c
			}
		}
	}
	return nil
}
