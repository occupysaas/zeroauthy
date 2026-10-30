package orglogin

import (
	"context"
	"errors"
	"net"
	"net/mail"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"golang.org/x/net/idna"
)

// NormalizeDiscoveryDomain canonicalizes an exact DNS name, never a URL or IP.
func NormalizeDiscoveryDomain(in string) (string, error) {
	if in == "" || strings.TrimSpace(in) != in || strings.ContainsAny(in, "*/:@[]\\?#") || strings.HasSuffix(in, ".") {
		return "", store.ErrInvalid
	}
	name, err := idna.Lookup.ToASCII(in)
	name = strings.ToLower(name)
	if err != nil || len(name) < 3 || len(name) > 253 || net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		return "", store.ErrInvalid
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", store.ErrInvalid
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", store.ErrInvalid
			}
		}
	}
	return name, nil
}

// Discover only reads current policy. Domain ownership attestation is never an
// assertion of user email ownership and never enrolls a member. The caller caps
// the filtered candidates, not the raw storage matches.
func Discover(ctx context.Context, st store.Store, tid, clientID, email string) ([]store.Organization, error) {
	if c, ok := st.(store.OrganizationsIISupporter); ok {
		if err := c.CheckOrganizationsIISupport(ctx); err != nil {
			return nil, err
		}
	}
	if !store.OrganizationsIISupported(st) {
		return nil, store.ErrOrganizationsIIUnavailable
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || strings.Count(email, "@") != 1 {
		return nil, store.ErrInvalid
	}
	domain, err := NormalizeDiscoveryDomain(strings.SplitN(email, "@", 2)[1])
	if err != nil {
		return nil, err
	}
	client, err := st.Clients().Get(ctx, tid, clientID)
	if err != nil {
		return nil, err
	}
	out := []store.Organization{}
	if client.OrganizationUsage != store.OrgUsageAllow && client.OrganizationUsage != store.OrgUsageRequire {
		return out, nil
	}
	matches, err := st.OrganizationsII().DiscoverOrganizations(ctx, tid, domain)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, match := range matches {
		if match.TenantID != tid || seen[match.ID] {
			continue
		}
		seen[match.ID] = true
		org, err := st.Organizations().Get(ctx, tid, match.ID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		d, err := st.OrganizationsII().GetDiscoveryDomainByName(ctx, tid, org.ID, domain)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if d.TenantID != tid || d.OrganizationID != org.ID || d.Domain != domain || d.Status != "verified" || !d.UseForOrganizationDiscovery {
			continue
		}
		if !client.IsFirstParty && org.ThirdPartyClientAccess != "allow" {
			continue
		}
		if err := CheckMemberClient(ctx, st, tid, org.ID, clientID); errors.Is(err, ErrNotMember) {
			continue
		} else if err != nil {
			return nil, err
		}
		usable := false
		for page := 0; ; page++ {
			links, err := st.Organizations().Connections(ctx, tid, org.ID, store.OrgPage{Page: page, PerPage: 100})
			if err != nil {
				return nil, err
			}
			for _, link := range links.Items {
				if link.IsEnabledSet && !link.IsEnabled {
					continue
				}
				conn, err := st.Connections().Get(ctx, tid, link.ConnectionID)
				if errors.Is(err, store.ErrNotFound) {
					continue
				}
				if err != nil {
					return nil, err
				}
				if conn.TenantID == tid && access.ConnectionUsable(client, conn) {
					usable = true
					break
				}
			}
			if usable || len(links.Items) < 100 {
				break
			}
		}
		if usable {
			out = append(out, *org)
		}
	}
	slices.SortFunc(out, func(a, b store.Organization) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}
