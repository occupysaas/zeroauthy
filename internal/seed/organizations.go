package seed

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type Organization struct {
	IsAppEntitlementActive bool                          `yaml:"is_app_entitlement_active"`
	ThirdPartyClientAccess string                        `yaml:"third_party_client_access"`
	Clients                []OrganizationClient          `yaml:"clients"`
	ClientGrants           []OrganizationClientGrant     `yaml:"client_grants"`
	DiscoveryDomains       []OrganizationDiscoveryDomain `yaml:"discovery_domains"`
	Name                   string                        `yaml:"name"`
	DisplayName            string                        `yaml:"display_name"`
	Branding               *OrganizationBranding         `yaml:"branding"`
	Metadata               map[string]string             `yaml:"metadata"`
	Connections            []OrganizationConnection      `yaml:"connections"`
	Members                []OrganizationMember          `yaml:"members"`
	MemberRoles            []OrganizationMemberRoles     `yaml:"member_roles"`
}
type OrganizationBranding struct {
	LogoURL *string             `yaml:"logo_url"`
	Colors  *OrganizationColors `yaml:"colors"`
}
type OrganizationColors struct {
	Primary        string `yaml:"primary"`
	PageBackground string `yaml:"page_background"`
}
type OrganizationClient struct {
	ClientID           string `yaml:"client_id"` // Existing client ID or unique application name.
	UseForMemberAccess bool   `yaml:"use_for_member_access"`
}
type OrganizationClientGrant struct {
	ClientID string `yaml:"client_id"`
	Audience string `yaml:"audience"`
}
type OrganizationDiscoveryDomain struct {
	Domain                      string `yaml:"domain"`
	Status                      string `yaml:"status"`
	UseForOrganizationDiscovery *bool  `yaml:"use_for_organization_discovery"`
}
type OrganizationConnection struct {
	IsEnabled                     *bool  `yaml:"is_enabled"`
	ConnectionName                string `yaml:"organization_connection_name"`
	OrganizationAccessLevel       string `yaml:"organization_access_level"`
	OrganizationMemberAccessLevel string `yaml:"organization_member_access_level"`
	Name                          string `yaml:"name"`
	AssignMembershipOnLogin       bool   `yaml:"assign_membership_on_login"`
	ShowAsButton                  *bool  `yaml:"show_as_button"`
	IsSignupEnabled               bool   `yaml:"is_signup_enabled"`
}
type OrganizationMember struct {
	UserID     string `yaml:"user_id"`
	Email      string `yaml:"email"`
	Connection string `yaml:"connection"`
}
type OrganizationMemberRoles struct {
	Member OrganizationMember `yaml:"member"`
	Roles  []string           `yaml:"roles"`
}

// Organizations are always create-only: console edits, removed links and
// membership changes survive restart even in the legacy apply seed mode.
func applyOrganization(ctx context.Context, st store.Store, tid string, in Organization, now time.Time) error {
	if _, err := st.Organizations().GetByName(ctx, tid, in.Name); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	org := store.Organization{TenantID: tid, ID: orgrules.NewID(), Name: in.Name, DisplayName: in.DisplayName, Metadata: in.Metadata, IsAppEntitlementActive: in.IsAppEntitlementActive, ThirdPartyClientAccess: in.ThirdPartyClientAccess, CreatedAt: now, UpdatedAt: now}
	if in.Branding != nil {
		org.Branding = &store.OrgBranding{LogoURL: in.Branding.LogoURL}
		if c := in.Branding.Colors; c != nil {
			org.Branding.Colors = &store.OrgColors{Primary: c.Primary, PageBackground: c.PageBackground}
		}
	}
	org, err := orgrules.NormalizeOrganization(org)
	if err != nil {
		return err
	}
	links := make([]store.OrganizationConnection, 0, len(in.Connections))
	for _, ref := range in.Connections {
		c, err := st.Connections().GetByName(ctx, tid, ref.Name)
		if err != nil {
			return fmt.Errorf("connection %q: %w", ref.Name, err)
		}
		link := store.OrganizationConnection{TenantID: tid, OrganizationID: org.ID, ConnectionID: c.ID, AssignMembershipOnLogin: ref.AssignMembershipOnLogin, ShowAsButton: true, IsSignupEnabled: ref.IsSignupEnabled}
		link.ConnectionName = ref.ConnectionName
		link.OrganizationAccessLevel = ref.OrganizationAccessLevel
		link.OrganizationMemberAccessLevel = ref.OrganizationMemberAccessLevel
		if ref.IsEnabled != nil {
			link.IsEnabled, link.IsEnabledSet = *ref.IsEnabled, true
		}
		if ref.ShowAsButton != nil {
			link.ShowAsButton = *ref.ShowAsButton
		}
		if err := orgrules.ValidateConnection(c.Strategy, link); err != nil {
			return fmt.Errorf("connection %q: %w", ref.Name, err)
		}
		links = append(links, link)
	}
	if err := st.Organizations().Create(ctx, &org, links); err != nil {
		return err
	}
	if err := applyOrganizationII(ctx, st, tid, org.ID, in); err != nil {
		return err
	}
	for _, ref := range in.Members {
		id, err := resolveOrganizationMember(ctx, st, tid, ref)
		if err != nil {
			return err
		}
		if err := st.Organizations().AddMembers(ctx, tid, org.ID, []string{id}); err != nil {
			return fmt.Errorf("member %q: %w", id, err)
		}
	}
	for _, assignment := range in.MemberRoles {
		id, err := resolveOrganizationMember(ctx, st, tid, assignment.Member)
		if err != nil {
			return err
		}
		for _, name := range assignment.Roles {
			roleID := ""
			for page := 0; ; page++ {
				found, err := st.RBAC().ListRoles(ctx, tid, store.RBACPage{Page: page, PerPage: 100, NameFilter: name})
				if err != nil {
					return err
				}
				for _, r := range found.Items {
					if r.Name == name {
						roleID = r.ID
						break
					}
				}
				if roleID != "" || (page+1)*100 >= found.Total {
					break
				}
			}
			if roleID == "" {
				return fmt.Errorf("member %q role %q: %w", id, name, store.ErrNotFound)
			}
			if err := st.Organizations().ChangeMemberRoles(ctx, tid, org.ID, id, true, []string{roleID}); err != nil {
				return fmt.Errorf("member %q role %q: %w", id, name, err)
			}
		}
	}
	return nil
}
func resolveOrganizationMember(ctx context.Context, st store.Store, tid string, ref OrganizationMember) (string, error) {
	if ref.UserID != "" && ref.Email == "" && ref.Connection == "" {
		u, err := st.Users().Get(ctx, tid, ref.UserID)
		if err != nil {
			return "", fmt.Errorf("member user_id %q: %w", ref.UserID, err)
		}
		return u.UserID, nil
	}
	if ref.UserID == "" && ref.Email != "" && ref.Connection != "" {
		u, err := st.Users().FindByLogin(ctx, tid, ref.Connection, ref.Email)
		if err != nil {
			return "", fmt.Errorf("member email %q connection %q: %w", ref.Email, ref.Connection, err)
		}
		return u.UserID, nil
	}
	return "", errors.New("member requires user_id or email together with connection")
}

// References are resolved inside Apply's transaction, including all tenants and
// organizations, so an invalid final reference rolls back the entire seed batch.
func resolveOrganizationClient(ctx context.Context, st store.Store, tid, ref string) (*store.Client, error) {
	if c, e := st.Clients().Get(ctx, tid, ref); e == nil {
		return c, nil
	} else if !errors.Is(e, store.ErrNotFound) {
		return nil, e
	}
	clients, _, e := st.Clients().List(ctx, tid, store.ClientFilter{}, store.Page{})
	if e != nil {
		return nil, e
	}
	var found *store.Client
	for _, c := range clients {
		if c.Name == ref {
			if found != nil {
				return nil, fmt.Errorf("ambiguous client %q", ref)
			}
			found = c
		}
	}
	if found == nil {
		return nil, fmt.Errorf("client %q: %w", ref, store.ErrNotFound)
	}
	return found, nil
}
func applyOrganizationII(ctx context.Context, st store.Store, tid, oid string, in Organization) error {
	active := in.IsAppEntitlementActive || in.ThirdPartyClientAccess != "" && in.ThirdPartyClientAccess != "block" || len(in.Clients) > 0 || len(in.ClientGrants) > 0 || len(in.DiscoveryDomains) > 0
	for _, c := range in.Connections {
		active = active || c.IsEnabled != nil || c.ConnectionName != "" || c.OrganizationAccessLevel != "" || c.OrganizationMemberAccessLevel != ""
	}
	if !active {
		return nil
	}
	if c, ok := st.(store.OrganizationsIISupporter); ok {
		if e := c.CheckOrganizationsIISupport(ctx); e != nil {
			return e
		}
	}
	if !store.OrganizationsIISupported(st) {
		return store.ErrOrganizationsIIUnavailable
	}
	clients := make([]store.OrganizationClient, 0, len(in.Clients))
	for _, ref := range in.Clients {
		c, e := resolveOrganizationClient(ctx, st, tid, ref.ClientID)
		if e != nil {
			return e
		}
		clients = append(clients, store.OrganizationClient{TenantID: tid, OrganizationID: oid, ClientID: c.ClientID, UseForMemberAccess: ref.UseForMemberAccess})
	}
	if len(clients) > 0 {
		if e := st.OrganizationsII().PutClients(ctx, tid, oid, clients); e != nil {
			return e
		}
	}
	for _, ref := range in.ClientGrants {
		c, e := resolveOrganizationClient(ctx, st, tid, ref.ClientID)
		if e != nil {
			return e
		}
		g, e := st.ClientGrants().Find(ctx, tid, c.ClientID, ref.Audience, store.SubjectTypeClient)
		if e != nil {
			return e
		}
		if e = st.OrganizationsII().PutClientGrant(ctx, tid, oid, g.ID); e != nil {
			return e
		}
	}
	for _, ref := range in.DiscoveryDomains {
		if ref.Status != "" && ref.Status != "pending" {
			return errors.New("seed: discovery domains require pending status; attest verified through Management API")
		}
		domain, e := orglogin.NormalizeDiscoveryDomain(ref.Domain)
		if e != nil {
			return e
		}
		enabled := true
		if ref.UseForOrganizationDiscovery != nil {
			enabled = *ref.UseForOrganizationDiscovery
		}
		d := store.OrganizationDiscoveryDomain{TenantID: tid, OrganizationID: oid, ID: "dd_" + secrets.RandomString(24), Domain: domain, Status: "pending", UseForOrganizationDiscovery: enabled, VerificationHost: "_zeroauthy-org." + domain, VerificationTXT: secrets.RandomString(32)}
		if e = st.OrganizationsII().PutDiscoveryDomain(ctx, &d, true); e != nil {
			return e
		}
	}
	return nil
}
