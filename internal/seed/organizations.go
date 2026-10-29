package seed

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type Organization struct {
	Name        string                    `yaml:"name"`
	DisplayName string                    `yaml:"display_name"`
	Branding    *OrganizationBranding     `yaml:"branding"`
	Metadata    map[string]string         `yaml:"metadata"`
	Connections []OrganizationConnection  `yaml:"connections"`
	Members     []OrganizationMember      `yaml:"members"`
	MemberRoles []OrganizationMemberRoles `yaml:"member_roles"`
}
type OrganizationBranding struct {
	LogoURL *string             `yaml:"logo_url"`
	Colors  *OrganizationColors `yaml:"colors"`
}
type OrganizationColors struct {
	Primary        string `yaml:"primary"`
	PageBackground string `yaml:"page_background"`
}
type OrganizationConnection struct {
	Name                    string `yaml:"name"`
	AssignMembershipOnLogin bool   `yaml:"assign_membership_on_login"`
	ShowAsButton            *bool  `yaml:"show_as_button"`
	IsSignupEnabled         bool   `yaml:"is_signup_enabled"`
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
	org := store.Organization{TenantID: tid, ID: orgrules.NewID(), Name: in.Name, DisplayName: in.DisplayName, Metadata: in.Metadata, CreatedAt: now, UpdatedAt: now}
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
