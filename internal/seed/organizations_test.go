package seed

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const organizationsSeed = `
tenants:
  - name: acme
    connections: [{name: Db}, {name: OtherDb}]
    users: [{connection: Db, email: org@acme.test, password: "Organization-Password-2026"}, {connection: OtherDb, email: org@acme.test, password: "Other-Organization-Password-2026"}]
    roles: [{name: Reader}]
    organizations:
      - name: acme-org
        display_name: Acme Organization
        branding: {colors: {primary: '#123456', page_background: '#ffffff'}}
        metadata: {department: engineering}
        connections: [{name: Db, assign_membership_on_login: true, is_signup_enabled: true}]
        members: [{email: org@acme.test, connection: Db}]
        member_roles: [{member: {email: org@acme.test, connection: Db}, roles: [Reader]}]
`

func TestOrganizationsSeed(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	apply := func(doc string) error {
		f, err := Parse([]byte(doc))
		if err != nil {
			return err
		}
		f.Mode = ModeCreateOnly
		return Apply(ctx, st, f, fixedNow, w)
	}
	if err := apply(organizationsSeed); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	org, err := st.Organizations().GetByName(ctx, tn.ID, "acme-org")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := st.Users().FindByLogin(ctx, tn.ID, "Db", "org@acme.test")
	if ok, err := st.Organizations().IsMember(ctx, tn.ID, org.ID, u.UserID); err != nil || !ok {
		t.Fatalf("membership %v %v", ok, err)
	}
	roles, err := st.Organizations().MemberRoles(ctx, tn.ID, org.ID, u.UserID, store.OrgPage{})
	if err != nil || len(roles.Items) != 1 {
		t.Fatalf("roles %+v %v", roles, err)
	}
	links, err := st.Organizations().Connections(ctx, tn.ID, org.ID, store.OrgPage{})
	if err != nil || len(links.Items) != 1 || !links.Items[0].IsSignupEnabled {
		t.Fatalf("connections %+v %v", links, err)
	}
	if org.Branding == nil || org.Branding.Colors.Primary != "#123456" || org.Metadata["department"] != "engineering" {
		t.Fatalf("org %+v", org)
	}
	other, _ := st.Users().FindByLogin(ctx, tn.ID, "OtherDb", "org@acme.test")
	if ok, _ := st.Organizations().IsMember(ctx, tn.ID, org.ID, other.UserID); ok {
		t.Fatal("email-only resolution added other connection identity")
	}
	if err := st.Organizations().ChangeMemberRoles(ctx, tn.ID, org.ID, u.UserID, false, roles.Items); err != nil {
		t.Fatal(err)
	}
	if err := st.Organizations().DeleteConnection(ctx, tn.ID, org.ID, links.Items[0].ConnectionID); err != nil {
		t.Fatal(err)
	}
	org.DisplayName = "Console edit"
	org.Metadata = nil
	if err := st.Organizations().Update(ctx, org); err != nil {
		t.Fatal(err)
	}
	if err := apply(organizationsSeed); err != nil {
		t.Fatal(err)
	}
	rolesAfter, _ := st.Organizations().MemberRoles(ctx, tn.ID, org.ID, u.UserID, store.OrgPage{})
	if len(rolesAfter.Items) != 0 {
		t.Fatal("restart restored removed role")
	}
	linksAfter, _ := st.Organizations().Connections(ctx, tn.ID, org.ID, store.OrgPage{})
	if len(linksAfter.Items) != 0 {
		t.Fatal("restart restored removed connection")
	}
	if err := st.Organizations().RemoveMembers(ctx, tn.ID, org.ID, []string{u.UserID}); err != nil {
		t.Fatal(err)
	}
	if err := apply(organizationsSeed); err != nil {
		t.Fatal(err)
	}
	org, _ = st.Organizations().GetByName(ctx, tn.ID, "acme-org")
	if org.DisplayName != "Console edit" || org.Metadata != nil {
		t.Fatalf("restart overwrote %+v", org)
	}
	if ok, _ := st.Organizations().IsMember(ctx, tn.ID, org.ID, u.UserID); ok {
		t.Fatal("restart restored removed member")
	}
	legacy, err := Parse([]byte(organizationsSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, legacy, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Organizations().GetByName(ctx, tn.ID, "acme-org"); got.DisplayName != "Console edit" {
		t.Fatal("legacy apply mode overwrote create-only organization")
	}
	byID := fmt.Sprintf("tenants:\n  - name: acme\n    organizations:\n      - name: by-id\n        members: [{user_id: %q}]\n        member_roles: [{member: {user_id: %q}, roles: [Reader]}]\n", u.UserID, u.UserID)
	if err := apply(byID); err != nil {
		t.Fatal(err)
	}
	idOrg, _ := st.Organizations().GetByName(ctx, tn.ID, "by-id")
	if ok, _ := st.Organizations().IsMember(ctx, tn.ID, idOrg.ID, u.UserID); !ok {
		t.Fatal("ID member missing")
	}
	idRoles, err := st.Organizations().MemberRoles(ctx, tn.ID, idOrg.ID, u.UserID, store.OrgPage{})
	if err != nil || len(idRoles.Items) != 1 {
		t.Fatalf("ID-ref roles %+v %v", idRoles, err)
	}
	// A linked identity's connection/email resolves to its canonical owner.
	linked := *other.OwnIdentity()
	linked.ProfileData = map[string]any{"email": "org@acme.test", "email_verified": true}
	if err := st.Users().Delete(ctx, tn.ID, other.UserID); err != nil {
		t.Fatal(err)
	}
	u.Identities = append(u.Identities, linked)
	if err := st.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := apply("tenants:\n  - name: acme\n    organizations:\n      - name: linked-identity\n        members: [{email: org@acme.test, connection: OtherDb}]\n"); err != nil {
		t.Fatal(err)
	}
	linkedOrg, _ := st.Organizations().GetByName(ctx, tn.ID, "linked-identity")
	if ok, _ := st.Organizations().IsMember(ctx, tn.ID, linkedOrg.ID, u.UserID); !ok {
		t.Fatal("linked identity did not resolve canonical member")
	}
	for _, tc := range []struct{ name, from, to, want string }{
		{"member", "members: [{email: org@acme.test", "members: [{email: absent@acme.test", "member"},
		{"connection", "connections: [{name: Db,", "connections: [{name: Missing,", "connection"},
		{"role", "roles: [Reader]", "roles: [Missing]", "role"},
		{"unknown user ID", "members: [{email: org@acme.test, connection: Db}]", "members: [{user_id: 'auth0|missing'}]", "member"},
		{"ambiguous member", "email: org@acme.test, connection: Db", "email: org@acme.test", "member"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fresh := memory.New()
			f, err := Parse([]byte(strings.ReplaceAll(organizationsSeed, tc.from, tc.to)))
			if err == nil {
				err = Apply(ctx, fresh, f, fixedNow, w)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wanted clear %s error: %v", tc.want, err)
			}
		})
	}
}

type oldOrganizationsStore struct{ store.Store }

func (s oldOrganizationsStore) OrganizationsSupported() bool { return false }
func (s oldOrganizationsStore) CheckOrganizationsSupport(context.Context) error {
	return store.ErrOrganizationsUnavailable
}
func (s oldOrganizationsStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(oldOrganizationsStore{tx}) })
}

func TestOrganizationsSeedClientCapability(t *testing.T) {
	for _, usage := range []string{"", "deny", "allow", "require"} {
		t.Run(usage, func(t *testing.T) {
			f, err := Parse([]byte("tenants:\n - name: acme\n   clients:\n    - client_id: org-client\n      app_type: spa\n      grant_types: [authorization_code]\n      organization_usage: " + fmt.Sprintf("%q", usage) + "\n"))
			if err != nil {
				t.Fatal(err)
			}
			err = Apply(t.Context(), oldOrganizationsStore{memory.New()}, f, fixedNow, testWrapper(t))
			if usage == "allow" || usage == "require" {
				if !errors.Is(err, store.ErrOrganizationsUnavailable) {
					t.Fatalf("organization client accepted old plugin: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
