package login

import (
	"context"
	"net/url"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestOrganizationEntitlementRevocationLogin(t *testing.T) {
	for _, revoke := range []string{"remove", "disable", "activate"} {
		t.Run(revoke, func(t *testing.T) {
			e := newEnv(t)
			org, _, user := organizationFixture(t, e, store.OrgBehaviorNoPrompt, true, false)
			ctx := context.Background()
			org.IsAppEntitlementActive = revoke != "activate"
			if err := e.st.Organizations().Update(ctx, org); err != nil {
				t.Fatal(err)
			}
			if revoke != "activate" {
				if err := e.st.OrganizationsII().PutClients(ctx, org.TenantID, org.ID, []store.OrganizationClient{{ClientID: "spa", UseForMemberAccess: true}}); err != nil {
					t.Fatal(err)
				}
			}
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t, "organization", org.ID)
			switch revoke {
			case "remove":
				if err := e.st.OrganizationsII().DeleteClients(ctx, org.TenantID, org.ID, []string{"spa"}); err != nil {
					t.Fatal(err)
				}
			case "disable":
				if err := e.st.OrganizationsII().PutClients(ctx, org.TenantID, org.ID, []store.OrganizationClient{{ClientID: "spa", UseForMemberAccess: false}}); err != nil {
					t.Fatal(err)
				}
			case "activate":
				org.IsAppEntitlementActive = true
				if err := e.st.Organizations().Update(ctx, org); err != nil {
					t.Fatal(err)
				}
			}
			rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
			loc, _ := url.Parse(rec.Header().Get("Location"))
			// Binding validation rejects revoked policy before credentials are processed.
			if rec.Code != 400 || loc.Query().Get("code") != "" {
				t.Fatalf("revoked login: %d %s %s", rec.Code, loc, rec.Body)
			}
			member, err := e.st.Organizations().IsMember(ctx, org.TenantID, org.ID, user.UserID)
			if err != nil || member {
				t.Fatalf("revoked membership=%v err=%v", member, err)
			}
		})
	}
}
