package login

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/url"
	"testing"
	"time"
)

func TestOrganizationConnectionsIIDisabledDuringLogin(t *testing.T) {
	for _, signup := range []bool{false, true} {
		t.Run(map[bool]string{false: "enrollment", true: "signup"}[signup], func(t *testing.T) {
			e := newEnv(t)
			org, conn, _ := organizationFixture(t, e, store.OrgBehaviorNoPrompt, true, true)
			b := e.browser("acme.example.test")
			args := []string{"organization", org.ID}
			if signup {
				args = append(args, "screen_hint", "signup")
			}
			_, state, csrf := b.begin(t, args...)
			ctx := context.Background()
			link, err := e.st.Organizations().GetConnection(ctx, org.TenantID, org.ID, conn.ID)
			if err != nil {
				t.Fatal(err)
			}
			link.IsEnabled = false
			link.IsEnabledSet = true
			link.OrganizationAccessLevel = "full"
			link.OrganizationMemberAccessLevel = "full"
			if err = e.st.Organizations().PutConnection(ctx, *link, false); err != nil {
				t.Fatal(err)
			}
			path := "/u/login"
			form := url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}}
			if signup {
				path = "/u/signup"
				form.Set("email", "disabled-signup@acme.test")
			}
			rec := b.do(t, "POST", path, form)
			if rec.Code < 400 {
				t.Fatalf("disabled request %d %s", rec.Code, rec.Header().Get("Location"))
			}
			members, err := e.st.Organizations().Members(ctx, org.TenantID, org.ID, store.OrgPage{})
			if err != nil || len(members.Items) != 0 {
				t.Fatalf("disabled enrollment wrote members %+v %v", members, err)
			}
			if signup {
				if _, err = e.st.Users().FindByLogin(ctx, org.TenantID, conn.Name, "disabled-signup@acme.test"); err == nil {
					t.Fatal("disabled signup created user")
				}
			}
		})
	}
}

func TestOrganizationConnectionsIIDisabledInvitation(t *testing.T) {
	e := newEnv(t)
	org, conn, user := organizationFixture(t, e, store.OrgBehaviorNoPrompt, true, true)
	ctx := context.Background()
	user.EmailVerified = true
	if err := e.st.Users().Update(ctx, user); err != nil {
		t.Fatal(err)
	}
	in := &store.OrganizationInvitation{TenantID: org.TenantID, OrganizationID: org.ID, ID: "disabled-invite", ClientID: "spa", InviteeEmail: user.Email, ConnectionID: conn.ID, TicketHash: orglogin.InvitationTicketHash("bearer"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
	if err := e.st.OrganizationsII().CreateInvitation(ctx, in); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "organization", org.ID, "invitation", "bearer")
	link, err := e.st.Organizations().GetConnection(ctx, org.TenantID, org.ID, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	link.IsEnabled = false
	link.IsEnabledSet = true
	if err = e.st.Organizations().PutConnection(ctx, *link, false); err != nil {
		t.Fatal(err)
	}
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {user.Email}, "password": {"alice password 1"}})
	if rec.Code < 400 {
		t.Fatalf("disabled invitation accepted %d", rec.Code)
	}
	if _, err = e.st.OrganizationsII().GetInvitation(ctx, org.TenantID, org.ID, in.ID); err != nil {
		t.Fatal("disabled invitation consumed", err)
	}
	member, err := e.st.Organizations().IsMember(ctx, org.TenantID, org.ID, user.UserID)
	if err != nil || member {
		t.Fatalf("disabled invitation enrolled %v %v", member, err)
	}
}
