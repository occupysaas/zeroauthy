package login

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/url"
	"testing"
	"time"
)

func TestInvitationAcceptance(t *testing.T) {
	for _, kind := range []string{"existing", "signup", "wrong-email", "unverified"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			o, conn, u := organizationFixture(t, e, store.OrgBehaviorNoPrompt, true, true)
			ctx := context.Background()
			// Even auto-enrollment must wait for invitation ownership verification.
			email := u.Email
			if kind == "signup" {
				email = "new-invited@acme.test"
			}
			if kind == "wrong-email" {
				email = "someone-else@acme.test"
			}
			u.EmailVerified = kind != "unverified"
			if err := e.st.Users().Update(ctx, u); err != nil {
				t.Fatal(err)
			}
			in := &store.OrganizationInvitation{TenantID: o.TenantID, OrganizationID: o.ID, ID: "invite", ClientID: "spa", InviteeEmail: email, ConnectionID: conn.ID, TicketHash: orglogin.InvitationTicketHash("bearer"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
			if err := e.st.OrganizationsII().CreateInvitation(ctx, in); err != nil {
				t.Fatal(err)
			}
			b := e.browser("acme.example.test")
			screen := "login"
			if kind == "signup" {
				screen = "signup"
			}
			_, state, csrf := b.begin(t, "organization", o.ID, "invitation", "bearer", "screen_hint", screen)
			form := url.Values{"state": {state}, "csrf": {csrf}, "username": {u.Email}, "password": {"alice password 1"}, "organization": {"evil"}, orglogin.InvitationIDParam: {"evil"}, "email_verified": {"true"}}
			path := "/u/login"
			if kind == "signup" {
				path = "/u/signup"
				form.Set("email", email)
				form.Set("password", "a good password 1")
			}
			rec := b.do(t, "POST", path, form)
			loc, _ := url.Parse(rec.Header().Get("Location"))
			target := u
			if kind == "signup" {
				var err error
				target, err = e.st.Users().FindByLogin(ctx, o.TenantID, conn.Name, email)
				if err != nil {
					t.Fatal(err)
				}
			}
			member, err := e.st.Organizations().IsMember(ctx, o.TenantID, o.ID, target.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "existing" {
				if !member || loc.Query().Get("code") == "" {
					t.Fatal(member, loc, rec.Body)
				}
				return
			}
			if member || loc.Query().Get("code") != "" {
				t.Fatal("unverified or wrong-email login enrolled", member, loc)
			}
			if _, err = e.st.OrganizationsII().GetInvitation(ctx, o.TenantID, o.ID, in.ID); err != nil {
				t.Fatal("failed invitation consumed", err)
			}
			if kind == "signup" || kind == "unverified" {
				// Model the established verification subsystem committing verified ownership;
				// its ticket and legacy-script semantics are covered by verification tests.
				target.EmailVerified = true
				if err = e.st.Users().Update(ctx, target); err != nil {
					t.Fatal(err)
				}
				b.do(t, "GET", "/u/login?state="+state, nil)
				form.Set("username", target.Email)
				form.Set("password", "alice password 1")
				if kind == "signup" {
					form.Set("password", "a good password 1")
				}
				rec = b.do(t, "POST", "/u/login", form)
				loc, _ = url.Parse(rec.Header().Get("Location"))
				member, err = e.st.Organizations().IsMember(ctx, o.TenantID, o.ID, target.UserID)
				if err != nil || !member || loc.Query().Get("code") == "" {
					t.Fatal("verified retry", member, err, loc, rec.Body)
				}
			}
		})
	}
}
