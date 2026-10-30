package login

import (
	"context"
	"errors"
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

func TestInvitationFederatedSignupPolicy(t *testing.T) {
	for _, kind := range []string{"new-disabled", "existing-disabled"} {
		t.Run(kind, func(t *testing.T) {
			s := newSocialEnv(t)
			ctx := context.Background()
			o, _, _ := organizationFixture(t, s.env, store.OrgBehaviorNoPrompt, false, false)
			if kind == "existing-disabled" {
				c, err := s.st.Clients().Get(ctx, o.TenantID, "spa")
				if err != nil {
					t.Fatal(err)
				}
				c.OrganizationUsage = store.OrgUsageAllow
				if err = s.st.Clients().Update(ctx, c); err != nil {
					t.Fatal(err)
				}
				toApp(t, s.explicitLogin(t, s.browser("acme.example.test"), s.idp, "corp", "Invited"), "app.acme.test")
			}
			if err := s.st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: o.TenantID, OrganizationID: o.ID, ConnectionID: "con_corp", ShowAsButton: true, IsSignupEnabled: false}, true); err != nil {
				t.Fatal(err)
			}
			invite := &store.OrganizationInvitation{TenantID: o.TenantID, OrganizationID: o.ID, ID: "social-invite", ClientID: "spa", InviteeEmail: "invited@idp.example", ConnectionID: "con_corp", TicketHash: orglogin.InvitationTicketHash("bearer"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
			if err := s.st.OrganizationsII().CreateInvitation(ctx, invite); err != nil {
				t.Fatal(err)
			}
			b := s.browser("acme.example.test")
			page := s.authorizeTo(t, b, "spa", "organization", o.ID, "invitation", "bearer", "connection", "corp")
			rec := b.do(t, "GET", page, nil)
			callback := s.idp.authorize(t, providerURL(t, rec), "Invited")
			rec = b.do(t, "GET", callback, nil)
			loc, _ := url.Parse(rec.Header().Get("Location"))
			u, err := s.st.Users().Get(ctx, o.TenantID, s.identityID("Invited"))
			if kind == "new-disabled" {
				if err == nil {
					t.Fatal("disabled first signup provisioned user", u)
				}
				if !errors.Is(err, store.ErrNotFound) {
					t.Fatal(err)
				}
				if _, err = s.st.OrganizationsII().GetInvitation(ctx, o.TenantID, o.ID, invite.ID); err != nil {
					t.Fatal("failed signup consumed invitation", err)
				}
				members, err := s.st.Organizations().Members(ctx, o.TenantID, o.ID, store.OrgPage{})
				if err != nil || len(members.Items) != 0 {
					t.Fatal(members, err)
				}
				if loc.Query().Get("code") != "" {
					t.Fatal("disabled signup issued code", loc)
				}
				for _, newTxn := range []bool{false, true} {
					if newTxn {
						page = s.authorizeTo(t, b, "spa", "organization", o.ID, "invitation", "bearer", "connection", "corp")
					}
					retry := b.do(t, "GET", page, nil)
					callback = s.idp.authorize(t, providerURL(t, retry), "Invited")
					retry = b.do(t, "GET", callback, nil)
					if _, err = s.st.Users().Get(ctx, o.TenantID, s.identityID("Invited")); !errors.Is(err, store.ErrNotFound) {
						t.Fatalf("retry created/preserved user: newTxn=%v err=%v", newTxn, err)
					}
					if _, err = s.st.OrganizationsII().GetInvitation(ctx, o.TenantID, o.ID, invite.ID); err != nil {
						t.Fatal("retry consumed invitation", err)
					}
					loc, _ = url.Parse(retry.Header().Get("Location"))
					if loc.Query().Get("code") != "" {
						t.Fatal("retry bypassed signup policy", loc)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			member, err := s.st.Organizations().IsMember(ctx, o.TenantID, o.ID, u.UserID)
			if err != nil || !member || loc.Query().Get("code") == "" {
				t.Fatal(member, err, loc, rec.Body)
			}
		})
	}
}

func TestInvitationSignupBindingRevision(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	o, _, _ := organizationFixture(t, e, store.OrgBehaviorNoPrompt, true, true)
	invite := &store.OrganizationInvitation{TenantID: o.TenantID, OrganizationID: o.ID, ID: "invite", ClientID: "spa", InviteeEmail: "new@acme.test", TicketHash: orglogin.InvitationTicketHash("bearer"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
	if err := e.st.OrganizationsII().CreateInvitation(ctx, invite); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "organization", o.ID, "invitation", "bearer", "screen_hint", "signup")
	before, err := e.st.AuthTransactions().Get(ctx, o.TenantID, state)
	if err != nil {
		t.Fatal(err)
	}
	b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"new@acme.test"}, "password": {"a good password 1"}})
	after, err := e.st.AuthTransactions().Get(ctx, o.TenantID, state)
	if err != nil {
		t.Fatal(err)
	}
	if after.Params[orglogin.InvitationSignupParam] != "1" {
		t.Fatal("missing signup provenance")
	}
	// Submission consumes the rendered form revision before signup's provenance
	// mutation. That prebinding revision must never be usable afterwards.
	prebinding := before.HostedState.Revision + 1
	if err = e.st.AuthTransactions().CompareAndSwapHosted(ctx, o.TenantID, state, prebinding, before.HostedState, e.h.Now()); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale revision after signup binding: before=%d after=%d err=%v", before.HostedState.Revision, after.HostedState.Revision, err)
	}
}
