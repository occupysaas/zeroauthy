package login

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// These tests catch offering unbound connections, missing membership writes,
// skipping organization discovery, and selecting an organization from form data
// without checking the authenticated user and connection.
func organizationFixture(t *testing.T, e *env, behavior string, auto, signup bool) (*store.Organization, *store.Connection, *store.User) {
	t.Helper()
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	c, err := e.st.Clients().Get(ctx, tn.ID, "spa")
	if err != nil {
		t.Fatal(err)
	}
	c.OrganizationUsage = store.OrgUsageRequire
	c.OrganizationRequireBehavior = behavior
	if err = e.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	conn, err := e.st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	user, err := e.st.Users().FindByLogin(ctx, tn.ID, conn.Name, "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	org := &store.Organization{TenantID: tn.ID, ID: "org_0000000000000001", Name: "acme-org", DisplayName: "Acme Organization", ThirdPartyClientAccess: "allow"}
	err = e.st.Organizations().Create(ctx, org, []store.OrganizationConnection{{TenantID: tn.ID, OrganizationID: org.ID, ConnectionID: conn.ID, AssignMembershipOnLogin: auto, ShowAsButton: true, IsSignupEnabled: signup}})
	if err != nil {
		t.Fatal(err)
	}
	return org, conn, user
}
func orgAuthorize(b *browser, org, prompt string) *httptest.ResponseRecorder {
	q := url.Values{"client_id": {"spa"}, "redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	if org != "" {
		q.Set("organization", org)
	}
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	return b.send("GET", "/authorize?"+q.Encode(), nil)
}
func TestOrganizationLoginPage(t *testing.T) {
	e := newEnv(t)
	org, conn, _ := organizationFixture(t, e, store.OrgBehaviorNoPrompt, false, false)
	b := e.browser("acme.example.test")
	page, _, _ := b.begin(t, "organization", org.ID)
	if page.Code != 200 || strings.Contains(page.Body.String(), "/u/signup?") {
		t.Fatalf("org signup must be hidden: %d %s", page.Code, page.Body)
	}
	// Disabling the only organization connection must remove the database form.
	if err := e.st.Organizations().DeleteConnection(context.Background(), org.TenantID, org.ID, conn.ID); err != nil {
		t.Fatal(err)
	}
	rec := orgAuthorize(b, org.ID, "")
	page = b.do(t, "GET", rec.Header().Get("Location"), nil)
	if page.Code != 400 || strings.Contains(page.Body.String(), `name="password"`) {
		t.Fatalf("empty intersection: %d %s", page.Code, page.Body)
	}
}
func TestOrganizationMembership(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprint(auto), func(t *testing.T) {
			e := newEnv(t)
			org, _, user := organizationFixture(t, e, store.OrgBehaviorNoPrompt, auto, false)
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t, "organization", org.ID)
			rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
			loc, _ := url.Parse(rec.Header().Get("Location"))
			member, err := e.st.Organizations().IsMember(context.Background(), org.TenantID, org.ID, user.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if member != auto {
				t.Fatalf("membership=%v want %v", member, auto)
			}
			if b.cookies[session.CookieName] == nil {
				t.Fatal("authenticated session lost")
			}
			if auto && loc.Query().Get("code") == "" {
				t.Fatalf("auto login: %s %s", loc, rec.Body)
			}
			if !auto && loc.Query().Get("error") != "access_denied" {
				t.Fatalf("nonmember login: %s %s", loc, rec.Body)
			}
		})
	}
}
func TestOrganizationPrompt(t *testing.T) {
	e := newEnv(t)
	org, _, _ := organizationFixture(t, e, store.OrgBehaviorPreLoginPrompt, true, false)
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t)
	if !strings.Contains(page.Body.String(), `name="organization"`) || strings.Contains(page.Body.String(), `name="password"`) {
		t.Fatalf("name prompt: %s", page.Body)
	}
	form := url.Values{"state": {state}, "csrf": {csrf}, "organization": {"missing"}}
	rec := b.do(t, "POST", "/u/login", form)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), `name="organization"`) || strings.Contains(rec.Body.String(), org.Name) {
		t.Fatalf("unknown: %d %s", rec.Code, rec.Body)
	}
	form.Set("organization", org.Name)
	rec = b.do(t, "POST", "/u/login", form)
	if rec.Code != 303 {
		t.Fatalf("select: %d %s", rec.Code, rec.Body)
	}
	page = b.do(t, "GET", rec.Header().Get("Location"), nil)
	if page.Code != 200 || !strings.Contains(page.Body.String(), `name="password"`) {
		t.Fatalf("continue: %d %s", page.Code, page.Body)
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), org.TenantID, state)
	if err != nil {
		t.Fatal(err)
	}
	if txn.Params[store.TxnParamOrgID] != org.ID || txn.Params[store.TxnParamOrgMode] != string(authz.OrgFixed) {
		t.Fatalf("unbound choice: %+v", txn.Params)
	}
}
func TestOrganizationPicker(t *testing.T) {
	e := newEnv(t)
	org, conn, user := organizationFixture(t, e, store.OrgBehaviorPostLoginPrompt, false, false)
	if err := e.st.Organizations().AddMembers(context.Background(), org.TenantID, org.ID, []string{user.UserID}); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
	if u, _ := url.Parse(rec.Header().Get("Location")); u.Query().Get("code") == "" {
		t.Fatalf("single choice: %s %s", u, rec.Body)
	}
	// Session reuse must use its last connection and silently select this member org.
	rec = orgAuthorize(b, "", "none")
	u, _ := url.Parse(rec.Header().Get("Location"))
	if u.Query().Get("code") == "" {
		t.Fatalf("session picker: %s %s", u, rec.Body)
	}
	// With no eligible org the silent picker requires interaction.
	if err := e.st.Organizations().DeleteConnection(context.Background(), org.TenantID, org.ID, conn.ID); err != nil {
		t.Fatal(err)
	}
	rec = orgAuthorize(b, "", "none")
	u, _ = url.Parse(rec.Header().Get("Location"))
	if u.Query().Get("error") != "interaction_required" {
		t.Fatalf("empty silent picker: %s", u)
	}
}

func TestOrganizationPickerNoChoicesDenied(t *testing.T) {
	e := newEnv(t)
	organizationFixture(t, e, store.OrgBehaviorPostLoginPrompt, false, false)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("error") != "access_denied" {
		t.Fatalf("empty picker must deny: %s", loc)
	}
}
func TestOrganizationMembershipFederationAtomic(t *testing.T) {
	for _, ms := range []bool{false, true} {
		for _, change := range []string{"member", "auto", "off", "disabled", "entitlement"} {
			t.Run(fmt.Sprintf("microsoft=%v/%s", ms, change), func(t *testing.T) {
				var s *socialEnv
				if ms {
					s = newMicrosoftEnv(t)
				} else {
					s = newSocialEnv(t)
				}
				org, _, _ := organizationFixture(t, s.env, store.OrgBehaviorNoPrompt, true, false)
				link := store.OrganizationConnection{TenantID: org.TenantID, OrganizationID: org.ID, ConnectionID: "con_corp", ShowAsButton: true, AssignMembershipOnLogin: change != "member"}
				if err := s.st.Organizations().PutConnection(context.Background(), link, true); err != nil {
					t.Fatal(err)
				}
				// An existing provider member must work even with auto-membership off.
				if change == "member" {
					client, _ := s.st.Clients().Get(context.Background(), org.TenantID, "spa")
					client.OrganizationUsage = store.OrgUsageAllow
					if err := s.st.Clients().Update(context.Background(), client); err != nil {
						t.Fatal(err)
					}
					toApp(t, s.explicitLogin(t, s.browser("acme.example.test"), s.idp, "corp", "Org-1"), "app.acme.test")
					client.OrganizationUsage = store.OrgUsageRequire
					if err := s.st.Clients().Update(context.Background(), client); err != nil {
						t.Fatal(err)
					}
				}
				b := s.browser("acme.example.test")
				if change == "member" { // create the provider identity through its first denied org login, then add it.
					u, err := s.st.Users().Get(context.Background(), org.TenantID, s.identityID("Org-1"))
					if err != nil {
						t.Fatal(err)
					}
					if err = s.st.Organizations().AddMembers(context.Background(), org.TenantID, org.ID, []string{u.UserID}); err != nil {
						t.Fatal(err)
					}
				}
				page := s.authorizeTo(t, b, "spa", "organization", org.ID, "connection", "corp")
				rec := b.do(t, "GET", page, nil)
				callback := s.idp.authorize(t, providerURL(t, rec), "Org-1")
				if change == "off" || change == "disabled" || change == "entitlement" {
					s.idp.beforeToken = func() {
						if change == "entitlement" {
							org.IsAppEntitlementActive = true
							if err := s.st.Organizations().Update(context.Background(), org); err != nil {
								t.Error(err)
							}
						} else if change == "disabled" {
							if err := s.st.Organizations().DeleteConnection(context.Background(), org.TenantID, org.ID, "con_corp"); err != nil {
								t.Error(err)
							}
						} else {
							link.AssignMembershipOnLogin = false
							if err := s.st.Organizations().PutConnection(context.Background(), link, false); err != nil {
								t.Error(err)
							}
						}
					}
				}
				rec = b.do(t, "GET", callback, nil)
				loc, _ := url.Parse(rec.Header().Get("Location"))
				allowed := change == "auto" || change == "member"
				if allowed && loc.Query().Get("code") == "" {
					t.Fatalf("member login: %d %s %s", rec.Code, loc, rec.Body)
				}
				if !allowed && loc.Query().Get("error") != "access_denied" {
					t.Fatalf("changed flags: %d %s %s", rec.Code, loc, rec.Body)
				}
				u, err := s.st.Users().Get(context.Background(), org.TenantID, s.identityID("Org-1"))
				if err != nil {
					t.Fatal(err)
				}
				member, err := s.st.Organizations().IsMember(context.Background(), org.TenantID, org.ID, u.UserID)
				if err != nil {
					t.Fatal(err)
				}
				if member != allowed {
					t.Fatalf("membership %v want %v", member, allowed)
				}
				if b.cookies[session.CookieName] == nil {
					t.Fatal("authenticated session lost")
				}
			})
		}
	}
}

func TestOrganizationPromptSessionAndBypass(t *testing.T) {
	e := newEnv(t)
	org, _, _ := organizationFixture(t, e, store.OrgBehaviorPreLoginPrompt, true, false)
	ctx := context.Background()
	c, _ := e.st.Clients().Get(ctx, org.TenantID, "spa")
	c.OrganizationDiscoveryMethods = []string{"email"}
	c.OrganizationUsage = store.OrgUsageAllow
	if err := e.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	// The name field stays available even with email-only discovery.
	page, state, csrf := b.begin(t)
	if !strings.Contains(page.Body.String(), `name="organization"`) {
		t.Fatal("email-only discovery lost name field")
	}
	// A direct signup request cannot bypass the unresolved organization prompt.
	rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"bypass@acme.test"}, "password": {"a good password 1"}})
	if rec.Code < 400 {
		t.Fatalf("pending prompt bypass: %d %s", rec.Code, rec.Body)
	}
	// First establish a session through an explicitly bound organization.
	_, state, csrf = b.begin(t, "organization", org.ID)
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
	if u, _ := url.Parse(rec.Header().Get("Location")); u.Query().Get("code") == "" {
		t.Fatalf("login: %s", u)
	}
	page, state, csrf = b.begin(t)
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "organization": {org.Name}})
	page = b.do(t, "GET", rec.Header().Get("Location"), nil)
	u, _ := url.Parse(page.Header().Get("Location"))
	if u.Query().Get("code") == "" {
		t.Fatalf("existing session must continue after naming org: %d %s", page.Code, page.Body)
	}
}
func TestOrganizationPickerChoicesAndTampering(t *testing.T) {
	e := newEnv(t)
	org, conn, user := organizationFixture(t, e, store.OrgBehaviorPostLoginPrompt, false, false)
	ctx := context.Background()
	for i := 0; i < 23; i++ {
		logo := fmt.Sprintf("https://logos.example/%02d.png", i)
		o := &store.Organization{TenantID: org.TenantID, ID: fmt.Sprintf("org_%016d", i+2), Name: fmt.Sprintf("org-%02d", i), DisplayName: fmt.Sprintf("Org %02d", 22-i), Branding: &store.OrgBranding{LogoURL: &logo}}
		if err := e.st.Organizations().Create(ctx, o, []store.OrganizationConnection{{TenantID: o.TenantID, OrganizationID: o.ID, ConnectionID: conn.ID, ShowAsButton: true}}); err != nil {
			t.Fatal(err)
		}
		if err := e.st.Organizations().AddMembers(ctx, o.TenantID, o.ID, []string{user.UserID}); err != nil {
			t.Fatal(err)
		}
	}
	choices, auto, err := PickerChoices(ctx, e.st, org.TenantID, user.UserID, conn.ID)
	if err != nil || auto != nil || len(choices) != 20 || choices[0].DisplayName != "Org 00" || choices[19].DisplayName != "Org 19" {
		t.Fatalf("picker ordering/limit: %+v %+v %v", choices, auto, err)
	}
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
	page := b.do(t, "GET", rec.Header().Get("Location"), nil)
	if !strings.Contains(page.Header().Get("Content-Security-Policy"), "https://logos.example") {
		t.Fatal("picker logos blocked by CSP")
	}
	if page.Code != 200 || strings.Count(page.Body.String(), `name="organization"`) != 20 || !strings.Contains(page.Body.String(), "https://logos.example/") {
		t.Fatalf("picker page: %d %s", page.Code, page.Body)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	state = loc.Query().Get("state")
	csrf = csrfField.FindStringSubmatch(page.Body.String())[1]
	foreign := mustTenant(t, e, "globex")
	cross := &store.Organization{TenantID: foreign.ID, ID: "org_9999999999999999", Name: "foreign", DisplayName: "Foreign"}
	if err := e.st.Organizations().Create(ctx, cross, nil); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{org.ID, cross.ID} {
		rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "organization": {id}})
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), `name="organization"`) {
			t.Fatalf("forged picker selection: %d %s", rec.Code, rec.Body)
		}
	}
	// A membership removed after the page was rendered cannot be selected.
	if err := e.st.Organizations().RemoveMembers(ctx, org.TenantID, choices[0].ID, []string{user.UserID}); err != nil {
		t.Fatal(err)
	}
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "organization": {choices[0].ID}})
	if rec.Code != 400 {
		t.Fatalf("removed member selected: %d %s", rec.Code, rec.Body)
	}
}
func TestOrganizationSignupAndFlagChanges(t *testing.T) {
	for _, change := range []string{"none", "signup-off", "auto-off", "disabled", "bad-password"} {
		t.Run(change, func(t *testing.T) {
			e := newEnv(t)
			org, conn, _ := organizationFixture(t, e, store.OrgBehaviorNoPrompt, true, true)
			ctx := context.Background()
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t, "organization", org.ID, "screen_hint", "signup")
			if change == "signup-off" || change == "auto-off" {
				link, err := e.st.Organizations().GetConnection(ctx, org.TenantID, org.ID, conn.ID)
				if err != nil {
					t.Fatal(err)
				}
				link.IsSignupEnabled = false
				if change == "auto-off" {
					link.AssignMembershipOnLogin = false
				}
				if err = e.st.Organizations().PutConnection(ctx, *link, false); err != nil {
					t.Fatal(err)
				}
			}
			if change == "disabled" {
				if err := e.st.Organizations().DeleteConnection(ctx, org.TenantID, org.ID, conn.ID); err != nil {
					t.Fatal(err)
				}
			}
			password := "a good password 1"
			if change == "bad-password" {
				password = "x"
			}
			rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"org-signup@acme.test"}, "password": {password}})
			user, err := e.st.Users().FindByLogin(ctx, org.TenantID, conn.Name, "org-signup@acme.test")
			members, merr := e.st.Organizations().Members(ctx, org.TenantID, org.ID, store.OrgPage{})
			if merr != nil {
				t.Fatal(merr)
			}
			if change == "none" {
				if rec.Code != 302 || err != nil || len(members.Items) != 1 || members.Items[0] != user.UserID {
					t.Fatalf("org signup: %d %+v %+v %v", rec.Code, user, members, err)
				}
			} else if rec.Code < 400 || err == nil || len(members.Items) != 0 {
				t.Fatalf("failed signup wrote user/member: %d %+v %+v %v", rec.Code, user, members, err)
			}
		})
	}
}

func TestOrganizationLoginPageConnections(t *testing.T) {
	s := newSocialEnv(t)
	org, _, _ := organizationFixture(t, s.env, store.OrgBehaviorNoPrompt, true, false)
	ctx := context.Background()
	if err := s.st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: org.TenantID, OrganizationID: org.ID, ConnectionID: "con_corp", ShowAsButton: false, AssignMembershipOnLogin: true}, true); err != nil {
		t.Fatal(err)
	}
	b := s.browser("acme.example.test")
	page, _, _ := b.begin(t, "organization", org.ID)
	if strings.Contains(page.Body.String(), `value="corp"`) || strings.Contains(page.Body.String(), `value="google-oauth2"`) {
		t.Fatalf("hidden/outside connection offered: %s", page.Body)
	}
	rec := orgAuthorize(b, org.ID, "")
	page = b.do(t, "GET", rec.Header().Get("Location"), nil)
	// A hidden button is usable by explicit connection selection.
	path := s.authorizeTo(t, b, "spa", "organization", org.ID, "connection", "corp")
	rec = b.do(t, "GET", path, nil)
	if rec.Code != 303 || !strings.HasPrefix(rec.Header().Get("Location"), s.idp.base()) {
		t.Fatalf("hidden explicit: %d %s", rec.Code, rec.Body)
	}
	// The hosted page refuses out-of-intersection connection selection.
	path = s.authorizeTo(t, b, "spa", "organization", org.ID, "connection", "google-oauth2")
	rec = b.do(t, "GET", path, nil)
	outside, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || outside.Host != "app.acme.test" || outside.Query().Get("error") != "invalid_request" {
		t.Fatalf("outside explicit: %d %s", rec.Code, rec.Body)
	}
}
func TestOrganizationMembershipSilent(t *testing.T) {
	for _, kind := range []string{"member", "auto", "nonmember", "disabled"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			org, conn, user := organizationFixture(t, e, store.OrgBehaviorNoPrompt, false, false)
			ctx := context.Background()
			b := e.browser("acme.example.test")
			// Establish an individual session, then restore the require client.
			c, _ := e.st.Clients().Get(ctx, org.TenantID, "spa")
			c.OrganizationUsage = store.OrgUsageAllow
			if err := e.st.Clients().Update(ctx, c); err != nil {
				t.Fatal(err)
			}
			_, state, csrf := b.begin(t)
			rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
			if rec.Code != 302 {
				t.Fatalf("session: %d %s", rec.Code, rec.Body)
			}
			c.OrganizationUsage = store.OrgUsageRequire
			if err := e.st.Clients().Update(ctx, c); err != nil {
				t.Fatal(err)
			}
			if kind == "member" {
				if err := e.st.Organizations().AddMembers(ctx, org.TenantID, org.ID, []string{user.UserID}); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "auto" {
				link, _ := e.st.Organizations().GetConnection(ctx, org.TenantID, org.ID, conn.ID)
				link.AssignMembershipOnLogin = true
				if err := e.st.Organizations().PutConnection(ctx, *link, false); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "disabled" {
				if err := e.st.Organizations().DeleteConnection(ctx, org.TenantID, org.ID, conn.ID); err != nil {
					t.Fatal(err)
				}
			}
			rec = orgAuthorize(b, org.ID, "none")
			u, _ := url.Parse(rec.Header().Get("Location"))
			allowed := kind == "member" || kind == "auto"
			if allowed && u.Query().Get("code") == "" || !allowed && u.Query().Get("error") != "login_required" {
				t.Fatalf("silent %s: %s", kind, u)
			}
			if b.cookies[session.CookieName] == nil {
				t.Fatal("silent failure discarded session")
			}
		})
	}
}

func TestOrganizationMembershipConsentRecheck(t *testing.T) {
	e := newEnv(t)
	b := e.signedIn(t)
	org, conn, user := organizationFixture(t, e, store.OrgBehaviorNoPrompt, false, false)
	ctx := context.Background()
	if err := e.st.Organizations().AddMembers(ctx, org.TenantID, org.ID, []string{user.UserID}); err != nil {
		t.Fatal(err)
	}
	client, err := e.st.Clients().Get(ctx, org.TenantID, "partner")
	if err != nil {
		t.Fatal(err)
	}
	client.OrganizationUsage = store.OrgUsageAllow
	client.RedirectionPolicy = "allow_always"
	if err = e.st.Clients().Update(ctx, client); err != nil {
		t.Fatal(err)
	}
	conn.EnabledClients = append(conn.EnabledClients, "partner")
	if err = e.st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	q := partnerQ("partner", "https://partner.example/cb")
	q.Set("organization", org.ID)
	state, csrf := b.toConsent(t, q)
	if err = e.st.Organizations().RemoveMembers(ctx, org.TenantID, org.ID, []string{user.UserID}); err != nil {
		t.Fatal(err)
	}
	rec := b.do(t, "POST", "/u/consent", url.Values{"state": {state}, "csrf": {csrf}, "action": {"accept"}})
	u, _ := url.Parse(rec.Header().Get("Location"))
	if u.Host != "partner.example" || u.Query().Get("error") != "access_denied" || u.Query().Get("code") != "" {
		t.Fatalf("removed member at consent: %d %s %s", rec.Code, u, rec.Body)
	}
}
func TestOrganizationPickerAutoMembership(t *testing.T) {
	for _, two := range []bool{false, true} {
		t.Run(fmt.Sprint(two), func(t *testing.T) {
			e := newEnv(t)
			org, conn, user := organizationFixture(t, e, store.OrgBehaviorPostLoginPrompt, true, false)
			ctx := context.Background()
			if two {
				o := &store.Organization{TenantID: org.TenantID, ID: "org_0000000000000002", Name: "other", DisplayName: "Other"}
				if err := e.st.Organizations().Create(ctx, o, []store.OrganizationConnection{{TenantID: o.TenantID, OrganizationID: o.ID, ConnectionID: conn.ID, AssignMembershipOnLogin: true, ShowAsButton: true}}); err != nil {
					t.Fatal(err)
				}
			}
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t)
			rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
			u, _ := url.Parse(rec.Header().Get("Location"))
			member, err := e.st.Organizations().IsMember(ctx, org.TenantID, org.ID, user.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if two {
				if u.Query().Get("error") != "access_denied" || member {
					t.Fatalf("ambiguous automatic assignment: %s %v", u, member)
				}
			} else if u.Query().Get("code") == "" || !member {
				t.Fatalf("unique automatic assignment: %s %v", u, member)
			}
		})
	}
}

func TestOrganizationPromptBeforeSignup(t *testing.T) {
	e := newEnv(t)
	org, _, _ := organizationFixture(t, e, store.OrgBehaviorPreLoginPrompt, true, true)
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t, "screen_hint", "signup")
	if page.Code != 200 || !strings.Contains(page.Body.String(), `name="organization"`) {
		t.Fatalf("signup must first name organization: %d %s", page.Code, page.Body)
	}
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "organization": {org.Name}})
	u, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 303 || u.Path != "/u/signup" {
		t.Fatalf("signup hint lost: %d %s", rec.Code, u)
	}
}

// Both the page template and the signup/login partial use the bound context,
// never a separate query parameter or an individual tenant-only view.
func TestOrganizationTemplates(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	org, _, _ := organizationFixture(t, e, store.OrgBehaviorNoPrompt, true, true)
	org.Metadata = map[string]string{"tier": "gold"}
	logo := "https://org-assets.test/logo.svg"
	org.Branding = &store.OrgBranding{LogoURL: &logo, Colors: &store.OrgColors{Primary: "#abcdef", PageBackground: "#fedcba"}}
	if err := e.st.Organizations().Update(ctx, org); err != nil {
		t.Fatal(err)
	}
	cfg, err := e.st.HostedLogins().Get(ctx, org.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	source := `<html><head>{% auth0:head %}</head><body><p>Page {{organization.name}} {{organization.metadata.tier}}</p>{% auth0:widget %}</body></html>`
	cfg.Template = &source
	cfg.Partials = map[string]map[string]map[string]string{"login": {"login": {"form-footer-end": `<p>Partial {{organization.display_name}} {{organization.branding.colors.primary}}</p>`}}, "signup": {"signup": {"form-footer-end": `<p>Signup partial {{organization.id}}</p>`}}}
	if err := e.st.HostedLogins().Put(ctx, cfg, cfg.Revision); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	page, state, _ := b.begin(t, "organization", org.ID)
	for _, want := range []string{"Page acme-org gold", "Partial Acme Organization #abcdef", logo} {
		if !strings.Contains(page.Body.String(), want) {
			t.Errorf("missing %s", want)
		}
	}

	signup := b.do(t, "GET", "/u/signup?state="+url.QueryEscape(state), nil)
	if signup.Code != 200 || !strings.Contains(signup.Body.String(), "Signup partial "+org.ID) || !strings.Contains(signup.Body.String(), "Page acme-org gold") {
		t.Fatalf("signup org context missing: status=%d", signup.Code)
	}
}
