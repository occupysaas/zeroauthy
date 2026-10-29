package login

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// GET and POST must use the same application policy before displaying choices;
// a forged blocked selection must leave the live form usable for an allowed one.
func TestOrganizationPickerClientPolicyHosted(t *testing.T) {
	e := newEnv(t)
	allowed, conn, user := organizationFixture(t, e, store.OrgBehaviorPostLoginPrompt, false, false)
	ctx := context.Background()
	c, err := e.st.Clients().Get(ctx, allowed.TenantID, "partner")
	if err != nil {
		t.Fatal(err)
	}
	c.IsFirstParty = false
	c.OrganizationUsage = store.OrgUsageRequire
	c.OrganizationRequireBehavior = store.OrgBehaviorPostLoginPrompt
	if err = e.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	conn.IsDomainConnection = true
	conn.EnabledClients = append(conn.EnabledClients, "partner")
	if err = e.st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	allowed.DisplayName = "ZZZ Allowed"
	if err = e.st.Organizations().Update(ctx, allowed); err != nil {
		t.Fatal(err)
	}
	blocked := &store.Organization{TenantID: allowed.TenantID, ID: "org_0000000000000002", Name: "blocked", DisplayName: "Blocked"}
	other := &store.Organization{TenantID: allowed.TenantID, ID: "org_0000000000000003", Name: "other", DisplayName: "ZZZ Other", ThirdPartyClientAccess: "allow"}
	for _, o := range []*store.Organization{blocked, other} {
		if err = e.st.Organizations().Create(ctx, o, []store.OrganizationConnection{{TenantID: o.TenantID, OrganizationID: o.ID, ConnectionID: conn.ID, ShowAsButton: true}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, o := range []*store.Organization{allowed, blocked, other} {
		if err = e.st.Organizations().AddMembers(ctx, o.TenantID, o.ID, []string{user.UserID}); err != nil {
			t.Fatal(err)
		}
	}
	// These blocked memberships sort before both allowed choices. A missing
	// filter in the transaction recheck would truncate both valid selections.
	for i := 0; i < 19; i++ {
		o := &store.Organization{TenantID: allowed.TenantID, ID: fmt.Sprintf("org_%016d", i+4), Name: fmt.Sprintf("blocked-%02d", i), DisplayName: fmt.Sprintf("Blocked %02d", i), ThirdPartyClientAccess: "block"}
		if err = e.st.Organizations().Create(ctx, o, []store.OrganizationConnection{{TenantID: o.TenantID, OrganizationID: o.ID, ConnectionID: conn.ID, ShowAsButton: true}}); err != nil {
			t.Fatal(err)
		}
		if err = e.st.Organizations().AddMembers(ctx, o.TenantID, o.ID, []string{user.UserID}); err != nil {
			t.Fatal(err)
		}
	}
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "client_id", "partner", "redirect_uri", "https://partner.example/cb", "audience", "https://api.acme.test", "scope", "read:things")
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	page := b.do(t, "GET", loc.String(), nil)
	if page.Code != 200 || strings.Count(page.Body.String(), `name="organization"`) != 2 || strings.Contains(page.Body.String(), blocked.ID) {
		t.Fatalf("application-filtered picker: %d %s", page.Code, page.Body)
	}
	state = loc.Query().Get("state")
	csrf = csrfField.FindStringSubmatch(page.Body.String())[1]
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "organization": {blocked.ID}})
	if rec.Code != 400 || strings.Count(rec.Body.String(), `name="organization"`) != 2 || strings.Contains(rec.Body.String(), blocked.ID) {
		t.Fatalf("blocked POST must re-render allowed choices: %d %s", rec.Code, rec.Body)
	}
	txn, err := e.st.AuthTransactions().Get(ctx, allowed.TenantID, state)
	if err != nil || txn.Params[store.TxnParamOrgID] != "" {
		t.Fatalf("forged choice bound transaction: %+v %v", txn, err)
	}
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "organization": {allowed.ID}})
	loc, err = url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Path != "/u/consent" {
		t.Fatalf("allowed selection must reach consent: %d %s %s", rec.Code, loc, rec.Body)
	}
	page = b.do(t, "GET", loc.RequestURI(), nil)
	state = loc.Query().Get("state")
	csrf = csrfField.FindStringSubmatch(page.Body.String())[1]
	rec = b.do(t, "POST", "/u/consent", url.Values{"state": {state}, "csrf": {csrf}, "action": {"accept"}})
	loc, err = url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Host != "partner.example" || loc.Query().Get("code") == "" {
		t.Fatalf("allowed selection after refusal: %d %s %s", rec.Code, loc, rec.Body)
	}
}
