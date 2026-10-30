package login

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func discoveryFixture(t *testing.T, count int, usage string, methods ...string) (*env, *store.Organization) {
	t.Helper()
	e := newEnv(t)
	org, conn, _ := organizationFixture(t, e, store.OrgBehaviorPreLoginPrompt, true, false)
	ctx := context.Background()
	c, _ := e.st.Clients().Get(ctx, org.TenantID, "spa")
	c.OrganizationDiscoveryMethods = methods
	c.OrganizationUsage = usage
	if err := e.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < count; i++ {
		o := org
		if i > 0 {
			o = &store.Organization{TenantID: org.TenantID, ID: fmt.Sprintf("org_%016d", i+1), Name: fmt.Sprintf("discovery-%d", i), DisplayName: fmt.Sprintf("Discovery %02d", i), ThirdPartyClientAccess: "allow"}
			if err := e.st.Organizations().Create(ctx, o, []store.OrganizationConnection{{TenantID: o.TenantID, OrganizationID: o.ID, ConnectionID: conn.ID, ShowAsButton: true}}); err != nil {
				t.Fatal(err)
			}
		}
		if err := e.st.OrganizationsII().PutDiscoveryDomain(ctx, &store.OrganizationDiscoveryDomain{TenantID: o.TenantID, OrganizationID: o.ID, ID: fmt.Sprintf("dom_%d", i), Domain: "acme.test", Status: "verified", UseForOrganizationDiscovery: true}, true); err != nil {
			t.Fatal(err)
		}
	}
	return e, org
}

func TestOrganizationDiscoveryPrompt(t *testing.T) {
	for _, count := range []int{0, 1, 3, 24} {
		for _, usage := range []string{store.OrgUsageAllow, store.OrgUsageRequire} {
			t.Run(fmt.Sprintf("%d/%s", count, usage), func(t *testing.T) {
				e, org := discoveryFixture(t, count, usage, store.OrgDiscoveryEmail)
				b := e.browser("acme.example.test")
				page, state, csrf := b.begin(t)
				if !strings.Contains(page.Body.String(), `name="email"`) || strings.Contains(page.Body.String(), `name="password"`) || strings.Contains(page.Body.String(), `name="organization"`) {
					t.Fatalf("email prompt: %s", page.Body)
				}
				rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "email": {"unknown@acme.test"}})
				if count == 1 {
					if rec.Code != 303 {
						t.Fatalf("single: %d %s", rec.Code, rec.Body)
					}
					txn, _ := e.st.AuthTransactions().Get(context.Background(), org.TenantID, state)
					if txn.Params[store.TxnParamOrgID] != org.ID || txn.Params[store.TxnParamOrgMode] != string(authz.OrgFixed) {
						t.Fatal("single choice unbound")
					}
				} else if count > 1 {
					want := min(count, 20)
					if rec.Code != 200 || strings.Count(rec.Body.String(), `name="organization"`) != want {
						t.Fatalf("picker: %d %s", rec.Code, rec.Body)
					}
				} else {
					if rec.Code != 400 || !strings.Contains(rec.Body.String(), `role="alert"`) {
						t.Fatalf("zero: %d %s", rec.Code, rec.Body)
					}
					if strings.Contains(rec.Body.String(), `value="personal"`) != (usage == store.OrgUsageAllow) {
						t.Fatal("personal continuation policy")
					}
				}
			})
		}
	}
	for _, methods := range [][]string{{store.OrgDiscoveryName}, {store.OrgDiscoveryName, store.OrgDiscoveryEmail}} {
		t.Run(strings.Join(methods, "/"), func(t *testing.T) {
			e, _ := discoveryFixture(t, 0, store.OrgUsageRequire, methods...)
			page, _, _ := e.browser("acme.example.test").begin(t)
			if !strings.Contains(page.Body.String(), `name="organization"`) {
				t.Fatal("missing configured name prompt")
			}
			if strings.Contains(page.Body.String(), `name="email"`) != (len(methods) == 2) {
				t.Fatal("configured email prompt")
			}
		})
	}
}

func TestOrganizationDiscoveryStalePost(t *testing.T) {
	for _, change := range []string{"domain", "app", "connection", "revision", "methods"} {
		t.Run(change, func(t *testing.T) {
			e, org := discoveryFixture(t, 2, store.OrgUsageRequire, store.OrgDiscoveryEmail)
			ctx := context.Background()
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t)
			page := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "email": {"unknown@acme.test"}})
			if page.Code != 200 {
				t.Fatalf("picker: %d %s", page.Code, page.Body)
			}
			before, _ := e.st.AuthTransactions().Get(ctx, org.TenantID, state)
			switch change {
			case "domain":
				if err := e.st.OrganizationsII().DeleteDiscoveryDomain(ctx, org.TenantID, org.ID, "dom_0"); err != nil {
					t.Fatal(err)
				}
			case "app":
				org.IsAppEntitlementActive = true
				if err := e.st.Organizations().Update(ctx, org); err != nil {
					t.Fatal(err)
				}
			case "connection":
				conn, _ := e.st.Connections().GetByName(ctx, org.TenantID, "Username-Password-Authentication")
				if err := e.st.Organizations().DeleteConnection(ctx, org.TenantID, org.ID, conn.ID); err != nil {
					t.Fatal(err)
				}
			case "revision":
				next := before.HostedState.Clone()
				if err := e.st.AuthTransactions().CompareAndSwapHosted(ctx, org.TenantID, state, before.HostedState.Revision, next, e.h.Now()); err != nil {
					t.Fatal(err)
				}
			case "methods":
				c, _ := e.st.Clients().Get(ctx, org.TenantID, "spa")
				c.OrganizationDiscoveryMethods = []string{store.OrgDiscoveryName}
				if err := e.st.Clients().Update(ctx, c); err != nil {
					t.Fatal(err)
				}
			}
			rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "organization": {org.ID}})
			if rec.Code < 400 {
				t.Fatalf("stale selection: %d %s", rec.Code, rec.Body)
			}
			current, err := e.st.AuthTransactions().Get(ctx, org.TenantID, state)
			if err == nil && current.Params[store.TxnParamOrgID] != "" {
				t.Fatal("stale selection bound organization")
			}
		})
	}
}

func TestOrganizationDiscoveryPersonalContinuation(t *testing.T) {
	e, org := discoveryFixture(t, 0, store.OrgUsageAllow, store.OrgDiscoveryEmail)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "email": {"unknown@acme.test"}})
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "action": {"personal"}})
	if rec.Code != 303 {
		t.Fatalf("personal choice: %d %s", rec.Code, rec.Body)
	}
	page := b.do(t, "GET", rec.Header().Get("Location"), nil)
	if page.Code != 200 || !strings.Contains(page.Body.String(), `name="password"`) {
		t.Fatalf("personal form: %d %s", page.Code, page.Body)
	}
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("personal authorization: %d %s %s", rec.Code, loc, rec.Body)
	}
	members, err := e.st.Organizations().Members(context.Background(), org.TenantID, org.ID, store.OrgPage{})
	if err != nil || len(members.Items) != 0 {
		t.Fatalf("discovery enrolled member: %+v %v", members, err)
	}
}

func TestOrganizationDiscoveryRateAndCSRF(t *testing.T) {
	e, org := discoveryFixture(t, 0, store.OrgUsageRequire, store.OrgDiscoveryEmail)
	ctx := context.Background()
	tn, _ := e.st.Tenants().Get(ctx, org.TenantID)
	tn.ProtectionSettingsInitialized = true
	tn.ProtectionSettings.SuspiciousIP.Allowlist = nil
	tn.ProtectionSettings.SuspiciousIP.Enabled = true
	tn.ProtectionSettings.SuspiciousIP.Shields = []string{"block"}
	tn.ProtectionSettings.SuspiciousIP.Stage.PreLogin = store.ProtectionRate{MaxAttempts: 1, Rate: 3600000}
	if err := e.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {"wrong"}, "email": {"unknown@acme.test"}})
	if rec.Code < 400 {
		t.Fatal("missing CSRF accepted")
	}
	// A rejected CSRF does not consume the valid transaction.
	b = e.browser("acme.example.test")
	_, state, csrf = b.begin(t)
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "email": {"unknown@acme.test"}})
	if rec.Code != 400 {
		t.Fatalf("first attempt: %d %s", rec.Code, rec.Body)
	}
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "email": {"another@acme.test"}})
	if rec.Code != 429 {
		t.Fatalf("rate limit: %d %s", rec.Code, rec.Body)
	}
}

// Any account-store access during the discovery form is a privacy regression.
type discoveryNoUsers struct{ store.Store }

func (s discoveryNoUsers) Users() store.Users {
	panic("organization discovery must not look up accounts")
}

func TestOrganizationDiscoveryNoAccountLookupAndFiltering(t *testing.T) {
	e, org := discoveryFixture(t, 24, store.OrgUsageRequire, store.OrgDiscoveryEmail)
	ctx := context.Background()
	for i := 0; i < 21; i++ {
		o, err := e.st.Organizations().Get(ctx, org.TenantID, fmt.Sprintf("org_%016d", i+1))
		if err != nil {
			t.Fatal(err)
		}
		o.IsAppEntitlementActive = true
		if err = e.st.Organizations().Update(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	e.h.Store = discoveryNoUsers{e.st}
	for _, email := range []string{"alice@acme.test", "unknown@acme.test"} {
		b := e.browser("acme.example.test")
		_, state, csrf := b.begin(t)
		page := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "email": {email}})
		if page.Code != 200 || strings.Count(page.Body.String(), `name="organization"`) != 3 {
			t.Fatalf("filter-before-cap: %d %s", page.Code, page.Body)
		}
		for i := 22; i <= 24; i++ {
			if !strings.Contains(page.Body.String(), fmt.Sprintf("org_%016d", i)) {
				t.Fatal("eligible candidate omitted")
			}
		}
	}
}

func TestOrganizationDiscoveryPersonalPolicyAndTampering(t *testing.T) {
	e, org := discoveryFixture(t, 0, store.OrgUsageAllow, store.OrgDiscoveryEmail)
	b := e.browser("acme.example.test")
	page, _, _ := b.begin(t, store.TxnParamOrgMode, string(authz.OrgPersonal), "za_org_email", "alice@acme.test")
	if !strings.Contains(page.Body.String(), `name="email"`) {
		t.Fatal("external parameter skipped discovery")
	}
	_, state, csrf := b.begin(t)
	b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "email": {"unknown@acme.test"}})
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "action": {"personal"}})
	if rec.Code != 303 {
		t.Fatal("personal selection failed")
	}
	ctx := context.Background()
	c, _ := e.st.Clients().Get(ctx, org.TenantID, "spa")
	c.OrganizationUsage = store.OrgUsageRequire
	if err := e.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	rec = b.do(t, "GET", rec.Header().Get("Location"), nil)
	if rec.Code < 400 {
		t.Fatalf("personal continuation after require: %d %s", rec.Code, rec.Body)
	}
}

func TestOrganizationDiscoveryNameFallbackAndSelection(t *testing.T) {
	for _, disable := range []bool{false, true} {
		t.Run(fmt.Sprint(disable), func(t *testing.T) {
			e, org := discoveryFixture(t, 0, store.OrgUsageRequire, store.OrgDiscoveryEmail, store.OrgDiscoveryName)
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t)
			page := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "email": {"unknown@acme.test"}})
			if page.Code != 400 || !strings.Contains(page.Body.String(), `name="organization"`) || !strings.Contains(page.Body.String(), `aria-describedby="organization-error"`) {
				t.Fatal("missing accessible name fallback")
			}
			if disable {
				c, _ := e.st.Clients().Get(context.Background(), org.TenantID, "spa")
				c.OrganizationDiscoveryMethods = []string{store.OrgDiscoveryName}
				if err := e.st.Clients().Update(context.Background(), c); err != nil {
					t.Fatal(err)
				}
				page = b.do(t, "GET", "/u/login?state="+state, nil)
				if strings.Contains(page.Body.String(), `name="email"`) {
					t.Fatal("disabled email flow retained")
				}
			}
			rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "action": {"name"}, "organization": {org.Name}})
			if rec.Code != 303 {
				t.Fatalf("name fallback: %d %s", rec.Code, rec.Body)
			}
		})
	}
	e, org := discoveryFixture(t, 2, store.OrgUsageRequire, store.OrgDiscoveryEmail)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "email": {"unknown@acme.test"}})
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "organization": {org.ID}, "za_org_email": {"evil@other.test"}})
	if rec.Code != 303 {
		t.Fatalf("picker selection: %d %s", rec.Code, rec.Body)
	}
	txn, _ := e.st.AuthTransactions().Get(context.Background(), org.TenantID, state)
	if txn.Params[store.TxnParamOrgID] != org.ID {
		t.Fatal("picker selection not bound")
	}
}

func TestOrganizationDiscoveryStalePostKeepsExplicitContext(t *testing.T) {
	for _, invitation := range []bool{false, true} {
		t.Run(fmt.Sprint(invitation), func(t *testing.T) {
			e, org := discoveryFixture(t, 2, store.OrgUsageRequire, store.OrgDiscoveryEmail)
			ctx := context.Background()
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t)
			b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "email": {"unknown@acme.test"}})
			txn, _ := e.st.AuthTransactions().Get(ctx, org.TenantID, state)
			// Model another request committing an explicit org/invitation after render.
			fixed := "org_0000000000000002"
			txn.Params[store.TxnParamOrgID] = fixed
			txn.Params[store.TxnParamOrgMode] = string(authz.OrgFixed)
			if invitation {
				txn.Params["za_invitation_id"] = "inv_bound"
			}
			txn.HostedState.Revision++
			if err := e.st.WithTx(ctx, func(tx store.Store) error {
				if err := tx.AuthTransactions().Delete(ctx, org.TenantID, state); err != nil {
					return err
				}
				return tx.AuthTransactions().Create(ctx, txn)
			}); err != nil {
				t.Fatal(err)
			}
			rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "organization": {org.ID}, "hosted_revision": {fmt.Sprint(txn.HostedState.Revision - 1)}})
			if rec.Code < 400 {
				t.Fatalf("stale explicit selection: %d %s", rec.Code, rec.Body)
			}
			current, err := e.st.AuthTransactions().Get(ctx, org.TenantID, state)
			if err != nil || current.Params[store.TxnParamOrgID] != fixed || current.Params["za_invitation_id"] != txn.Params["za_invitation_id"] {
				t.Fatalf("explicit context replaced: %+v %v", current, err)
			}
		})
	}
}

func TestOrganizationDiscoveryLocalizedForm(t *testing.T) {
	e, org := discoveryFixture(t, 0, store.OrgUsageRequire, store.OrgDiscoveryEmail)
	ctx := context.Background()
	cfg, err := e.st.HostedLogins().Get(ctx, org.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CustomText = store.CustomText{"organizations": {"en": {"organization-selection": {"email": "Work address override", "invalid-organization": "Retry discovery override"}}}}
	if err = e.st.HostedLogins().Put(ctx, cfg, cfg.Revision); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t)
	if !strings.Contains(page.Body.String(), "Work address override") {
		t.Fatal("email label not localized")
	}
	page = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "email": {"unknown@acme.test"}})
	for _, want := range []string{"Retry discovery override", `role="alert"`, `aria-invalid="true"`, `aria-describedby="organization-error"`} {
		if !strings.Contains(page.Body.String(), want) {
			t.Fatalf("missing localized accessible error %s", want)
		}
	}
}
