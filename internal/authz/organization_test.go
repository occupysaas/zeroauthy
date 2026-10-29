package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// noOrgStore is a storage plugin without the Organizations capability.
type noOrgStore struct{ store.Store }

func (noOrgStore) OrganizationsSupported() bool { return false }
func (noOrgStore) CheckOrganizationsSupport(context.Context) error {
	return store.ErrOrganizationsUnavailable
}

// addOrg stores an organization in tenant tid. An empty id is generated.
func addOrg(t *testing.T, st store.Store, tid, id, name, thirdParty string) *store.Organization {
	t.Helper()
	if id == "" {
		id = orgrules.NewID()
	}
	if thirdParty == "" {
		thirdParty = "block"
	}
	o := &store.Organization{TenantID: tid, ID: id, Name: name, DisplayName: name, ThirdPartyClientAccess: thirdParty,
		CreatedAt: fixedNow(), UpdatedAt: fixedNow()}
	if err := st.Organizations().Create(context.Background(), o, nil); err != nil {
		t.Fatal(err)
	}
	return o
}

// setOrgClient sets a client's organization usage and behavior.
func setOrgClient(t *testing.T, st store.Store, tid, clientID, usage, behavior string) {
	t.Helper()
	c, err := st.Clients().Get(context.Background(), tid, clientID)
	if err != nil {
		t.Fatal(err)
	}
	c.OrganizationUsage, c.OrganizationRequireBehavior = usage, behavior
	if err := st.Clients().Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func setOrgNames(f *fixture, on bool) {
	if f.tenant.SettingsExtra == nil {
		f.tenant.SettingsExtra = map[string]any{}
	}
	f.tenant.SettingsExtra[orgNamesSetting] = on
}

func TestResolveOrganization(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	acme := addOrg(t, f.st, f.tenant.ID, "", "acme-corp", "block")
	open := addOrg(t, f.st, f.tenant.ID, "", "open-corp", "allow")
	// Review Focus 2: an organization named like another organization's ID.
	lower := addOrg(t, f.st, f.tenant.ID, "org_abcdefghijklmnop", "lower", "")
	squatter := addOrg(t, f.st, f.tenant.ID, "org_SQUATTERsquatter", "org_abcdefghijklmnop", "")
	byName := addOrg(t, f.st, f.tenant.ID, "", "org_zzzzzzzzzzzzzzzz", "")
	globex, err := f.st.Tenants().GetByName(ctx, "globex")
	if err != nil {
		t.Fatal(err)
	}
	foreign := addOrg(t, f.st, globex.ID, "", "foreign", "")

	type tc struct {
		name         string
		usage, behav string
		thirdParty   bool
		names        bool
		oldPlugin    bool
		raw          string
		wantCode     string
		wantID       string
		wantMode     OrgMode
	}
	cases := []tc{
		{name: "deny with organization", usage: "deny", raw: acme.ID, wantCode: "invalid_request"},
		{name: "unset usage with organization", raw: acme.ID, wantCode: "invalid_request"},
		{name: "deny with a name", usage: "deny", names: true, raw: "acme-corp", wantCode: "invalid_request"},
		{name: "allow with id", usage: "allow", raw: acme.ID, wantID: acme.ID, wantMode: OrgFixed},
		{name: "require with id", usage: "require", raw: acme.ID, wantID: acme.ID, wantMode: OrgFixed},
		{name: "require pre_login_prompt with id", usage: "require", behav: "pre_login_prompt", raw: acme.ID, wantID: acme.ID, wantMode: OrgFixed},
		{name: "unknown id", usage: "allow", raw: "org_0000000000000000", wantCode: "invalid_request"},
		{name: "unknown id with require", usage: "require", raw: "org_0000000000000000", wantCode: "invalid_request"},
		{name: "unknown id with pre_login_prompt", usage: "require", behav: "pre_login_prompt", raw: "org_0000000000000000", wantCode: "invalid_request"},
		{name: "name while names are off", usage: "allow", raw: "acme-corp", wantCode: "invalid_request"},
		{name: "not id-shaped while names are off", usage: "allow", raw: "xyz", wantCode: "invalid_request"},
		{name: "id-shaped name while names are off", usage: "allow", raw: "org_zzzzzzzzzzzzzzzz", wantCode: "invalid_request"},
		{name: "name while names are on", usage: "allow", names: true, raw: "acme-corp", wantID: acme.ID, wantMode: OrgFixed},
		{name: "names are exact", usage: "allow", names: true, raw: "ACME-corp", wantCode: "invalid_request"},
		{name: "unknown name while names are on", usage: "allow", names: true, raw: "nope", wantCode: "invalid_request"},
		{name: "id wins over an equal name", usage: "allow", names: true, raw: lower.ID, wantID: lower.ID, wantMode: OrgFixed},
		{name: "id-shaped name without an id match", usage: "allow", names: true, raw: byName.Name, wantID: byName.ID, wantMode: OrgFixed},
		{name: "id still works while names are on", usage: "allow", names: true, raw: squatter.ID, wantID: squatter.ID, wantMode: OrgFixed},
		{name: "third party blocked", usage: "allow", thirdParty: true, raw: acme.ID, wantCode: "access_denied"},
		{name: "third party blocked by default", usage: "allow", thirdParty: true, raw: lower.ID, wantCode: "access_denied"},
		{name: "third party allowed", usage: "allow", thirdParty: true, raw: open.ID, wantID: open.ID, wantMode: OrgFixed},
		{name: "another tenant's organization", usage: "allow", raw: foreign.ID, wantCode: "invalid_request"},
		{name: "another tenant's organization by name", usage: "allow", names: true, raw: foreign.Name, wantCode: "invalid_request"},
		{name: "old plugin with organization", usage: "allow", oldPlugin: true, raw: acme.ID, wantCode: "invalid_request"},
		{name: "old plugin without organization", usage: "allow", oldPlugin: true, wantMode: OrgNone},
		{name: "old plugin require", usage: "require", oldPlugin: true, wantCode: "invalid_request"},

		// Spec §5.1 step 4: no organization.
		{name: "unset", wantMode: OrgNone},
		{name: "deny", usage: "deny", wantMode: OrgNone},
		{name: "deny pre_login_prompt", usage: "deny", behav: "pre_login_prompt", wantMode: OrgNone},
		{name: "deny post_login_prompt", usage: "deny", behav: "post_login_prompt", wantMode: OrgNone},
		{name: "allow", usage: "allow", wantMode: OrgNone},
		{name: "allow no_prompt", usage: "allow", behav: "no_prompt", wantMode: OrgNone},
		{name: "allow pre_login_prompt", usage: "allow", behav: "pre_login_prompt", wantMode: OrgPromptBefore},
		{name: "allow post_login_prompt", usage: "allow", behav: "post_login_prompt", wantMode: OrgNone},
		{name: "require unset behavior", usage: "require", wantCode: "invalid_request"},
		{name: "require no_prompt", usage: "require", behav: "no_prompt", wantCode: "invalid_request"},
		{name: "require pre_login_prompt", usage: "require", behav: "pre_login_prompt", wantMode: OrgPromptBefore},
		{name: "require post_login_prompt", usage: "require", behav: "post_login_prompt", wantMode: OrgPickAfter},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tn := *f.tenant
			tn.SettingsExtra = map[string]any{orgNamesSetting: c.names}
			client := &store.Client{TenantID: tn.ID, ClientID: "x", IsFirstParty: !c.thirdParty,
				OrganizationUsage: c.usage, OrganizationRequireBehavior: c.behav}
			var st store.Store = f.st
			if c.oldPlugin {
				st = noOrgStore{f.st}
			}
			d, e := ResolveOrganization(ctx, st, tenant.Resolved{Tenant: &tn, Host: "acme.example.test"}, client, c.raw)
			if c.wantCode != "" {
				if e == nil || e.Code != c.wantCode || e.Description == "" {
					t.Fatalf("got %+v, %+v; want %s", d, e, c.wantCode)
				}
				return
			}
			if e != nil || d.OrgID != c.wantID || d.Mode != c.wantMode {
				t.Fatalf("got %+v, %+v; want %q %q", d, e, c.wantID, c.wantMode)
			}
		})
	}
}

// orgTxn follows an /authorize redirect to the hosted login and returns its
// transaction.
func (e *env) orgTxn(t *testing.T, rec *httptest.ResponseRecorder) *store.AuthTransaction {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Path != "/u/login" {
		t.Fatalf("Location = %s", rec.Header().Get("Location"))
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	return txn
}

func wantCallbackError(t *testing.T, loc *url.URL, host, code string) {
	t.Helper()
	if loc.Host != host || loc.Query().Get("error") != code || loc.Query().Get("error_description") == "" || loc.Query().Get("code") != "" {
		t.Fatalf("Location = %s, want %s error=%s", loc, host, code)
	}
}

func TestOrganizationBinding(t *testing.T) {
	ctx := context.Background()

	t.Run("resolved organization lands in the transaction", func(t *testing.T) {
		e := newEnv(t)
		org := addOrg(t, e.st, e.tenant.ID, "", "acme-corp", "")
		setOrgClient(t, e.st, e.tenant.ID, "spa", "allow", "")
		rec := e.get(t, with(goodQuery(), "organization", org.ID))
		txn := e.orgTxn(t, rec)
		if txn.Params[store.TxnParamOrgID] != org.ID || txn.Params[store.TxnParamOrgMode] != string(OrgFixed) {
			t.Fatalf("params = %v", txn.Params)
		}
	})

	t.Run("name resolves to the id in the transaction", func(t *testing.T) {
		e := newEnv(t)
		org := addOrg(t, e.st, e.tenant.ID, "", "acme-corp", "")
		setOrgClient(t, e.st, e.tenant.ID, "spa", "allow", "")
		tn := *e.tenant
		tn.SettingsExtra = map[string]any{orgNamesSetting: true}
		if err := e.st.Tenants().Update(ctx, &tn); err != nil {
			t.Fatal(err)
		}
		rec := e.get(t, with(goodQuery(), "organization", "acme-corp"))
		txn := e.orgTxn(t, rec)
		if txn.Params[store.TxnParamOrgID] != org.ID {
			t.Fatalf("params = %v", txn.Params)
		}
	})

	t.Run("internal keys cannot be injected", func(t *testing.T) {
		e := newEnv(t)
		a := addOrg(t, e.st, e.tenant.ID, "", "acme-corp", "")
		b := addOrg(t, e.st, e.tenant.ID, "", "beta-corp", "")
		// A deny client cannot smuggle a binding in.
		rec := e.get(t, with(goodQuery(), store.TxnParamOrgID, a.ID, store.TxnParamOrgMode, string(OrgFixed)))
		txn := e.orgTxn(t, rec)
		if _, ok := txn.Params[store.TxnParamOrgID]; ok {
			t.Fatalf("params = %v", txn.Params)
		}
		if _, ok := txn.Params[store.TxnParamOrgMode]; ok {
			t.Fatalf("params = %v", txn.Params)
		}
		// POST bodies are read the same way.
		setOrgClient(t, e.st, e.tenant.ID, "spa", "allow", "")
		rec = e.post(t, with(goodQuery(), "organization", a.ID, store.TxnParamOrgID, b.ID))
		txn = e.orgTxn(t, rec)
		if txn.Params[store.TxnParamOrgID] != a.ID {
			t.Fatalf("params = %v", txn.Params)
		}
	})

	t.Run("a later step cannot change the binding", func(t *testing.T) {
		e := newEnv(t)
		a := addOrg(t, e.st, e.tenant.ID, "", "acme-corp", "")
		b := addOrg(t, e.st, e.tenant.ID, "", "beta-corp", "")
		setOrgClient(t, e.st, e.tenant.ID, "spa", "allow", "")
		rec := e.get(t, with(goodQuery(), "organization", a.ID))
		txn := e.orgTxn(t, rec)

		// A transaction whose raw organization differs from the binding
		// keeps the binding when the request is validated again.
		params := map[string]string{}
		for k, v := range txn.Params {
			params[k] = v
		}
		params["organization"] = b.ID
		fr := flowFromParams(params)
		if _, verr, _ := e.h.validateFlow(ctx, tenant.Resolved{Tenant: e.tenant, Host: "acme.example.test"}, &fr); verr != nil {
			t.Fatalf("validate: %+v", verr)
		}
		if fr.OrgID != a.ID || fr.OrgMode != OrgFixed || fr.Params()[store.TxnParamOrgID] != a.ID {
			t.Fatalf("binding = %q %q", fr.OrgID, fr.OrgMode)
		}

		// Fail closed: a bound organization that is gone, or a client that
		// stopped accepting organizations, refuses the request.
		fr = flowFromParams(txn.Params)
		setOrgClient(t, e.st, e.tenant.ID, "spa", "deny", "")
		if _, verr, _ := e.h.validateFlow(ctx, tenant.Resolved{Tenant: e.tenant, Host: "acme.example.test"}, &fr); verr == nil || verr.Code != "invalid_request" {
			t.Fatalf("deny client: %+v", verr)
		}
		setOrgClient(t, e.st, e.tenant.ID, "spa", "allow", "")
		if err := e.st.Organizations().Delete(ctx, e.tenant.ID, a.ID); err != nil {
			t.Fatal(err)
		}
		fr = flowFromParams(txn.Params)
		if _, verr, _ := e.h.validateFlow(ctx, tenant.Resolved{Tenant: e.tenant, Host: "acme.example.test"}, &fr); verr == nil || verr.Code != "invalid_request" {
			t.Fatalf("deleted organization: %+v", verr)
		}
	})

	t.Run("pushed organization binds and request_uri cannot override it", func(t *testing.T) {
		e := newEnv(t)
		a := addOrg(t, e.st, e.tenant.ID, "", "acme-corp", "")
		b := addOrg(t, e.st, e.tenant.ID, "", "beta-corp", "")
		setOrgClient(t, e.st, e.tenant.ID, "par-web", "allow", "")
		pushed := parParams()
		pushed["organization"] = a.ID
		pushed[store.TxnParamOrgID], pushed[store.TxnParamOrgMode] = a.ID, string(OrgFixed)
		q := parQuery("par-web", e.push(t, e.tenant.ID, "par-web", pushed, PARLifetime))
		q.Set("organization", b.ID) // P1: ignored
		rec := e.get(t, q)
		txn := e.orgTxn(t, rec)
		if txn.Params[store.TxnParamOrgID] != a.ID || txn.Params["organization"] != a.ID {
			t.Fatalf("params = %v", txn.Params)
		}

		// request_uri cannot add an organization to a request pushed without one.
		q = parQuery("par-web", e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime))
		q.Set("organization", b.ID)
		rec = e.get(t, q)
		txn = e.orgTxn(t, rec)
		if _, ok := txn.Params[store.TxnParamOrgID]; ok || txn.Params["organization"] != "" {
			t.Fatalf("params = %v", txn.Params)
		}
	})

	t.Run("errors redirect with invalid_request", func(t *testing.T) {
		e := newEnv(t)
		org := addOrg(t, e.st, e.tenant.ID, "", "acme-corp", "")
		// deny (unset) client
		wantCallbackError(t, location(t, e.get(t, with(goodQuery(), "organization", org.ID))), "app.acme.test", "invalid_request")
		setOrgClient(t, e.st, e.tenant.ID, "spa", "allow", "")
		for _, raw := range []string{"org_0000000000000000", "acme-corp", "xyz"} {
			loc := location(t, e.get(t, with(goodQuery(), "organization", raw)))
			wantCallbackError(t, loc, "app.acme.test", "invalid_request")
			if loc.Query().Get("state") != "st" {
				t.Fatalf("Location = %s", loc)
			}
		}
		// Invitations stay refused, with or without an organization.
		wantCallbackError(t, location(t, e.get(t, with(goodQuery(), "invitation", "junk"))), "app.acme.test", "invalid_request")
		wantCallbackError(t, location(t, e.get(t, with(goodQuery(), "invitation", "junk", "organization", org.ID))), "app.acme.test", "invalid_request")
		// organization= with an empty value counts as absent.
		e.orgTxn(t, e.serve(t, httptestRequest("https://acme.example.test/authorize?"+goodQuery().Encode()+"&organization=")))
	})

	t.Run("require no_prompt", func(t *testing.T) {
		e := newEnv(t)
		org := addOrg(t, e.st, e.tenant.ID, "", "acme-corp", "")
		setOrgClient(t, e.st, e.tenant.ID, "spa", "require", "no_prompt")
		wantCallbackError(t, location(t, e.get(t, goodQuery())), "app.acme.test", "invalid_request")
		// The organization check runs before the login check.
		wantCallbackError(t, location(t, e.get(t, with(goodQuery(), "prompt", "none"))), "app.acme.test", "invalid_request")
		// A valid organization without a session is the normal login_required.
		wantCallbackError(t, location(t, e.get(t, with(goodQuery(), "prompt", "none", "organization", org.ID))), "app.acme.test", "login_required")
		rec := e.get(t, with(goodQuery(), "organization", org.ID))
		e.orgTxn(t, rec)
	})

	t.Run("prompt and picker modes are bound", func(t *testing.T) {
		e := newEnv(t)
		for behavior, mode := range map[string]OrgMode{"pre_login_prompt": OrgPromptBefore, "post_login_prompt": OrgPickAfter} {
			setOrgClient(t, e.st, e.tenant.ID, "spa", "require", behavior)
			rec := e.get(t, goodQuery())
			txn := e.orgTxn(t, rec)
			if txn.Params[store.TxnParamOrgMode] != string(mode) || txn.Params[store.TxnParamOrgID] != "" {
				t.Fatalf("%s: params = %v", behavior, txn.Params)
			}
		}
	})

	t.Run("an organization session is checked before reuse", func(t *testing.T) {
		e := newEnv(t)
		org := addOrg(t, e.st, e.tenant.ID, "", "acme-corp", "")
		setOrgClient(t, e.st, e.tenant.ID, "spa", "allow", "")
		cookie := e.login(t, fixedNow())
		rec := e.get(t, with(goodQuery(), "organization", org.ID), cookie)
		wantCallbackError(t, location(t, rec), "app.acme.test", "access_denied")
		// Without an organization the session still issues a code.
		loc := location(t, e.get(t, goodQuery(), cookie))
		if loc.Query().Get("code") == "" {
			t.Fatalf("Location = %s", loc)
		}
	})

	t.Run("connection outside the organization is not a pre-authentication error", func(t *testing.T) {
		e := newEnv(t)
		org := addOrg(t, e.st, e.tenant.ID, "", "acme-corp", "")
		setOrgClient(t, e.st, e.tenant.ID, "spa", "allow", "")
		rec := e.get(t, with(goodQuery(), "organization", org.ID, "connection", "Username-Password-Authentication"))
		e.orgTxn(t, rec)
	})

	t.Run("third-party client and blocked organization", func(t *testing.T) {
		e := newEnv(t)
		blocked := addOrg(t, e.st, e.tenant.ID, "", "acme-corp", "block")
		open := addOrg(t, e.st, e.tenant.ID, "", "open-corp", "allow")
		setOrgClient(t, e.st, e.tenant.ID, "partner-open", "allow", "")
		q := url.Values{"client_id": {"partner-open"}, "redirect_uri": {"https://open.example/cb"}, "response_type": {"code"},
			"scope": {"openid"}, "state": {"st"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
		wantCallbackError(t, location(t, e.get(t, with(q, "organization", blocked.ID))), "open.example", "access_denied")
		rec := e.get(t, with(q, "organization", open.ID))
		e.orgTxn(t, rec)
	})

	t.Run("old plugin refuses the organization parameter", func(t *testing.T) {
		e := newEnv(t)
		org := addOrg(t, e.st, e.tenant.ID, "", "acme-corp", "")
		setOrgClient(t, e.st, e.tenant.ID, "spa", "allow", "")
		e.h.Store = noOrgStore{e.st}
		wantCallbackError(t, location(t, e.get(t, with(goodQuery(), "organization", org.ID))), "app.acme.test", "invalid_request")
		rec := e.get(t, goodQuery())
		e.orgTxn(t, rec)
	})
}

func TestOrganizationBindingRecheck(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, usage, behavior string
		mode                  OrgMode
	}{
		{"empty fixed ID", "allow", "pre_login_prompt", OrgFixed},
		{"pre prompt changed", "require", "post_login_prompt", OrgPromptBefore},
		{"post prompt changed", "require", "pre_login_prompt", OrgPickAfter},
		{"picker now optional", "allow", "post_login_prompt", OrgPickAfter},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := Request{OrgMode: tc.mode}
			c := &store.Client{OrganizationUsage: tc.usage, OrganizationRequireBehavior: tc.behavior}
			if e := bindOrganization(context.Background(), f.st, f.tenant, c, &req); e == nil || e.Code != "invalid_request" {
				t.Fatalf("stale binding accepted: %+v", e)
			}
		})
	}
}

// The final issuance boundary rechecks membership after any post-login Action
// wait, even when an earlier continuation already approved the organization.
func TestOrganizationMembershipAtCodeIssuance(t *testing.T) {
	e := newEnv(t)
	org := addOrg(t, e.st, e.tenant.ID, "", "acme-corp", "")
	setOrgClient(t, e.st, e.tenant.ID, "spa", "allow", "")
	cookie := e.login(t, fixedNow())
	sess := e.session(t, cookie)
	client, err := e.st.Clients().Get(context.Background(), e.tenant.ID, "spa")
	if err != nil {
		t.Fatal(err)
	}
	req := ParseRequest(goodQuery())
	req.OrgID = org.ID
	req.OrgMode = OrgFixed
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://acme.example.test/authorize", nil)
	e.h.issueCode(rec, r, e.res(), client, req, sess, []string{"openid"}, nil)
	wantCallbackError(t, location(t, rec), "app.acme.test", "access_denied")
}
