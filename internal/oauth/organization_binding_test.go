package oauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (f *fixture) addOrg(t *testing.T, name string) *store.Organization {
	t.Helper()
	o := &store.Organization{TenantID: f.tenantID(t, "acme"), ID: orgrules.NewID(), Name: name, DisplayName: name,
		ThirdPartyClientAccess: "block", CreatedAt: fixedNow(), UpdatedAt: fixedNow()}
	if err := f.st.Organizations().Create(context.Background(), o, nil); err != nil {
		t.Fatal(err)
	}
	return o
}

// setOrgUsage writes a client's organization usage straight to the store,
// as legacy data would hold it.
func (f *fixture) setOrgUsage(t *testing.T, clientID, usage, behavior string) {
	t.Helper()
	c, err := f.st.Clients().Get(context.Background(), f.tenantID(t, "acme"), clientID)
	if err != nil {
		t.Fatal(err)
	}
	c.OrganizationUsage, c.OrganizationRequireBehavior = usage, behavior
	if err := f.st.Clients().Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func TestOrganizationBinding(t *testing.T) {
	ctx := context.Background()

	t.Run("pushed organization binds", func(t *testing.T) {
		f := newFixture(t)
		org := f.addOrg(t, "acme-corp")
		f.setOrgUsage(t, "par-web", "allow", "")
		rec, body := f.par(t, acmeHost, formType, parForm("organization", org.ID).Encode())
		if rec.Code != http.StatusCreated {
			t.Fatalf("status %d, body %v", rec.Code, body)
		}
		id, _ := strings.CutPrefix(body["request_uri"].(string), authz.RequestURIPrefix)
		p, err := f.st.PushedAuthRequests().Get(ctx, f.tenantID(t, "acme"), secrets.HashToken(id))
		if err != nil {
			t.Fatal(err)
		}
		if p.Params[store.TxnParamOrgID] != org.ID || p.Params[store.TxnParamOrgMode] != string(authz.OrgFixed) || p.Params["organization"] != org.ID {
			t.Fatalf("stored params = %v", p.Params)
		}
	})

	t.Run("pushed internal keys are not stored", func(t *testing.T) {
		f := newFixture(t)
		org := f.addOrg(t, "acme-corp")
		rec, body := f.par(t, acmeHost, formType, parForm(store.TxnParamOrgID, org.ID, store.TxnParamOrgMode, string(authz.OrgFixed)).Encode())
		if rec.Code != http.StatusCreated {
			t.Fatalf("status %d, body %v", rec.Code, body)
		}
		id, _ := strings.CutPrefix(body["request_uri"].(string), authz.RequestURIPrefix)
		p, err := f.st.PushedAuthRequests().Get(ctx, f.tenantID(t, "acme"), secrets.HashToken(id))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := p.Params[store.TxnParamOrgID]; ok {
			t.Fatalf("stored params = %v", p.Params)
		}
		if _, ok := p.Params[store.TxnParamOrgMode]; ok {
			t.Fatalf("stored params = %v", p.Params)
		}
	})

	t.Run("pushed organization errors", func(t *testing.T) {
		f := newFixture(t)
		org := f.addOrg(t, "acme-corp")
		// par-web is deny (unset).
		rec, body := f.par(t, acmeHost, formType, parForm("organization", org.ID).Encode())
		if rec.Code != http.StatusBadRequest || body["error"] != "invalid_request" {
			t.Fatalf("deny: %d %v", rec.Code, body)
		}
		f.setOrgUsage(t, "par-web", "allow", "")
		for _, raw := range []string{"org_0000000000000000", "acme-corp"} {
			rec, body = f.par(t, acmeHost, formType, parForm("organization", raw).Encode())
			if rec.Code != http.StatusBadRequest || body["error"] != "invalid_request" {
				t.Fatalf("%s: %d %v", raw, rec.Code, body)
			}
		}
		f.setOrgUsage(t, "par-web", "require", "no_prompt")
		rec, body = f.par(t, acmeHost, formType, parForm().Encode())
		if rec.Code != http.StatusBadRequest || body["error"] != "invalid_request" {
			t.Fatalf("require: %d %v", rec.Code, body)
		}
	})

	t.Run("client credentials refuses organization", func(t *testing.T) {
		f := newFixture(t)
		org := f.addOrg(t, "acme-corp")
		for _, usage := range []string{"", "allow", "require"} {
			f.setOrgUsage(t, "m2m", usage, "")
			for _, raw := range []string{org.ID, "org_0000000000000000", "acme-corp"} {
				rec, body := f.call(t, false, tokenCall{host: acmeHost, form: cc("m2m", "m2m-secret", "audience", "https://api.acme.test", "organization", raw)})
				if rec.Code != http.StatusBadRequest || body["error"] != "invalid_request" {
					t.Fatalf("%q/%s: %d %v", usage, raw, rec.Code, body)
				}
			}
			rec, body := f.call(t, false, tokenCall{host: acmeHost, form: cc("m2m", "m2m-secret", "audience", "https://api.acme.test")})
			if rec.Code != http.StatusOK {
				t.Fatalf("%q without organization: %d %v", usage, rec.Code, body)
			}
		}
		// Without a client grant the audience is refused first.
		rec, body := f.call(t, false, tokenCall{host: acmeHost, form: cc("m2m", "m2m-secret", "audience", "https://granted.test", "organization", org.ID)})
		if rec.Code != http.StatusForbidden || body["error"] != "access_denied" {
			t.Fatalf("no grant: %d %v", rec.Code, body)
		}
	})

	t.Run("password grants ignore organization", func(t *testing.T) {
		f := newFixture(t)
		org := f.addOrg(t, "acme-corp")
		for _, usage := range []string{"deny", "allow"} {
			f.setOrgUsage(t, "ropg", usage, "")
			for _, form := range []url.Values{
				pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "scope", "openid", "organization", org.ID),
				pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "scope", "openid", "organization", "xyz",
					"grant_type", "http://auth0.com/oauth/grant-type/password-realm", "realm", "Username-Password-Authentication"),
			} {
				rec, body := f.call(t, false, tokenCall{host: acmeHost, form: form})
				if rec.Code != http.StatusOK {
					t.Fatalf("%s %s: %d %v", usage, form.Get("grant_type"), rec.Code, body)
				}
				for _, tok := range []string{"access_token", "id_token"} {
					claims, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body[tok].(string))
					if claims["org_id"] != nil || claims["org_name"] != nil {
						t.Fatalf("%s = %v", tok, claims)
					}
				}
			}
		}
	})

	t.Run("device code accepts organization without validating it", func(t *testing.T) {
		f := newFixture(t)
		for _, raw := range []string{"org_0000000000000000", "acme-corp"} {
			rec, body := f.deviceCode(t, acmeHost, formType, url.Values{"client_id": {"dev"}, "scope": {"openid"}, "organization": {raw}}.Encode())
			if rec.Code != http.StatusOK || body["device_code"] == nil {
				t.Fatalf("%s: %d %v", raw, rec.Code, body)
			}
		}
	})

	t.Run("require clients cannot use password or device grants", func(t *testing.T) {
		f := newFixture(t)
		f.setOrgUsage(t, "ropg", "require", "no_prompt")
		for _, form := range []url.Values{
			pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1"),
			pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1",
				"grant_type", "http://auth0.com/oauth/grant-type/password-realm", "realm", "Username-Password-Authentication"),
		} {
			rec, body := f.call(t, false, tokenCall{host: acmeHost, form: form})
			if rec.Code != http.StatusForbidden || body["error"] != "unauthorized_client" {
				t.Fatalf("%s: %d %v", form.Get("grant_type"), rec.Code, body)
			}
		}
		f.setOrgUsage(t, "dev", "require", "post_login_prompt")
		raw, _ := f.newDeviceCode(t, "dev", store.DeviceCodeApproved, f.aliceID(t), []string{"openid"})
		code, body := f.pollAt(t, fixedNow().Add(time.Second), deviceForm("dev", raw))
		if code != http.StatusForbidden || body["error"] != "unauthorized_client" {
			t.Fatalf("device: %d %v", code, body)
		}
	})
}
