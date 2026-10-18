package oauth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// The tenant's Management API is created on first use, so a client
// credentials request for it is refused for want of a grant (not as an
// unknown audience), and works once a client grant exists.
func TestClientCredentialsManagementAPI(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	aud := "https://acme.example.test/api/v2/"
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", aud)})
	if rec.Code != http.StatusForbidden || body["error"] != "access_denied" || body["error_description"] != "client is not authorized for this audience" {
		t.Fatalf("no grant: %d %v", rec.Code, body)
	}
	tenantID := f.tenantID(t, "acme")
	rs, err := f.st.ResourceServers().GetByIdentifier(ctx, tenantID, aud)
	if err != nil || !rs.IsSystem {
		t.Fatalf("management API = %+v, %v", rs, err)
	}
	if err := f.st.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: tenantID, ID: "cg_mgmt", ClientID: "m2m", Audience: aud,
		Scopes: []string{"read:clients", "read:client_keys"}, SubjectType: store.SubjectTypeClient, CreatedAt: fixedNow()}); err != nil {
		t.Fatal(err)
	}
	rec, body = f.call(t, true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", aud, "scope", "read:clients")})
	if rec.Code != http.StatusOK || body["scope"] != "read:clients" {
		t.Fatalf("with grant: %d %v", rec.Code, body)
	}
	claims, _ := verifyToken(t, f.keys, tenantID, body["access_token"].(string))
	if claims["aud"] != aud || claims["iss"] != "https://acme.example.test/" || claims["gty"] != "client-credentials" {
		t.Errorf("claims = %v", claims)
	}
	// Another tenant's Management API is unknown here.
	rec, body = f.call(t, true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", "https://globex.example.test/api/v2/")})
	if rec.Code != http.StatusForbidden || body["error_description"] != "unknown audience" {
		t.Errorf("other tenant's API: %d %v", rec.Code, body)
	}
}

// operatorFixture is the system tenant with an operator and a plain user.
func operatorFixture(t *testing.T) (*fixture, tenant.Resolved, *store.Client, *store.ResourceServer) {
	t.Helper()
	f := newFixture(t)
	ctx := context.Background()
	tn, err := system.Ensure(ctx, f.st, system.Config{Host: "admin.example.test", Wrapper: f.wrapper})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.keys.Ensure(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"auth0|op", "auth0|plain"} {
		if err := f.st.Users().Create(ctx, &store.User{TenantID: tn.ID, UserID: id, Email: id[6:] + "@example.test",
			Identities: []store.Identity{{Connection: system.OperatorsConnection, Provider: "auth0", UserID: id[6:]}}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.st.Operators().Upsert(ctx, &store.Operator{TenantID: tn.ID, UserID: "auth0|op", Tenants: []string{"acme", "globex"}}); err != nil {
		t.Fatal(err)
	}
	c, err := f.st.Clients().Get(ctx, tn.ID, system.ConsoleClientID)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := f.st.ResourceServers().GetByIdentifier(ctx, tn.ID, tenant.OperatorAudience)
	if err != nil {
		t.Fatal(err)
	}
	return f, tenant.Resolved{Tenant: tn, Host: "admin.example.test"}, c, rs
}

func TestOperatorClaim(t *testing.T) {
	f, res, c, rs := operatorFixture(t)
	ctx := context.Background()
	user, _ := f.st.Users().Get(ctx, res.Tenant.ID, "auth0|op")
	resp, oerr := f.h.mintUserTokens(ctx, res, c, userTokens{user: user, rs: rs, lifetime: 3600e9, scopes: []string{"openid"}})
	if oerr != nil {
		t.Fatal(oerr)
	}
	claims, _ := verifyToken(t, f.keys, res.Tenant.ID, resp.AccessToken)
	ops, _ := claims[tenant.OperatorClaim].([]any)
	if len(ops) != 2 || ops[0] != "acme" || ops[1] != "globex" {
		t.Fatalf("operator claim = %v (claims %v)", claims[tenant.OperatorClaim], claims)
	}
	// Only the access token carries it, and only for the operator audience.
	if resp.IdToken == nil {
		t.Fatal("no id token")
	}
	idc, _ := verifyToken(t, f.keys, res.Tenant.ID, *resp.IdToken)
	if _, ok := idc[tenant.OperatorClaim]; ok {
		t.Error("id token carries the operator claim")
	}
	resp, oerr = f.h.mintUserTokens(ctx, res, c, userTokens{user: user, lifetime: 3600e9, scopes: []string{"openid"}})
	if oerr != nil {
		t.Fatal(oerr)
	}
	if claims, _ := verifyToken(t, f.keys, res.Tenant.ID, resp.AccessToken); claims[tenant.OperatorClaim] != nil {
		t.Error("userinfo-only token carries the operator claim")
	}
}

func TestOperatorAudienceRefusesNonOperators(t *testing.T) {
	f, res, c, rs := operatorFixture(t)
	ctx := context.Background()
	user, _ := f.st.Users().Get(ctx, res.Tenant.ID, "auth0|plain")
	_, oerr := f.h.mintUserTokens(ctx, res, c, userTokens{user: user, rs: rs, lifetime: 3600e9})
	if oerr == nil || oerr.Code != "access_denied" {
		t.Fatalf("non-operator: %v", oerr)
	}
	// The same user may still sign in without the operator audience.
	if _, oerr := f.h.mintUserTokens(ctx, res, c, userTokens{user: user, lifetime: 3600e9, scopes: []string{"openid"}}); oerr != nil {
		t.Fatalf("no audience: %v", oerr)
	}
}

// A tenant other than the system tenant never mints the claim, even for
// an API that (against the seed's rules) uses the operator audience.
func TestOperatorClaimOnlyFromSystemTenant(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tn, _ := f.st.Tenants().GetByName(ctx, "acme")
	rs := &store.ResourceServer{TenantID: tn.ID, ID: "rs_fake", Identifier: tenant.OperatorAudience, Name: "Fake"}
	user := &store.User{TenantID: tn.ID, UserID: "auth0|x"}
	c, _ := f.st.Clients().Get(ctx, tn.ID, "code-spa")
	resp, oerr := f.h.mintUserTokens(ctx, tenant.Resolved{Tenant: tn, Host: "acme.example.test"}, c, userTokens{user: user, rs: rs, lifetime: 3600e9})
	if oerr != nil {
		t.Fatal(oerr)
	}
	claims, _ := verifyToken(t, f.keys, tn.ID, resp.AccessToken)
	if _, ok := claims[tenant.OperatorClaim]; ok || !slices.Contains([]string{tenant.OperatorAudience}, claims["aud"].(string)) {
		t.Errorf("claims = %v", claims)
	}
}

// Operator tokens are bound to the console: another client of the system
// tenant cannot obtain one, even for an operator.
func TestOperatorAudienceOnlyForConsole(t *testing.T) {
	f, res, c, rs := operatorFixture(t)
	ctx := context.Background()
	other := *c
	other.ClientID = "another-spa"
	user, _ := f.st.Users().Get(ctx, res.Tenant.ID, "auth0|op")
	_, oerr := f.h.mintUserTokens(ctx, res, &other, userTokens{user: user, rs: rs, lifetime: 3600e9})
	if oerr == nil || oerr.Code != "access_denied" {
		t.Fatalf("another client: %v", oerr)
	}
}

// The system tenant has no M2M Management API, not even on first use.
func TestClientCredentialsNoManagementAPIOnSystemTenant(t *testing.T) {
	f, res, _, _ := operatorFixture(t)
	ctx := context.Background()
	h, err := secrets.Hash("sys-secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.Clients().Create(ctx, &store.Client{TenantID: res.Tenant.ID, ClientID: "sys-m2m", AppType: store.AppTypeNonInteractive,
		TokenEndpointAuthMethod: store.AuthMethodClientSecretPost, GrantTypes: []string{"client_credentials"},
		Secrets: []store.ClientSecret{{Hash: h}}}); err != nil {
		t.Fatal(err)
	}
	aud := "https://admin.example.test/api/v2/"
	rec, body := f.call(t, true, tokenCall{host: "admin.example.test", form: cc("sys-m2m", "sys-secret", "audience", aud)})
	if rec.Code != http.StatusForbidden || body["error_description"] != "unknown audience" {
		t.Fatalf("system tenant: %d %v", rec.Code, body)
	}
	if _, err := f.st.ResourceServers().GetByIdentifier(ctx, res.Tenant.ID, aud); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("created on the system tenant: %v", err)
	}
}
