package oauth

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestRBACUserGrants(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	user, err := f.st.Users().FindByLogin(ctx, tid, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	api, err := f.st.ResourceServers().GetByIdentifier(ctx, tid, acmeAPI)
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.st.Clients().Get(ctx, tid, "rt-spa")
	if err != nil {
		t.Fatal(err)
	}
	tn, err := f.st.Tenants().Get(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	key := store.PermissionKey{ResourceServerIdentifier: acmeAPI, PermissionName: "read:things"}
	if err := f.st.RBAC().ChangeUserPermissions(ctx, tid, user.UserID, true, []store.PermissionKey{key}); err != nil {
		t.Fatal(err)
	}
	for _, dialect := range []string{"access_token", "access_token_authz", "rfc9068_profile", "rfc9068_profile_authz"} {
		for _, on := range []bool{true, false} {
			api.EnforcePolicies = on
			api.TokenDialect = dialect
			if err := f.st.ResourceServers().Update(ctx, api); err != nil {
				t.Fatal(err)
			}
			resp, _, e := f.h.mintUserTokens(ctx, tenant.Resolved{Tenant: tn, Host: "acme.example.test"}, c, userTokens{user: user, rs: api, scopes: []string{"openid", "read:things", "write:things"}, lifetime: DefaultAccessTokenLifetime})
			if e != nil {
				t.Fatal(e)
			}
			want := "openid read:things"
			if !on {
				want += " write:things"
			}
			if resp.Scope == nil || *resp.Scope != want {
				t.Fatalf("%s RBAC=%v scope=%v want %s", dialect, on, resp.Scope, want)
			}
			claims, _ := verifyToken(t, f.keys, tid, resp.AccessToken)
			p, exists := claims["permissions"]
			if exists != (on && strings.HasSuffix(dialect, "_authz")) {
				t.Fatalf("%s permissions %v", dialect, p)
			}
			if exists && len(p.([]any)) != 1 {
				t.Fatal(p)
			}
		}
	}
}
func TestRBACRevocation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	user, _ := f.st.Users().FindByLogin(ctx, tid, "Username-Password-Authentication", "alice@acme.test")
	api, _ := f.st.ResourceServers().GetByIdentifier(ctx, tid, acmeAPI)
	api.EnforcePolicies = true
	api.TokenDialect = "access_token_authz"
	if err := f.st.ResourceServers().Update(ctx, api); err != nil {
		t.Fatal(err)
	}
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access", "read:things", "write:things"}, acmeAPI)
	for _, step := range []struct {
		add   bool
		scope string
	}{{true, "openid offline_access read:things"}, {false, "openid offline_access"}, {true, "openid offline_access read:things"}} {
		if err := f.st.RBAC().ChangeUserPermissions(ctx, tid, user.UserID, step.add, []store.PermissionKey{{ResourceServerIdentifier: acmeAPI, PermissionName: "read:things"}}); err != nil {
			t.Fatal(err)
		}
		code, body := f.refresh(t, refreshForm("rt-spa", raw))
		if code != 200 || body["scope"] != step.scope {
			t.Fatalf("refresh %d %v", code, body)
		}
		raw = body["refresh_token"].(string)
	}
	if err := f.st.RBAC().ChangeUserPermissions(ctx, tid, user.UserID, true, []store.PermissionKey{{ResourceServerIdentifier: acmeAPI, PermissionName: "write:things"}}); err != nil {
		t.Fatal(err)
	}
	code, body := f.refresh(t, refreshForm("rt-spa", raw))
	if code != 200 || body["scope"] != "openid offline_access read:things write:things" {
		t.Fatalf("ceiling %d %v", code, body)
	}
}

// The token endpoint must re-evaluate assignments after authorization, across
// every grant, rather than trusting the scopes recorded on a code or approval.
func TestRBACGrantEndpoints(t *testing.T) {
	for _, dialect := range []string{"access_token", "access_token_authz", "rfc9068_profile", "rfc9068_profile_authz"} {
		t.Run(dialect, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			tid := f.tenantID(t, "acme")
			uid := f.aliceID(t)
			api, _ := f.st.ResourceServers().GetByIdentifier(ctx, tid, acmeAPI)
			api.EnforcePolicies = true
			api.TokenDialect = dialect
			if err := f.st.ResourceServers().Update(ctx, api); err != nil {
				t.Fatal(err)
			}
			if err := f.st.RBAC().ChangeUserPermissions(ctx, tid, uid, true, []store.PermissionKey{{ResourceServerIdentifier: acmeAPI, PermissionName: "read:things"}}); err != nil {
				t.Fatal(err)
			}
			code := f.issueCode(t, "code-spa", "https://app.acme.test/cb", acmeAPI, []string{"openid", "read:things", "write:things"}, pkceChallenge)
			device, _ := f.newDeviceCode(t, "dev", store.DeviceCodeApproved, uid, []string{"openid", "read:things", "write:things"})
			// Remove after the code and device approval have already been persisted.
			if err := f.st.RBAC().ChangeUserPermissions(ctx, tid, uid, false, []store.PermissionKey{{ResourceServerIdentifier: acmeAPI, PermissionName: "read:things"}}); err != nil {
				t.Fatal(err)
			}
			cases := []struct {
				name string
				form url.Values
			}{
				{"code", codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)},
				{"device", deviceForm("dev", device)},
				{"password", pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", "openid read:things write:things")},
			}
			realm := pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", "openid read:things write:things")
			realm.Set("grant_type", GrantPasswordRealm)
			realm.Set("realm", "Username-Password-Authentication")
			cases = append(cases, struct {
				name string
				form url.Values
			}{"realm", realm})
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: tc.form})
					if rec.Code != 200 || body["scope"] != "openid" {
						t.Fatalf("%s status=%d scope=%v error=%v", tc.name, rec.Code, body["scope"], body["error"])
					}
					at, _ := verifyToken(t, f.keys, tid, body["access_token"].(string))
					if p, ok := at["permissions"]; ok && len(p.([]any)) != 0 {
						t.Fatal("revoked permission survived")
					}
					id, _ := verifyToken(t, f.keys, tid, body["id_token"].(string))
					if id["permissions"] != nil {
						t.Fatal("permissions leaked into ID token")
					}
				})
			}
			// Machine tokens keep the client grant even though the user has no rights.
			rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", acmeAPI, "scope", "read:things")})
			if rec.Code != 200 || body["scope"] != "read:things" {
				t.Fatalf("M2M status=%d error=%v", rec.Code, body["error"])
			}
			at, _ := verifyToken(t, f.keys, tid, body["access_token"].(string))
			if at["permissions"] != nil {
				t.Fatal("M2M user permission claim")
			}
			if strings.HasPrefix(dialect, "rfc9068") && at["client_id"] != "m2m" {
				t.Fatal("M2M profile lost")
			}
		})
	}
}

type failingRBACStore struct{ store.Store }

func (s failingRBACStore) RBAC() store.RBAC { return store.UnimplementedRBAC{} }
func TestRBACIsolationAndFailure(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid", "read:things"}, acmeAPI)
	f.h.Store = failingRBACStore{f.st}
	code, body := f.refresh(t, refreshForm("rt-spa", raw))
	if code != 500 || body["error"] != "server_error" || body["access_token"] != nil {
		t.Fatalf("failed snapshot status=%d error=%v", code, body["error"])
	}
	_ = ctx
	_ = tid
}

func TestRBACRefreshCeilingFromGrant(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	uid := f.aliceID(t)
	api, _ := f.st.ResourceServers().GetByIdentifier(ctx, tid, acmeAPI)
	api.EnforcePolicies = true
	api.TokenDialect = "access_token_authz"
	api.Scopes = append(api.Scopes, store.Scope{Value: "delete:things"})
	if err := f.st.ResourceServers().Update(ctx, api); err != nil {
		t.Fatal(err)
	}
	key := store.PermissionKey{ResourceServerIdentifier: acmeAPI, PermissionName: "read:things"}
	if err := f.st.RBAC().ChangeUserPermissions(ctx, tid, uid, true, []store.PermissionKey{key}); err != nil {
		t.Fatal(err)
	}
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", "openid offline_access read:things write:things")})
	if rec.Code != 200 || body["scope"] != "openid offline_access read:things" {
		t.Fatalf("initial status=%d scope=%v", rec.Code, body["scope"])
	}
	raw := body["refresh_token"].(string)
	rt := f.storedRT(t, raw)
	if !slices.Contains(rt.Scopes, "write:things") {
		t.Fatal("pre-RBAC scope ceiling lost")
	}
	if err := f.st.RBAC().ChangeUserPermissions(ctx, tid, uid, true, []store.PermissionKey{{ResourceServerIdentifier: acmeAPI, PermissionName: "write:things"}, {ResourceServerIdentifier: acmeAPI, PermissionName: "delete:things"}}); err != nil {
		t.Fatal(err)
	}
	code, body := f.refresh(t, refreshForm("ropg", raw, "client_secret", "ropg-secret"))
	if code != 200 || body["scope"] != "openid offline_access read:things write:things" {
		t.Fatalf("refresh status=%d scope=%v error=%v", code, body["scope"], body["error"])
	}
	claims, _ := verifyToken(t, f.keys, tid, body["access_token"].(string))
	if len(claims["permissions"].([]any)) != 3 {
		t.Fatal("unrequested assignment missing from permissions")
	}
}

type changingRBACStore struct {
	store.Store
	beforeSnapshot func()
}
type changingRBAC struct {
	store.RBAC
	beforeSnapshot func()
}

func (s changingRBACStore) RBAC() store.RBAC { return changingRBAC{s.Store.RBAC(), s.beforeSnapshot} }
func (r changingRBAC) Snapshot(ctx context.Context, tid, uid, aud string) (*store.AuthorizationSnapshot, error) {
	r.beforeSnapshot()
	return r.RBAC.Snapshot(ctx, tid, uid, aud)
}
func TestRBACCurrentOfflineAccessSetting(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	code := f.issueCode(t, "rt-spa", "https://app.acme.test/cb", acmeAPI, []string{"openid", "offline_access", "read:things"}, pkceChallenge)
	f.h.Store = changingRBACStore{f.st, func() {
		api, err := f.st.ResourceServers().GetByIdentifier(ctx, tid, acmeAPI)
		if err != nil {
			t.Fatal(err)
		}
		api.AllowOfflineAccess = false
		if err := f.st.ResourceServers().Update(ctx, api); err != nil {
			t.Fatal(err)
		}
	}}
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: codeForm(code, "rt-spa", "https://app.acme.test/cb", pkceVerifier)})
	if rec.Code != 200 {
		t.Fatalf("status=%d error=%v", rec.Code, body["error"])
	}
	if body["refresh_token"] != nil {
		t.Fatal("refresh token issued after current API disabled offline access")
	}
}

func TestRBACEmptyScopeResponse(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	api, _ := f.st.ResourceServers().GetByIdentifier(ctx, tid, acmeAPI)
	api.EnforcePolicies = true
	if err := f.st.ResourceServers().Update(ctx, api); err != nil {
		t.Fatal(err)
	}
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", "read:things")})
	if rec.Code != 200 {
		t.Fatalf("status=%d error=%v", rec.Code, body["error"])
	}
	if scope, present := body["scope"]; !present || scope != "" {
		t.Fatalf("empty granted scope must be explicit, got %v present=%v", scope, present)
	}
}
