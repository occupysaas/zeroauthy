package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type organizationFixture struct {
	*fixture
	tid, uid, connID string
	org              *store.Organization
}

func newOrganizationFixture(t *testing.T) *organizationFixture {
	t.Helper()
	return organizationFixtureWith(t, newFixture(t))
}
func organizationFixtureWith(t *testing.T, f *fixture) *organizationFixture {
	t.Helper()
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	uid := f.aliceID(t)
	conn, err := f.st.Connections().GetByName(ctx, tid, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	org := &store.Organization{TenantID: tid, ID: "org_ABCDEFGHIJKLMNOP", Name: "acme-corp", DisplayName: "Acme", ThirdPartyClientAccess: "allow"}
	if err := f.st.Organizations().Create(ctx, org, []store.OrganizationConnection{{TenantID: tid, OrganizationID: org.ID, ConnectionID: conn.ID, ShowAsButton: true, AssignMembershipOnLogin: true}}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.Organizations().AddMembers(ctx, tid, org.ID, []string{uid}); err != nil {
		t.Fatal(err)
	}
	c, err := f.st.Clients().Get(ctx, tid, "rt-spa")
	if err != nil {
		t.Fatal(err)
	}
	c.OrganizationUsage = "allow"
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	return &organizationFixture{f, tid, uid, conn.ID, org}
}
func (f *organizationFixture) code(t *testing.T, orgID string) string {
	t.Helper()
	return f.codeWith(t, orgID, acmeAPI, f.connID)
}
func (f *organizationFixture) codeWith(t *testing.T, orgID, audience, connectionID string) string {
	t.Helper()
	if orgID == "" {
		connectionID = ""
	}
	raw := secrets.RandomString(43)
	ac := &store.AuthCode{TenantID: f.tid, CodeHash: secrets.HashToken(raw), ClientID: "rt-spa", RedirectURI: "https://app.acme.test/cb", UserID: f.uid, SessionID: "expired-session", Scopes: []string{"openid", "offline_access", "read:things", "write:things", "org:things", "other:things"}, Audience: audience, CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256", OrganizationID: orgID, OrganizationConnectionID: connectionID, AuthTime: fixedNow().Add(-time.Minute), ExpiresAt: fixedNow().Add(time.Minute), CreatedAt: fixedNow()}
	if err := f.st.AuthCodes().Create(context.Background(), ac); err != nil {
		t.Fatal(err)
	}
	return raw
}
func (f *organizationFixture) exchange(t *testing.T, orgID string) (int, map[string]any) {
	t.Helper()
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: codeForm(f.code(t, orgID), "rt-spa", "https://app.acme.test/cb", pkceVerifier)})
	return rec.Code, body
}
func (f *organizationFixture) names(t *testing.T, on bool) {
	t.Helper()
	tn, err := f.st.Tenants().Get(context.Background(), f.tid)
	if err != nil {
		t.Fatal(err)
	}
	if tn.SettingsExtra == nil {
		tn.SettingsExtra = map[string]any{}
	}
	tn.SettingsExtra["allow_organization_name_in_authentication_api"] = on
	if err := f.st.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
}
func (f *organizationFixture) role(t *testing.T, id, permission, orgID string) {
	t.Helper()
	ctx := context.Background()
	r := f.st.RBAC()
	if err := r.CreateRole(ctx, &store.Role{TenantID: f.tid, ID: id, Name: id}); err != nil {
		t.Fatal(err)
	}
	if err := r.ChangeRolePermissions(ctx, f.tid, id, true, []store.PermissionKey{{ResourceServerIdentifier: acmeAPI, PermissionName: permission}}); err != nil {
		t.Fatal(err)
	}
	var err error
	if orgID == "" {
		err = r.ChangeUserRoles(ctx, f.tid, f.uid, true, []string{id})
	} else {
		err = f.st.Organizations().ChangeMemberRoles(ctx, f.tid, orgID, f.uid, true, []string{id})
	}
	if err != nil {
		t.Fatal(err)
	}
}
func (f *organizationFixture) permissions(t *testing.T, dialect string) {
	t.Helper()
	ctx := context.Background()
	api, err := f.st.ResourceServers().GetByIdentifier(ctx, f.tid, acmeAPI)
	if err != nil {
		t.Fatal(err)
	}
	api.EnforcePolicies = true
	api.TokenDialect = dialect
	api.Scopes = append(api.Scopes, store.Scope{Value: "org:things"}, store.Scope{Value: "other:things"})
	if err := f.st.ResourceServers().Update(ctx, api); err != nil {
		t.Fatal(err)
	}
	if err := f.st.RBAC().ChangeUserPermissions(ctx, f.tid, f.uid, true, []store.PermissionKey{{ResourceServerIdentifier: acmeAPI, PermissionName: "read:things"}}); err != nil {
		t.Fatal(err)
	}
	f.role(t, "rol_tenant", "write:things", "")
	f.role(t, "rol_org", "org:things", f.org.ID)
	other := &store.Organization{TenantID: f.tid, ID: "org_QRSTUVWXYZabcdef", Name: "other", DisplayName: "Other"}
	if err := f.st.Organizations().Create(ctx, other, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.st.Organizations().AddMembers(ctx, f.tid, other.ID, []string{f.uid}); err != nil {
		t.Fatal(err)
	}
	f.role(t, "rol_other", "other:things", other.ID)
}
func TestOrganizationTokens(t *testing.T) {
	for _, names := range []bool{false, true} {
		for _, third := range []bool{false, true} {
			t.Run(fmt.Sprintf("names=%v/third=%v", names, third), func(t *testing.T) {
				f := newOrganizationFixture(t)
				f.names(t, names)
				ctx := context.Background()
				if err := f.st.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: f.tid, ID: "cg_org", ClientID: "rt-spa", Audience: acmeAPI, SubjectType: store.SubjectTypeUser, Scopes: []string{"read:things", "write:things"}}); err != nil {
					t.Fatal(err)
				}
				c, err := f.st.Clients().Get(ctx, f.tid, "rt-spa")
				if err != nil {
					t.Fatal(err)
				}
				c.IsFirstParty = !third
				c.ThirdPartySecurityMode = store.SecurityModePermissive
				if err := f.st.Clients().Update(ctx, c); err != nil {
					t.Fatal(err)
				}
				status, body := f.exchange(t, f.org.ID)
				if status != 200 {
					t.Fatalf("status=%d error=%v", status, body["error"])
				}
				for _, key := range []string{"access_token", "id_token"} {
					claims, _ := verifyToken(t, f.keys, f.tid, body[key].(string))
					if claims["org_id"] != f.org.ID {
						t.Fatalf("%s org_id=%v", key, claims["org_id"])
					}
					want := any(nil)
					if names {
						want = "acme-corp"
					}
					if claims["org_name"] != want {
						t.Fatalf("%s org_name=%v want=%v", key, claims["org_name"], want)
					}
				}
				if rt := f.storedRT(t, body["refresh_token"].(string)); rt.OrganizationID != f.org.ID || rt.OrganizationConnectionID != f.connID {
					t.Fatal("refresh lost organization")
				}
			})
		}
	}
	for _, dialect := range []string{"access_token", "access_token_authz", "rfc9068_profile", "rfc9068_profile_authz"} {
		t.Run(dialect, func(t *testing.T) {
			f := newOrganizationFixture(t)
			f.permissions(t, dialect)
			status, body := f.exchange(t, f.org.ID)
			if status != 200 || body["scope"] != "openid offline_access read:things write:things org:things" {
				t.Fatalf("status=%d scope=%v error=%v", status, body["scope"], body["error"])
			}
			at, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
			if strings.HasSuffix(dialect, "_authz") {
				if !reflect.DeepEqual(at["permissions"], []any{"org:things", "read:things", "write:things"}) {
					t.Fatalf("permissions=%v", at["permissions"])
				}
			} else if at["permissions"] != nil {
				t.Fatal("unexpected permissions claim")
			}
			status, body = f.exchange(t, "")
			if status != 200 || body["scope"] != "openid offline_access read:things write:things" {
				t.Fatalf("individual status=%d scope=%v", status, body["scope"])
			}
			at, _ = verifyToken(t, f.keys, f.tid, body["access_token"].(string))
			if at["org_id"] != nil || at["org_name"] != nil {
				t.Fatal("individual carries organization")
			}
		})
	}
	t.Run("third party blocked at exchange", func(t *testing.T) {
		f := newOrganizationFixture(t)
		ctx := context.Background()
		c, _ := f.st.Clients().Get(ctx, f.tid, "rt-spa")
		c.IsFirstParty = false
		c.ThirdPartySecurityMode = store.SecurityModePermissive
		if err := f.st.Clients().Update(ctx, c); err != nil {
			t.Fatal(err)
		}
		f.org.ThirdPartyClientAccess = "block"
		if err := f.st.Organizations().Update(ctx, f.org); err != nil {
			t.Fatal(err)
		}
		status, body := f.exchange(t, f.org.ID)
		if status != 400 || body["error"] != "invalid_grant" || body["access_token"] != nil {
			t.Fatalf("status=%d error=%v", status, body["error"])
		}
	})
}
func TestOrganizationRefresh(t *testing.T) {
	t.Run("renamed organization permissions and family", func(t *testing.T) {
		f := newOrganizationFixture(t)
		f.names(t, true)
		f.permissions(t, "access_token_authz")
		status, body := f.exchange(t, f.org.ID)
		if status != 200 {
			t.Fatalf("status=%d error=%v", status, body["error"])
		}
		raw := body["refresh_token"].(string)
		family := f.storedRT(t, raw).FamilyID
		f.org.Name = "renamed"
		if err := f.st.Organizations().Update(context.Background(), f.org); err != nil {
			t.Fatal(err)
		}
		if err := f.st.Organizations().ChangeMemberRoles(context.Background(), f.tid, f.org.ID, f.uid, false, []string{"rol_org"}); err != nil {
			t.Fatal(err)
		}
		status, body = f.refresh(t, refreshForm("rt-spa", raw))
		if status != 200 || body["scope"] != "openid offline_access read:things write:things" {
			t.Fatalf("status=%d scope=%v error=%v", status, body["scope"], body["error"])
		}
		for _, key := range []string{"access_token", "id_token"} {
			claims, _ := verifyToken(t, f.keys, f.tid, body[key].(string))
			if claims["org_id"] != f.org.ID || claims["org_name"] != "renamed" {
				t.Fatalf("%s organization=%v/%v", key, claims["org_id"], claims["org_name"])
			}
		}
		next := f.storedRT(t, body["refresh_token"].(string))
		if next.OrganizationID != f.org.ID || next.OrganizationConnectionID != f.connID || next.FamilyID != family {
			t.Fatal("rotation lost organization/family")
		}
	})
	for _, change := range []string{"member removed", "organization deleted", "connection disabled", "client deny", "individual client require"} {
		t.Run(change, func(t *testing.T) {
			f := newOrganizationFixture(t)
			orgID := f.org.ID
			if change == "individual client require" {
				orgID = ""
			}
			status, body := f.exchange(t, orgID)
			if status != 200 {
				t.Fatalf("status=%d error=%v", status, body["error"])
			}
			raw := body["refresh_token"].(string)
			ctx := context.Background()
			var err error
			switch change {
			case "member removed":
				err = f.st.Organizations().RemoveMembers(ctx, f.tid, f.org.ID, []string{f.uid})
			case "organization deleted":
				err = f.st.Organizations().Delete(ctx, f.tid, f.org.ID)
			case "connection disabled":
				err = f.st.Organizations().DeleteConnection(ctx, f.tid, f.org.ID, f.connID)
			default:
				c, e := f.st.Clients().Get(ctx, f.tid, "rt-spa")
				if e != nil {
					t.Fatal(e)
				}
				c.OrganizationUsage = "deny"
				if orgID == "" {
					c.OrganizationUsage = "require"
				}
				err = f.st.Clients().Update(ctx, c)
			}
			if err != nil {
				t.Fatal(err)
			}
			status, body = f.refresh(t, refreshForm("rt-spa", raw))
			if status != 400 || body["error"] != "invalid_grant" || body["access_token"] != nil || body["id_token"] != nil || body["refresh_token"] != nil {
				t.Fatalf("status=%d error=%v token issued=%v", status, body["error"], body["access_token"] != nil)
			}
			rt := f.storedRT(t, raw)
			if rt.RevokedAt != nil || rt.RotatedAt != nil {
				t.Fatal("rejected organization refresh changed original token")
			}
			if change == "member removed" {
				member, e := f.st.Organizations().IsMember(ctx, f.tid, f.org.ID, f.uid)
				if e != nil || member {
					t.Fatal("refresh auto-enrolled removed member")
				}
				if err := f.st.Organizations().AddMembers(ctx, f.tid, f.org.ID, []string{f.uid}); err != nil {
					t.Fatal(err)
				}
				status, body = f.refresh(t, refreshForm("rt-spa", raw))
				if status != 200 {
					t.Fatalf("restored membership status=%d error=%v", status, body["error"])
				}
				claims, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
				if claims["org_id"] != f.org.ID {
					t.Fatal("restored grant downgraded to individual")
				}

			}
		})
	}
}

// A real Action removes an organization assignment through an external call.
// This flow keeps its snapshot; the following refresh observes the removal.
// The same boundary holds at authorize and refresh, and custom claims cannot
// replace the trusted organization on either token.
func TestOrganizationActionsPermissionSnapshot(t *testing.T) {
	af := newActionsFixture(t)
	f := organizationFixtureWith(t, af.fixture)
	f.names(t, true)
	f.permissions(t, "access_token_authz")
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := f.st.Organizations().ChangeMemberRoles(r.Context(), f.tid, f.org.ID, f.uid, false, []string{"rol_org"}); err != nil {
			http.Error(w, "assignment", 500)
			return
		}
		w.WriteHeader(204)
	}))
	defer relay.Close()
	af.actions.PostLogin(t, f.tid, "org-snapshot", fmt.Sprintf(`exports.onExecutePostLogin=async(event,api)=>{const r=await fetch(%q);if(!r.ok)throw Error('assignment');api.idToken.setCustomClaim('org_id','forged');api.accessToken.setCustomClaim('org_name','forged');};`, relay.URL))
	q := url.Values{"client_id": {"rt-spa"}, "redirect_uri": {"https://rt.acme.test/cb"}, "response_type": {"code"}, "scope": {"openid offline_access read:things write:things org:things other:things"}, "audience": {acmeAPI}, "organization": {f.org.ID}, "code_challenge": {pkceChallenge}, "code_challenge_method": {"S256"}}
	r := httptest.NewRequest("GET", "https://acme.example.test/authorize?"+q.Encode(), nil)
	r.AddCookie(af.sessionCookie(t))
	rec := httptest.NewRecorder()
	tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(af.az.Authorize)).ServeHTTP(rec, r)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != 302 || loc.Query().Get("code") == "" {
		t.Fatalf("authorize status=%d location=%s", rec.Code, rec.Header().Get("Location"))
	}
	code := loc.Query().Get("code")
	stored, err := f.st.AuthCodes().Get(context.Background(), f.tid, secrets.HashToken(code))
	if err != nil {
		t.Fatal(err)
	}
	if stored.OrganizationID != f.org.ID || stored.OrganizationConnectionID != f.connID {
		t.Fatal("code lost organization/connection binding")
	}
	status, body := af.token(t, codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier))
	if status != 200 {
		t.Fatalf("exchange status=%d error=%v", status, body["error"])
	}
	assert := func(body map[string]any, want string) {
		t.Helper()
		if body["scope"] != want {
			t.Fatalf("scope=%v want=%s", body["scope"], want)
		}
		for _, key := range []string{"access_token", "id_token"} {
			claims, _ := verifyToken(t, f.keys, f.tid, body[key].(string))
			if claims["org_id"] != f.org.ID || claims["org_name"] != "acme-corp" {
				t.Fatalf("%s organization claims=%v/%v", key, claims["org_id"], claims["org_name"])
			}
		}
	}
	assert(body, "openid offline_access read:things write:things org:things")
	raw := body["refresh_token"].(string)
	if err := f.st.Organizations().ChangeMemberRoles(context.Background(), f.tid, f.org.ID, f.uid, true, []string{"rol_org"}); err != nil {
		t.Fatal(err)
	}
	status, body = f.refresh(t, refreshForm("rt-spa", raw))
	if status != 200 {
		t.Fatalf("refresh status=%d error=%v", status, body["error"])
	}
	assert(body, "openid offline_access read:things write:things org:things")
	raw = body["refresh_token"].(string)
	status, body = f.refresh(t, refreshForm("rt-spa", raw))
	if status != 200 {
		t.Fatalf("refresh status=%d error=%v", status, body["error"])
	}
	assert(body, "openid offline_access read:things write:things")
}

func TestOrganizationRevokedAtMint(t *testing.T) {
	for _, grant := range []string{"code", "refresh"} {
		t.Run(grant, func(t *testing.T) {
			f := newOrganizationFixture(t)
			var raw string
			if grant == "refresh" {
				status, body := f.exchange(t, f.org.ID)
				if status != 200 {
					t.Fatal(status, body["error"])
				}
				raw = body["refresh_token"].(string)
			}
			changed := false
			f.h.Minter.Now = func() time.Time {
				if !changed {
					changed = true
					if err := f.st.Organizations().RemoveMembers(context.Background(), f.tid, f.org.ID, []string{f.uid}); err != nil {
						t.Fatal(err)
					}
				}
				return fixedNow()
			}
			var status int
			var body map[string]any
			if grant == "code" {
				status, body = f.exchange(t, f.org.ID)
			} else {
				status, body = f.refresh(t, refreshForm("rt-spa", raw))
			}
			if !changed {
				t.Fatal("membership change did not reach mint boundary")
			}
			if status != 400 || body["error"] != "invalid_grant" || body["access_token"] != nil {
				t.Fatalf("status=%d error=%v issued=%v", status, body["error"], body["access_token"] != nil)
			}
			if raw != "" {
				rt := f.storedRT(t, raw)
				if rt.RevokedAt != nil || rt.RotatedAt != nil {
					t.Fatal("failed refresh changed family")
				}
			}
		})
	}
}

// A linked user's primary identity is unrelated to the authenticated connection
// pinned on the family. The browser session may already have been swept.
func TestOrganizationOriginalConnection(t *testing.T) {
	f := newOrganizationFixture(t)
	ctx := context.Background()
	alternative := &store.Connection{TenantID: f.tid, ID: "con_alternative", Name: "Alternative", Strategy: store.StrategyDatabase, EnabledClients: []string{"rt-spa"}}
	if err := f.st.Connections().Create(ctx, alternative); err != nil {
		t.Fatal(err)
	}
	if err := f.st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: f.tid, OrganizationID: f.org.ID, ConnectionID: alternative.ID, ShowAsButton: true}, true); err != nil {
		t.Fatal(err)
	}
	user, err := f.st.Users().Get(ctx, f.tid, f.uid)
	if err != nil {
		t.Fatal(err)
	}
	user.Identities = append([]store.Identity{{Connection: alternative.Name, Provider: "auth0", UserID: "linked"}}, user.Identities...)
	if err := f.st.Users().Update(ctx, user); err != nil {
		t.Fatal(err)
	}
	status, body := f.exchange(t, f.org.ID)
	if status != 200 {
		t.Fatalf("exchange status=%d error=%v", status, body["error"])
	}
	raw := body["refresh_token"].(string)
	env := actionstest.New(t, f.st, f.wrapper)
	f.h.Actions = env.Engine
	env.PostLogin(t, f.tid, "original-connection", `exports.onExecutePostLogin=async(event,api)=>{api.accessToken.setCustomClaim("https://example.test/connection",event.connection.id);};`)
	status, body = f.refresh(t, refreshForm("rt-spa", raw))
	if status != 200 {
		t.Fatalf("refresh status=%d error=%v", status, body["error"])
	}
	at, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
	if at["https://example.test/connection"] != f.connID {
		t.Fatalf("Action connection=%v want original %s", at["https://example.test/connection"], f.connID)
	}
	raw = body["refresh_token"].(string)
	if err := f.st.Organizations().DeleteConnection(ctx, f.tid, f.org.ID, f.connID); err != nil {
		t.Fatal(err)
	}
	status, body = f.refresh(t, refreshForm("rt-spa", raw))
	if status != 400 || body["error"] != "invalid_grant" || body["access_token"] != nil {
		t.Fatalf("disabled original connection status=%d error=%v", status, body["error"])
	}
	if rt := f.storedRT(t, raw); rt.RevokedAt != nil || rt.RotatedAt != nil {
		t.Fatal("connection refusal changed refresh token")
	}
}

func TestOrganizationUserinfoAudienceToken(t *testing.T) {
	f := newOrganizationFixture(t)
	f.names(t, true)
	code := f.codeWith(t, f.org.ID, "", f.connID)
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: codeForm(code, "rt-spa", "https://app.acme.test/cb", pkceVerifier)})
	if rec.Code != 200 {
		t.Fatalf("status=%d error=%v", rec.Code, body["error"])
	}
	at, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
	if at["aud"] != "https://acme.example.test/userinfo" || at["org_id"] != f.org.ID || at["org_name"] != "acme-corp" {
		t.Fatalf("userinfo-audience claims=%v/%v/%v", at["aud"], at["org_id"], at["org_name"])
	}
}

func TestOrganizationCodeRevalidation(t *testing.T) {
	for _, change := range []string{"member", "organization", "connection", "client", "missing original connection"} {
		t.Run(change, func(t *testing.T) {
			f := newOrganizationFixture(t)
			ctx := context.Background()
			connectionID := f.connID
			if change == "missing original connection" {
				connectionID = ""
			}
			code := f.codeWith(t, f.org.ID, acmeAPI, connectionID)
			var err error
			switch change {
			case "member":
				err = f.st.Organizations().RemoveMembers(ctx, f.tid, f.org.ID, []string{f.uid})
			case "organization":
				err = f.st.Organizations().Delete(ctx, f.tid, f.org.ID)
			case "connection":
				err = f.st.Organizations().DeleteConnection(ctx, f.tid, f.org.ID, f.connID)
			case "client":
				c, e := f.st.Clients().Get(ctx, f.tid, "rt-spa")
				if e != nil {
					t.Fatal(e)
				}
				c.OrganizationUsage = "deny"
				err = f.st.Clients().Update(ctx, c)
			}
			if err != nil {
				t.Fatal(err)
			}
			rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: codeForm(code, "rt-spa", "https://app.acme.test/cb", pkceVerifier)})
			if rec.Code != 400 || body["error"] != "invalid_grant" || body["access_token"] != nil {
				t.Fatalf("status=%d error=%v issued=%v", rec.Code, body["error"], body["access_token"] != nil)
			}
		})
	}
}
