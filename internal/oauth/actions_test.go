package oauth

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const acmeUserScopes = "openid profile offline_access read:things"

func TestActionsFrozenPermissionsRespectCurrentAPIDefinition(t *testing.T) {
	f := newActionsFixture(t)
	ctx := context.Background()
	f.setRBAC(t, true)
	writePermission := []store.PermissionKey{{ResourceServerIdentifier: acmeAPI, PermissionName: "write:things"}}
	if err := f.st.RBAC().ChangeUserPermissions(ctx, f.tid, f.aliceID(t), true, writePermission); err != nil {
		t.Fatal(err)
	}
	api, err := f.st.ResourceServers().GetByIdentifier(ctx, f.tid, acmeAPI)
	if err != nil {
		t.Fatal(err)
	}
	api.TokenDialect = "access_token_authz"
	if err := f.st.ResourceServers().Update(ctx, api); err != nil {
		t.Fatal(err)
	}
	f.actions.PostLogin(t, f.tid, "snapshot-only", `exports.onExecutePostLogin=async()=>{};`)
	code := f.authorize(t, "rt-spa", "https://rt.acme.test/cb", acmeUserScopes)
	// Assignment changes stay frozen; API definition changes still apply.
	if err := f.st.RBAC().ChangeUserPermissions(ctx, f.tid, f.aliceID(t), false, writePermission); err != nil {
		t.Fatal(err)
	}
	// The assignment existed when the flow ran, but the API no longer defines it.
	api.Scopes = []store.Scope{{Value: "write:things"}}
	if err := f.st.ResourceServers().Update(ctx, api); err != nil {
		t.Fatal(err)
	}
	status, body := f.token(t, codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier))
	if status != 200 {
		t.Fatalf("exchange %d %v", status, body)
	}
	claims, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
	if slices.Contains(strings.Fields(body["scope"].(string)), "read:things") {
		t.Fatalf("removed API scope survived: %v", body["scope"])
	}
	if p := claims["permissions"].([]any); len(p) != 1 || p[0] != "write:things" {
		t.Fatalf("want frozen write assignment without removed read API permission: %v", p)
	}
}

// A Management API side effect during an Action belongs to the next issuance.
// Exercise both immediate tokens and effects sealed onto an authorization code.
func TestActionsRBACSnapshotBeforeExternalAssignment(t *testing.T) {
	for _, grant := range []string{"password", "code", "device", "refresh"} {
		t.Run(grant, func(t *testing.T) {
			f := newActionsFixture(t)
			ctx := context.Background()
			api, _ := f.st.ResourceServers().GetByIdentifier(ctx, f.tid, acmeAPI)
			api.EnforcePolicies, api.TokenDialect = true, "access_token_authz"
			if err := f.st.ResourceServers().Update(ctx, api); err != nil {
				t.Fatal(err)
			}
			var refresh string
			if grant == "refresh" {
				status, body := f.token(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", acmeUserScopes))
				if status != 200 {
					t.Fatal(body)
				}
				refresh = body["refresh_token"].(string)
			}
			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := f.st.RBAC().ChangeUserPermissions(r.Context(), f.tid, f.aliceID(t), true, []store.PermissionKey{{ResourceServerIdentifier: acmeAPI, PermissionName: "read:things"}})
				if err != nil {
					http.Error(w, "assignment", 500)
					return
				}
				w.WriteHeader(204)
			}))
			defer relay.Close()
			f.actions.PostLogin(t, f.tid, "external-assignment", fmt.Sprintf(`exports.onExecutePostLogin=async()=>{const r=await fetch(%q);if(!r.ok)throw Error('assignment');};`, relay.URL))
			for issuance := 0; issuance < 2; issuance++ {
				form := pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", acmeUserScopes)
				switch grant {
				case "code":
					form = codeForm(f.authorize(t, "rt-spa", "https://rt.acme.test/cb", acmeUserScopes), "rt-spa", "https://rt.acme.test/cb", pkceVerifier)
				case "device":
					form = deviceForm("dev", f.approveDevice(t, acmeUserScopes))
				case "refresh":
					form = refreshForm("ropg", refresh, "client_secret", "ropg-secret")
				}
				status, body := f.token(t, form)
				if status != 200 {
					t.Fatalf("issuance %d: %d %v", issuance, status, body)
				}
				claims, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
				permissions := claims["permissions"].([]any)
				if len(permissions) != issuance {
					t.Fatalf("issuance %d permissions=%v; current flow must keep its pre-Action snapshot", issuance, permissions)
				}
				if grant == "refresh" {
					if raw, ok := body["refresh_token"].(string); ok {
						refresh = raw
					}
				}
			}
		})
	}
}

// actionsFixture is the token fixture with a real Actions engine, and the
// /authorize handlers for the flows whose post-login flow runs there.
type actionsFixture struct {
	*fixture
	actions *actionstest.Env
	az      *authz.Handlers
	tid     string
}

func newActionsFixture(t *testing.T) *actionsFixture {
	t.Helper()
	f := newFixture(t)
	env := actionstest.New(t, f.st, f.wrapper)
	f.h.Actions = env.Engine
	az := &authz.Handlers{Store: f.st, Sessions: &session.Manager{Store: f.st, Now: fixedNow}, Now: fixedNow,
		Actions: env.Engine, Wrapper: f.wrapper}
	af := &actionsFixture{fixture: f, actions: env, az: az, tid: f.tenantID(t, "acme")}
	// The device client logs in through the default directory too.
	ctx := context.Background()
	conn, err := f.st.Connections().GetByName(ctx, af.tid, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	conn.EnabledClients = append(conn.EnabledClients, "dev")
	if err := f.st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	return af
}

func (f *actionsFixture) sessionCookie(t *testing.T) *http.Cookie {
	t.Helper()
	tn, err := f.st.Tenants().Get(context.Background(), f.tid)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if _, err := f.az.Sessions.Start(context.Background(), rec, httptest.NewRequest("GET", "/", nil), tn, f.aliceID(t),
		"Username-Password-Authentication", fixedNow()); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()[0]
}

// authorize runs /authorize for alice with a session and returns the code.
func (f *actionsFixture) authorize(t *testing.T, clientID, redirectURI, scope string) string {
	t.Helper()
	q := url.Values{"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"}, "scope": {scope},
		"audience": {acmeAPI}, "state": {"st"}, "code_challenge": {pkceChallenge}, "code_challenge_method": {"S256"}}
	r := httptest.NewRequest("GET", "https://acme.example.test/authorize?"+q.Encode(), nil)
	r.AddCookie(f.sessionCookie(t))
	rec := httptest.NewRecorder()
	tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.az.Authorize)).ServeHTTP(rec, r)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("authorize: %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	return loc.Query().Get("code")
}

// approveDevice creates a device code for scope and approves it in the
// browser with a session; it returns the device_code.
func (f *actionsFixture) approveDevice(t *testing.T, scope string) string {
	t.Helper()
	raw := secrets.RandomString(24)
	hash := secrets.HashToken(raw)
	dc := &store.DeviceCode{TenantID: f.tid, DeviceCodeHash: hash, UserCodeHash: "uc-" + hash, ClientID: "dev",
		Scopes: strings.Fields(scope), Audience: acmeAPI, Status: store.DeviceCodePending,
		ExpiresAt: fixedNow().Add(DeviceCodeLifetime), CreatedAt: fixedNow()}
	if err := f.st.DeviceCodes().Create(context.Background(), dc); err != nil {
		t.Fatal(err)
	}
	tn, _ := f.st.Tenants().Get(context.Background(), f.tid)
	r := httptest.NewRequest("POST", "https://acme.example.test/activate", nil)
	r.AddCookie(f.sessionCookie(t))
	rec := httptest.NewRecorder()
	f.az.ContinueDevice(rec, r, tenant.Resolved{Tenant: tn, Host: "acme.example.test"}, dc, "")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/device/success" {
		t.Fatalf("approve: %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	return raw
}

func (f *actionsFixture) token(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: form})
	return rec.Code, body
}

func (f *actionsFixture) setRBAC(t *testing.T, on bool) {
	t.Helper()
	ctx := context.Background()
	api, err := f.st.ResourceServers().GetByIdentifier(ctx, f.tid, acmeAPI)
	if err != nil {
		t.Fatal(err)
	}
	api.EnforcePolicies = on
	if err := f.st.ResourceServers().Update(ctx, api); err != nil {
		t.Fatal(err)
	}
	if err := f.st.RBAC().ChangeUserPermissions(ctx, f.tid, f.aliceID(t), true,
		[]store.PermissionKey{{ResourceServerIdentifier: acmeAPI, PermissionName: "read:things"}}); err != nil {
		t.Fatal(err)
	}
}

const tokenEffectsAction = `exports.onExecutePostLogin = async (event, api) => {
  api.accessToken.setCustomClaim("https://acme.test/protocol", event.transaction.protocol);
  api.accessToken.setCustomClaim("https://acme.test/can_redirect", api.redirect.canRedirect());
  api.accessToken.setCustomClaim("https://acme.test/body", Object.keys(event.request.body).sort().join(","));
  api.accessToken.setCustomClaim("sub", "forged");
  api.accessToken.setCustomClaim("https://auth0.com/x", "refused");
  api.idToken.setCustomClaim("https://acme.test/email", event.user.email);
  api.transaction.addTargetScope("write:things");
  api.accessToken.addScope("write:x");
  api.accessToken.removeScope("profile");
};`

// TestActionsUserGrants: post-login effects reach the tokens of every user
// grant in spec §7's order, with and without RBAC.
func TestActionsUserGrants(t *testing.T) {
	for _, rbac := range []bool{false, true} {
		for _, grant := range []string{"code", "device", "password", "password-realm", "refresh"} {
			name := grant + map[bool]string{false: "/rbac-off", true: "/rbac-on"}[rbac]
			t.Run(name, func(t *testing.T) {
				f := newActionsFixture(t)
				f.actions.PostLogin(t, f.tid, "effects", tokenEffectsAction)
				f.setRBAC(t, rbac)
				var form url.Values
				protocol, canRedirect := "", false
				switch grant {
				case "code":
					code := f.authorize(t, "rt-spa", "https://rt.acme.test/cb", acmeUserScopes)
					form, protocol, canRedirect = codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier), "oidc-basic-profile", true
				case "device":
					form, protocol = deviceForm("dev", f.approveDevice(t, acmeUserScopes)), "oauth2-device-code"
				case "password", "refresh":
					form, protocol = pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", acmeUserScopes), "oauth2-password"
				case "password-realm":
					form = pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", acmeUserScopes,
						"grant_type", GrantPasswordRealm, "realm", "Username-Password-Authentication")
					protocol = "oauth2-resource-owner"
				}
				status, body := f.token(t, form)
				if status != 200 {
					t.Fatalf("token: %d %v", status, body)
				}
				raw, _ := body["refresh_token"].(string)
				if grant == "refresh" {
					f.setRBAC(t, rbac) // unchanged; the flow runs again
					status, body = f.token(t, refreshForm("ropg", raw, "client_secret", "ropg-secret"))
					if status != 200 {
						t.Fatalf("refresh: %d %v", status, body)
					}
					protocol = "oauth2-refresh-token"
				}
				want := "openid offline_access read:things write:things write:x"
				if rbac {
					want = "openid offline_access read:things write:x" // the target addition is dropped by RBAC
				}
				at, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
				if body["scope"] != want || at["scope"] != want {
					t.Fatalf("scope: response %v, JWT %v, want %q", body["scope"], at["scope"], want)
				}
				if at["https://acme.test/protocol"] != protocol || at["https://acme.test/can_redirect"] != canRedirect {
					t.Fatalf("access token claims %v", at)
				}
				if at["sub"] != f.aliceID(t) || at["https://auth0.com/x"] != nil {
					t.Fatalf("reserved or Auth0 claims applied: %v", at)
				}
				b, _ := at["https://acme.test/body"].(string)
				for _, secret := range []string{"password", "client_secret", "client_assertion", "code_verifier", "refresh_token", "device_code", "code"} {
					if slices.Contains(strings.Split(b, ","), secret) {
						t.Fatalf("%s reached event.request.body: %q", secret, b)
					}
				}
				// /authorize flows pass no body; token-endpoint grants pass theirs.
				if fromAuthorize := grant == "code" || grant == "device"; fromAuthorize != (b == "") ||
					(!fromAuthorize && !slices.Contains(strings.Split(b, ","), "grant_type")) {
					t.Fatalf("event.request.body = %q", b)
				}
				id, _ := verifyToken(t, f.keys, f.tid, body["id_token"].(string))
				if id["https://acme.test/email"] != "alice@acme.test" || id["https://acme.test/protocol"] != nil {
					t.Fatalf("ID token claims %v", id)
				}
				// The refresh family's ceiling is the authorized set before
				// Actions' accessToken edits: write:x never enters it.
				if next, ok := body["refresh_token"].(string); ok {
					raw = next // rotated
				}
				if raw == "" {
					t.Fatal("no refresh token")
				}
				// Nor does the transaction.addTargetScope addition (write:things),
				// with RBAC on or off: the ceiling is Plan 26's pre-RBAC set.
				if rt := f.storedRT(t, raw); slices.Contains(rt.Scopes, "write:x") || slices.Contains(rt.Scopes, "write:things") ||
					!slices.Contains(rt.Scopes, "profile") || !slices.Contains(rt.Scopes, "read:things") {
					t.Fatalf("refresh ceiling %v", rt.Scopes)
				}
			})
		}
	}
}

// TestActionsTokenEndpointSurfaces: denials and failures of the post-login
// flow at the token endpoint, and redirects there.
func TestActionsTokenEndpointSurfaces(t *testing.T) {
	password := func() url.Values {
		return pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", "openid offline_access")
	}
	cases := []struct {
		name, body, code, desc string
		status                 int
	}{
		{"deny", `api.access.deny("Konto gesperrt für dich");`, "access_denied", "Konto gesperrt f?r dich", 403},
		{"validation", `api.validation.error("invalid_profile", "fix it");`, "invalid_profile", "fix it", 403},
		{"throw", `throw new Error("secret detail");`, "server_error", "internal error", 500},
		{"sendUserTo", `api.redirect.sendUserTo("https://example.test/");`, "server_error", "internal error", 500},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newActionsFixture(t)
			f.actions.PostLogin(t, f.tid, "surface", `exports.onExecutePostLogin = async (event, api) => {`+c.body+`};`)
			status, body := f.token(t, password())
			if status != c.status || body["error"] != c.code || body["error_description"] != c.desc || body["access_token"] != nil {
				t.Fatalf("got %d %v", status, body)
			}
		})
	}
	t.Run("refresh re-runs and fails closed", func(t *testing.T) {
		f := newActionsFixture(t)
		f.actions.PostLogin(t, f.tid, "ok", `exports.onExecutePostLogin = async () => {};`)
		_, body := f.token(t, password())
		raw := body["refresh_token"].(string)
		f.actions.PostLogin(t, f.tid, "nope", `exports.onExecutePostLogin = async (event, api) => { api.access.deny("revoked"); };`)
		status, body := f.token(t, refreshForm("ropg", raw, "client_secret", "ropg-secret"))
		if status != 403 || body["error"] != "access_denied" || body["access_token"] != nil {
			t.Fatalf("refresh: %d %v", status, body)
		}
	})
}

// TestActionsClientCredentials: the credentials-exchange flow edits the
// machine token.
func TestActionsClientCredentials(t *testing.T) {
	m2m := func() url.Values { return cc("m2m", "m2m-secret", "audience", acmeAPI, "scope", "read:things") }
	t.Run("claims and target scopes", func(t *testing.T) {
		f := newActionsFixture(t)
		f.actions.CredentialsExchange(t, f.tid, "cc", `exports.onExecuteCredentialsExchange = async (event, api) => {
		  api.accessToken.setCustomClaim("https://acme.test/client", event.client.client_id);
		  api.accessToken.setCustomClaim("https://acme.test/body", Object.keys(event.request.body).sort().join(","));
		  api.accessToken.setCustomClaim("gty", "forged");
		  api.transaction.addTargetScope("write:things");
		  api.transaction.addTargetScope("delete:everything");
		};`)
		status, body := f.token(t, m2m())
		if status != 200 || body["scope"] != "read:things write:things" {
			t.Fatalf("got %d %v", status, body)
		}
		at, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
		if at["scope"] != body["scope"] || at["https://acme.test/client"] != "m2m" || at["gty"] != "client-credentials" {
			t.Fatalf("claims %v", at)
		}
		if b := at["https://acme.test/body"].(string); strings.Contains(b, "client_secret") {
			t.Fatalf("client secret reached the event: %q", b)
		}
	})
	t.Run("target scopes stay within the API's defined scopes", func(t *testing.T) {
		f := newActionsFixture(t)
		ctx := context.Background()
		g, err := f.st.ClientGrants().Find(ctx, f.tid, "m2m", acmeAPI, store.SubjectTypeClient)
		if err != nil || g.AllowAllScopes || !slices.Contains(g.Scopes, "write:things") {
			t.Fatalf("grant %+v %v", g, err)
		}
		// The API stops defining write:things; the grant still lists it.
		api, err := f.st.ResourceServers().GetByIdentifier(ctx, f.tid, acmeAPI)
		if err != nil {
			t.Fatal(err)
		}
		api.Scopes = slices.DeleteFunc(api.Scopes, func(s store.Scope) bool { return s.Value == "write:things" })
		if err := f.st.ResourceServers().Update(ctx, api); err != nil {
			t.Fatal(err)
		}
		f.actions.CredentialsExchange(t, f.tid, "cc", `exports.onExecuteCredentialsExchange = async (event, api) => {
		  api.transaction.addTargetScope("write:things");
		};`)
		status, body := f.token(t, m2m())
		if status != 200 || body["scope"] != "read:things" {
			t.Fatalf("got %d %v", status, body)
		}
	})
	t.Run("non-namespaced claims are dropped for the Management API", func(t *testing.T) {
		f := newActionsFixture(t)
		f.actions.CredentialsExchange(t, f.tid, "cc", `exports.onExecuteCredentialsExchange = async (event, api) => {
		  api.accessToken.setCustomClaim("plain", 1);
		  api.accessToken.setCustomClaim("https://acme.test/ns", 2);
		};`)
		status, body := f.token(t, m2m())
		at, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
		if status != 200 || at["plain"] != 1.0 || at["https://acme.test/ns"] != 2.0 {
			t.Fatalf("custom API: %d %v", status, at)
		}
		// The same API marked as zeroauthy's own (the Management API).
		ctx := context.Background()
		api, err := f.st.ResourceServers().GetByIdentifier(ctx, f.tid, acmeAPI)
		if err != nil {
			t.Fatal(err)
		}
		api.IsSystem = true
		if err := f.st.ResourceServers().Update(ctx, api); err != nil {
			t.Fatal(err)
		}
		status, body = f.token(t, m2m())
		at, _ = verifyToken(t, f.keys, f.tid, body["access_token"].(string))
		if status != 200 || at["plain"] != nil || at["https://acme.test/ns"] != 2.0 {
			t.Fatalf("system API: %d %v", status, at)
		}
	})
	for _, c := range []struct {
		code   string
		status int
	}{{"invalid_scope", 400}, {"invalid_request", 400}, {"server_error", 500}} {
		t.Run("deny "+c.code, func(t *testing.T) {
			f := newActionsFixture(t)
			f.actions.CredentialsExchange(t, f.tid, "cc", `exports.onExecuteCredentialsExchange = async (event, api) => {
			  api.access.deny("`+c.code+`", "no token for you");
			};`)
			status, body := f.token(t, m2m())
			if status != c.status || body["error"] != c.code || body["error_description"] != "no token for you" || body["access_token"] != nil {
				t.Fatalf("got %d %v", status, body)
			}
		})
	}
	for name, code := range map[string]string{
		"unknown deny code": `api.access.deny("access_denied", "x");`,
		"throw":             `throw new Error("boom");`,
		"post-login api":    `api.accessToken.addScope("x");`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newActionsFixture(t)
			f.actions.CredentialsExchange(t, f.tid, "cc", `exports.onExecuteCredentialsExchange = async (event, api) => {`+code+`};`)
			status, body := f.token(t, m2m())
			if status != 500 || body["error"] != "server_error" || body["access_token"] != nil {
				t.Fatalf("got %d %v", status, body)
			}
		})
	}
}

// TestActionsRefreshReadds: Action additions are not kept by the refresh
// family; on refresh they are present only when the re-run flow adds them
// again.
func TestActionsRefreshReadds(t *testing.T) {
	for _, rbac := range []bool{false, true} {
		for _, again := range []bool{false, true} {
			t.Run(fmt.Sprintf("rbac=%v/readd=%v", rbac, again), func(t *testing.T) {
				f := newActionsFixture(t)
				f.setRBAC(t, rbac)
				cond := `event.transaction.protocol !== "oauth2-refresh-token"`
				if again {
					cond = "true"
				}
				f.actions.PostLogin(t, f.tid, "cond", `exports.onExecutePostLogin = async (event, api) => {
				  if (`+cond+`) {
				    api.transaction.addTargetScope("write:things");
				    api.accessToken.addScope("write:x");
				    api.accessToken.setCustomClaim("https://acme.test/c", 1);
				  }
				};`)
				status, body := f.token(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", "openid offline_access read:things"))
				if status != 200 {
					t.Fatalf("password: %d %v", status, body)
				}
				raw := body["refresh_token"].(string)
				if rt := f.storedRT(t, raw); slices.Contains(rt.Scopes, "write:things") || slices.Contains(rt.Scopes, "write:x") {
					t.Fatalf("ceiling %v", rt.Scopes)
				}
				status, body = f.token(t, refreshForm("ropg", raw, "client_secret", "ropg-secret"))
				if status != 200 {
					t.Fatalf("refresh: %d %v", status, body)
				}
				want := "openid offline_access read:things"
				switch {
				case again && !rbac:
					want += " write:things write:x"
				case again:
					want += " write:x"
				}
				at, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
				if body["scope"] != want || at["scope"] != want || (at["https://acme.test/c"] != nil) != again {
					t.Fatalf("refresh scope %v (JWT %v), want %q; claims %v", body["scope"], at["scope"], want, at)
				}
			})
		}
	}
}

// rotating makes ropg's refresh tokens rotate, without leeway.
func (f *actionsFixture) rotating(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	c, err := f.st.Clients().Get(ctx, f.tid, "ropg")
	if err != nil {
		t.Fatal(err)
	}
	c.RefreshToken.Rotating = true
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
}

// TestActionsRefreshOfflineRemoved: removeScope("offline_access") on refresh
// returns no refresh token and neither rotates nor extends the presented one.
func TestActionsRefreshOfflineRemoved(t *testing.T) {
	f := newActionsFixture(t)
	f.rotating(t)
	f.actions.PostLogin(t, f.tid, "drop", `exports.onExecutePostLogin = async (event, api) => {
	  if (event.transaction.protocol === "oauth2-refresh-token") api.accessToken.removeScope("offline_access");
	};`)
	_, body := f.token(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", "openid offline_access"))
	raw := body["refresh_token"].(string)
	status, body := f.token(t, refreshForm("ropg", raw, "client_secret", "ropg-secret"))
	if status != 200 || body["refresh_token"] != nil || body["scope"] != "openid" {
		t.Fatalf("refresh: %d %v", status, body)
	}
	if rt := f.storedRT(t, raw); rt.RotatedAt != nil || rt.RevokedAt != nil {
		t.Fatalf("presented token changed: %+v", rt)
	}
}

// TestActionsRefreshReplayRunsNothing: a replayed (rotated) refresh token is
// refused before the post-login flow: no Action, no execution record.
func TestActionsRefreshReplayRunsNothing(t *testing.T) {
	f := newActionsFixture(t)
	f.rotating(t)
	counts := &actionstest.Counts{}
	cs := actionstest.CountingStore{Store: f.st, Counts: counts}
	f.h.Store, f.actions.Engine.Store = cs, cs
	f.actions.PostLogin(t, f.tid, "count", `exports.onExecutePostLogin = async (event, api) => {};`)
	_, body := f.token(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", "openid offline_access"))
	first := body["refresh_token"].(string)
	if status, body := f.token(t, refreshForm("ropg", first, "client_secret", "ropg-secret")); status != 200 || body["refresh_token"] == nil {
		t.Fatalf("refresh: %d %v", status, body)
	}
	counts.Reset()
	status, body := f.token(t, refreshForm("ropg", first, "client_secret", "ropg-secret"))
	if status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("replay: %d %v", status, body)
	}
	if n := counts.Snapshot(); n["Actions.Bindings"] != 0 || n["Actions.CreateExecution"] != 0 {
		t.Fatalf("replay ran the flow: %v", n)
	}
}

// TestActionsNoBindingsCost: without bound post-login Actions a refresh
// costs one bindings read and no other added query.
func TestActionsNoBindingsCost(t *testing.T) {
	f := newActionsFixture(t)
	counts := &actionstest.Counts{}
	cs := actionstest.CountingStore{Store: f.st, Counts: counts}
	f.h.Store, f.actions.Engine.Store = cs, cs
	_, body := f.token(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", "openid offline_access"))
	raw := body["refresh_token"].(string)
	run := func(engine bool) map[string]int {
		f.h.Actions = nil
		if engine {
			f.h.Actions = f.actions.Engine
		}
		counts.Reset()
		if status, body := f.token(t, refreshForm("ropg", raw, "client_secret", "ropg-secret")); status != 200 {
			t.Fatalf("refresh: %d %v", status, body)
		}
		return counts.Snapshot()
	}
	assertOneBindingsRead(t, run(false), run(true))
}

// assertOneBindingsRead checks that with differs from without by exactly
// one Actions accessor call, that is one Bindings read.
func assertOneBindingsRead(t *testing.T, without, with map[string]int) {
	t.Helper()
	want := maps.Clone(without)
	want["Actions"]++
	want["Actions.Bindings"]++
	if !maps.Equal(with, want) {
		t.Fatalf("queries with an engine and no bindings %v, want %v", with, want)
	}
}

// credentialsByGrant lists each token grant's credential parameters. Every
// registered grant must be listed, so a new grant cannot leak its
// credentials into event.request.body unnoticed.
var credentialsByGrant = map[string][]string{
	"authorization_code": {"code", "code_verifier", "client_secret", "client_assertion"},
	"client_credentials": {"client_secret", "client_assertion"},
	"refresh_token":      {"refresh_token", "client_secret", "client_assertion"},
	"password":           {"password", "client_secret", "client_assertion"},
	GrantPasswordRealm:   {"password", "client_secret", "client_assertion"},
	GrantDeviceCode:      {"device_code", "client_secret", "client_assertion"},
}

func TestActionsBodyStripsEveryGrant(t *testing.T) {
	for grant := range grantHandlers {
		creds, ok := credentialsByGrant[grant]
		if !ok {
			t.Errorf("grant %q has no credential list: add it here and strip its credentials from event.request.body", grant)
			continue
		}
		body := map[string]any{"grant_type": grant, "scope": "openid"}
		for _, c := range creds {
			body[c] = "secret"
		}
		got := actions.StripCredentials(body)
		for _, c := range creds {
			if _, leaked := got[c]; leaked {
				t.Errorf("grant %q: %s reaches event.request.body", grant, c)
			}
		}
		if got["scope"] != "openid" || got["grant_type"] != grant {
			t.Errorf("grant %q: body %v", grant, got)
		}
	}
}

// thirdParty prepares the permissive third-party client "partner" for
// /authorize: a callback, a domain connection, and delete:things on the API.
func (f *actionsFixture) thirdParty(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	c, err := f.st.Clients().Get(ctx, f.tid, "partner")
	if err != nil {
		t.Fatal(err)
	}
	c.Callbacks = []string{"https://partner.acme.test/cb"}
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	conn, err := f.st.Connections().GetByName(ctx, f.tid, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	conn.IsDomainConnection = true
	if err := f.st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	api, err := f.st.ResourceServers().GetByIdentifier(ctx, f.tid, acmeAPI)
	if err != nil {
		t.Fatal(err)
	}
	api.Scopes = append(api.Scopes, store.Scope{Value: "delete:things"})
	if err := f.st.ResourceServers().Update(ctx, api); err != nil {
		t.Fatal(err)
	}
}

func (f *actionsFixture) userGrant(t *testing.T, clientID string, scopes ...string) {
	t.Helper()
	if _, err := f.st.UserGrants().Upsert(context.Background(), &store.UserGrant{TenantID: f.tid, ID: "ugr_" + secrets.RandomString(8),
		ClientID: clientID, UserID: f.aliceID(t), Audience: acmeAPI, Scopes: scopes, CreatedAt: fixedNow(), UpdatedAt: fixedNow()}); err != nil {
		t.Fatal(err)
	}
}

// partnerAuthorize runs /authorize for partner and, when the consent page
// is shown, accepts it; it returns the code.
func (f *actionsFixture) partnerAuthorize(t *testing.T, scope string, extra ...string) string {
	t.Helper()
	q := url.Values{"client_id": {"partner"}, "redirect_uri": {"https://partner.acme.test/cb"}, "response_type": {"code"},
		"scope": {scope}, "audience": {acmeAPI}, "state": {"st"}}
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	ck := f.sessionCookie(t)
	r := httptest.NewRequest("GET", "https://acme.example.test/authorize?"+q.Encode(), nil)
	r.AddCookie(ck)
	rec := httptest.NewRecorder()
	tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.az.Authorize)).ServeHTTP(rec, r)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc == nil {
		t.Fatalf("authorize: %d %s", rec.Code, rec.Body)
	}
	if loc.Path == "/u/consent" {
		ctx := context.Background()
		txn, err := f.st.AuthTransactions().Get(ctx, f.tid, loc.Query().Get("state"))
		if err != nil {
			t.Fatal(err)
		}
		tn, _ := f.st.Tenants().Get(ctx, f.tid)
		res := tenant.Resolved{Tenant: tn, Host: "acme.example.test"}
		cr := httptest.NewRequest("POST", "https://acme.example.test/u/consent", nil)
		cr.AddCookie(ck)
		sess, err := f.az.ActiveSession(ctx, cr, res)
		if err != nil || sess == nil {
			t.Fatalf("session: %v", err)
		}
		view, err := f.az.ConsentView(ctx, res, txn, sess)
		if err != nil || slices.Contains(view.Scopes, "write:things") || !slices.Contains(view.Scopes, "delete:things") {
			t.Fatalf("consent view %+v, %v", view, err)
		}
		rec = httptest.NewRecorder()
		f.az.Consent(rec, cr, res, txn, sess, true)
		if loc, _ = url.Parse(rec.Header().Get("Location")); rec.Code != http.StatusFound || loc == nil {
			t.Fatalf("consent: %d %s", rec.Code, rec.Body)
		}
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code: %s", loc)
	}
	return code
}

// TestActionsCeilingExcludesEdits: the refresh ceiling is the issued set
// minus the Actions' target additions, so scopes the Actions removed (never
// consented) stay out too, and prompt=none still gets its refresh token.
func TestActionsCeilingExcludesEdits(t *testing.T) {
	const scope = "openid offline_access read:things write:things"
	action := `exports.onExecutePostLogin = async (event, api) => {
	  if (event.transaction.protocol !== "oauth2-refresh-token") {
	    api.transaction.removeTargetScope("write:things");
	    api.transaction.addTargetScope("delete:things");
	  }
	};`
	for _, promptNone := range []bool{false, true} {
		t.Run(fmt.Sprintf("prompt_none=%v", promptNone), func(t *testing.T) {
			f := newActionsFixture(t)
			f.thirdParty(t)
			f.actions.PostLogin(t, f.tid, "edit", action)
			var extra []string
			if promptNone {
				// Consented earlier to everything the edited request asks.
				f.userGrant(t, "partner", "openid", "offline_access", "read:things", "delete:things")
				extra = []string{"prompt", "none"}
			}
			code := f.partnerAuthorize(t, scope, extra...)
			status, body := f.token(t, url.Values{"grant_type": {"authorization_code"}, "client_id": {"partner"},
				"client_secret": {"partner-secret"}, "code": {code}, "redirect_uri": {"https://partner.acme.test/cb"}})
			if status != 200 || body["scope"] != "openid offline_access read:things delete:things" {
				t.Fatalf("code exchange: %d %v", status, body)
			}
			raw, _ := body["refresh_token"].(string)
			if raw == "" {
				t.Fatal("no refresh token")
			}
			if rt := f.storedRT(t, raw); !slices.Equal(rt.Scopes, []string{"openid", "offline_access", "read:things"}) {
				t.Fatalf("refresh ceiling %v", rt.Scopes)
			}
			status, body = f.token(t, refreshForm("partner", raw, "client_secret", "partner-secret"))
			if status != 200 || body["scope"] != "openid offline_access read:things" {
				t.Fatalf("refresh: %d %v", status, body)
			}
		})
	}
}

// TestActionsRefreshConsentedAdditions: refresh has no consent step, so for
// a client that goes through consent the re-run flow's target additions are
// kept only when the user's grant holds them. First-party clients that
// skip consent are not limited (TestActionsRefreshReadds).
func TestActionsRefreshConsentedAdditions(t *testing.T) {
	for _, granted := range []bool{false, true} {
		t.Run(fmt.Sprintf("granted=%v", granted), func(t *testing.T) {
			f := newActionsFixture(t)
			f.thirdParty(t)
			scopes := []string{"openid", "offline_access", "read:things"}
			if granted {
				scopes = append(scopes, "delete:things")
			}
			f.userGrant(t, "partner", scopes...)
			f.actions.PostLogin(t, f.tid, "add", `exports.onExecutePostLogin = async (event, api) => {
			  api.transaction.addTargetScope("delete:things");
			};`)
			raw, _ := f.issueRefresh(t, "partner", []string{"openid", "offline_access", "read:things"}, acmeAPI)
			status, body := f.token(t, refreshForm("partner", raw, "client_secret", "partner-secret"))
			want := "openid offline_access read:things"
			if granted {
				want += " delete:things"
			}
			if status != 200 || body["scope"] != want {
				t.Fatalf("refresh: %d %v, want %q", status, body, want)
			}
		})
	}
}

// TestActionsRefreshTargetOfflineRemoved: removing offline_access as a
// target scope on refresh also ends the exchange without a refresh token.
func TestActionsRefreshTargetOfflineRemoved(t *testing.T) {
	f := newActionsFixture(t)
	f.rotating(t)
	f.actions.PostLogin(t, f.tid, "drop", `exports.onExecutePostLogin = async (event, api) => {
	  if (event.transaction.protocol === "oauth2-refresh-token") api.transaction.removeTargetScope("offline_access");
	};`)
	_, body := f.token(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", "openid offline_access"))
	raw := body["refresh_token"].(string)
	status, body := f.token(t, refreshForm("ropg", raw, "client_secret", "ropg-secret"))
	if status != 200 || body["refresh_token"] != nil || body["scope"] != "openid" {
		t.Fatalf("refresh: %d %v", status, body)
	}
	if rt := f.storedRT(t, raw); rt.RotatedAt != nil || rt.RevokedAt != nil {
		t.Fatalf("presented token changed: %+v", rt)
	}
}
