package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const acmeUserScopes = "openid profile offline_access read:things"

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
				if b, _ := at["https://acme.test/body"].(string); strings.Contains(b, "password") || strings.Contains(b, "secret") ||
					strings.Contains(b, "verifier") || strings.Contains(b, "refresh_token,") || slices.Contains(strings.Split(b, ","), "code") {
					t.Fatalf("credentials reached event.request.body: %q", b)
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
				if rt := f.storedRT(t, raw); slices.Contains(rt.Scopes, "write:x") || !slices.Contains(rt.Scopes, "profile") {
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
