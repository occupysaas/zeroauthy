package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

// myOrgSeed is flowSeed with an organization application, two
// organizations (acme: alice the admin and bob; other: carol the admin) and
// a machine client (Plan 42b).
var myOrgSeed = strings.Replace(strings.Replace(strings.Replace(flowSeed, "    clients:\n", `    roles: [{name: Org Admin}, {name: Member}]
    clients:
      - {client_id: admin, app_type: non_interactive, client_secret: admin-s3cret, grant_types: [client_credentials]}
      - client_id: portal
        app_type: spa
        organization_usage: allow
        grant_types: [authorization_code, refresh_token]
        callbacks: ["https://app.flow.test/cb"]
        web_origins: ["https://app.flow.test"]
`, 1), "enabled_clients: [spa, tv, spa2]}\n", "enabled_clients: [spa, tv, spa2, portal]}\n", 1), `      - {connection: Username-Password-Authentication, email: alice@flow.test, password: "alice password 1", email_verified: true}
`, `      - {connection: Username-Password-Authentication, email: alice@flow.test, password: "alice password 1", email_verified: true}
      - {connection: Username-Password-Authentication, email: bob@flow.test, password: "bob password 1", email_verified: true}
      - {connection: Username-Password-Authentication, email: carol@flow.test, password: "carol password 1", email_verified: true}
    organizations:
      - name: acme
        display_name: Acme
        connections: [{name: Username-Password-Authentication}]
        members: [{email: alice@flow.test, connection: Username-Password-Authentication}, {email: bob@flow.test, connection: Username-Password-Authentication}]
        member_roles: [{member: {email: alice@flow.test, connection: Username-Password-Authentication}, roles: [Org Admin]}, {member: {email: bob@flow.test, connection: Username-Password-Authentication}, roles: [Member]}]
      - name: other
        display_name: Other
        connections: [{name: Username-Password-Authentication}]
        members: [{email: carol@flow.test, connection: Username-Password-Authentication}]
        member_roles: [{member: {email: carol@flow.test, connection: Username-Password-Authentication}, roles: [Org Admin]}]
`, 1)

type myOrgEnv struct {
	*flowEnv
	tn        *store.Tenant
	api       *store.ResourceServer
	canonical string
	orgs      map[string]*store.Organization
	roles     map[string]string // name → ID
}

func newMyOrgEnv(t *testing.T) *myOrgEnv {
	t.Helper()
	ctx := context.Background()
	e := newFlowEnvSeed(t, myOrgSeed, nil)
	tn, _ := e.st.Tenants().GetByName(ctx, "flow")
	api, err := tenantsetup.MyOrgAPI(ctx, e.st, tn, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env := &myOrgEnv{flowEnv: e, tn: tn, api: api, canonical: tn.CanonicalHost, orgs: map[string]*store.Organization{}, roles: map[string]string{}}
	roles, err := e.st.RBAC().ListRoles(ctx, tn.ID, store.RBACPage{PerPage: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles.Items {
		env.roles[r.Name] = r.ID
	}
	keys := []store.PermissionKey{}
	scopes := []string{}
	for _, s := range tenantsetup.MyOrgAPIScopes {
		keys = append(keys, store.PermissionKey{ResourceServerIdentifier: api.Identifier, PermissionName: s.Value})
		scopes = append(scopes, s.Value)
	}
	if err := e.st.RBAC().ChangeRolePermissions(ctx, tn.ID, env.roles["Org Admin"], true, keys); err != nil {
		t.Fatal(err)
	}
	if err := e.st.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: tn.ID, ID: "cgr_portal", ClientID: "portal", Audience: api.Identifier, SubjectType: store.SubjectTypeUser, Scopes: scopes, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	repo, _ := store.MyOrg(ctx, e.st)
	if err := repo.PutMyOrgClientConfig(ctx, &store.MyOrgClientConfig{TenantID: tn.ID, ClientID: "portal", Doc: []byte(`{"allowed_strategies":[],"connection_deletion_behavior":"allow","invitation_landing_client_id":"portal","enforce_permission_ceiling":false,"enforce_self_assignment_restriction":false}`)}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"acme", "other"} {
		o, err := e.st.Organizations().GetByName(ctx, tn.ID, name)
		if err != nil {
			t.Fatal(err)
		}
		env.orgs[name] = o
	}
	return env
}

var myOrgScopes = func() string {
	out := []string{"openid"}
	for _, s := range tenantsetup.MyOrgAPIScopes {
		out = append(out, s.Value)
	}
	return strings.Join(out, " ")
}()

// tokenResponse runs /authorize (with extra parameters), login as email on
// host and the code exchange; it returns the token endpoint's JSON or the
// authorization error.
func (e *myOrgEnv) tokenResponse(t *testing.T, host, email, password string, extra ...string) map[string]any {
	t.Helper()
	base := "https://" + host
	c := e.client(t)
	c.Transport = handlerTransport{e.srv.Config.Handler}
	params := append([]string{"client_id", "portal", "audience", base + "/my-org/", "scope", myOrgScopes}, extra...)
	resp, _ := fetch(t, c, authorizeURL(base, params...))
	loc, _ := resp.Location()
	if loc != nil && loc.Query().Get("error") != "" {
		return map[string]any{"error": loc.Query().Get("error"), "error_description": loc.Query().Get("error_description")}
	}
	for loc != nil && loc.Path == "/u/login" {
		_, page := fetch(t, c, base+loc.RequestURI())
		csrf := csrfRe.FindStringSubmatch(page)
		if csrf == nil {
			t.Fatalf("login page: %s", page)
		}
		form := url.Values{"hosted_revision": {hostedRevision(page)}, "state": {loc.Query().Get("state")}, "csrf": {csrf[1]}, "username": {email}, "password": {password}}
		req, _ := http.NewRequest("POST", base+"/u/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, _ = mustDo(t, c, req)
		loc, _ = resp.Location()
	}
	if loc == nil || loc.Query().Get("code") == "" {
		if loc != nil && loc.Query().Get("error") != "" {
			return map[string]any{"error": loc.Query().Get("error"), "error_description": loc.Query().Get("error_description")}
		}
		t.Fatalf("no code: %v", loc)
	}
	r := httptest.NewRequest("POST", base+"/oauth/token", strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "client_id": {"portal"}, "code": {loc.Query().Get("code")}, "redirect_uri": {"https://app.flow.test/cb"}, "code_verifier": {verifier}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.srv.Config.Handler.ServeHTTP(rec, r)
	return decodeJSON(rec)
}

// token is an access token of email in organization org on host.
func (e *myOrgEnv) token(t *testing.T, host, org, email, password string) string {
	t.Helper()
	out := e.tokenResponse(t, host, email, password, "organization", e.orgs[org].ID)
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("token for %s in %s: %v", email, org, out)
	}
	return tok
}

func jwtClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Tokens for the My Organization API need an organization, carry org_id,
// live 600 seconds and hold the my_org permissions of the user's
// organization roles within the client grant (LR42b-5).
func TestMyOrgTokens(t *testing.T) {
	e := newMyOrgEnv(t)
	out := e.tokenResponse(t, e.canonical, "alice@flow.test", "alice password 1", "organization", e.orgs["acme"].ID)
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("admin token: %v", out)
	}
	claims := jwtClaims(t, access)
	scopes := strings.Fields(claims["scope"].(string))
	for _, s := range tenantsetup.MyOrgAPIScopes {
		if !slices.Contains(scopes, s.Value) {
			t.Errorf("admin token lacks %s: %v", s.Value, scopes)
		}
	}
	if claims["org_id"] != e.orgs["acme"].ID {
		t.Errorf("org_id %v", claims["org_id"])
	}
	if exp, iat := claims["exp"].(float64), claims["iat"].(float64); exp-iat != 600 {
		t.Errorf("lifetime %v", exp-iat)
	}
	idClaims := jwtClaims(t, out["id_token"].(string))
	perms, _ := idClaims["urn:auth0:my_org_current_user_permissions"].([]any)
	if len(perms) != len(tenantsetup.MyOrgAPIScopes) {
		t.Errorf("ID token permissions %v", idClaims["urn:auth0:my_org_current_user_permissions"])
	}
	// A member without a role carrying my_org permissions gets none.
	bob := jwtClaims(t, e.token(t, e.canonical, "acme", "bob@flow.test", "bob password 1"))
	for _, s := range strings.Fields(bob["scope"].(string)) {
		if strings.Contains(s, ":my_org:") {
			t.Errorf("member token holds %s", s)
		}
	}
	// No organization: refused.
	if out := e.tokenResponse(t, e.canonical, "alice@flow.test", "alice password 1"); out["access_token"] != nil || out["error"] == nil {
		t.Errorf("token without organization: %v", out)
	}
	// Client credentials: refused.
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"admin"}, "client_secret": {"admin-s3cret"}, "audience": {"https://" + e.canonical + "/my-org/"}}
	r := httptest.NewRequest("POST", "https://"+e.canonical+"/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.srv.Config.Handler.ServeHTTP(rec, r)
	if decodeJSON(rec)["error"] != "access_denied" {
		t.Errorf("client credentials = %d %s", rec.Code, rec.Body)
	}
}

// The API is mounted on tenant hosts, with client-origin CORS.
func TestMyOrgMounted(t *testing.T) {
	e := newMyOrgEnv(t)
	tok := e.token(t, e.canonical, "acme", "alice@flow.test", "alice password 1")
	r := httptest.NewRequest("GET", "https://"+e.canonical+"/my-org/v1/details", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Origin", "https://app.flow.test")
	rec := httptest.NewRecorder()
	e.srv.Config.Handler.ServeHTTP(rec, r)
	if rec.Code == 401 || rec.Code == 403 || rec.Code == 404 || rec.Header().Get("Access-Control-Allow-Origin") != "https://app.flow.test" {
		t.Fatalf("details = %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
}

// Refreshing keeps the organization and the my_org scopes.
func TestMyOrgRefresh(t *testing.T) {
	e := newMyOrgEnv(t)
	out := e.tokenResponse(t, e.canonical, "alice@flow.test", "alice password 1", "organization", e.orgs["acme"].ID, "scope", myOrgScopes+" offline_access")
	rt, _ := out["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh token: %v", out)
	}
	r := httptest.NewRequest("POST", "https://"+e.canonical+"/oauth/token", strings.NewReader(url.Values{"grant_type": {"refresh_token"}, "client_id": {"portal"}, "refresh_token": {rt}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.srv.Config.Handler.ServeHTTP(rec, r)
	got := decodeJSON(rec)
	access, _ := got["access_token"].(string)
	if access == "" {
		t.Fatalf("refresh = %d %s", rec.Code, rec.Body)
	}
	c := jwtClaims(t, access)
	if c["org_id"] != e.orgs["acme"].ID || !strings.Contains(c["scope"].(string), "read:my_org:members") {
		t.Fatalf("refreshed claims %v", c)
	}
}
