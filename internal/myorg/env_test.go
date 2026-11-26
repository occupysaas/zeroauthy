package myorg

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

const host = "login.acme.test"

var allScopes = func() []string {
	out := []string{}
	for _, s := range tenantsetup.MyOrgAPIScopes {
		out = append(out, s.Value)
	}
	return out
}()

type env struct {
	st    store.Store
	w     keys.Wrapper
	km    *keys.Manager
	tn    *store.Tenant
	conn  *store.Connection
	orgA  *store.Organization
	orgB  *store.Organization
	admin *store.User // admin of A
	bob   *store.User // member of A
	carol *store.User // admin of B
	roles map[string]string
	h     *Handlers
	now   time.Time
	logs  *bytes.Buffer
	route http.Handler
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	tn, err := tenantsetup.UpsertTenant(ctx, st, "acme", now, func(t *store.Tenant) error {
		t.Domains, t.CanonicalHost = []string{host}, host
		return nil
	})
	must(t, err)
	must(t, km.Ensure(ctx, tn.ID))
	api, err := tenantsetup.MyOrgAPI(ctx, st, tn, now)
	must(t, err)
	must(t, tenantsetup.UpsertConnection(ctx, st, tn.ID, "Username-Password-Authentication", now, func(c *store.Connection) error {
		c.Strategy = store.StrategyDatabase
		c.EnabledClients = []string{"portal"}
		return nil
	}))
	conn, _ := st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
	must(t, st.Clients().Create(ctx, &store.Client{TenantID: tn.ID, ClientID: "portal", Name: "Portal", AppType: store.AppTypeSPA, IsFirstParty: true, InitiateLoginURI: "https://app.acme.test/login"}))
	e := &env{st: st, w: w, km: km, tn: tn, conn: conn, now: now, logs: &bytes.Buffer{}, roles: map[string]string{}}
	for _, name := range []string{"Org Admin", "Member", "Hidden"} {
		id := "rol_" + strings.ReplaceAll(strings.ToLower(name), " ", "")
		must(t, st.RBAC().CreateRole(ctx, &store.Role{TenantID: tn.ID, ID: id, Name: name, Description: name + " role"}))
		e.roles[name] = id
	}
	keysAll := []store.PermissionKey{}
	for _, s := range allScopes {
		keysAll = append(keysAll, store.PermissionKey{ResourceServerIdentifier: api.Identifier, PermissionName: s})
	}
	must(t, st.RBAC().ChangeRolePermissions(ctx, tn.ID, e.roles["Org Admin"], true, keysAll))
	repo, _ := store.MyOrg(ctx, st)
	must(t, repo.SetMyOrgRoleVisible(ctx, tn.ID, e.roles["Org Admin"], true))
	must(t, repo.SetMyOrgRoleVisible(ctx, tn.ID, e.roles["Member"], true))
	e.setConfig(t, `{"allowed_strategies":["oidc"],"connection_deletion_behavior":"allow","invitation_landing_client_id":"portal","enforce_permission_ceiling":false,"enforce_self_assignment_restriction":false}`)
	e.admin = e.user(t, "auth0|admin", "admin@acme.test")
	e.bob = e.user(t, "auth0|bob", "bob@acme.test")
	e.carol = e.user(t, "auth0|carol", "carol@other.test")
	e.orgA = e.org(t, "org_aaaaaaaaaaaaaaaa", "acme-org")
	e.orgB = e.org(t, "org_bbbbbbbbbbbbbbbb", "other-org")
	e.member(t, e.orgA, e.admin, "Org Admin")
	e.member(t, e.orgA, e.bob, "Member")
	e.member(t, e.orgB, e.carol, "Org Admin")
	e.h = &Handlers{Store: st, Keys: km, Wrapper: w, Now: func() time.Time { return e.now }, Log: slog.New(slog.NewTextHandler(e.logs, nil))}
	e.route = e.h.Routes()
	return e
}

func must(t *testing.T, err error) {
	if err != nil {
		_, _, line, _ := runtime.Caller(1)
		t.Fatalf("line %d: %v", line, err)
	}
}

func (e *env) setConfig(t *testing.T, doc string) {
	t.Helper()
	repo, _ := store.MyOrg(context.Background(), e.st)
	must(t, repo.PutMyOrgClientConfig(context.Background(), &store.MyOrgClientConfig{TenantID: e.tn.ID, ClientID: "portal", Doc: []byte(doc)}))
}

func (e *env) user(t *testing.T, uid, email string) *store.User {
	t.Helper()
	u := &store.User{TenantID: e.tn.ID, UserID: uid, Email: email, EmailVerified: true, Name: strings.Split(email, "@")[0], CreatedAt: e.now, UpdatedAt: e.now,
		Identities: []store.Identity{{Connection: e.conn.Name, Provider: store.StrategyDatabase, UserID: strings.TrimPrefix(uid, "auth0|")}}}
	must(t, e.st.Users().Create(context.Background(), u))
	got, _ := e.st.Users().Get(context.Background(), e.tn.ID, uid)
	return got
}

func (e *env) org(t *testing.T, id, name string) *store.Organization {
	t.Helper()
	o := &store.Organization{TenantID: e.tn.ID, ID: id, Name: name, DisplayName: strings.ToUpper(name), ThirdPartyClientAccess: "block", CreatedAt: e.now, UpdatedAt: e.now}
	must(t, e.st.Organizations().Create(context.Background(), o, []store.OrganizationConnection{{TenantID: e.tn.ID, OrganizationID: id, ConnectionID: e.conn.ID, ShowAsButton: true}}))
	return o
}

func (e *env) member(t *testing.T, o *store.Organization, u *store.User, roles ...string) {
	t.Helper()
	ctx := context.Background()
	must(t, e.st.Organizations().AddMembers(ctx, e.tn.ID, o.ID, []string{u.UserID}))
	ids := []string{}
	for _, r := range roles {
		ids = append(ids, e.roles[r])
	}
	if len(ids) > 0 {
		must(t, e.st.Organizations().ChangeMemberRoles(ctx, e.tn.ID, o.ID, u.UserID, true, ids))
	}
}

// tokenFor signs a My Organization access token.
func (e *env) tokenFor(t *testing.T, uid, orgID string, scopes ...string) string {
	t.Helper()
	if scopes == nil {
		scopes = allScopes
	}
	claims := map[string]any{"iss": "https://" + host + "/", "aud": []string{"https://" + host + "/my-org/"}, "sub": uid, "azp": "portal",
		"scope": strings.Join(scopes, " "), "iat": e.now.Unix(), "exp": e.now.Add(10 * time.Minute).Unix(), "jti": "j1"}
	if orgID != "" {
		claims["org_id"] = orgID
	}
	raw, err := e.km.SignWithType(context.Background(), e.tn.ID, claims, "at+jwt")
	must(t, err)
	return raw
}

func (e *env) adminToken(t *testing.T, scopes ...string) string {
	return e.tokenFor(t, e.admin.UserID, e.orgA.ID, scopes...)
}

func (e *env) do(t *testing.T, tok, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, "https://"+host+Path+path, rd)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: e.tn, Host: host}))
	rec := httptest.NewRecorder()
	http.StripPrefix(Path, e.route).ServeHTTP(rec, r)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}
