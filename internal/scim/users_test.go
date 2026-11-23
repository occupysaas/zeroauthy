package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

var testNow = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

type env struct {
	t      *testing.T
	st     *memory.Store
	h      *Handler
	srv    *httptest.Server
	tn     *store.Tenant
	ended  []string
	tokens map[string]string // connection → token
}

var allScopes = []string{"get:users", "post:users", "put:users", "patch:users", "delete:users", "get:groups", "post:groups", "put:groups", "patch:groups", "delete:groups"}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := memory.New()
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	tn := &store.Tenant{ID: "ten_scim", Name: "acme", CanonicalHost: "acme.example.test"}
	if err := st.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, st: st, tn: tn, tokens: map[string]string{}}
	e.h = &Handler{Store: st, Now: func() time.Time { return testNow },
		EndSessions: func(_ context.Context, tx store.Store, tid, uid string) error {
			e.ended = append(e.ended, uid)
			_, err := tx.Sessions().DeleteByUser(context.Background(), tid, uid)
			return err
		}}
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: tn, Host: "acme.example.test"})))
		})
	})
	r.Mount("/scim/v2/connections/{connection_id}", e.h.Routes())
	e.srv = httptest.NewServer(r)
	t.Cleanup(e.srv.Close)
	for _, c := range []struct{ id, name, strategy string }{{"con_a", "corp-saml", "samlp"}, {"con_b", "corp-oidc", "oidc"}, {"con_db", "Username-Password-Authentication", "auth0"}} {
		if err := st.Connections().Create(ctx, &store.Connection{TenantID: tn.ID, ID: c.id, Name: c.name, Strategy: c.strategy}); err != nil {
			t.Fatal(err)
		}
		if c.strategy == "auth0" {
			continue
		}
		e.configure(c.id, nil)
		e.tokens[c.id] = e.token(c.id, allScopes, nil)
	}
	return e
}

func (e *env) configure(conn string, mapping []store.SCIMMapping) {
	e.t.Helper()
	if mapping == nil {
		mapping = DefaultMapping()
	}
	if err := e.st.Directory().CreateSCIMConfig(context.Background(), &store.SCIMConfig{TenantID: e.tn.ID, ConnectionID: conn, UserIDAttribute: DefaultUserIDAttribute,
		Mapping: mapping, CreatedAt: testNow, UpdatedAt: testNow}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) token(conn string, scopes []string, expires *time.Time) string {
	e.t.Helper()
	raw := "tok-" + conn + "-" + strings.Join(scopes, ",") + "-" + time.Now().Format(time.RFC3339Nano)
	if err := e.st.Directory().CreateSCIMToken(context.Background(), &store.SCIMToken{TenantID: e.tn.ID, ConnectionID: conn, ID: "tok_" + HashToken(raw)[:12],
		Hash: HashToken(raw), Scopes: scopes, CreatedAt: testNow.Add(-time.Hour), ExpiresAt: expires}); err != nil {
		e.t.Fatal(err)
	}
	return raw
}

func (e *env) do(method, conn, path, token string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd *strings.Reader
	if s, ok := body.(string); ok {
		rd = strings.NewReader(s)
	} else if body != nil {
		raw, _ := json.Marshal(body)
		rd = strings.NewReader(string(raw))
	} else {
		rd = strings.NewReader("")
	}
	req, _ := http.NewRequest(method, e.srv.URL+"/scim/v2/connections/"+conn+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", MediaType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

const jdoe = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"e-jdoe","userName":"jdoe","displayName":"J Doe",
	"name":{"givenName":"J","familyName":"Doe"},"emails":[{"primary":true,"value":"jdoe@corp.test"}],"active":true}`

func TestSCIMUsers(t *testing.T) {
	e := newEnv(t)
	tok := e.tokens["con_a"]
	code, created := e.do("POST", "con_a", "/Users", tok, jdoe)
	if code != 201 || created["id"] != "samlp|corp-saml|e-jdoe" || created["externalId"] != "e-jdoe" || created["userName"] != "jdoe" || created["active"] != true {
		t.Fatalf("create %d %v", code, created)
	}
	u, err := e.st.Users().Get(context.Background(), e.tn.ID, "samlp|corp-saml|e-jdoe")
	if err != nil || u.Email != "jdoe@corp.test" || u.Name != "J Doe" || len(u.Identities) != 1 || u.Identities[0].UserID != "corp-saml|e-jdoe" {
		t.Fatalf("stored %+v %v", u, err)
	}
	// A later federated login with the same subject finds this user.
	if found, err := e.st.Users().FindByIdentity(context.Background(), e.tn.ID, "con_a", "e-jdoe"); err != nil || found.UserID != u.UserID {
		t.Fatalf("identity index %v %v", found, err)
	}
	if code, out := e.do("POST", "con_a", "/Users", tok, jdoe); code != 409 || out["scimType"] != "uniqueness" {
		t.Fatalf("duplicate %d %v", code, out)
	}
	code, got := e.do("GET", "con_a", "/Users/samlp|corp-saml|e-jdoe", tok, nil)
	if code != 200 || got["displayName"] != "J Doe" || got["meta"].(map[string]any)["resourceType"] != "User" {
		t.Fatalf("get %d %v", code, got)
	}
	e.do("POST", "con_a", "/Users", tok, strings.NewReplacer("e-jdoe", "e-asmith", `"jdoe"`, `"asmith"`, "jdoe@", "asmith@").Replace(jdoe))
	for filter, want := range map[string]int{
		`userName eq "jdoe"`: 1, `externalId eq "e-asmith"`: 1, `emails[type eq "work"].value eq "x"`: 0,
		`emails.value eq "asmith@corp.test"`: 1, `userName eq "jdoe" or userName eq "asmith"`: 2, `active eq true and userName eq "jdoe"`: 1,
		`id eq "samlp|corp-saml|e-jdoe"`: 1,
	} {
		code, list := e.do("GET", "con_a", "/Users?filter="+urlEscape(filter), tok, nil)
		if code != 200 || int(list["totalResults"].(float64)) != want {
			t.Errorf("filter %s: %d %v", filter, code, list["totalResults"])
		}
	}
	if code, out := e.do("GET", "con_a", "/Users?filter="+urlEscape(`userName co "j"`), tok, nil); code != 400 || out["scimType"] != "invalidFilter" {
		t.Errorf("unsupported operator %d %v", code, out)
	}
	if code, out := e.do("GET", "con_a", "/Users?filter="+urlEscape(`title eq "x"`), tok, nil); code != 400 || out["scimType"] != "invalidFilter" {
		t.Errorf("unmapped attribute %d %v", code, out)
	}
	code, page := e.do("GET", "con_a", "/Users?startIndex=2&count=1", tok, nil)
	if code != 200 || page["totalResults"].(float64) != 2 || page["itemsPerPage"].(float64) != 1 || page["startIndex"].(float64) != 2 {
		t.Errorf("paging %d %v", code, page)
	}
	// PUT replaces; the user ID attribute cannot change.
	code, put := e.do("PUT", "con_a", "/Users/samlp|corp-saml|e-jdoe", tok, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"e-jdoe","userName":"jdoe2"}`)
	if code != 200 || put["userName"] != "jdoe2" || put["displayName"] != nil {
		t.Fatalf("put %d %v", code, put)
	}
	if code, out := e.do("PUT", "con_a", "/Users/samlp|corp-saml|e-jdoe", tok, `{"externalId":"other","userName":"x"}`); code != 400 || out["scimType"] != "mutability" {
		t.Errorf("subject change %d %v", code, out)
	}
	code, patched := e.do("PATCH", "con_a", "/Users/samlp|corp-saml|e-jdoe", tok, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"displayName","value":"Jay Doe"},{"op":"add","path":"name.givenName","value":"Jay"}]}`)
	if code != 200 || patched["displayName"] != "Jay Doe" || patched["userName"] != "jdoe2" || patched["name"].(map[string]any)["givenName"] != "Jay" {
		t.Fatalf("patch %d %v", code, patched)
	}
	for name, body := range map[string]string{
		"password":   `{"externalId":"e-p","userName":"p","password":"x"}`,
		"no subject": `{"userName":"p"}`,
		"bad json":   `{"userName":`,
		"bad name":   `{"externalId":"e-q","displayName":42}`,
	} {
		if code, _ := e.do("POST", "con_a", "/Users", tok, body); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _ := e.do("DELETE", "con_a", "/Users/samlp|corp-saml|e-asmith", tok, nil); code != 204 {
		t.Fatalf("delete %d", code)
	}
	if _, err := e.st.Users().Get(context.Background(), e.tn.ID, "samlp|corp-saml|e-asmith"); err == nil {
		t.Fatal("user survived DELETE")
	}
	if code, _ := e.do("GET", "con_a", "/Users/samlp|corp-saml|e-asmith", tok, nil); code != 404 {
		t.Fatalf("deleted user %d", code)
	}
}

func urlEscape(s string) string {
	return strings.NewReplacer(" ", "%20", `"`, "%22", "|", "%7C", "[", "%5B", "]", "%5D").Replace(s)
}

// TestSCIMConnectionIsolation is Plan 37c Review Focus 1: a token acts only
// on its own connection's users.
func TestSCIMConnectionIsolation(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.do("POST", "con_b", "/Users", e.tokens["con_b"], jdoe); code != 201 {
		t.Fatalf("seed user %d", code)
	}
	b := "/Users/oidc|corp-oidc|e-jdoe"
	for _, m := range []string{"GET", "PUT", "PATCH", "DELETE"} {
		body := `{"externalId":"e-jdoe","userName":"x"}`
		if m == "PATCH" {
			body = `{"Operations":[{"op":"replace","path":"userName","value":"x"}]}`
		}
		// Connection A's token at connection A's endpoint: B's user is not there.
		if code, _ := e.do(m, "con_a", b, e.tokens["con_a"], body); code != 404 {
			t.Errorf("%s B's user via A: %d", m, code)
		}
		// Connection A's token at connection B's endpoint: refused.
		if code, _ := e.do(m, "con_b", b, e.tokens["con_a"], body); code != 401 {
			t.Errorf("%s with A's token on B: %d", m, code)
		}
	}
	if code, list := e.do("GET", "con_a", "/Users", e.tokens["con_a"], nil); code != 200 || list["totalResults"].(float64) != 0 {
		t.Errorf("A lists B's users: %v", list)
	}
	if u, err := e.st.Users().Get(context.Background(), e.tn.ID, "oidc|corp-oidc|e-jdoe"); err != nil || u.Nickname != "jdoe" {
		t.Fatalf("B's user changed: %+v %v", u, err)
	}
	// Token problems.
	expired := testNow.Add(-time.Minute)
	for name, tc := range map[string]struct {
		conn, token string
		want        int
	}{
		"no token":          {"con_a", "", 401},
		"unknown token":     {"con_a", "nope", 401},
		"expired":           {"con_a", e.token("con_a", allScopes, &expired), 401},
		"missing scope":     {"con_a", e.tokenAt("con_a", []string{"post:users"}), 403},
		"non-SCIM strategy": {"con_db", e.tokens["con_a"], 401},
	} {
		if code, out := e.do("GET", tc.conn, "/Users", tc.token, nil); code != tc.want {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
}

// tokenAt issues a token after deleting an old one to stay within the limit.
func (e *env) tokenAt(conn string, scopes []string) string {
	toks, _ := e.st.Directory().ListSCIMTokens(context.Background(), e.tn.ID, conn)
	for _, tk := range toks {
		if tk.Hash != HashToken(e.tokens[conn]) {
			_ = e.st.Directory().DeleteSCIMToken(context.Background(), e.tn.ID, conn, tk.ID)
		}
	}
	return e.token(conn, scopes, nil)
}

// TestSCIMDeactivate is Plan 37c Review Focus 2: active=false blocks the
// user, ends sessions (with back-channel logout) and revokes refresh tokens.
func TestSCIMDeactivate(t *testing.T) {
	e := newEnv(t)
	tok := e.tokens["con_a"]
	if code, _ := e.do("POST", "con_a", "/Users", tok, jdoe); code != 201 {
		t.Fatal("create")
	}
	ctx := context.Background()
	uid := "samlp|corp-saml|e-jdoe"
	if err := e.st.Sessions().Create(ctx, &store.LoginSession{TenantID: e.tn.ID, ID: "ses_1", TokenHash: "th", UserID: uid, CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour), IdleExpiresAt: testNow.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.RefreshTokens().Create(ctx, &store.RefreshToken{TenantID: e.tn.ID, ID: "rt_1", TokenHash: "rh", FamilyID: "f1", UserID: uid, ClientID: "c1", CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	before, _ := e.st.Users().Get(ctx, e.tn.ID, uid)
	code, out := e.do("PATCH", "con_a", "/Users/"+uid, tok, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`)
	if code != 200 || out["active"] != false {
		t.Fatalf("deactivate %d %v", code, out)
	}
	u, _ := e.st.Users().Get(ctx, e.tn.ID, uid)
	if !u.Blocked || u.Version <= before.Version {
		t.Fatalf("not blocked or version not bumped: %+v", u)
	}
	if len(e.ended) != 1 || e.ended[0] != uid {
		t.Fatalf("sessions not ended through the logout path: %v", e.ended)
	}
	if ss, _ := e.st.Sessions().ListByUser(ctx, e.tn.ID, uid); len(ss) != 0 {
		t.Fatalf("sessions survived: %d", len(ss))
	}
	rt, err := e.st.RefreshTokens().Get(ctx, e.tn.ID, "rt_1")
	if err == nil && rt.RevokedAt == nil {
		t.Fatal("refresh token not revoked")
	}
	// Already inactive: no second logout; reactivation unblocks.
	e.do("PATCH", "con_a", "/Users/"+uid, tok, `{"Operations":[{"op":"replace","path":"active","value":false}]}`)
	if len(e.ended) != 1 {
		t.Fatalf("logout repeated: %v", e.ended)
	}
	if code, out := e.do("PATCH", "con_a", "/Users/"+uid, tok, `{"Operations":[{"op":"replace","value":{"active":true}}]}`); code != 200 || out["active"] != true {
		t.Fatalf("reactivate %d %v", code, out)
	}
}
