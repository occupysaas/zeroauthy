package mgmt_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

var allCGScopes = []string{"read:client_grants", "create:client_grants", "update:client_grants", "delete:client_grants"}

// cgEnv is an rsEnv with an application to grant to, and an API.
type cgEnv struct {
	*rsEnv
	client string
}

const ordersAPI = "https://api.orders.test/v1"

func newCGEnv(t *testing.T) *cgEnv {
	t.Helper()
	e := &cgEnv{rsEnv: newRSEnv(t)}
	e.client = e.clientsEnv.mustCreate(t, map[string]any{"name": "M2M", "app_type": "non_interactive"})["client_id"].(string)
	e.rsEnv.mustCreate(t, map[string]any{"identifier": ordersAPI, "scopes": []map[string]any{{"value": "read:orders"}, {"value": "write:orders"}}})
	return e
}

func (e *cgEnv) newClient(t *testing.T) string {
	t.Helper()
	return e.clientsEnv.mustCreate(t, map[string]any{"name": "Another", "app_type": "non_interactive"})["client_id"].(string)
}

func (e *cgEnv) create(t *testing.T, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.call(t, e.tn, m2mCaller(allCGScopes...), "POST", "/api/v2/client-grants", body, e.h.CreateClientGrant)
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *cgEnv) mustCreate(t *testing.T, body any) map[string]any {
	t.Helper()
	rec, out := e.create(t, body)
	if rec.Code != 201 {
		t.Fatalf("create %v = %d %s", body, rec.Code, rec.Body)
	}
	return out
}

func (e *cgEnv) grant(t *testing.T, scopes ...string) map[string]any {
	t.Helper()
	return e.mustCreate(t, map[string]any{"client_id": e.client, "audience": ordersAPI, "scope": scopes})
}

func (e *cgEnv) get(t *testing.T, id string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.call(t, e.tn, m2mCaller("read:client_grants"), "GET", "/api/v2/client-grants/"+id, nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetClientGrant(w, r, id) })
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *cgEnv) patch(t *testing.T, id string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.call(t, e.tn, m2mCaller(allCGScopes...), "PATCH", "/api/v2/client-grants/"+id, body, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateClientGrant(w, r, id) })
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *cgEnv) del(t *testing.T, id string) *httptest.ResponseRecorder {
	t.Helper()
	rec, _ := e.call(t, e.tn, m2mCaller(allCGScopes...), "DELETE", "/api/v2/client-grants/"+id, nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteClientGrant(w, r, id) })
	return rec
}

func (e *cgEnv) list(t *testing.T, query string) (*httptest.ResponseRecorder, any) {
	t.Helper()
	return e.call(t, e.tn, m2mCaller("read:client_grants"), "GET", "/api/v2/client-grants"+query, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetClientGrants(w, r, mgmtapi.GetClientGrantsParams{})
	})
}

var grantID = regexp.MustCompile(`^cgr_[A-Za-z0-9]{16}$`)

// A8: a grant made with a client, an audience and scopes.
func TestCreateClientGrant(t *testing.T) {
	e := newCGEnv(t)
	out := e.grant(t, "read:orders")
	id, _ := out["id"].(string)
	if !grantID.MatchString(id) || out["client_id"] != e.client || out["audience"] != ordersAPI ||
		out["subject_type"] != "client" || !slices.Equal(strs(out["scope"]), []string{"read:orders"}) || len(out) != 5 {
		t.Fatalf("create = %v", out)
	}
	g, err := e.st.ClientGrants().Find(context.Background(), e.tn.ID, e.client, ordersAPI, store.SubjectTypeClient)
	if err != nil || g.ID != id || g.Origin != store.OriginAPI || g.AllowAllScopes || !slices.Equal(g.Scopes, []string{"read:orders"}) || g.CreatedAt.IsZero() {
		t.Errorf("stored = %+v, %v", g, err)
	}

	t.Run("user subject type", func(t *testing.T) {
		u := e.mustCreate(t, map[string]any{"client_id": e.client, "audience": ordersAPI, "subject_type": "user", "scope": []string{"write:orders"}})
		if u["subject_type"] != "user" || u["id"] == id {
			t.Errorf("user grant = %v", u)
		}
	})
	t.Run("empty scope", func(t *testing.T) {
		c := e.newClient(t)
		out := e.mustCreate(t, map[string]any{"client_id": c, "audience": ordersAPI, "scope": []string{}})
		if s, ok := out["scope"].([]any); !ok || len(s) != 0 {
			t.Errorf("scope = %#v, want []", out["scope"])
		}
	})
	t.Run("allow all scopes", func(t *testing.T) {
		c := e.newClient(t)
		out := e.mustCreate(t, map[string]any{"client_id": c, "audience": ordersAPI, "allow_all_scopes": true})
		if _, has := out["scope"]; has || out["allow_all_scopes"] != true {
			t.Errorf("allow_all_scopes grant = %v", out)
		}
		g, err := e.st.ClientGrants().Find(context.Background(), e.tn.ID, c, ordersAPI, store.SubjectTypeClient)
		if err != nil || !g.AllowAllScopes || len(g.Scopes) != 0 {
			t.Errorf("stored = %+v, %v", g, err)
		}
	})
	t.Run("duplicate scopes are dropped", func(t *testing.T) {
		c := e.newClient(t)
		out := e.mustCreate(t, map[string]any{"client_id": c, "audience": ordersAPI, "scope": []string{"read:orders", "read:orders"}})
		if got := strs(out["scope"]); !slices.Equal(got, []string{"read:orders"}) {
			t.Errorf("scope = %v", got)
		}
	})
}

func TestCreateClientGrantRefusals(t *testing.T) {
	e := newCGEnv(t)
	e.grant(t, "read:orders")
	other := e.newClient(t)
	cases := []struct {
		name   string
		body   any
		status int
		code   string
	}{
		{"not an object", `[1]`, 400, "invalid_body"},
		{"no client_id", map[string]any{"audience": ordersAPI, "scope": []string{}}, 400, "invalid_body"},
		{"no audience", map[string]any{"client_id": other, "scope": []string{}}, 400, "invalid_body"},
		{"empty client_id", map[string]any{"client_id": "", "audience": ordersAPI, "scope": []string{}}, 400, "invalid_body"},
		{"no scope", map[string]any{"client_id": other, "audience": ordersAPI}, 400, "invalid_body"},
		{"allow_all_scopes false alone", map[string]any{"client_id": other, "audience": ordersAPI, "allow_all_scopes": false}, 400, "invalid_body"},
		{"scope null", map[string]any{"client_id": other, "audience": ordersAPI, "scope": nil}, 400, "invalid_body"},
		{"scope not a list", map[string]any{"client_id": other, "audience": ordersAPI, "scope": "read:orders"}, 400, "invalid_body"},
		{"allow all with scopes", map[string]any{"client_id": other, "audience": ordersAPI, "allow_all_scopes": true, "scope": []string{"read:orders"}}, 400, "invalid_body"},
		{"unknown property", map[string]any{"client_id": other, "audience": ordersAPI, "scope": []string{}, "colour": "blue"}, 400, "invalid_body"},
		{"id is not accepted", map[string]any{"client_id": other, "audience": ordersAPI, "scope": []string{}, "id": "cgr_x"}, 400, "invalid_body"},
		{"bad subject type", map[string]any{"client_id": other, "audience": ordersAPI, "scope": []string{}, "subject_type": "robot"}, 400, "invalid_body"},
		{"undefined scope", map[string]any{"client_id": other, "audience": ordersAPI, "scope": []string{"read:orders", "delete:orders"}}, 400, "invalid_body"},
		{"unknown client", map[string]any{"client_id": "nope", "audience": ordersAPI, "scope": []string{}}, 404, "inexistent_client"},
		{"unknown audience", map[string]any{"client_id": other, "audience": "https://nope.test", "scope": []string{}}, 404, "inexistent_resource_server"},
		{"audience is case-sensitive", map[string]any{"client_id": other, "audience": strings.ToUpper(ordersAPI), "scope": []string{}}, 404, "inexistent_resource_server"},
		{"duplicate", map[string]any{"client_id": e.client, "audience": ordersAPI, "scope": []string{}}, 409, "client_grant_conflict"},
		{"duplicate with allow_all_scopes", map[string]any{"client_id": e.client, "audience": ordersAPI, "allow_all_scopes": true}, 409, "client_grant_conflict"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, _ := e.create(t, tc.body)
			wantError(t, rec, tc.status, tc.code)
		})
	}
	// Nothing was created by the refusals.
	if _, total, _ := e.st.ClientGrants().List(context.Background(), e.tn.ID, store.ClientGrantFilter{}, store.Page{}); total != 1 {
		t.Errorf("%d grants, want 1", total)
	}
}

// D-0041: the organization and rich authorization fields are accepted only
// with their inert values, and none is stored or reported.
func TestClientGrantInertFields(t *testing.T) {
	e := newCGEnv(t)
	base := func(extra map[string]any) map[string]any {
		b := map[string]any{"client_id": e.client, "audience": ordersAPI, "scope": []string{"read:orders"}}
		for k, v := range extra {
			b[k] = v
		}
		return b
	}
	for _, bad := range []map[string]any{
		{"organization_usage": "allow"}, {"organization_usage": "require"}, {"organization_usage": "bogus"}, {"organization_usage": 1},
		{"allow_any_organization": true}, {"allow_any_organization": "yes"},
		{"authorization_details_types": []string{"payment"}}, {"authorization_details_types": "payment"},
		{"default_for": "third_party_clients"},
	} {
		rec, _ := e.create(t, base(bad))
		wantError(t, rec, 400, "invalid_body")
	}
	out := e.mustCreate(t, base(map[string]any{"organization_usage": "deny", "allow_any_organization": false, "authorization_details_types": []string{}, "default_for": nil}))
	for _, k := range []string{"organization_usage", "allow_any_organization", "authorization_details_types", "default_for"} {
		if _, has := out[k]; has {
			t.Errorf("%s reported: %v", k, out)
		}
	}
	id := out["id"].(string)
	if rec, _ := e.patch(t, id, map[string]any{"allow_any_organization": true}); rec.Code != 400 {
		t.Errorf("patch allow_any_organization true = %d", rec.Code)
	}
	// Only inert organization fields: accepted, nothing changes.
	rec, out := e.patch(t, id, map[string]any{"organization_usage": "deny", "allow_any_organization": false})
	if rec.Code != 200 || !slices.Equal(strs(out["scope"]), []string{"read:orders"}) {
		t.Errorf("patch inert = %d %s", rec.Code, rec.Body)
	}
}

func TestGetClientGrant(t *testing.T) {
	e := newCGEnv(t)
	made := e.grant(t, "read:orders")
	rec, out := e.get(t, made["id"].(string))
	if rec.Code != 200 || out["id"] != made["id"] || out["audience"] != ordersAPI || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("get = %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.get(t, "cgr_0000000000000000")
	wantError(t, rec, 404, "inexistent_client_grant")
	for _, bad := range []string{"nope", "cg_abc", "cgr_", "CGR_abc", "cgr_a-b", "cgr_" + strings.Repeat("a", 65)} {
		rec, _ = e.get(t, bad)
		wantError(t, rec, 400, "invalid_uri")
	}
	// Another tenant's grant is not found.
	other := newCGEnv(t)
	rec, _ = other.get(t, made["id"].(string))
	wantError(t, rec, 404, "inexistent_client_grant")
}

// Older seeded grants have 24 characters after cgr_; they are in the right
// format.
func TestClientGrantLongSeededID(t *testing.T) {
	e := newCGEnv(t)
	id := "cgr_" + strings.Repeat("aB3", 8)
	if err := e.st.ClientGrants().Create(context.Background(), &store.ClientGrant{TenantID: e.tn.ID, ID: id, ClientID: e.client, Audience: ordersAPI,
		Scopes: []string{"read:orders"}, SubjectType: store.SubjectTypeClient, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if rec, out := e.get(t, id); rec.Code != 200 || out["id"] != id {
		t.Errorf("get = %d %s", rec.Code, rec.Body)
	}
	if rec, out := e.patch(t, id, map[string]any{"scope": []string{"write:orders"}}); rec.Code != 200 || !slices.Equal(strs(out["scope"]), []string{"write:orders"}) {
		t.Errorf("patch = %d %s", rec.Code, rec.Body)
	}
	if rec := e.del(t, id); rec.Code != 204 {
		t.Errorf("delete = %d", rec.Code)
	}
}

// A10.
func TestUpdateClientGrant(t *testing.T) {
	e := newCGEnv(t)
	id := e.grant(t, "read:orders")["id"].(string)

	rec, out := e.patch(t, id, map[string]any{"scope": []string{"write:orders", "read:orders"}})
	if rec.Code != 200 || !slices.Equal(strs(out["scope"]), []string{"write:orders", "read:orders"}) || out["id"] != id || out["audience"] != ordersAPI {
		t.Fatalf("patch scope = %d %s", rec.Code, rec.Body)
	}
	g, _ := e.st.ClientGrants().Find(context.Background(), e.tn.ID, e.client, ordersAPI, store.SubjectTypeClient)
	if g.Origin != store.OriginAPI || g.ID != id {
		t.Errorf("stored = %+v", g)
	}

	rec, out = e.patch(t, id, map[string]any{"scope": []string{}})
	if rec.Code != 200 || len(out["scope"].([]any)) != 0 {
		t.Errorf("patch to no scope = %d %s", rec.Code, rec.Body)
	}

	rec, out = e.patch(t, id, map[string]any{"allow_all_scopes": true})
	if _, has := out["scope"]; rec.Code != 200 || has || out["allow_all_scopes"] != true {
		t.Errorf("patch allow_all_scopes = %d %s", rec.Code, rec.Body)
	}
	g, _ = e.st.ClientGrants().Find(context.Background(), e.tn.ID, e.client, ordersAPI, store.SubjectTypeClient)
	if !g.AllowAllScopes || len(g.Scopes) != 0 {
		t.Errorf("stored = %+v", g)
	}

	// Explicit scopes replace allow_all_scopes.
	rec, out = e.patch(t, id, map[string]any{"scope": []string{"read:orders"}})
	if _, has := out["allow_all_scopes"]; rec.Code != 200 || has || !slices.Equal(strs(out["scope"]), []string{"read:orders"}) {
		t.Errorf("patch scope after allow_all = %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.patch(t, id, map[string]any{"allow_all_scopes": true, "scope": []string{"read:orders"}})
	wantError(t, rec, 400, "invalid_body")

	for name, body := range map[string]any{
		"empty body":         map[string]any{},
		"client_id":          map[string]any{"client_id": e.client},
		"audience":           map[string]any{"audience": ordersAPI},
		"subject_type":       map[string]any{"subject_type": "user"},
		"unknown":            map[string]any{"colour": "blue"},
		"undefined scope":    map[string]any{"scope": []string{"delete:orders"}},
		"scope not a list":   map[string]any{"scope": 3},
		"scope null":         map[string]any{"scope": nil},
		"allow_all not bool": map[string]any{"allow_all_scopes": "yes"},
		"not an object":      `"x"`,
	} {
		t.Run(name, func(t *testing.T) {
			rec, _ := e.patch(t, id, body)
			wantError(t, rec, 400, "invalid_body")
		})
	}
	if rec, out := e.get(t, id); rec.Code != 200 || !slices.Equal(strs(out["scope"]), []string{"read:orders"}) {
		t.Errorf("a refused patch changed the grant: %s", rec.Body)
	}

	rec, _ = e.patch(t, "cgr_0000000000000000", map[string]any{"scope": []string{}})
	wantError(t, rec, 404, "inexistent_client_grant")
	rec, _ = e.patch(t, "nope", map[string]any{"scope": []string{}})
	wantError(t, rec, 400, "invalid_uri")
	// The ID is checked before the body.
	rec, _ = e.patch(t, "nope", map[string]any{})
	wantError(t, rec, 400, "invalid_uri")
}

// An API's scope that goes also goes from the grants, so PATCH never sees a
// grant naming an undefined scope (review focus 3); a PATCH naming a scope
// that went is refused.
func TestUpdateClientGrantAfterScopeRemoval(t *testing.T) {
	e := newCGEnv(t)
	id := e.grant(t, "read:orders", "write:orders")["id"].(string)
	rs, err := e.st.ResourceServers().GetByIdentifier(context.Background(), e.tn.ID, ordersAPI)
	if err != nil {
		t.Fatal(err)
	}
	if rec, _ := e.rsEnv.patch(t, rs.ID, map[string]any{"scopes": []map[string]any{{"value": "read:orders"}}}); rec.Code != 200 {
		t.Fatalf("patch API = %d %s", rec.Code, rec.Body)
	}
	if _, out := e.get(t, id); !slices.Equal(strs(out["scope"]), []string{"read:orders"}) {
		t.Errorf("scope = %v", out["scope"])
	}
	rec, _ := e.patch(t, id, map[string]any{"scope": []string{"write:orders"}})
	wantError(t, rec, 400, "invalid_body")
}

func TestDeleteClientGrant(t *testing.T) {
	e := newCGEnv(t)
	id := e.grant(t, "read:orders")["id"].(string)
	for i := range 2 {
		rec := e.del(t, id)
		if rec.Code != 204 || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("delete #%d = %d %q", i, rec.Code, rec.Body)
		}
	}
	if rec := e.del(t, "cgr_0000000000000000"); rec.Code != 204 {
		t.Errorf("delete unknown = %d", rec.Code)
	}
	for _, bad := range []string{"nope", "cgr_", "cgr_a/b"} {
		wantError(t, e.del(t, bad), 400, "invalid_uri")
	}
	rec, _ := e.get(t, id)
	wantError(t, rec, 404, "inexistent_client_grant")
	// Granting again after the delete works.
	e.grant(t, "read:orders")
}

// Review focus 1.
func TestClientGrantManagementAPI(t *testing.T) {
	e := newCGEnv(t)
	own := e.mapi.Identifier
	mgmtScopes := []string{"read:clients", "read:client_grants"}

	t.Run("management scopes on the tenant's own", func(t *testing.T) {
		out := e.mustCreate(t, map[string]any{"client_id": e.client, "audience": own, "scope": mgmtScopes})
		if out["subject_type"] != "client" || !slices.Equal(strs(out["scope"]), mgmtScopes) {
			t.Errorf("grant = %v", out)
		}
	})
	c := e.newClient(t)
	t.Run("only management scopes", func(t *testing.T) {
		rec, _ := e.create(t, map[string]any{"client_id": c, "audience": own, "scope": []string{"read:clients", "read:orders"}})
		wantError(t, rec, 400, "invalid_body")
	})
	t.Run("not for users", func(t *testing.T) {
		rec, _ := e.create(t, map[string]any{"client_id": c, "audience": own, "subject_type": "user", "scope": []string{"read:clients"}})
		wantError(t, rec, 400, "invalid_body")
	})
	t.Run("another tenant's", func(t *testing.T) {
		for _, aud := range []string{"https://globex.example.com/api/v2/", "https://login.globex.test/api/v2/"} {
			rec, _ := e.create(t, map[string]any{"client_id": c, "audience": aud, "scope": []string{"read:clients"}})
			wantError(t, rec, 400, "invalid_body")
		}
	})
	t.Run("an ordinary API with such an identifier", func(t *testing.T) {
		const aud = "https://api.example.com/api/v2/"
		e.rsEnv.mustCreate(t, map[string]any{"identifier": aud, "scopes": []map[string]any{{"value": "read:things"}}})
		out := e.mustCreate(t, map[string]any{"client_id": c, "audience": aud, "scope": []string{"read:things"}})
		if !slices.Equal(strs(out["scope"]), []string{"read:things"}) {
			t.Errorf("grant = %v", out)
		}
		rec, _ := e.create(t, map[string]any{"client_id": e.newClient(t), "audience": aud, "scope": []string{"read:clients"}})
		wantError(t, rec, 400, "invalid_body")
	})
	t.Run("the operator API", func(t *testing.T) {
		rec, _ := e.create(t, map[string]any{"client_id": c, "audience": "urn:zeroauthy:management", "scope": []string{"read:tenants"}})
		wantError(t, rec, 400, "invalid_body")
		rec, _ = e.create(t, map[string]any{"client_id": c, "audience": "urn:zeroauthy:management", "allow_all_scopes": true})
		wantError(t, rec, 400, "invalid_body")
	})
	t.Run("allow_all_scopes", func(t *testing.T) {
		out := e.mustCreate(t, map[string]any{"client_id": c, "audience": own, "allow_all_scopes": true})
		if out["allow_all_scopes"] != true {
			t.Errorf("grant = %v", out)
		}
		// All the Management API's scopes, and never user grants.
		g, _ := e.st.ClientGrants().Find(context.Background(), e.tn.ID, c, own, store.SubjectTypeClient)
		if got := g.EffectiveScopes(e.mapi.Scopes); len(got) != len(tenantsetup.ManagementAPIScopes) {
			t.Errorf("effective scopes = %d, want %d", len(got), len(tenantsetup.ManagementAPIScopes))
		}
	})
	t.Run("patch keeps the rules", func(t *testing.T) {
		id := e.mustCreate(t, map[string]any{"client_id": e.newClient(t), "audience": own, "scope": []string{"read:clients"}})["id"].(string)
		rec, _ := e.patch(t, id, map[string]any{"scope": []string{"read:orders"}})
		wantError(t, rec, 400, "invalid_body")
		rec, out := e.patch(t, id, map[string]any{"scope": []string{"delete:clients"}})
		if rec.Code != 200 || !slices.Equal(strs(out["scope"]), []string{"delete:clients"}) {
			t.Errorf("patch = %d %s", rec.Code, rec.Body)
		}
	})
}

// The tenant's Management API is created with its first token; a grant to
// it before then creates it.
func TestClientGrantManagementAPINotYetCreated(t *testing.T) {
	e := newClientsEnv(t)
	e.h.BaseDomain = baseDomain
	c := e.mustCreate(t, map[string]any{"name": "M2M", "app_type": "non_interactive"})["client_id"].(string)
	own := "https://acme.example.com/api/v2/"
	rec, out := e.call(t, e.tn, m2mCaller(allCGScopes...), "POST", "/api/v2/client-grants", map[string]any{"client_id": c, "audience": own, "scope": []string{"read:clients"}}, e.h.CreateClientGrant)
	if rec.Code != 201 {
		t.Fatalf("create = %d %v", rec.Code, out)
	}
	if rs, err := e.st.ResourceServers().GetByIdentifier(context.Background(), e.tn.ID, own); err != nil || !rs.IsSystem {
		t.Errorf("Management API = %+v, %v", rs, err)
	}
}

// A9.
func TestListClientGrants(t *testing.T) {
	e := newCGEnv(t)
	ctx := context.Background()
	e.rsEnv.mustCreate(t, map[string]any{"identifier": "https://api.two.test", "scopes": []map[string]any{{"value": "s"}}})
	c2 := e.newClient(t)
	mk := func(id, client, aud, subject string) {
		t.Helper()
		if err := e.st.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: e.tn.ID, ID: id, ClientID: client, Audience: aud, Scopes: []string{}, SubjectType: subject, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	mk("cgr_b", e.client, ordersAPI, store.SubjectTypeClient)
	mk("cgr_a", c2, ordersAPI, store.SubjectTypeClient)
	mk("cgr_c", e.client, "https://api.two.test", store.SubjectTypeClient)
	mk("cgr_d", e.client, ordersAPI, store.SubjectTypeUser)
	mk("cgr_A", c2, "https://api.two.test", store.SubjectTypeUser)

	ids := func(v any) []string {
		t.Helper()
		var list []any
		switch v := v.(type) {
		case []any:
			list = v
		case map[string]any:
			list = v["client_grants"].([]any)
		default:
			t.Fatalf("list = %#v", v)
		}
		out := []string{}
		for _, g := range list {
			out = append(out, g.(map[string]any)["id"].(string))
		}
		return out
	}
	q := func(query string) []string {
		t.Helper()
		rec, v := e.list(t, query)
		if rec.Code != 200 {
			t.Fatalf("%s = %d %s", query, rec.Code, rec.Body)
		}
		return ids(v)
	}
	// By ID in byte order, not creation order.
	if got := q(""); !slices.Equal(got, []string{"cgr_A", "cgr_a", "cgr_b", "cgr_c", "cgr_d"}) {
		t.Errorf("all = %v", got)
	}
	for query, want := range map[string][]string{
		"?client_id=" + e.client:                                               {"cgr_b", "cgr_c", "cgr_d"},
		"?audience=" + ordersAPI:                                               {"cgr_a", "cgr_b", "cgr_d"},
		"?audience=" + strings.ToUpper(ordersAPI):                              {},
		"?audience=https://api.two.test&subject_type=user":                     {"cgr_A"},
		"?client_id=" + e.client + "&subject_type=client":                      {"cgr_b", "cgr_c"},
		"?client_id=" + e.client + "&audience=" + ordersAPI:                    {"cgr_b", "cgr_d"},
		"?client_id=" + c2 + "&audience=" + ordersAPI + "&subject_type=client": {"cgr_a"},
		"?client_id=nobody":                                                    {},
		"?per_page=2":                                                          {"cgr_A", "cgr_a"},
		"?per_page=2&page=1":                                                   {"cgr_b", "cgr_c"},
		"?per_page=2&page=2":                                                   {"cgr_d"},
		"?per_page=2&page=9":                                                   {},
	} {
		if got := q(query); !slices.Equal(got, want) {
			t.Errorf("%s = %v, want %v", query, got, want)
		}
	}

	t.Run("totals", func(t *testing.T) {
		rec, v := e.list(t, "?include_totals=true&per_page=2&page=1")
		m, _ := v.(map[string]any)
		if rec.Code != 200 || m["total"] != float64(5) || m["start"] != float64(2) || m["limit"] != float64(2) || !slices.Equal(ids(v), []string{"cgr_b", "cgr_c"}) {
			t.Errorf("totals = %d %s", rec.Code, rec.Body)
		}
		rec, _ = e.list(t, "?include_totals=true&client_id=nobody")
		if !strings.Contains(rec.Body.String(), `"client_grants":[]`) || !strings.Contains(rec.Body.String(), `"total":0`) {
			t.Errorf("empty = %s", rec.Body)
		}
	})
	t.Run("refusals", func(t *testing.T) {
		for _, query := range []string{"?per_page=101", "?page=-1", "?include_totals=maybe", "?subject_type=robot&client_id=x", "?client_id=has%20space", "?client_id=" + strings.Repeat("x", 256)} {
			rec, _ := e.list(t, query)
			wantError(t, rec, 400, "invalid_query_string")
		}
		// subject_type alone, and a bad checkpoint, have no errorCode.
		for _, query := range []string{"?subject_type=client", "?subject_type=user&take=5", "?from=garbage", "?from=" + "djE6bm9wZQ", "?take=2&from=" + forgedCursors()[0]} {
			rec, _ := e.list(t, query)
			if rec.Code != 400 || strings.Contains(rec.Body.String(), "errorCode") {
				t.Errorf("%s = %d %s, want 400 without errorCode", query, rec.Code, rec.Body)
			}
		}
		for _, query := range []string{"?take=0", "?take=101", "?take=x", "?take="} {
			rec, _ := e.list(t, query)
			wantError(t, rec, 400, "invalid_query_string")
		}
	})
	t.Run("another tenant is not listed", func(t *testing.T) {
		other := newCGEnv(t)
		if got := ids(func() any { _, v := other.list(t, ""); return v }()); len(got) != 0 {
			t.Errorf("other tenant lists %v", got)
		}
	})
}

// forgedCursors are values that decode but are not cursors.
func forgedCursors() []string {
	return []string{"dHdvOmNncl9h", "djE6Y2dyXyE"} // "two:cgr_a", "v1:cgr_!"
}

func TestCheckpointPaging(t *testing.T) {
	e := newCGEnv(t)
	ctx := context.Background()
	const n = 7
	for i := range n {
		if err := e.st.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: e.tn.ID, ID: fmt.Sprintf("cgr_%02d", i), ClientID: fmt.Sprintf("c%d", i),
			Audience: ordersAPI, Scopes: []string{}, SubjectType: store.SubjectTypeClient, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	page := func(query string) (ids []string, next string) {
		t.Helper()
		rec, v := e.list(t, query)
		m, ok := v.(map[string]any)
		if rec.Code != 200 || !ok {
			t.Fatalf("%s = %d %s", query, rec.Code, rec.Body)
		}
		for _, g := range m["client_grants"].([]any) {
			ids = append(ids, g.(map[string]any)["id"].(string))
		}
		next, _ = m["next"].(string)
		if _, has := m["next"]; has && next == "" {
			t.Errorf("%s: next is %v", query, m["next"])
		}
		for _, k := range []string{"total", "start", "limit"} {
			if _, has := m[k]; has {
				t.Errorf("%s: unexpected %s", query, k)
			}
		}
		return ids, next
	}

	t.Run("walk", func(t *testing.T) {
		var all []string
		query := "?take=3"
		for pages := 0; ; pages++ {
			if pages > n {
				t.Fatal("too many pages")
			}
			ids, next := page(query)
			all = append(all, ids...)
			if next == "" {
				if len(ids) == 0 {
					t.Error("the last page is empty")
				}
				break
			}
			if len(ids) != 3 {
				t.Errorf("a page with next has %d grants", len(ids))
			}
			query = "?take=3&from=" + next
		}
		if len(all) != n || !slices.IsSorted(all) || len(slices.Compact(slices.Clone(all))) != n {
			t.Errorf("walk = %v", all)
		}
	})
	t.Run("exact last page has no next", func(t *testing.T) {
		ids, next := page("?take=7")
		if len(ids) != 7 || next != "" {
			t.Errorf("take=7 = %v next %q", ids, next)
		}
		ids, next = page("?take=100")
		if len(ids) != 7 || next != "" {
			t.Errorf("take=100 = %v next %q", ids, next)
		}
		_, next = page("?take=6")
		ids, next2 := page("?take=6&from=" + next)
		if !slices.Equal(ids, []string{"cgr_06"}) || next2 != "" {
			t.Errorf("last = %v next %q", ids, next2)
		}
	})
	t.Run("default take and from alone", func(t *testing.T) {
		_, next := page("?take=2")
		ids, _ := page("?from=" + next)
		if len(ids) != 5 || ids[0] != "cgr_02" {
			t.Errorf("from alone = %v", ids)
		}
	})
	t.Run("take wins over page and include_totals", func(t *testing.T) {
		ids, _ := page("?take=2&page=3&per_page=1&include_totals=true")
		if !slices.Equal(ids, []string{"cgr_00", "cgr_01"}) {
			t.Errorf("ids = %v", ids)
		}
		// Even values the offset parameters would refuse.
		if ids, _ := page("?take=2&per_page=500&include_totals=maybe"); len(ids) != 2 {
			t.Errorf("ids = %v", ids)
		}
	})
	t.Run("filters apply to every page", func(t *testing.T) {
		ids, next := page("?take=2&client_id=c3")
		if !slices.Equal(ids, []string{"cgr_03"}) || next != "" {
			t.Errorf("filtered = %v next %q", ids, next)
		}
	})
	t.Run("grants added or removed between pages", func(t *testing.T) {
		ids, next := page("?take=3")
		if !slices.Equal(ids, []string{"cgr_00", "cgr_01", "cgr_02"}) {
			t.Fatalf("first = %v", ids)
		}
		// One before the cursor goes, one after it comes.
		if err := e.st.ClientGrants().Delete(ctx, e.tn.ID, "cgr_01"); err != nil {
			t.Fatal(err)
		}
		if err := e.st.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: e.tn.ID, ID: "cgr_025", ClientID: "late", Audience: ordersAPI, Scopes: []string{}, SubjectType: store.SubjectTypeClient, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		ids, _ = page("?take=10&from=" + next)
		if !slices.Equal(ids, []string{"cgr_025", "cgr_03", "cgr_04", "cgr_05", "cgr_06"}) {
			t.Errorf("after = %v", ids)
		}
	})
	t.Run("a cursor reaches only the caller's tenant", func(t *testing.T) {
		_, next := page("?take=2")
		other := newCGEnv(t)
		if err := other.st.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: other.tn.ID, ID: "cgr_zz", ClientID: "x", Audience: ordersAPI, Scopes: []string{}, SubjectType: store.SubjectTypeClient, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		rec, v := other.list(t, "?take=5&from="+next)
		var got []string
		for _, g := range v.(map[string]any)["client_grants"].([]any) {
			got = append(got, g.(map[string]any)["id"].(string))
		}
		if rec.Code != 200 || !slices.Equal(got, []string{"cgr_zz"}) {
			t.Errorf("other tenant with the cursor = %d %v", rec.Code, got)
		}
	})
	t.Run("the cursor is opaque", func(t *testing.T) {
		_, next := page("?take=2")
		if strings.Contains(next, "cgr_") {
			t.Errorf("cursor %q shows an ID", next)
		}
	})
}
