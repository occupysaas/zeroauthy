package mgmt_test

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

var orgScopes = []string{
	"read:organizations", "create:organizations", "update:organizations", "delete:organizations",
	"read:organization_connections", "create:organization_connections", "update:organization_connections", "delete:organization_connections",
	"read:organization_client_grants",
}

type orgEnv struct {
	*clientsEnv
	t      *testing.T
	caller mgmt.Caller
}

// Connections of the acme tenant used by the organization tests.
const (
	orgDB    = "con_orgdb000000000001"
	orgDB2   = "con_orgdb000000000002"
	orgOIDC  = "con_orgoidc0000000001"
	orgGhost = "con_ghost000000000001"
)

func newOrgEnv(t *testing.T) *orgEnv {
	t.Helper()
	e := newClientsEnv(t)
	ctx := context.Background()
	for _, c := range []store.Connection{
		{TenantID: e.tn.ID, ID: orgDB, Name: "org-db", Strategy: store.StrategyDatabase},
		{TenantID: e.tn.ID, ID: orgDB2, Name: "org-db-2", Strategy: store.StrategyDatabase},
		{TenantID: e.tn.ID, ID: orgOIDC, Name: "org-corp", Strategy: "oidc"},
	} {
		if err := e.st.Connections().Create(ctx, &c); err != nil {
			t.Fatal(err)
		}
	}
	return &orgEnv{clientsEnv: e, t: t, caller: m2mCaller(orgScopes...)}
}

// do calls fn as e.caller on tn and checks the status.
func (e *orgEnv) do(tn *store.Tenant, method, target string, body any, fn http.HandlerFunc, want int) any {
	e.t.Helper()
	rec, out := e.call(e.t, tn, e.caller, method, target, body, fn)
	if rec.Code != want {
		e.t.Fatalf("%s %s %v = %d %s, want %d", method, target, body, rec.Code, rec.Body, want)
	}
	return out
}

func (e *orgEnv) obj(method, target string, body any, fn http.HandlerFunc, want int) map[string]any {
	e.t.Helper()
	m, _ := e.do(e.tn, method, target, body, fn, want).(map[string]any)
	return m
}

func (e *orgEnv) list(target string, fn http.HandlerFunc) []any {
	e.t.Helper()
	l, ok := e.do(e.tn, "GET", target, nil, fn, 200).([]any)
	if !ok {
		e.t.Fatalf("GET %s: not a bare array", target)
	}
	return l
}

// fail checks the status and errorCode ("" for none) of a refused call.
func (e *orgEnv) fail(method, target string, body any, fn http.HandlerFunc, want int, code string) {
	e.t.Helper()
	out := e.obj(method, target, body, fn, want)
	got, has := out["errorCode"]
	if code == "" && has || code != "" && got != code {
		e.t.Errorf("%s %s %v errorCode=%v, want %q", method, target, body, got, code)
	}
}

func keysOf(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (e *orgEnv) create(body any, want int) map[string]any {
	e.t.Helper()
	return e.obj("POST", "/organizations", body, e.h.CreateOrganization, want)
}

func (e *orgEnv) get(id string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { e.h.GetOrganization(w, r, id) }
}
func (e *orgEnv) patch(id string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { e.h.UpdateOrganization(w, r, id) }
}
func (e *orgEnv) del(id string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { e.h.DeleteOrganization(w, r, id) }
}
func (e *orgEnv) byName(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { e.h.GetOrganizationByName(w, r, name) }
}
func (e *orgEnv) conns(id string, all bool) http.HandlerFunc {
	if all {
		return func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationAllConnections(w, r, id) }
	}
	return func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationConnections(w, r, id) }
}
func (e *orgEnv) addConn(id string, all bool) http.HandlerFunc {
	if all {
		return func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationAllConnection(w, r, id) }
	}
	return func(w http.ResponseWriter, r *http.Request) { e.h.CreateOrganizationConnection(w, r, id) }
}
func (e *orgEnv) conn(method, id, cid string, all bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case method == "GET" && all:
			e.h.GetOrganizationAllConnection(w, r, id, cid)
		case method == "GET":
			e.h.GetOrganizationConnection(w, r, id, cid)
		case method == "PATCH" && all:
			e.h.UpdateOrganizationAllConnection(w, r, id, cid)
		case method == "PATCH":
			e.h.UpdateOrganizationConnection(w, r, id, cid)
		case all:
			e.h.DeleteOrganizationAllConnection(w, r, id, cid)
		default:
			e.h.DeleteOrganizationConnection(w, r, id, cid)
		}
	}
}

func TestOrganizationsContract(t *testing.T) {
	e := newOrgEnv(t)

	// Minimal create: constant fields present, branding/metadata omitted,
	// never enabled_connections.
	o := e.create(map[string]any{"name": "acme-co"}, 201)
	id, _ := o["id"].(string)
	if !orgrules.ValidID(id) || o["display_name"] != "acme-co" || o["third_party_client_access"] != "block" || o["is_app_entitlement_active"] != false {
		t.Fatalf("create=%v", o)
	}
	if got := keysOf(o); !slices.Equal(got, []string{"display_name", "id", "is_app_entitlement_active", "name", "third_party_client_access"}) {
		t.Fatalf("create keys=%v", got)
	}
	e.fail("POST", "/organizations", map[string]any{"name": "acme-co"}, e.h.CreateOrganization, 409, "")

	// Full create echoes enabled_connections with the connection summary.
	full := e.create(map[string]any{
		"name": "full_org", "display_name": "Full Org", "third_party_client_access": "allow", "is_app_entitlement_active": false,
		"branding": map[string]any{"logo_url": "https://cdn.example.test/logo.png", "colors": map[string]any{"primary": "#112233", "page_background": "#fff"}},
		"metadata": map[string]any{"tier": "gold"},
		"enabled_connections": []any{
			map[string]any{"connection_id": orgDB},
			map[string]any{"connection_id": orgOIDC, "show_as_button": false, "assign_membership_on_login": true},
		},
	}, 201)
	fullID := full["id"].(string)
	ecs, _ := full["enabled_connections"].([]any)
	if len(ecs) != 2 || full["display_name"] != "Full Org" || full["third_party_client_access"] != "allow" {
		t.Fatalf("full=%v", full)
	}
	db := ecs[0].(map[string]any)
	if db["connection_id"] != orgDB || db["assign_membership_on_login"] != false || db["is_signup_enabled"] != false || db["show_as_button"] != true ||
		fmt.Sprint(db["connection"]) != "map[name:org-db strategy:auth0]" {
		t.Fatalf("db entry=%v", db)
	}
	if oidc := ecs[1].(map[string]any); oidc["show_as_button"] != false || fmt.Sprint(oidc["connection"]) != "map[name:org-corp strategy:oidc]" {
		t.Fatalf("oidc entry=%v", oidc)
	}
	if b := full["branding"].(map[string]any); b["logo_url"] != "https://cdn.example.test/logo.png" || fmt.Sprint(b["colors"]) != "map[page_background:#fff primary:#112233]" {
		t.Fatalf("branding=%v", b)
	}

	// enabled_connections on create needs create:organization_connections.
	e.caller = m2mCaller("create:organizations")
	e.fail("POST", "/organizations", map[string]any{"name": "scoped", "enabled_connections": []any{map[string]any{"connection_id": orgDB}}}, e.h.CreateOrganization, 403, "insufficient_scope")
	e.create(map[string]any{"name": "scoped"}, 201)
	e.caller = m2mCaller(orgScopes...)

	meta := func(n int) map[string]any {
		m := map[string]any{}
		for i := range n {
			m[fmt.Sprintf("k%d", i)] = "v"
		}
		return m
	}
	tooMany := []any{}
	for range 11 {
		tooMany = append(tooMany, map[string]any{"connection_id": orgDB})
	}
	for name, body := range map[string]map[string]any{
		"no name":                  {"display_name": "x"},
		"unknown property":         {"name": "x1", "colour": "blue"},
		"empty display_name":       {"name": "x2", "display_name": ""},
		"null display_name":        {"name": "x2", "display_name": nil},
		"upper-case name":          {"name": "Upper"},
		"leading hyphen":           {"name": "-lead"},
		"leading underscore":       {"name": "_lead"},
		"dot":                      {"name": "a.b"},
		"space":                    {"name": "a b"},
		"51 characters":            {"name": strings.Repeat("a", 51)},
		"26 metadata keys":         {"name": "x3", "metadata": meta(26)},
		"number metadata value":    {"name": "x3", "metadata": map[string]any{"a": 1}},
		"256 char metadata value":  {"name": "x3", "metadata": map[string]any{"a": strings.Repeat("v", 256)}},
		"bad metadata key":         {"name": "x3", "metadata": map[string]any{"a b": "v"}},
		"one color":                {"name": "x4", "branding": map[string]any{"colors": map[string]any{"primary": "#000000"}}},
		"empty colors":             {"name": "x4", "branding": map[string]any{"colors": map[string]any{}}},
		"word color":               {"name": "x4", "branding": map[string]any{"colors": map[string]any{"primary": "red", "page_background": "#000"}}},
		"http logo":                {"name": "x4", "branding": map[string]any{"logo_url": "http://cdn.example.test/l.png"}},
		"unknown branding":         {"name": "x4", "branding": map[string]any{"font": "x"}},
		"third party value":        {"name": "x5", "third_party_client_access": "maybe"},
		"null app entitlement":     {"name": "x5", "is_app_entitlement_active": nil},
		"token_quota":              {"name": "x5", "token_quota": map[string]any{}},
		"11 connections":           {"name": "x6", "enabled_connections": tooMany},
		"camelCase connection":     {"name": "x6", "enabled_connections": []any{map[string]any{"connection_id": orgDB, "assignMembershipOnLogin": true}}},
		"signup without assign":    {"name": "x6", "enabled_connections": []any{map[string]any{"connection_id": orgDB, "is_signup_enabled": true}}},
		"hidden database button":   {"name": "x6", "enabled_connections": []any{map[string]any{"connection_id": orgDB, "show_as_button": false}}},
		"signup on enterprise":     {"name": "x6", "enabled_connections": []any{map[string]any{"connection_id": orgOIDC, "is_signup_enabled": true, "assign_membership_on_login": true}}},
		"no connection_id":         {"name": "x6", "enabled_connections": []any{map[string]any{"show_as_button": true}}},
		"malformed connection_id":  {"name": "x6", "enabled_connections": []any{map[string]any{"connection_id": "nope"}}},
		"enabled_connections type": {"name": "x6", "enabled_connections": "con_x"},
	} {
		t.Run("create "+name, func(t *testing.T) {
			e.t = t
			e.fail("POST", "/organizations", body, e.h.CreateOrganization, 400, "invalid_body")
		})
	}
	e.t = t
	// Observed without errorCode.
	for _, body := range []map[string]any{
		{"name": "x3", "metadata": map[string]any{"a": nil}},
		{"name": "x3", "metadata": map[string]any{"a": ""}},
		{"name": "x3", "metadata": map[string]any{strings.Repeat("k", 51): "v"}},
		{"name": "x3", "metadata": map[string]any{strings.Repeat("k", 256): "v"}},
	} {
		e.fail("POST", "/organizations", body, e.h.CreateOrganization, 400, "")
	}
	e.fail("POST", "/organizations", map[string]any{"name": "x7", "enabled_connections": []any{map[string]any{"connection_id": orgGhost}}}, e.h.CreateOrganization, 404, "inexistent_connection")
	e.fail("POST", "/organizations", map[string]any{"name": "x7", "enabled_connections": []any{map[string]any{"connection_id": orgDB}, map[string]any{"connection_id": orgDB}}}, e.h.CreateOrganization, 409, "")
	e.create(map[string]any{"name": "a", "display_name": strings.Repeat("d", 255), "metadata": meta(25)}, 201)
	e.create(map[string]any{"name": strings.Repeat("z", 50), "branding": map[string]any{"logo_url": "https://cdn.example.test/l.png"}, "metadata": map[string]any{strings.Repeat("k", 50): strings.Repeat("v", 255)}}, 201)
	e.create(map[string]any{"name": "obs_org-1", "branding": nil, "metadata": map[string]any{}}, 201)
	for _, n := range []string{"x1", "x2", "x3", "x4", "x5", "x6", "x7"} {
		e.obj("GET", "/organizations/name/"+n, nil, e.byName(n), 404)
	}

	// Reads never carry enabled_connections.
	got := e.obj("GET", "/organizations/"+fullID, nil, e.get(fullID), 200)
	if _, ok := got["enabled_connections"]; ok || got["metadata"].(map[string]any)["tier"] != "gold" {
		t.Fatalf("get=%v", got)
	}
	e.fail("GET", "/organizations/nope", nil, e.get("nope"), 400, "invalid_uri")
	e.fail("GET", "/organizations/org_0000000000000000", nil, e.get("org_0000000000000000"), 404, "")
	if n := e.obj("GET", "/organizations/name/full_org", nil, e.byName("full_org"), 200); n["id"] != fullID || n["enabled_connections"] != nil {
		t.Fatalf("by name=%v", n)
	}
	e.fail("GET", "/organizations/name/Full_Org", nil, e.byName("Full_Org"), 400, "invalid_uri")
	e.fail("GET", "/organizations/name/missing", nil, e.byName("missing"), 404, "")

	// Lists: bare array by name, totals, checkpoint with next.
	all := e.list("/organizations", e.h.ListOrganizations)
	var names []string
	for _, v := range all {
		item := v.(map[string]any)
		if _, ok := item["enabled_connections"]; ok {
			t.Fatalf("list item=%v", item)
		}
		names = append(names, item["name"].(string))
	}
	if len(names) != 6 || names[0] != "a" || names[1] != "acme-co" || names[2] != "full_org" || names[3] != "obs_org-1" {
		t.Fatalf("names=%v", names)
	}
	page := e.obj("GET", "/organizations?include_totals=true&per_page=2&page=1", nil, e.h.ListOrganizations, 200)
	if got := keysOf(page); !slices.Equal(got, []string{"limit", "organizations", "start", "total"}) || page["start"] != float64(2) || page["limit"] != float64(2) || page["total"] != float64(6) || len(page["organizations"].([]any)) != 2 {
		t.Fatalf("totals=%v", page)
	}
	cp := e.obj("GET", "/organizations?take=4&include_totals=true&page=1001", nil, e.h.ListOrganizations, 200)
	if got := keysOf(cp); !slices.Equal(got, []string{"next", "organizations"}) || len(cp["organizations"].([]any)) != 4 {
		t.Fatalf("checkpoint=%v", cp)
	}
	if first := cp["organizations"].([]any)[0].(map[string]any); first["id"] != id {
		t.Fatalf("checkpoint without sort is creation order: %v", first)
	}
	rest := e.obj("GET", "/organizations?from="+cp["next"].(string), nil, e.h.ListOrganizations, 200)
	if _, more := rest["next"]; more || len(rest["organizations"].([]any)) != 2 {
		t.Fatalf("rest=%v", rest)
	}
	desc := e.list("/organizations?sort=name:-1", e.h.ListOrganizations)
	if desc[len(desc)-1].(map[string]any)["name"] != "a" {
		t.Fatalf("sort desc=%v", desc)
	}
	e.obj("GET", "/organizations?sort=display_name:1&take=2", nil, e.h.ListOrganizations, 200)
	for q, code := range map[string]string{
		"per_page=101": "invalid_query_string", "take=0": "invalid_query_string", "take=101": "invalid_query_string",
		"sort=id:1": "invalid_query_string", "sort=name": "invalid_query_string", "page=1001": "invalid_paging",
		"from=garbage": "", "q=x": "invalid_query_string", "include_client_association_for=": "invalid_query_string",
	} {
		e.fail("GET", "/organizations?"+q, nil, e.h.ListOrganizations, 400, code)
	}

	// PATCH replaces branding and metadata whole; {} or null clears them.
	p := e.obj("PATCH", "/organizations/"+fullID, map[string]any{"display_name": "Renamed"}, e.patch(fullID), 200)
	if p["display_name"] != "Renamed" || p["branding"] == nil || p["metadata"] == nil {
		t.Fatalf("patch display_name=%v", p)
	}
	e.obj("PATCH", "/organizations/"+fullID, map[string]any{"metadata": map[string]any{"a": "1", "b": "2"}}, e.patch(fullID), 200)
	p = e.obj("PATCH", "/organizations/"+fullID, map[string]any{"metadata": map[string]any{"c": "3"}}, e.patch(fullID), 200)
	if fmt.Sprint(p["metadata"]) != "map[c:3]" {
		t.Fatalf("metadata replace=%v", p)
	}
	for _, clear := range []any{map[string]any{}, nil} {
		e.obj("PATCH", "/organizations/"+fullID, map[string]any{"metadata": map[string]any{"c": "3"}}, e.patch(fullID), 200)
		if p = e.obj("PATCH", "/organizations/"+fullID, map[string]any{"metadata": clear}, e.patch(fullID), 200); p["metadata"] != nil {
			t.Fatalf("metadata %v clear=%v", clear, p)
		}
	}
	p = e.obj("PATCH", "/organizations/"+fullID, map[string]any{"branding": map[string]any{"logo_url": "https://cdn.example.test/new.png"}}, e.patch(fullID), 200)
	if fmt.Sprint(p["branding"]) != "map[logo_url:https://cdn.example.test/new.png]" {
		t.Fatalf("branding replace=%v", p)
	}
	p = e.obj("PATCH", "/organizations/"+fullID, map[string]any{"branding": map[string]any{"colors": map[string]any{"primary": "#000", "page_background": "#ffffff"}}}, e.patch(fullID), 200)
	if fmt.Sprint(p["branding"]) != "map[colors:map[page_background:#ffffff primary:#000]]" {
		t.Fatalf("branding colors replace=%v", p)
	}
	for _, clear := range []any{map[string]any{}, nil} {
		e.obj("PATCH", "/organizations/"+fullID, map[string]any{"branding": map[string]any{"logo_url": "https://cdn.example.test/l.png"}}, e.patch(fullID), 200)
		if p = e.obj("PATCH", "/organizations/"+fullID, map[string]any{"branding": clear}, e.patch(fullID), 200); p["branding"] != nil {
			t.Fatalf("branding %v clear=%v", clear, p)
		}
	}
	p = e.obj("PATCH", "/organizations/"+fullID, map[string]any{"name": "full-renamed", "third_party_client_access": "block", "is_app_entitlement_active": false}, e.patch(fullID), 200)
	if p["name"] != "full-renamed" || p["third_party_client_access"] != "block" || p["display_name"] != "Renamed" {
		t.Fatalf("rename=%v", p)
	}
	e.fail("PATCH", "/organizations/"+fullID, map[string]any{}, e.patch(fullID), 400, "")
	e.fail("PATCH", "/organizations/"+fullID, map[string]any{"name": "acme-co"}, e.patch(fullID), 409, "")
	e.fail("PATCH", "/organizations/"+fullID, map[string]any{"metadata": map[string]any{"k": nil}}, e.patch(fullID), 400, "")
	e.fail("PATCH", "/organizations/"+fullID, map[string]any{"metadata": map[string]any{"k": ""}}, e.patch(fullID), 400, "")
	for _, body := range []map[string]any{
		{"name": "Bad"}, {"display_name": ""}, {"display_name": strings.Repeat("d", 256)},
		{"branding": map[string]any{"colors": map[string]any{"primary": "#000"}}}, {"enabled_connections": []any{}}, {"id": fullID},
		{"is_app_entitlement_active": nil}, {"metadata": meta(26)},
	} {
		e.fail("PATCH", "/organizations/"+fullID, body, e.patch(fullID), 400, "invalid_body")
	}
	e.fail("PATCH", "/organizations/org_0000000000000000", map[string]any{"display_name": "x"}, e.patch("org_0000000000000000"), 404, "")
	e.fail("PATCH", "/organizations/bad", map[string]any{"display_name": "x"}, e.patch("bad"), 400, "invalid_uri")
	if p := e.obj("GET", "/organizations/"+fullID, nil, e.get(fullID), 200); p["name"] != "full-renamed" || p["branding"] != nil || p["metadata"] != nil {
		t.Fatalf("after failed patches=%v", p)
	}

	// Enabled connections.
	ec := "/organizations/" + fullID + "/enabled_connections"
	l := e.list(ec, e.conns(fullID, false))
	if len(l) != 2 || fmt.Sprint(l[0].(map[string]any)["connection"]) != "map[name:org-db strategy:auth0]" {
		t.Fatalf("enabled=%v", l)
	}
	tot := e.obj("GET", ec+"?include_totals=true&per_page=1", nil, e.conns(fullID, false), 200)
	if got := keysOf(tot); !slices.Equal(got, []string{"enabled_connections", "limit", "start", "total"}) || tot["total"] != float64(2) || tot["limit"] != float64(1) {
		t.Fatalf("enabled totals=%v", tot)
	}
	empty := e.obj("GET", "/organizations/"+id+"/enabled_connections?include_totals=true", nil, e.conns(id, false), 200)
	if empty["limit"] != float64(0) || empty["total"] != float64(0) || len(empty["enabled_connections"].([]any)) != 0 {
		t.Fatalf("empty totals=%v", empty)
	}
	for _, q := range []string{"per_page=101", "take=1", "from=x", "is_enabled=true"} {
		e.fail("GET", ec+"?"+q, nil, e.conns(fullID, false), 400, "invalid_query_string")
	}
	added := e.obj("POST", ec, map[string]any{"connection_id": orgDB2}, e.addConn(fullID, false), 201)
	if added["show_as_button"] != true || added["assign_membership_on_login"] != false || added["is_signup_enabled"] != false || fmt.Sprint(added["connection"]) != "map[name:org-db-2 strategy:auth0]" {
		t.Fatalf("added=%v", added)
	}
	if got := keysOf(added); !slices.Equal(got, []string{"assign_membership_on_login", "connection", "connection_id", "is_signup_enabled", "show_as_button"}) {
		t.Fatalf("entry keys=%v", got)
	}
	e.fail("POST", ec, map[string]any{"connection_id": orgDB2}, e.addConn(fullID, false), 409, "")
	e.fail("POST", ec, map[string]any{"connection_id": orgGhost}, e.addConn(fullID, false), 404, "inexistent_connection")
	for _, body := range []map[string]any{{}, {"connection_id": orgDB2, "is_enabled": true}, {"connectionId": orgDB2}, {"connection_id": 5}} {
		e.fail("POST", ec, body, e.addConn(fullID, false), 400, "invalid_body")
	}
	e.fail("POST", "/organizations/org_0000000000000000/enabled_connections", map[string]any{"connection_id": orgDB2}, e.addConn("org_0000000000000000", false), 404, "")
	one := e.obj("GET", ec+"/"+orgDB2, nil, e.conn("GET", fullID, orgDB2, false), 200)
	if one["connection_id"] != orgDB2 {
		t.Fatalf("one=%v", one)
	}
	e.fail("GET", ec+"/"+orgGhost, nil, e.conn("GET", fullID, orgGhost, false), 404, "")
	e.fail("GET", ec+"/bad", nil, e.conn("GET", fullID, "bad", false), 400, "invalid_uri")
	patchConn := func(body any, want int) map[string]any {
		t.Helper()
		return e.obj("PATCH", ec+"/"+orgDB2, body, e.conn("PATCH", fullID, orgDB2, false), want)
	}
	if got := patchConn(map[string]any{"assign_membership_on_login": true}, 200); got["assign_membership_on_login"] != true || got["connection"] == nil {
		t.Fatalf("patch assign=%v", got)
	}
	patchConn(map[string]any{"is_signup_enabled": true}, 200)
	// Observed: the signup/assign rule on PATCH has no errorCode, in both
	// directions; a hidden database button is invalid_body.
	e.fail("PATCH", ec+"/"+orgDB2, map[string]any{"assign_membership_on_login": false}, e.conn("PATCH", fullID, orgDB2, false), 400, "")
	patchConn(map[string]any{"is_signup_enabled": false, "assign_membership_on_login": false}, 200)
	e.fail("PATCH", ec+"/"+orgDB2, map[string]any{"is_signup_enabled": true}, e.conn("PATCH", fullID, orgDB2, false), 400, "")
	e.fail("PATCH", ec+"/"+orgDB2, map[string]any{"show_as_button": false}, e.conn("PATCH", fullID, orgDB2, false), 400, "invalid_body")
	e.fail("PATCH", ec+"/"+orgDB2, map[string]any{"show_as_button": false, "is_signup_enabled": true}, e.conn("PATCH", fullID, orgDB2, false), 400, "invalid_body")
	patchConn(map[string]any{"show_as_button": true}, 200)
	for _, body := range []map[string]any{{"connection_id": orgDB}, {"is_enabled": true}, {"show_as_button": "yes"}, {"showAsButton": true}} {
		patchConn(body, 400)
	}
	if got := patchConn(map[string]any{}, 200); got["assign_membership_on_login"] != false || got["show_as_button"] != true {
		t.Fatalf("patch {}=%v", got)
	}
	e.obj("PATCH", ec+"/"+orgOIDC, map[string]any{"show_as_button": true}, e.conn("PATCH", fullID, orgOIDC, false), 200)
	e.fail("PATCH", "/organizations/"+id+"/enabled_connections/"+orgDB, map[string]any{}, e.conn("PATCH", id, orgDB, false), 404, "inexistent_connection")
	e.fail("PATCH", ec+"/bad", map[string]any{}, e.conn("PATCH", fullID, "bad", false), 400, "invalid_uri")
	e.do(e.tn, "DELETE", ec+"/"+orgDB2, nil, e.conn("DELETE", fullID, orgDB2, false), 204)
	e.do(e.tn, "DELETE", ec+"/"+orgDB2, nil, e.conn("DELETE", fullID, orgDB2, false), 204)
	e.fail("DELETE", ec+"/"+orgGhost, nil, e.conn("DELETE", fullID, orgGhost, false), 404, "inexistent_connection")
	e.fail("DELETE", ec+"/bad", nil, e.conn("DELETE", fullID, "bad", false), 400, "invalid_uri")
	e.fail("DELETE", "/organizations/org_0000000000000000/enabled_connections/"+orgDB, nil, e.conn("DELETE", "org_0000000000000000", orgDB, false), 404, "")
	if l := e.list(ec, e.conns(fullID, false)); len(l) != 2 {
		t.Fatalf("after delete=%v", l)
	}

	// Cross-tenant: another tenant sees none of acme's organizations.
	other, err := tenantsetup.UpsertTenant(context.Background(), e.st, "other", now, func(tn *store.Tenant) error {
		tn.Domains, tn.CanonicalHost = []string{"login.other.test"}, "login.other.test"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e.do(other, "GET", "/organizations/"+fullID, nil, e.get(fullID), 404)
	e.do(other, "GET", "/organizations/name/acme-co", nil, e.byName("acme-co"), 404)
	e.do(other, "PATCH", "/organizations/"+fullID, map[string]any{"display_name": "x"}, e.patch(fullID), 404)
	e.do(other, "DELETE", "/organizations/"+fullID, nil, e.del(fullID), 404)
	e.do(other, "GET", ec, nil, e.conns(fullID, false), 404)
	e.do(other, "GET", ec+"/"+orgDB, nil, e.conn("GET", fullID, orgDB, false), 404)
	if l, _ := e.do(other, "GET", "/organizations", nil, e.h.ListOrganizations, 200).([]any); len(l) != 0 {
		t.Fatalf("other tenant list=%v", l)
	}

	// DELETE is not idempotent and cascades the links.
	e.do(e.tn, "DELETE", "/organizations/"+fullID, nil, e.del(fullID), 204)
	e.fail("DELETE", "/organizations/"+fullID, nil, e.del(fullID), 404, "")
	e.fail("DELETE", "/organizations/bad", nil, e.del("bad"), 400, "invalid_uri")
	e.fail("GET", "/organizations/"+fullID, nil, e.get(fullID), 404, "")
	e.fail("GET", ec, nil, e.conns(fullID, false), 404, "")
	if links, _ := e.st.Organizations().ConnectionsByConnection(context.Background(), e.tn.ID, orgDB); len(links) != 0 {
		t.Fatalf("links survived delete: %v", links)
	}
}

// TestOrganizationsAllConnections covers the Early Access
// /organizations/{id}/connections resource the Deploy CLI uses: the same
// links as enabled_connections, with is_enabled and the access levels.
func TestOrganizationsAllConnections(t *testing.T) {
	e := newOrgEnv(t)
	id := e.create(map[string]any{"name": "deploy"}, 201)["id"].(string)
	base := "/organizations/" + id + "/connections"
	created := e.obj("POST", base, map[string]any{"connection_id": orgDB, "assign_membership_on_login": true, "is_enabled": true, "organization_access_level": "none", "organization_member_access_level": "limited", "organization_connection_name": nil}, e.addConn(id, true), 201)
	want := []string{"assign_membership_on_login", "connection", "connection_id", "is_enabled", "is_signup_enabled", "organization_access_level", "organization_connection_name", "organization_member_access_level", "show_as_button"}
	if got := keysOf(created); !slices.Equal(got, want) || created["is_enabled"] != true || created["organization_access_level"] != "none" || created["organization_member_access_level"] != "limited" {
		t.Fatalf("created=%v", created)
	}
	// State is shared with enabled_connections, in both directions.
	e.fail("POST", "/organizations/"+id+"/enabled_connections", map[string]any{"connection_id": orgDB}, e.addConn(id, false), 409, "")
	e.obj("POST", "/organizations/"+id+"/enabled_connections", map[string]any{"connection_id": orgOIDC, "show_as_button": false}, e.addConn(id, false), 201)
	e.fail("POST", base, map[string]any{"connection_id": orgOIDC}, e.addConn(id, true), 409, "")
	l := e.list(base, e.conns(id, true))
	if len(l) != 2 || l[1].(map[string]any)["show_as_button"] != false || l[1].(map[string]any)["is_enabled"] != true {
		t.Fatalf("list=%v", l)
	}
	tot := e.obj("GET", base+"?include_totals=true&is_enabled=true", nil, e.conns(id, true), 200)
	if got := keysOf(tot); !slices.Equal(got, []string{"connections", "limit", "start", "total"}) || tot["total"] != float64(2) {
		t.Fatalf("totals=%v", tot)
	}
	if none := e.obj("GET", base+"?include_totals=true&is_enabled=false", nil, e.conns(id, true), 200); none["total"] != float64(0) || len(none["connections"].([]any)) != 0 {
		t.Fatalf("disabled=%v", none)
	}
	for _, body := range []map[string]any{
		{"connection_id": orgDB2, "show_as_button": false},
		{"connection_id": orgDB2, "unknown": true},
	} {
		e.fail("POST", base, body, e.addConn(id, true), 400, "invalid_body")
	}
	one := e.obj("GET", base+"/"+orgDB, nil, e.conn("GET", id, orgDB, true), 200)
	if one["organization_member_access_level"] != "limited" {
		t.Fatalf("one=%v", one)
	}
	got := e.obj("PATCH", base+"/"+orgDB, map[string]any{"assign_membership_on_login": true, "is_signup_enabled": true, "is_enabled": true, "organization_access_level": "none"}, e.conn("PATCH", id, orgDB, true), 200)
	if got["is_signup_enabled"] != true || got["is_enabled"] != true {
		t.Fatalf("patch=%v", got)
	}
	if ec := e.obj("GET", "/organizations/"+id+"/enabled_connections/"+orgDB, nil, e.conn("GET", id, orgDB, false), 200); ec["is_signup_enabled"] != true || ec["is_enabled"] != nil {
		t.Fatalf("shared patch=%v", ec)
	}
	e.fail("PATCH", base+"/"+orgDB, map[string]any{"organization_access_level": "admin"}, e.conn("PATCH", id, orgDB, true), 400, "invalid_body")
	e.fail("PATCH", base+"/"+orgDB2, map[string]any{}, e.conn("PATCH", id, orgDB2, true), 404, "inexistent_connection")
	e.do(e.tn, "DELETE", base+"/"+orgDB, nil, e.conn("DELETE", id, orgDB, true), 204)
	e.fail("GET", "/organizations/"+id+"/enabled_connections/"+orgDB, nil, e.conn("GET", id, orgDB, false), 404, "")
	e.fail("DELETE", base+"/"+orgGhost, nil, e.conn("DELETE", id, orgGhost, true), 404, "inexistent_connection")
	e.fail("GET", "/organizations/org_0000000000000000/connections", nil, e.conns("org_0000000000000000", true), 404, "")
}

// Empty association lists retain their documented offset shape.
func TestOrganizationsClientGrants(t *testing.T) {
	e := newOrgEnv(t)
	id := e.create(map[string]any{"name": "grants"}, 201)["id"].(string)
	list := func(id string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationClientGrants(w, r, id) }
	}
	if l := e.list("/organizations/"+id+"/client-grants", list(id)); len(l) != 0 {
		t.Fatalf("list=%v", l)
	}
	page := e.obj("GET", "/organizations/"+id+"/client-grants?include_totals=true&page=0&per_page=50", nil, list(id), 200)
	if fmt.Sprint(page) != "map[client_grants:[] limit:50 start:0 total:0]" {
		t.Fatalf("page=%v", page)
	}
	e.fail("GET", "/organizations/"+id+"/client-grants?per_page=101", nil, list(id), 400, "invalid_query_string")
	e.fail("GET", "/organizations/"+id+"/client-grants?take=1", nil, list(id), 400, "invalid_query_string")
	e.fail("GET", "/organizations/org_0000000000000000/client-grants", nil, list("org_0000000000000000"), 404, "not_found")
	e.fail("GET", "/organizations/bad/client-grants", nil, list("bad"), 400, "invalid_uri")
}

// noOrgStore is a store behind a storage plugin without the Organizations
// capability.
type noOrgStore struct{ store.Store }

func (noOrgStore) OrganizationsSupported() bool { return false }
func (noOrgStore) CheckOrganizationsSupport(context.Context) error {
	return store.ErrOrganizationsUnavailable
}

func TestOrganizationsUnsupportedPlugin(t *testing.T) {
	e := newOrgEnv(t)
	id := e.create(map[string]any{"name": "kept"}, 201)["id"].(string)
	e.h.Store = noOrgStore{e.st}
	for name, fn := range map[string]http.HandlerFunc{
		"list": e.h.ListOrganizations, "create": e.h.CreateOrganization, "get": e.get(id), "by name": e.byName("kept"),
		"patch": e.patch(id), "delete": e.del(id), "connections": e.conns(id, false), "add connection": e.addConn(id, false),
		"connection": e.conn("GET", id, orgDB, false), "patch connection": e.conn("PATCH", id, orgDB, false),
		"delete connection": e.conn("DELETE", id, orgDB, false), "all connections": e.conns(id, true),
		"add all connection": e.addConn(id, true), "all connection": e.conn("GET", id, orgDB, true),
		"patch all connection": e.conn("PATCH", id, orgDB, true), "delete all connection": e.conn("DELETE", id, orgDB, true),
		"client grants": func(w http.ResponseWriter, r *http.Request) { e.h.ListOrganizationClientGrants(w, r, id) },
	} {
		t.Run(name, func(t *testing.T) {
			rec, _ := e.call(t, e.tn, e.caller, "POST", "/organizations", map[string]any{"name": "new", "display_name": "x"}, fn)
			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("status=%d %s", rec.Code, rec.Body)
			}
		})
	}
}
