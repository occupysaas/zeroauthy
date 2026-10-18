package mgmt_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

var allRSScopes = []string{"read:resource_servers", "create:resource_servers", "update:resource_servers", "delete:resource_servers"}

const baseDomain = "example.com"

// rsEnv is a clientsEnv whose tenant also has its Management API.
type rsEnv struct {
	*clientsEnv
	mapi *store.ResourceServer
}

func newRSEnv(t *testing.T) *rsEnv {
	t.Helper()
	e := &rsEnv{clientsEnv: newClientsEnv(t)}
	e.h.BaseDomain = baseDomain
	mapi, err := tenantsetup.ManagementAPI(context.Background(), e.st, e.tn, baseDomain, now)
	if err != nil {
		t.Fatal(err)
	}
	e.mapi = mapi
	return e
}

func (e *rsEnv) create(t *testing.T, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.call(t, e.tn, m2mCaller(allRSScopes...), "POST", "/api/v2/resource-servers", body, e.h.CreateResourceServer)
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *rsEnv) mustCreate(t *testing.T, body any) map[string]any {
	t.Helper()
	rec, out := e.create(t, body)
	if rec.Code != 201 {
		t.Fatalf("create %v = %d %s", body, rec.Code, rec.Body)
	}
	return out
}

func (e *rsEnv) patchIn(t *testing.T, tn *store.Tenant, id string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.call(t, tn, m2mCaller(allRSScopes...), "PATCH", "/api/v2/resource-servers/"+url.PathEscape(id), body, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateResourceServer(w, r, id) })
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *rsEnv) patch(t *testing.T, id string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	return e.patchIn(t, e.tn, id, body)
}

func (e *rsEnv) get(t *testing.T, id, query string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.call(t, e.tn, m2mCaller("read:resource_servers"), "GET", "/api/v2/resource-servers/"+url.PathEscape(id)+query, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetResourceServer(w, r, id, mgmtapi.GetResourceServerParams{})
	})
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *rsEnv) list(t *testing.T, query string) (*httptest.ResponseRecorder, any) {
	t.Helper()
	return e.call(t, e.tn, m2mCaller("read:resource_servers"), "GET", "/api/v2/resource-servers"+query, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetResourceServers(w, r, mgmtapi.GetResourceServersParams{})
	})
}

func (e *rsEnv) del(t *testing.T, tn *store.Tenant, id string) *httptest.ResponseRecorder {
	t.Helper()
	rec, _ := e.call(t, tn, m2mCaller(allRSScopes...), "DELETE", "/api/v2/resource-servers/"+url.PathEscape(id), nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteResourceServer(w, r, id) })
	return rec
}

func scopeValues(v any) []string {
	var out []string
	for _, s := range v.([]any) {
		out = append(out, s.(map[string]any)["value"].(string))
	}
	return out
}

var hex24 = regexp.MustCompile(`^[0-9a-f]{24}$`)

// A1: the defaults of an API created with only an identifier.
func TestCreateResourceServerDefaults(t *testing.T) {
	e := newRSEnv(t)
	out := e.mustCreate(t, map[string]any{"identifier": "https://api.test"})
	id, _ := out["id"].(string)
	if !hex24.MatchString(id) || out["identifier"] != "https://api.test" || out["signing_alg"] != "RS256" ||
		out["token_lifetime"] != float64(86400) || out["token_lifetime_for_web"] != float64(7200) ||
		out["allow_offline_access"] != false || out["skip_consent_for_verifiable_first_party_clients"] != false ||
		out["enforce_policies"] != false || out["token_dialect"] != "access_token" {
		t.Fatalf("defaults = %v", out)
	}
	sta := out["subject_type_authorization"].(map[string]any)
	if sta["client"].(map[string]any)["policy"] != "require_client_grant" || sta["user"].(map[string]any)["policy"] != "allow_all" {
		t.Errorf("subject_type_authorization = %v", sta)
	}
	for _, absent := range []string{"name", "scopes", "is_system", "signing_secret", "tenant"} {
		if _, ok := out[absent]; ok {
			t.Errorf("%s is in the response: %v", absent, out[absent])
		}
	}
	stored, err := e.st.ResourceServers().Get(context.Background(), e.tn.ID, id)
	if err != nil || stored.Origin != store.OriginAPI || stored.Name != "" || stored.IsSystem || stored.SigningAlg != "RS256" ||
		stored.TokenLifetime != 86400 || stored.TokenLifetimeForWeb != 7200 {
		t.Fatalf("stored = %+v, %v", stored, err)
	}

	// Everything given is kept.
	out = e.mustCreate(t, map[string]any{
		"identifier": "orders", "name": "Orders", "token_lifetime": 3600, "token_lifetime_for_web": 1800,
		"allow_offline_access": true, "skip_consent_for_verifiable_first_party_clients": true, "signing_alg": "RS256",
		"scopes":                     []map[string]any{{"value": "read:orders", "description": "Read orders"}, {"value": "write:orders"}},
		"subject_type_authorization": map[string]any{"user": map[string]any{"policy": "require_client_grant"}, "client": map[string]any{"policy": "deny_all"}},
	})
	if out["name"] != "Orders" || out["token_lifetime"] != float64(3600) || out["token_lifetime_for_web"] != float64(1800) ||
		out["allow_offline_access"] != true || out["skip_consent_for_verifiable_first_party_clients"] != true ||
		!slices.Equal(scopeValues(out["scopes"]), []string{"read:orders", "write:orders"}) {
		t.Fatalf("given = %v", out)
	}
	sta = out["subject_type_authorization"].(map[string]any)
	if sta["client"].(map[string]any)["policy"] != "deny_all" || sta["user"].(map[string]any)["policy"] != "require_client_grant" {
		t.Errorf("subject_type_authorization = %v", sta)
	}
	// Only some of the policies: the others take their defaults.
	out = e.mustCreate(t, map[string]any{"identifier": "partial", "subject_type_authorization": map[string]any{"user": map[string]any{"policy": "deny_all"}}})
	sta = out["subject_type_authorization"].(map[string]any)
	if sta["client"].(map[string]any)["policy"] != "require_client_grant" || sta["user"].(map[string]any)["policy"] != "deny_all" {
		t.Errorf("partial subject_type_authorization = %v", sta)
	}
}

func TestCreateResourceServerRefusals(t *testing.T) {
	e := newRSEnv(t)
	long := func(n int) string { return strings.Repeat("a", n) }
	scope := func(v, d string) []map[string]any { return []map[string]any{{"value": v, "description": d}} }
	id := func(extra map[string]any) map[string]any {
		m := map[string]any{"identifier": "https://refused.test"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	for name, body := range map[string]any{
		"no identifier":       map[string]any{"name": "x"},
		"empty identifier":    map[string]any{"identifier": ""},
		"long identifier":     map[string]any{"identifier": long(601)},
		"identifier type":     map[string]any{"identifier": 5},
		"null identifier":     map[string]any{"identifier": nil},
		"unknown property":    id(map[string]any{"colour": "blue"}),
		"id":                  id(map[string]any{"id": "abc"}),
		"is_system":           id(map[string]any{"is_system": true}),
		"empty name":          id(map[string]any{"name": ""}),
		"long name":           id(map[string]any{"name": long(201)}),
		"name with <":         id(map[string]any{"name": "a<b"}),
		"name with >":         id(map[string]any{"name": "a>b"}),
		"name type":           id(map[string]any{"name": 5}),
		"empty scope":         id(map[string]any{"scopes": scope("", "")}),
		"long scope":          id(map[string]any{"scopes": scope(long(281), "")}),
		"long description":    id(map[string]any{"scopes": scope("a", long(501))}),
		"duplicate scope":     id(map[string]any{"scopes": []map[string]any{{"value": "a"}, {"value": "a"}}}),
		"scope property":      id(map[string]any{"scopes": []map[string]any{{"value": "a", "colour": "blue"}}}),
		"scopes type":         id(map[string]any{"scopes": "a"}),
		"lifetime zero":       id(map[string]any{"token_lifetime": 0}),
		"lifetime negative":   id(map[string]any{"token_lifetime": -5}),
		"lifetime too long":   id(map[string]any{"token_lifetime": 2592001}),
		"lifetime string":     id(map[string]any{"token_lifetime": "3600"}),
		"lifetime fraction":   id(map[string]any{"token_lifetime": 1.5}),
		"web zero":            id(map[string]any{"token_lifetime_for_web": 0}),
		"web too long":        id(map[string]any{"token_lifetime_for_web": 2592001}),
		"web above lifetime":  id(map[string]any{"token_lifetime": 100, "token_lifetime_for_web": 101}),
		"web above default":   id(map[string]any{"token_lifetime_for_web": 86401}),
		"HS256":               id(map[string]any{"signing_alg": "HS256"}),
		"PS256":               id(map[string]any{"signing_alg": "PS256"}),
		"ES256":               id(map[string]any{"signing_alg": "ES256"}),
		"signing_secret":      id(map[string]any{"signing_secret": strings.Repeat("s", 32)}),
		"offline type":        id(map[string]any{"allow_offline_access": "yes"}),
		"skip type":           id(map[string]any{"skip_consent_for_verifiable_first_party_clients": nil}),
		"user policy":         id(map[string]any{"subject_type_authorization": map[string]any{"user": map[string]any{"policy": "maybe"}}}),
		"client allow_all":    id(map[string]any{"subject_type_authorization": map[string]any{"client": map[string]any{"policy": "allow_all"}}}),
		"policy property":     id(map[string]any{"subject_type_authorization": map[string]any{"user": map[string]any{"policy": "deny_all", "x": 1}}}),
		"subject type":        id(map[string]any{"subject_type_authorization": map[string]any{"robot": map[string]any{"policy": "deny_all"}}}),
		"enforce_policies":    id(map[string]any{"enforce_policies": true}),
		"token_dialect":       id(map[string]any{"token_dialect": "rfc9068_profile"}),
		"consent_policy":      id(map[string]any{"consent_policy": "transactional-authorization-with-mfa"}),
		"proof_of_possession": id(map[string]any{"proof_of_possession": map[string]any{"mechanism": "mtls", "required": true}}),
		"authz details":       id(map[string]any{"authorization_details": []map[string]any{{"type": "payment"}}}),
		"token_encryption":    id(map[string]any{"token_encryption": map[string]any{"format": "compact-nested-jwe"}}),
		"not an object":       "[1,2]",
		"not JSON":            "{",
	} {
		t.Run(name, func(t *testing.T) {
			rec, _ := e.create(t, body)
			wantError(t, rec, 400, "invalid_body")
		})
	}
	// The limits themselves, and the settings that are accepted as they are.
	e.mustCreate(t, map[string]any{"identifier": long(600), "name": long(200), "token_lifetime": 2592000, "token_lifetime_for_web": 2592000,
		"scopes": scope(long(280), long(500))})
	e.mustCreate(t, map[string]any{"identifier": "ok", "token_lifetime": 100, "token_lifetime_for_web": 100})
	out := e.mustCreate(t, map[string]any{"identifier": "ok-null", "enforce_policies": false, "token_dialect": "access_token",
		"consent_policy": nil, "proof_of_possession": nil, "authorization_details": []any{}, "token_encryption": nil})
	if out["enforce_policies"] != false || out["token_dialect"] != "access_token" {
		t.Errorf("accepted settings = %v", out)
	}
	if apis, _ := e.st.ResourceServers().List(context.Background(), e.tn.ID); len(apis) != 1+3 {
		t.Fatalf("%d APIs stored after refusals, want 4", len(apis))
	}
}

// A2: any string is an identifier, compared case-sensitively; a duplicate is
// a conflict; the Management API's identifiers are reserved.
func TestCreateResourceServerIdentifiers(t *testing.T) {
	e := newRSEnv(t)
	for _, id := range []string{"https://api.test/", "urn:orders", "orders", "has a space", "HTTPS://API.TEST/", "https://api.test"} {
		e.mustCreate(t, map[string]any{"identifier": id})
	}
	rec, _ := e.create(t, map[string]any{"identifier": "orders"})
	wantError(t, rec, 409, "resource_server_conflict")
	rec, _ = e.create(t, map[string]any{"identifier": e.mapi.Identifier})
	wantError(t, rec, 400, "reserved_identifier")
	rec, _ = e.create(t, map[string]any{"identifier": "urn:zeroauthy:management"})
	wantError(t, rec, 400, "reserved_identifier")
	// Another tenant's Management API identifier is an ordinary string here.
	e.mustCreate(t, map[string]any{"identifier": "https://globex.example.com/api/v2/"})

	// The same identifier in another tenant is not a conflict.
	other, err := tenantsetup.UpsertTenant(context.Background(), e.st, "globex", now, func(tn *store.Tenant) error { tn.Domains = []string{"login.globex.test"}; return nil })
	if err != nil {
		t.Fatal(err)
	}
	rec, _ = e.call(t, other, m2mCaller(allRSScopes...), "POST", "/api/v2/resource-servers", map[string]any{"identifier": "orders"}, e.h.CreateResourceServer)
	if rec.Code != 201 {
		t.Fatalf("create in another tenant = %d %s", rec.Code, rec.Body)
	}
}

func TestGetResourceServer(t *testing.T) {
	e := newRSEnv(t)
	created := e.mustCreate(t, map[string]any{"identifier": "https://api.test/v1", "name": "Orders", "scopes": []map[string]any{{"value": "read:orders", "description": "Read"}}})
	id := created["id"].(string)
	rec, out := e.get(t, id, "")
	if rec.Code != 200 || out["identifier"] != "https://api.test/v1" || out["name"] != "Orders" || !slices.Equal(scopeValues(out["scopes"]), []string{"read:orders"}) {
		t.Fatalf("get = %d %v", rec.Code, out)
	}
	// The identifier works in place of the ID (auth0-cli reads by audience).
	rec, out = e.get(t, "https://api.test/v1", "")
	if rec.Code != 200 || out["id"] != id {
		t.Fatalf("get by identifier = %d %v", rec.Code, out)
	}
	// An ID wins over an identifier that looks like it.
	other := e.mustCreate(t, map[string]any{"identifier": id})
	if _, out = e.get(t, id, ""); out["id"] != id || other["id"] == id {
		t.Errorf("get by an ID that is also an identifier = %v", out)
	}
	for _, missing := range []string{"nope", "HTTPS://API.TEST/V1", "0123456789abcdef01234567", ""} {
		rec, _ = e.get(t, missing, "")
		wantError(t, rec, 404, "inexistent_resource_server")
	}
	// The system API is readable.
	rec, out = e.get(t, e.mapi.ID, "")
	if rec.Code != 200 || out["is_system"] != true || out["name"] != tenantsetup.ManagementAPIName || out["identifier"] != e.mapi.Identifier {
		t.Fatalf("get system API = %d %v", rec.Code, out)
	}
	if len(scopeValues(out["scopes"])) != len(tenantsetup.ManagementAPIScopes) {
		t.Errorf("system API scopes = %v", out["scopes"])
	}
	// Another tenant's API does not exist here.
	other2, _ := tenantsetup.UpsertTenant(context.Background(), e.st, "globex", now, func(tn *store.Tenant) error { tn.Domains = []string{"login.globex.test"}; return nil })
	rec, _ = e.call(t, other2, m2mCaller("read:resource_servers"), "GET", "/api/v2/resource-servers/"+id, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetResourceServer(w, r, id, mgmtapi.GetResourceServerParams{})
	})
	wantError(t, rec, 404, "inexistent_resource_server")

	// fields: nothing is always added (clients always keep tenant).
	rec, out = e.get(t, id, "?fields=name,token_lifetime")
	if rec.Code != 200 || len(out) != 2 || out["name"] != "Orders" || out["token_lifetime"] != float64(86400) {
		t.Fatalf("fields = %d %v", rec.Code, out)
	}
	rec, out = e.get(t, id, "?fields=scopes,identifier&include_fields=false")
	if _, ok := out["scopes"]; ok || out["id"] != id || out["identifier"] != nil {
		t.Fatalf("include_fields=false = %d %v", rec.Code, out)
	}
	rec, _ = e.get(t, id, "?include_fields=maybe")
	wantError(t, rec, 400, "invalid_query_string")
}

// A7: creation order with the system API first, offset paging under
// resource_servers, the identifiers filter and fields.
func TestListResourceServers(t *testing.T) {
	e := newRSEnv(t)
	// Created before the Management API, but listed after it.
	early := &store.ResourceServer{TenantID: e.tn.ID, ID: "rs_early", Identifier: "early", SigningAlg: "RS256", CreatedAt: now.Add(-time.Hour)}
	if err := e.st.ResourceServers().Create(context.Background(), early); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		e.mustCreate(t, map[string]any{"identifier": id, "name": "API " + id})
	}
	identifiers := func(v any) []string {
		var out []string
		for _, m := range v.([]any) {
			out = append(out, m.(map[string]any)["identifier"].(string))
		}
		return out
	}
	rec, out := e.list(t, "")
	want := []string{e.mapi.Identifier, "early", "a", "b", "c"}
	if _, isArray := out.([]any); rec.Code != 200 || !isArray || !slices.Equal(identifiers(out), want) {
		t.Fatalf("list = %d %v", rec.Code, out)
	}
	if first := out.([]any)[0].(map[string]any); first["is_system"] != true {
		t.Errorf("first = %v", first)
	}

	rec, out = e.list(t, "?include_totals=true&per_page=2&page=1")
	page := out.(map[string]any)
	if rec.Code != 200 || page["total"] != float64(5) || page["start"] != float64(2) || page["limit"] != float64(2) ||
		!slices.Equal(identifiers(page["resource_servers"]), []string{"a", "b"}) {
		t.Fatalf("page = %d %v", rec.Code, out)
	}
	_, out = e.list(t, "?include_totals=true&per_page=2&page=9")
	if page = out.(map[string]any); page["start"] != float64(18) || len(page["resource_servers"].([]any)) != 0 || page["total"] != float64(5) {
		t.Errorf("page past the end = %v", out)
	}
	_, out = e.list(t, "?page=1&per_page=4")
	if !slices.Equal(identifiers(out), []string{"c"}) {
		t.Errorf("bare page = %v", out)
	}

	// identifiers is repeated; a comma does not split.
	_, out = e.list(t, "?identifiers=c&identifiers=a&identifiers=nope")
	if !slices.Equal(identifiers(out), []string{"a", "c"}) {
		t.Errorf("identifiers = %v", out)
	}
	_, out = e.list(t, "?identifiers=a,c")
	if len(out.([]any)) != 0 {
		t.Errorf("comma-separated identifiers = %v", out)
	}
	_, out = e.list(t, "?identifiers=A")
	if len(out.([]any)) != 0 {
		t.Errorf("identifiers are case-sensitive: %v", out)
	}
	_, out = e.list(t, "?include_totals=true&identifiers=b")
	if page = out.(map[string]any); page["total"] != float64(1) {
		t.Errorf("filtered total = %v", out)
	}

	// fields: nothing is always added, so an API without a name is {}.
	_, out = e.list(t, "?fields=name")
	if got := out.([]any); len(got) != 5 || len(got[1].(map[string]any)) != 0 || got[2].(map[string]any)["name"] != "API a" || len(got[2].(map[string]any)) != 1 {
		t.Errorf("fields=name = %v", out)
	}
	_, out = e.list(t, "?fields=identifier&include_fields=false&identifiers=a")
	if got := out.([]any); len(got) != 1 || got[0].(map[string]any)["identifier"] != nil || got[0].(map[string]any)["name"] != "API a" {
		t.Errorf("include_fields=false = %v", out)
	}

	for _, q := range []string{"?from=abc", "?take=5", "?from=abc&take=5", "?per_page=0", "?per_page=101", "?page=-1", "?include_totals=maybe"} {
		rec, _ = e.list(t, q)
		wantError(t, rec, 400, "invalid_query_string")
	}
	// A tenant sees only its own APIs.
	rec, out = e.call(t, e.sys, m2mCaller("read:resource_servers"), "GET", "/api/v2/resource-servers", nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetResourceServers(w, r, mgmtapi.GetResourceServersParams{})
	})
	if got := identifiers(out); rec.Code != 200 || !slices.Equal(got, []string{"urn:zeroauthy:management"}) {
		t.Errorf("system tenant list = %d %v", rec.Code, got)
	}
}

func TestUpdateResourceServer(t *testing.T) {
	e := newRSEnv(t)
	created := e.mustCreate(t, map[string]any{"identifier": "https://api.test", "name": "Orders",
		"scopes": []map[string]any{{"value": "read:orders", "description": "Read"}, {"value": "write:orders"}}, "token_lifetime": 3600})
	id := created["id"].(string)

	// An empty body is accepted and changes nothing.
	rec, out := e.patch(t, id, map[string]any{})
	if rec.Code != 200 || out["name"] != "Orders" || out["token_lifetime"] != float64(3600) || out["id"] != id {
		t.Fatalf("empty patch = %d %v", rec.Code, out)
	}

	// Each field, alone.
	for name, tc := range map[string]struct {
		body map[string]any
		key  string
		want any
	}{
		"name":           {map[string]any{"name": "Orders v2"}, "name", "Orders v2"},
		"token_lifetime": {map[string]any{"token_lifetime": 600}, "token_lifetime", float64(600)},
		"web":            {map[string]any{"token_lifetime_for_web": 300}, "token_lifetime_for_web", float64(300)},
		"offline":        {map[string]any{"allow_offline_access": true}, "allow_offline_access", true},
		"skip consent":   {map[string]any{"skip_consent_for_verifiable_first_party_clients": true}, "skip_consent_for_verifiable_first_party_clients", true},
		"signing_alg":    {map[string]any{"signing_alg": "RS256"}, "signing_alg", "RS256"},
		"enforce":        {map[string]any{"enforce_policies": false}, "enforce_policies", false},
		"dialect":        {map[string]any{"token_dialect": "access_token"}, "token_dialect", "access_token"},
	} {
		rec, out := e.patch(t, id, tc.body)
		if rec.Code != 200 || out[tc.key] != tc.want {
			t.Errorf("%s: %d %v", name, rec.Code, out)
		}
	}
	_, out = e.get(t, id, "")
	if out["name"] != "Orders v2" || out["token_lifetime"] != float64(600) || out["allow_offline_access"] != true || out["identifier"] != "https://api.test" ||
		!slices.Equal(scopeValues(out["scopes"]), []string{"read:orders", "write:orders"}) {
		t.Fatalf("after patches = %v", out)
	}
	stored, _ := e.st.ResourceServers().Get(context.Background(), e.tn.ID, id)
	if stored.Origin != store.OriginAPI || stored.Identifier != "https://api.test" || stored.CreatedAt.IsZero() {
		t.Errorf("identity changed: %+v", stored)
	}

	// token_lifetime below the stored web lifetime is accepted; sending
	// the web lifetime above the lifetime is not.
	rec, out = e.patch(t, id, map[string]any{"token_lifetime": 100})
	if rec.Code != 200 || out["token_lifetime"] != float64(100) || out["token_lifetime_for_web"] != float64(300) {
		t.Fatalf("lower token_lifetime = %d %v", rec.Code, out)
	}
	rec, _ = e.patch(t, id, map[string]any{"token_lifetime_for_web": 101})
	wantError(t, rec, 400, "invalid_body")
	rec, out = e.patch(t, id, map[string]any{"token_lifetime": 5000, "token_lifetime_for_web": 5000})
	if rec.Code != 200 || out["token_lifetime_for_web"] != float64(5000) {
		t.Errorf("both = %d %v", rec.Code, out)
	}

	// A3: identifier, id and is_system are unknown properties on PATCH,
	// even unchanged.
	for _, body := range []map[string]any{
		{"identifier": "https://api.test"}, {"identifier": "https://other.test"}, {"id": id}, {"is_system": false},
		{"colour": "blue"}, {"name": ""}, {"name": "a<b"}, {"token_lifetime": 0}, {"token_lifetime": 2592001},
		{"signing_alg": "HS256"}, {"signing_alg": "PS256"}, {"signing_secret": strings.Repeat("s", 32)},
		{"enforce_policies": true}, {"token_dialect": "rfc9068_profile_authz"}, {"consent_policy": "x"},
		{"proof_of_possession": map[string]any{"mechanism": "dpop"}}, {"token_encryption": map[string]any{}},
		{"authorization_details": []map[string]any{{"type": "x"}}},
		{"scopes": []map[string]any{{"value": ""}}}, {"scopes": []map[string]any{{"value": "a"}, {"value": "a"}}},
		{"subject_type_authorization": map[string]any{"client": map[string]any{"policy": "allow_all"}}},
	} {
		rec, _ = e.patch(t, id, body)
		if rec.Code != 400 {
			t.Errorf("%v = %d %s", body, rec.Code, rec.Body)
			continue
		}
		wantError(t, rec, 400, "invalid_body")
	}
	// Nothing of that was applied.
	_, out = e.get(t, id, "")
	if out["token_lifetime"] != float64(5000) || out["name"] != "Orders v2" || out["identifier"] != "https://api.test" {
		t.Errorf("after refusals = %v", out)
	}

	rec, _ = e.patch(t, "nope", map[string]any{"name": "x"})
	wantError(t, rec, 404, "inexistent_resource_server")
	rec, _ = e.patch(t, "https://api.test", map[string]any{"name": "x"})
	wantError(t, rec, 404, "inexistent_resource_server") // PATCH takes the ID only
}

func TestUpdateResourceServerPolicies(t *testing.T) {
	e := newRSEnv(t)
	id := e.mustCreate(t, map[string]any{"identifier": "https://api.test"})["id"].(string)
	policies := func(out map[string]any) [2]any {
		sta := out["subject_type_authorization"].(map[string]any)
		return [2]any{sta["user"].(map[string]any)["policy"], sta["client"].(map[string]any)["policy"]}
	}
	// Only the sent subject type changes.
	_, out := e.patch(t, id, map[string]any{"subject_type_authorization": map[string]any{"user": map[string]any{"policy": "deny_all"}}})
	if got := policies(out); got != [2]any{"deny_all", "require_client_grant"} {
		t.Errorf("user only = %v", got)
	}
	_, out = e.patch(t, id, map[string]any{"subject_type_authorization": map[string]any{"client": map[string]any{"policy": "deny_all"}}})
	if got := policies(out); got != [2]any{"deny_all", "deny_all"} {
		t.Errorf("client only = %v", got)
	}
	_, out = e.patch(t, id, map[string]any{"subject_type_authorization": map[string]any{}})
	if got := policies(out); got != [2]any{"deny_all", "deny_all"} {
		t.Errorf("empty = %v", got)
	}
	_, out = e.patch(t, id, map[string]any{"subject_type_authorization": map[string]any{"user": map[string]any{"policy": "allow_all"}, "client": map[string]any{"policy": "require_client_grant"}}})
	if got := policies(out); got != [2]any{"allow_all", "require_client_grant"} {
		t.Errorf("both = %v", got)
	}
}

// A5, review focus 3: scopes replace the list, and a removed scope is
// removed from the client grants that carry it.
func TestUpdateResourceServerScopes(t *testing.T) {
	e := newRSEnv(t)
	ctx := context.Background()
	id := e.mustCreate(t, map[string]any{"identifier": "https://api.test",
		"scopes": []map[string]any{{"value": "read", "description": "R"}, {"value": "write"}, {"value": "admin"}}})["id"].(string)
	e.mustCreate(t, map[string]any{"identifier": "https://other.test", "scopes": []map[string]any{{"value": "read"}, {"value": "admin"}}})
	grant := func(id, client, aud, subject string, scopes ...string) {
		t.Helper()
		if err := e.st.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: e.tn.ID, ID: id, ClientID: client, Audience: aud, Scopes: scopes, SubjectType: subject, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	grant("cg_1", "c1", "https://api.test", store.SubjectTypeClient, "read", "write", "admin")
	grant("cg_2", "c2", "https://api.test", store.SubjectTypeClient, "admin")
	grant("cg_3", "c1", "https://api.test", store.SubjectTypeUser, "read")
	grant("cg_4", "c1", "https://other.test", store.SubjectTypeClient, "read", "admin")

	rec, out := e.patch(t, id, map[string]any{"scopes": []map[string]any{{"value": "read", "description": "Read"}, {"value": "extra"}}})
	if rec.Code != 200 || !slices.Equal(scopeValues(out["scopes"]), []string{"read", "extra"}) {
		t.Fatalf("replace = %d %v", rec.Code, out)
	}
	if out["scopes"].([]any)[0].(map[string]any)["description"] != "Read" {
		t.Errorf("description not replaced: %v", out["scopes"])
	}
	for id, want := range map[string][]string{"cg_1": {"read"}, "cg_2": {}, "cg_3": {"read"}, "cg_4": {"read", "admin"}} {
		var got *store.ClientGrant
		grants, _, _ := e.st.ClientGrants().List(ctx, e.tn.ID, store.ClientGrantFilter{}, store.Page{})
		for _, g := range grants {
			if g.ID == id {
				got = g
			}
		}
		if got == nil || !slices.Equal(got.Scopes, want) && !(len(got.Scopes) == 0 && len(want) == 0) {
			t.Errorf("grant %s scopes = %+v, want %v", id, got, want)
		}
	}
	// The grants stay, even with no scope left.
	if grants, _, _ := e.st.ClientGrants().List(ctx, e.tn.ID, store.ClientGrantFilter{Audience: "https://api.test"}, store.Page{}); len(grants) != 3 {
		t.Errorf("%d grants for the API, want 3", len(grants))
	}

	// An empty list removes every scope; the field is then absent.
	rec, out = e.patch(t, id, map[string]any{"scopes": []any{}})
	if _, has := out["scopes"]; rec.Code != 200 || has {
		t.Fatalf("empty scopes = %d %v", rec.Code, out)
	}
	if g, err := e.st.ClientGrants().Find(ctx, e.tn.ID, "c1", "https://api.test", store.SubjectTypeClient); err != nil || len(g.Scopes) != 0 {
		t.Errorf("grant after removing every scope = %+v, %v", g, err)
	}
}

// A4: a system API accepts no name and keeps what zeroauthy depends on.
func TestUpdateSystemResourceServer(t *testing.T) {
	e := newRSEnv(t)
	sysAPI, err := e.st.ResourceServers().GetByIdentifier(context.Background(), e.sys.ID, tenant.OperatorAudience)
	if err != nil {
		t.Fatal(err)
	}

	// The tenant's Management API.
	rec, _ := e.patch(t, e.mapi.ID, map[string]any{"name": "Mine"})
	wantError(t, rec, 400, "invalid_body")
	rec, _ = e.patch(t, e.mapi.ID, map[string]any{"name": tenantsetup.ManagementAPIName})
	wantError(t, rec, 400, "invalid_body") // the property itself is unknown
	for name, body := range map[string]map[string]any{
		"token_lifetime": {"token_lifetime": 3600},
		"web":            {"token_lifetime_for_web": 600},
		"offline":        {"allow_offline_access": true},
		"skip consent":   {"skip_consent_for_verifiable_first_party_clients": true},
		"client policy":  {"subject_type_authorization": map[string]any{"client": map[string]any{"policy": "deny_all"}}},
	} {
		rec, out := e.patch(t, e.mapi.ID, body)
		if rec.Code != 200 || out["is_system"] != true {
			t.Errorf("mapi %s: %d %s", name, rec.Code, rec.Body)
		}
	}
	for name, body := range map[string]map[string]any{
		"user allow_all":   {"subject_type_authorization": map[string]any{"user": map[string]any{"policy": "allow_all"}}},
		"user client_gr":   {"subject_type_authorization": map[string]any{"user": map[string]any{"policy": "require_client_grant"}}},
		"fewer scopes":     {"scopes": []map[string]any{{"value": "read:clients"}}},
		"no scopes":        {"scopes": []any{}},
		"changed scope":    {"scopes": append(scopesBody(tenantsetup.ManagementAPIScopes[1:]), map[string]any{"value": "extra:thing"})},
		"scope descripton": {"scopes": []map[string]any{{"value": "read:clients", "description": "Other"}}},
	} {
		rec, _ := e.patch(t, e.mapi.ID, body)
		if rec.Code != 400 {
			t.Errorf("mapi %s: %d %s", name, rec.Code, rec.Body)
			continue
		}
		wantError(t, rec, 400, "invalid_body")
	}
	// Naming what is fixed with its current value is accepted, as
	// auth0-deploy-cli sends it back (A11).
	rec, out := e.patch(t, e.mapi.ID, map[string]any{
		"scopes":                     scopesBody(tenantsetup.ManagementAPIScopes),
		"subject_type_authorization": map[string]any{"user": map[string]any{"policy": "deny_all"}, "client": map[string]any{"policy": "deny_all"}},
		"signing_alg":                "RS256", "token_lifetime": 7200,
	})
	if rec.Code != 200 || out["token_lifetime"] != float64(7200) {
		t.Fatalf("same values = %d %s", rec.Code, rec.Body)
	}
	stored, _ := e.st.ResourceServers().Get(context.Background(), e.tn.ID, e.mapi.ID)
	if !stored.IsSystem || stored.Name != tenantsetup.ManagementAPIName || stored.Identifier != e.mapi.Identifier ||
		len(stored.Scopes) != len(tenantsetup.ManagementAPIScopes) || stored.SubjectTypeAuthorization.User != store.PolicyDenyAll || stored.Origin != "" {
		t.Errorf("the Management API changed: %+v", stored)
	}

	// The system tenant's own API: only the lifetimes change.
	rec, _ = e.patchIn(t, e.sys, sysAPI.ID, map[string]any{"name": "x"})
	wantError(t, rec, 400, "invalid_body")
	for name, body := range map[string]map[string]any{
		"offline off":   {"allow_offline_access": false},
		"consent":       {"skip_consent_for_verifiable_first_party_clients": false},
		"client policy": {"subject_type_authorization": map[string]any{"client": map[string]any{"policy": "require_client_grant"}}},
		"user policy":   {"subject_type_authorization": map[string]any{"user": map[string]any{"policy": "deny_all"}}},
		"scopes":        {"scopes": []map[string]any{{"value": "x"}}},
	} {
		rec, _ := e.patchIn(t, e.sys, sysAPI.ID, body)
		if rec.Code != 400 {
			t.Errorf("system API %s: %d %s", name, rec.Code, rec.Body)
		}
	}
	for name, body := range map[string]map[string]any{
		"token_lifetime": {"token_lifetime": 1800},
		"same values":    {"allow_offline_access": true, "skip_consent_for_verifiable_first_party_clients": true, "subject_type_authorization": map[string]any{"client": map[string]any{"policy": "deny_all"}, "user": map[string]any{"policy": "allow_all"}}},
	} {
		rec, _ := e.patchIn(t, e.sys, sysAPI.ID, body)
		if rec.Code != 200 {
			t.Errorf("system API %s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func scopesBody(scopes []store.Scope) []map[string]any {
	out := make([]map[string]any, len(scopes))
	for i, s := range scopes {
		out[i] = map[string]any{"value": s.Value, "description": s.Description}
	}
	return out
}

// A6: DELETE is 204 with an empty body, also for unknown and malformed IDs
// and a second time; a system API is refused.
func TestDeleteResourceServer(t *testing.T) {
	e := newRSEnv(t)
	id := e.mustCreate(t, map[string]any{"identifier": "https://api.test"})["id"].(string)
	keep := e.mustCreate(t, map[string]any{"identifier": "https://keep.test"})["id"].(string)
	for i, target := range []string{id, id, "nope", "0123456789abcdef01234567", "%00%zz", "https://keep.test"} {
		rec := e.del(t, e.tn, target)
		if rec.Code != 204 || rec.Body.Len() != 0 {
			t.Fatalf("delete #%d %q = %d %q", i, target, rec.Code, rec.Body)
		}
	}
	if _, err := e.st.ResourceServers().Get(context.Background(), e.tn.ID, id); err == nil {
		t.Error("the API is still stored")
	}
	if _, err := e.st.ResourceServers().Get(context.Background(), e.tn.ID, keep); err != nil {
		t.Errorf("another API was deleted: %v", err)
	}
	rec, _ := e.get(t, id, "")
	wantError(t, rec, 404, "inexistent_resource_server")

	rec = e.del(t, e.tn, e.mapi.ID)
	wantError(t, rec, 400, "delete_system_resource_server")
	sysAPI, _ := e.st.ResourceServers().GetByIdentifier(context.Background(), e.sys.ID, tenant.OperatorAudience)
	rec = e.del(t, e.sys, sysAPI.ID)
	wantError(t, rec, 400, "delete_system_resource_server")
	if _, err := e.st.ResourceServers().Get(context.Background(), e.tn.ID, e.mapi.ID); err != nil {
		t.Errorf("the Management API was deleted: %v", err)
	}
	// An ID of another tenant is unknown here: 204, and nothing happens.
	other, _ := tenantsetup.UpsertTenant(context.Background(), e.st, "globex", now, func(tn *store.Tenant) error { tn.Domains = []string{"login.globex.test"}; return nil })
	if rec = e.del(t, other, keep); rec.Code != 204 {
		t.Errorf("delete in another tenant = %d", rec.Code)
	}
	if _, err := e.st.ResourceServers().Get(context.Background(), e.tn.ID, keep); err != nil {
		t.Errorf("another tenant deleted the API: %v", err)
	}
}

// Review focus 2: deleting an API takes its client grants and the user
// grants for its audience with it, and refresh tokens issued for it stop
// working; other APIs keep theirs.
func TestDeleteResourceServerCascades(t *testing.T) {
	e := newRSEnv(t)
	ctx := context.Background()
	gone := e.mustCreate(t, map[string]any{"identifier": "https://gone.test", "scopes": []map[string]any{{"value": "read"}}})["id"].(string)
	e.mustCreate(t, map[string]any{"identifier": "https://kept.test", "scopes": []map[string]any{{"value": "read"}}})
	for _, aud := range []string{"https://gone.test", "https://kept.test"} {
		suffix := strings.TrimPrefix(aud, "https://")
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		must(e.st.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: e.tn.ID, ID: "cg_" + suffix, ClientID: "c1", Audience: aud, Scopes: []string{"read"}, SubjectType: store.SubjectTypeClient, CreatedAt: now}))
		must(e.st.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: e.tn.ID, ID: "cgu_" + suffix, ClientID: "c1", Audience: aud, Scopes: []string{"read"}, SubjectType: store.SubjectTypeUser, CreatedAt: now}))
		_, err := e.st.UserGrants().Upsert(ctx, &store.UserGrant{TenantID: e.tn.ID, ID: "ug_" + suffix, ClientID: "c1", UserID: "auth0|u1", Audience: aud, Scopes: []string{"read"}, CreatedAt: now, UpdatedAt: now})
		must(err)
		must(e.st.RefreshTokens().Create(ctx, &store.RefreshToken{TenantID: e.tn.ID, ID: "rt_" + suffix, TokenHash: "h_" + suffix, FamilyID: "f_" + suffix,
			ClientID: "c1", UserID: "auth0|u1", Audience: aud, Scopes: []string{"read"}, CreatedAt: now}))
	}
	// A refresh token with no audience (userinfo only) is not affected.
	if err := e.st.RefreshTokens().Create(ctx, &store.RefreshToken{TenantID: e.tn.ID, ID: "rt_none", TokenHash: "h_none", FamilyID: "f_none", ClientID: "c1", UserID: "auth0|u1", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}

	if rec := e.del(t, e.tn, gone); rec.Code != 204 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	for _, aud := range []string{"https://gone.test"} {
		for _, subject := range []string{store.SubjectTypeClient, store.SubjectTypeUser} {
			if _, err := e.st.ClientGrants().Find(ctx, e.tn.ID, "c1", aud, subject); err == nil {
				t.Errorf("%s grant for %s survived", subject, aud)
			}
		}
		if _, err := e.st.UserGrants().Find(ctx, e.tn.ID, "c1", "auth0|u1", aud); err == nil {
			t.Errorf("user grant for %s survived", aud)
		}
		if _, err := e.st.RefreshTokens().GetByTokenHash(ctx, e.tn.ID, "h_gone.test"); err == nil {
			t.Error("refresh token for the deleted API survived")
		}
	}
	for _, subject := range []string{store.SubjectTypeClient, store.SubjectTypeUser} {
		if _, err := e.st.ClientGrants().Find(ctx, e.tn.ID, "c1", "https://kept.test", subject); err != nil {
			t.Errorf("%s grant for the other API: %v", subject, err)
		}
	}
	if _, err := e.st.UserGrants().Find(ctx, e.tn.ID, "c1", "auth0|u1", "https://kept.test"); err != nil {
		t.Errorf("user grant for the other API: %v", err)
	}
	for _, h := range []string{"h_kept.test", "h_none"} {
		if _, err := e.st.RefreshTokens().GetByTokenHash(ctx, e.tn.ID, h); err != nil {
			t.Errorf("refresh token %s: %v", h, err)
		}
	}
	// Creating the API again starts clean.
	e.mustCreate(t, map[string]any{"identifier": "https://gone.test", "scopes": []map[string]any{{"value": "read"}}})
	if grants, _, _ := e.st.ClientGrants().List(ctx, e.tn.ID, store.ClientGrantFilter{Audience: "https://gone.test"}, store.Page{}); len(grants) != 0 {
		t.Errorf("%d grants for the re-created API", len(grants))
	}
}

// The response is valid JSON of the declared shape for every handler.
func TestResourceServerResponseHeaders(t *testing.T) {
	e := newRSEnv(t)
	rec, _ := e.create(t, map[string]any{"identifier": "https://api.test"})
	if ct := rec.Header().Get("Content-Type"); rec.Code != 201 || !strings.HasPrefix(ct, "application/json") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("create: %d %q %q", rec.Code, ct, rec.Header().Get("Cache-Control"))
	}
	rec = e.del(t, e.tn, "nope")
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("delete: Cache-Control %q", rec.Header().Get("Cache-Control"))
	}
}
