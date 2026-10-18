package mgmt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

type clientsEnv struct {
	st  store.Store
	w   keys.Wrapper
	tn  *store.Tenant
	sys *store.Tenant
	h   *mgmt.Handlers
}

var allClientScopes = []string{"read:clients", "create:clients", "update:clients", "delete:clients", "read:client_keys", "update:client_keys"}

func m2mCaller(scopes ...string) mgmt.Caller {
	return mgmt.Caller{Kind: mgmt.M2M, ClientID: "m2m", Scopes: scopes}
}

func newClientsEnv(t *testing.T) *clientsEnv {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tn, err := tenantsetup.UpsertTenant(ctx, st, "acme", now, func(tn *store.Tenant) error {
		tn.Domains = []string{"login.acme.test"}
		tn.PushedAuthorizationRequestsSupported = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sys, err := system.Ensure(ctx, st, system.Config{Host: systemHost, Wrapper: w})
	if err != nil {
		t.Fatal(err)
	}
	clock := now
	tick := func() time.Time { clock = clock.Add(time.Second); return clock }
	return &clientsEnv{st: st, w: w, tn: tn, sys: sys, h: &mgmt.Handlers{Store: st, Wrapper: w, Now: tick}}
}

// call runs fn as the handler of a request to tn by caller.
func (e *clientsEnv) call(t *testing.T, tn *store.Tenant, caller mgmt.Caller, method, target string, body any, fn http.HandlerFunc) (*httptest.ResponseRecorder, any) {
	t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case string:
		rd = bytes.NewReader([]byte(b))
	default:
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, "https://login.acme.test"+target, rd)
	ctx := tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: tn, Host: "login.acme.test"})
	req = req.WithContext(mgmt.WithCaller(ctx, caller))
	rec := httptest.NewRecorder()
	fn(rec, req)
	var out any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func (e *clientsEnv) create(t *testing.T, caller mgmt.Caller, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.call(t, e.tn, caller, "POST", "/api/v2/clients", body, e.h.CreateClient)
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *clientsEnv) mustCreate(t *testing.T, body any) map[string]any {
	t.Helper()
	rec, out := e.create(t, m2mCaller(allClientScopes...), body)
	if rec.Code != 201 {
		t.Fatalf("create %v = %d %s", body, rec.Code, rec.Body)
	}
	return out
}

func (e *clientsEnv) patch(t *testing.T, caller mgmt.Caller, id string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.call(t, e.tn, caller, "PATCH", "/api/v2/clients/"+id, body, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateClient(w, r, id) })
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *clientsEnv) list(t *testing.T, query string) (*httptest.ResponseRecorder, any) {
	t.Helper()
	return e.call(t, e.tn, m2mCaller("read:clients"), "GET", "/api/v2/clients"+query, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetClients(w, r, mgmtapi.GetClientsParams{})
	})
}

func wantError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != status || body["errorCode"] != code || body["statusCode"] != float64(status) {
		t.Fatalf("got %d %s, want %d %s", rec.Code, rec.Body, status, code)
	}
}

func strs(v any) []string {
	var out []string
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	return out
}

func TestCreateClientDefaults(t *testing.T) {
	e := newClientsEnv(t)
	spa := e.mustCreate(t, map[string]any{"name": "Web app", "app_type": "spa"})
	id, _ := spa["client_id"].(string)
	if len(id) != 32 || spa["tenant"] != "acme" || spa["token_endpoint_auth_method"] != "none" ||
		spa["is_first_party"] != true || spa["oidc_conformant"] != true || spa["global"] != false ||
		spa["client_secret"] != nil || !slices.Equal(strs(spa["grant_types"]), []string{"authorization_code", "refresh_token"}) {
		t.Fatalf("spa = %v", spa)
	}
	rt := spa["refresh_token"].(map[string]any)
	if rt["rotation_type"] != "rotating" || rt["expiration_type"] != "expiring" || rt["infinite_token_lifetime"] != false {
		t.Errorf("spa refresh_token = %v", rt)
	}
	if jc := spa["jwt_configuration"].(map[string]any); jc["alg"] != "RS256" || jc["lifetime_in_seconds"] != float64(36000) {
		t.Errorf("jwt_configuration = %v", jc)
	}
	for _, f := range []string{"callbacks", "allowed_logout_urls", "web_origins", "allowed_origins"} {
		if v, ok := spa[f].([]any); !ok || len(v) != 0 {
			t.Errorf("%s = %v, want []", f, spa[f])
		}
	}
	stored, err := e.st.Clients().Get(context.Background(), e.tn.ID, id)
	if err != nil || stored.Origin != store.OriginAPI || stored.Secrets != nil {
		t.Fatalf("stored = %+v, %v", stored, err)
	}

	// No app_type: a confidential regular web application with a secret.
	web := e.mustCreate(t, map[string]any{"name": "Server"})
	secret, _ := web["client_secret"].(string)
	if web["app_type"] != "regular_web" || web["token_endpoint_auth_method"] != "client_secret_post" || len(secret) != 64 ||
		!slices.Equal(strs(web["grant_types"]), []string{"authorization_code", "refresh_token", "client_credentials"}) {
		t.Fatalf("web = %v", web)
	}
	rt = web["refresh_token"].(map[string]any)
	if rt["rotation_type"] != "non-rotating" || rt["expiration_type"] != "non-expiring" || rt["infinite_token_lifetime"] != true {
		t.Errorf("web refresh_token = %v", rt)
	}
	stored, _ = e.st.Clients().Get(context.Background(), e.tn.ID, web["client_id"].(string))
	if len(stored.Secrets) != 1 || stored.Secrets[0].Hash != "" {
		t.Fatalf("secrets = %+v", stored.Secrets)
	}
	if got, err := keys.OpenClientSecret(e.w, e.tn.ID, stored.ClientID, stored.Secrets[0].Sealed); err != nil || got != secret {
		t.Fatalf("sealed secret = %q, %v", got, err)
	}

	// M2: without read:client_keys the secret is left out.
	rec, out := e.create(t, m2mCaller("create:clients"), map[string]any{"name": "Quiet", "app_type": "non_interactive", "grant_types": []string{"client_credentials"}})
	if rec.Code != 201 || out["client_secret"] != nil {
		t.Fatalf("create without read:client_keys = %d %v", rec.Code, out)
	}
}

func TestCreateClientSuppliedSecret(t *testing.T) {
	e := newClientsEnv(t)
	secret := strings.Repeat("s", 48)
	out := e.mustCreate(t, map[string]any{"name": "M2M", "app_type": "non_interactive", "client_secret": secret})
	if out["client_secret"] != secret {
		t.Fatalf("secret = %v", out["client_secret"])
	}
	rec, _ := e.create(t, m2mCaller(allClientScopes...), map[string]any{"name": "Short", "client_secret": strings.Repeat("s", 47)})
	wantError(t, rec, 400, "invalid_body")
	rec, _ = e.create(t, m2mCaller(allClientScopes...), map[string]any{"name": "Public", "app_type": "spa", "client_secret": secret})
	wantError(t, rec, 400, "invalid_body")
}

func TestCreateClientRefusals(t *testing.T) {
	e := newClientsEnv(t)
	all := m2mCaller(allClientScopes...)
	for name, tc := range map[string]struct {
		body   any
		status int
		code   string
	}{
		"client_id":           {map[string]any{"name": "x", "client_id": "mine"}, 403, "operation_not_supported"},
		"unknown property":    {map[string]any{"name": "x", "colour": "blue"}, 400, "invalid_body"},
		"no name":             {map[string]any{"app_type": "spa"}, 400, "invalid_body"},
		"empty name":          {map[string]any{"name": ""}, 400, "invalid_body"},
		"bad app_type":        {map[string]any{"name": "x", "app_type": "robot"}, 400, "invalid_body"},
		"bad callback":        {map[string]any{"name": "x", "callbacks": []string{"not a url"}}, 400, "invalid_body"},
		"bad origin":          {map[string]any{"name": "x", "web_origins": []string{"https://a.test/path"}}, 400, "invalid_body"},
		"not OIDC-conformant": {map[string]any{"name": "x", "oidc_conformant": false}, 400, "invalid_body"},
		"unknown grant":       {map[string]any{"name": "x", "grant_types": []string{"telepathy"}}, 400, "invalid_body"},
		"HS256":               {map[string]any{"name": "x", "jwt_configuration": map[string]any{"alg": "HS256"}}, 400, "invalid_body"},
		"wrong type":          {map[string]any{"name": 5}, 400, "invalid_body"},
		"not an object":       {"[1,2]", 400, "invalid_body"},
		"not JSON":            {"{", 400, "invalid_body"},
		"refresh unknown":     {map[string]any{"name": "x", "refresh_token": map[string]any{"forever": true}}, 400, "invalid_body"},
		"SPA non-expiring":    {map[string]any{"name": "x", "app_type": "spa", "refresh_token": map[string]any{"rotation_type": "non-rotating", "expiration_type": "non-expiring"}}, 400, "invalid_body"},
	} {
		t.Run(name, func(t *testing.T) {
			rec, _ := e.create(t, all, tc.body)
			wantError(t, rec, tc.status, tc.code)
		})
	}
	// Fields Auth0's tools send are accepted and ignored (D-0039), as
	// auth0-cli's apps create sends them.
	out := e.mustCreate(t, map[string]any{"name": "cli", "description": "", "client_metadata": map[string]any{},
		"oidc_conformant": true, "jwt_configuration": map[string]any{"alg": "RS256"}, "app_type": "spa",
		"grant_types": []string{"implicit", "authorization_code", "refresh_token"}, "token_endpoint_auth_method": "none"})
	if out["description"] != nil || !slices.Contains(strs(out["grant_types"]), "implicit") {
		t.Fatalf("cli create = %v", out)
	}
	clients, _ := e.st.Clients().List(context.Background(), e.tn.ID)
	if len(clients) != 1 {
		t.Fatalf("%d clients stored after refusals", len(clients))
	}
}

func TestGetClient(t *testing.T) {
	e := newClientsEnv(t)
	c := e.mustCreate(t, map[string]any{"name": "Server", "app_type": "regular_web", "callbacks": []string{"https://a.test/cb"}})
	id := c["client_id"].(string)
	get := func(caller mgmt.Caller, id, query string) (*httptest.ResponseRecorder, map[string]any) {
		rec, out := e.call(t, e.tn, caller, "GET", "/api/v2/clients/"+id+query, nil, func(w http.ResponseWriter, r *http.Request) {
			e.h.GetClient(w, r, id, mgmtapi.GetClientParams{})
		})
		m, _ := out.(map[string]any)
		return rec, m
	}
	rec, out := get(m2mCaller("read:clients"), id, "")
	if rec.Code != 200 || out["client_id"] != id || out["client_secret"] != nil || !slices.Equal(strs(out["callbacks"]), []string{"https://a.test/cb"}) {
		t.Fatalf("get = %d %v", rec.Code, out)
	}
	if _, out = get(m2mCaller("read:clients", "read:client_keys"), id, ""); out["client_secret"] != c["client_secret"] {
		t.Fatalf("with read:client_keys: secret %v, want %v", out["client_secret"], c["client_secret"])
	}
	// M7: fields, with tenant always present.
	if _, out = get(m2mCaller("read:clients"), id, "?fields=name,callbacks"); len(out) != 3 || out["name"] != "Server" || out["tenant"] != "acme" {
		t.Fatalf("fields = %v", out)
	}
	if _, out = get(m2mCaller("read:clients"), id, "?fields=name,tenant&include_fields=false"); out["name"] != nil || out["tenant"] != "acme" || out["client_id"] != id {
		t.Fatalf("exclude fields = %v", out)
	}
	rec, _ = get(m2mCaller("read:clients"), "nope", "")
	wantError(t, rec, 404, "inexistent_client")

	// A legacy hashed secret cannot be revealed.
	stored, _ := e.st.Clients().Get(context.Background(), e.tn.ID, id)
	stored.Secrets = []store.ClientSecret{{Hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA", CreatedAt: now}}
	if err := e.st.Clients().Update(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	if _, out = get(m2mCaller("read:clients", "read:client_keys"), id, ""); out["client_secret"] != nil {
		t.Fatalf("legacy secret revealed: %v", out["client_secret"])
	}
}

func TestListClients(t *testing.T) {
	e := newClientsEnv(t)
	var ids []string
	for _, b := range []map[string]any{
		{"name": "zeta", "app_type": "spa"},
		{"name": "alpha", "app_type": "regular_web"},
		{"name": "mid", "app_type": "non_interactive", "is_first_party": false, "grant_types": []string{"client_credentials"}},
	} {
		ids = append(ids, e.mustCreate(t, b)["client_id"].(string))
	}
	names := func(v any) []string {
		var out []string
		for _, c := range v.([]any) {
			out = append(out, c.(map[string]any)["name"].(string))
		}
		return out
	}
	// M6: creation order, bare array.
	rec, out := e.list(t, "")
	if rec.Code != 200 || !slices.Equal(names(out), []string{"zeta", "alpha", "mid"}) {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	for _, c := range out.([]any) {
		if c.(map[string]any)["client_secret"] != nil {
			t.Error("secret listed without read:client_keys")
		}
	}
	rec, out = e.list(t, "?include_totals=true&per_page=2&page=1")
	page := out.(map[string]any)
	if rec.Code != 200 || page["total"] != float64(3) || page["start"] != float64(2) || page["limit"] != float64(2) || !slices.Equal(names(page["clients"]), []string{"mid"}) {
		t.Fatalf("page = %d %s", rec.Code, rec.Body)
	}
	if _, out = e.list(t, "?app_type=spa,non_interactive"); !slices.Equal(names(out), []string{"zeta", "mid"}) {
		t.Errorf("app_type filter = %v", names(out))
	}
	if _, out = e.list(t, "?is_first_party=false"); !slices.Equal(names(out), []string{"mid"}) {
		t.Errorf("is_first_party filter = %v", names(out))
	}
	if _, out = e.list(t, "?fields=name"); len(out.([]any)[0].(map[string]any)) != 2 {
		t.Errorf("fields = %v", out)
	}
	for _, q := range []string{"?per_page=101", "?page=-1", "?app_type=robot", "?is_first_party=maybe", "?include_totals=yes"} {
		rec, _ := e.list(t, q)
		wantError(t, rec, 400, "invalid_query_string")
	}
}

func TestUpdateClient(t *testing.T) {
	e := newClientsEnv(t)
	all := m2mCaller(allClientScopes...)
	c := e.mustCreate(t, map[string]any{"name": "Server", "app_type": "regular_web"})
	id := c["client_id"].(string)
	oldSecret := c["client_secret"].(string)

	rec, out := e.patch(t, all, id, map[string]any{"callbacks": []string{"https://a.test/cb"}, "name": "Renamed",
		"refresh_token": map[string]any{"leeway": 30}, "jwt_configuration": map[string]any{"lifetime_in_seconds": 600}})
	if rec.Code != 200 || out["name"] != "Renamed" || !slices.Equal(strs(out["callbacks"]), []string{"https://a.test/cb"}) ||
		out["client_secret"] != oldSecret || out["refresh_token"].(map[string]any)["leeway"] != float64(30) ||
		out["jwt_configuration"].(map[string]any)["lifetime_in_seconds"] != float64(600) {
		t.Fatalf("patch = %d %v", rec.Code, out)
	}
	// What auth0-cli's apps update sends back: the values it read.
	rec, _ = e.patch(t, all, id, map[string]any{"name": "Renamed", "description": "", "app_type": "regular_web",
		"refresh_token": out["refresh_token"], "client_metadata": map[string]any{}, "token_endpoint_auth_method": "client_secret_post"})
	if rec.Code != 200 {
		t.Fatalf("auth0-cli style update = %d %s", rec.Code, rec.Body)
	}

	// M8: party and security mode are fixed.
	rec, _ = e.patch(t, all, id, map[string]any{"is_first_party": false})
	wantError(t, rec, 400, "invalid_body")
	rec, _ = e.patch(t, all, id, map[string]any{"third_party_security_mode": "permissive"})
	wantError(t, rec, 400, "invalid_body")
	if rec, _ = e.patch(t, all, id, map[string]any{"is_first_party": true}); rec.Code != 200 {
		t.Fatalf("unchanged is_first_party = %d %s", rec.Code, rec.Body)
	}
	// client_id may be sent only unchanged.
	if rec, _ = e.patch(t, all, id, map[string]any{"client_id": id}); rec.Code != 200 {
		t.Fatalf("same client_id = %d", rec.Code)
	}
	rec, _ = e.patch(t, all, id, map[string]any{"client_id": "other"})
	wantError(t, rec, 400, "invalid_body")
	rec, _ = e.patch(t, all, id, map[string]any{"tenant": "acme"})
	wantError(t, rec, 400, "invalid_body")

	// M3: the secret needs update:client_keys, settings update:clients.
	secret := strings.Repeat("k", 50)
	rec, _ = e.patch(t, m2mCaller("update:clients"), id, map[string]any{"client_secret": secret})
	wantError(t, rec, 403, "insufficient_scope")
	rec, _ = e.patch(t, m2mCaller("update:client_keys"), id, map[string]any{"client_secret": secret, "name": "x"})
	wantError(t, rec, 403, "insufficient_scope")
	rec, out = e.patch(t, m2mCaller("update:client_keys", "read:client_keys"), id, map[string]any{"client_secret": secret})
	if rec.Code != 200 || out["client_secret"] != secret {
		t.Fatalf("set secret = %d %v", rec.Code, out)
	}

	// Becoming public drops the secret; becoming confidential again
	// generates one.
	rec, out = e.patch(t, all, id, map[string]any{"token_endpoint_auth_method": "none"})
	if rec.Code != 200 || out["client_secret"] != nil {
		t.Fatalf("to public = %d %v", rec.Code, out)
	}
	rec, out = e.patch(t, all, id, map[string]any{"token_endpoint_auth_method": "client_secret_basic"})
	if s, _ := out["client_secret"].(string); rec.Code != 200 || len(s) != 64 || s == secret {
		t.Fatalf("to confidential = %d %v", rec.Code, out)
	}

	rec, _ = e.patch(t, all, "nope", map[string]any{"name": "x"})
	wantError(t, rec, 404, "inexistent_client")
	rec, _ = e.patch(t, all, id, map[string]any{"require_pushed_authorization_requests": true, "token_endpoint_auth_method": "none"})
	wantError(t, rec, 400, "invalid_body")
}

func TestRotateClientSecret(t *testing.T) {
	e := newClientsEnv(t)
	c := e.mustCreate(t, map[string]any{"name": "Server"})
	id := c["client_id"].(string)
	rotate := func(id string) (*httptest.ResponseRecorder, map[string]any) {
		rec, out := e.call(t, e.tn, m2mCaller("update:client_keys"), "POST", "/api/v2/clients/"+id+"/rotate-secret", nil, func(w http.ResponseWriter, r *http.Request) {
			e.h.RotateClientSecret(w, r, id)
		})
		m, _ := out.(map[string]any)
		return rec, m
	}
	rec, out := rotate(id)
	s, _ := out["client_secret"].(string)
	if rec.Code != 200 || len(s) != 64 || s == c["client_secret"] {
		t.Fatalf("rotate = %d %v", rec.Code, out)
	}
	stored, _ := e.st.Clients().Get(context.Background(), e.tn.ID, id)
	if len(stored.Secrets) != 1 {
		t.Fatalf("secrets after rotation = %d, want 1 (no overlap, M4)", len(stored.Secrets))
	}
	rec, _ = rotate("nope")
	wantError(t, rec, 404, "inexistent_client")
	spa := e.mustCreate(t, map[string]any{"name": "SPA", "app_type": "spa"})
	rec, _ = rotate(spa["client_id"].(string))
	wantError(t, rec, 400, "invalid_body")
}

// Review Focus 3: deleting a client in use removes its grants, refresh
// tokens and connection memberships, and nothing else.
func TestDeleteClientCascades(t *testing.T) {
	e := newClientsEnv(t)
	ctx := context.Background()
	gone := e.mustCreate(t, map[string]any{"name": "Gone"})["client_id"].(string)
	kept := e.mustCreate(t, map[string]any{"name": "Kept"})["client_id"].(string)
	err := tenantsetup.UpsertConnection(ctx, e.st, e.tn.ID, "db", now, func(c *store.Connection) error {
		c.Strategy, c.EnabledClients = store.StrategyDatabase, []string{gone, kept}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{gone, kept} {
		suffix := string(rune('a' + i))
		if err := e.st.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: e.tn.ID, ID: "cg" + suffix, ClientID: id, Audience: "https://api.test", SubjectType: store.SubjectTypeClient}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.st.UserGrants().Upsert(ctx, &store.UserGrant{TenantID: e.tn.ID, ID: "ug" + suffix, ClientID: id, UserID: "auth0|u", Audience: "https://api.test"}); err != nil {
			t.Fatal(err)
		}
		if err := e.st.RefreshTokens().Create(ctx, &store.RefreshToken{TenantID: e.tn.ID, ID: "rt" + suffix, TokenHash: "h" + suffix, FamilyID: "f" + suffix, ClientID: id, UserID: "auth0|u"}); err != nil {
			t.Fatal(err)
		}
	}
	del := func(tn *store.Tenant, id string) *httptest.ResponseRecorder {
		rec, _ := e.call(t, tn, m2mCaller("delete:clients"), "DELETE", "/api/v2/clients/"+id, nil, func(w http.ResponseWriter, r *http.Request) {
			e.h.DeleteClient(w, r, id)
		})
		return rec
	}
	if rec := del(e.tn, gone); rec.Code != 204 || rec.Body.Len() != 0 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if _, err := e.st.Clients().Get(ctx, e.tn.ID, gone); err != store.ErrNotFound {
		t.Fatalf("client still there: %v", err)
	}
	if _, err := e.st.ClientGrants().Find(ctx, e.tn.ID, gone, "https://api.test", store.SubjectTypeClient); err != store.ErrNotFound {
		t.Error("client grant kept")
	}
	if _, err := e.st.UserGrants().Find(ctx, e.tn.ID, gone, "auth0|u", "https://api.test"); err != store.ErrNotFound {
		t.Error("user grant kept")
	}
	if _, err := e.st.RefreshTokens().GetByTokenHash(ctx, e.tn.ID, "ha"); err != store.ErrNotFound {
		t.Error("refresh token kept")
	}
	conn, _ := e.st.Connections().GetByName(ctx, e.tn.ID, "db")
	if !slices.Equal(conn.EnabledClients, []string{kept}) {
		t.Errorf("enabled clients = %v", conn.EnabledClients)
	}
	if _, err := e.st.RefreshTokens().GetByTokenHash(ctx, e.tn.ID, "hb"); err != nil {
		t.Error("the other client's refresh token was removed")
	}
	// M9: deleting again is 204 too.
	if rec := del(e.tn, gone); rec.Code != 204 {
		t.Fatalf("second delete = %d", rec.Code)
	}
	// The console's client cannot be deleted.
	if rec := del(e.sys, system.ConsoleClientID); rec.Code != 403 {
		t.Fatalf("delete console client = %d", rec.Code)
	}
	if _, err := e.st.Clients().Get(ctx, e.sys.ID, system.ConsoleClientID); err != nil {
		t.Fatal(err)
	}
}
