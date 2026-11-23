package server

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var dirSyncMgmtScopes = []string{"read:directory_provisionings", "create:directory_provisionings", "update:directory_provisionings", "delete:directory_provisionings"}

func newDirSyncManagement(t *testing.T) (*orgAPI, store.Store, string, string) {
	t.Helper()
	quoted := `"` + strings.Join(append(slices.Clone(orgMgmtScopes), dirSyncMgmtScopes...), `", "`) + `", `
	seedText := strings.Replace(usersSeed, `"read:connections", "create:connections"`, quoted+`"read:connections", "create:connections"`, 1)
	h, st := newMgmtEnvSeed(t, seedText, func(d *Deps) {
		// Google's real endpoints: the tests only follow the redirect.
		d.Federation = &federation.FlowService{Service: federation.Service{Wrapper: d.Wrapper}, Store: d.Store, Providers: federation.NewProviders(federation.NetworkPolicy{}, nil)}
	})
	a := &orgAPI{t: t, h: h, c: newMgmtContract(t), admin: clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")}
	create := func(body map[string]any) string {
		code, out, raw := a.call("POST", "/connections", a.admin, body)
		if code != 201 {
			t.Fatalf("create connection %d %s", code, raw)
		}
		return out["id"].(string)
	}
	ws := create(map[string]any{"name": "workspace", "strategy": "google-apps",
		"options": map[string]any{"client_id": "ws-client", "client_secret": "ws-secret", "domain": "corp.example.com", "api_enable_groups": true}})
	oidc := create(map[string]any{"name": "corp-oidc", "strategy": "oidc",
		"options": map[string]any{"type": "back_channel", "client_id": "c", "client_secret": "s", "discovery_url": "https://idp.example/.well-known/openid-configuration", "scopes": "openid"}})
	return a, st, ws, oidc
}

// TestDirectoryProvisioningRoutes: configuration CRUD on google-apps
// connections only, the default mapping, on-demand synchronization (which
// needs the administrator consent), the group selection and the tenant
// list, validated against the contract.
func TestDirectoryProvisioningRoutes(t *testing.T) {
	a, st, ws, oidc := newDirSyncManagement(t)
	admin := a.admin
	must := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		code, out, raw := a.call(method, path, admin, body)
		if code != want {
			t.Fatalf("%s %s=%d %s", method, path, code, raw)
		}
		return out
	}
	base := "/connections/" + ws + "/directory-provisioning"
	must("GET", base, nil, 404)
	if code, _, _ := a.call("POST", "/connections/"+oidc+"/directory-provisioning", admin, nil); code != 400 {
		t.Fatalf("oidc connection accepted: %d", code)
	}
	dm := must("GET", base+"/default-mapping", nil, 200)
	if m := dm["mapping"].([]any); len(m) != 5 || m[0].(map[string]any)["idp"] != "primaryEmail" {
		t.Fatalf("default mapping %v", dm)
	}
	cfg := must("POST", base, nil, 201)
	if cfg["strategy"] != "google-apps" || cfg["connection_name"] != "workspace" || cfg["synchronize_automatically"] != false || cfg["synchronize_groups"] != "off" || len(cfg["mapping"].([]any)) != 5 {
		t.Fatalf("created %v", cfg)
	}
	must("POST", base, nil, 409)
	for name, body := range map[string]any{
		"unknown auth0 field": map[string]any{"mapping": []any{map[string]any{"auth0": "password", "idp": "x"}}},
		"bad path":            map[string]any{"mapping": []any{map[string]any{"auth0": "email", "idp": "a..b"}}},
		"unknown property":    map[string]any{"synchronize": true},
		"bad groups mode":     map[string]any{"synchronize_groups": "some"},
	} {
		if code, _, raw := a.call("PATCH", base, admin, body); code != 400 {
			t.Errorf("%s = %d %s", name, code, raw)
		}
	}
	upd := must("PATCH", base, map[string]any{"synchronize_automatically": true, "synchronize_groups": "selected",
		"mapping": []any{map[string]any{"auth0": "email", "idp": "primaryEmail"}, map[string]any{"auth0": "app_metadata.department", "idp": "organizations[primary eq true].department"}}}, 200)
	if upd["synchronize_automatically"] != true || upd["synchronize_groups"] != "selected" || len(upd["mapping"].([]any)) != 2 {
		t.Fatalf("updated %v", upd)
	}

	// On-demand synchronization needs the administrator's grant.
	if code, out, _ := a.call("POST", base+"/synchronizations", admin, nil); code != 400 || !strings.Contains(out["message"].(string), "administrator") {
		t.Fatalf("synchronization without grant %d %v", code, out)
	}
	ctx := context.Background()
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	p, _ := st.DirectorySync().GetProvisioning(ctx, tn.ID, ws)
	p.AdminGrant = []byte("sealed")
	if err := st.DirectorySync().UpdateProvisioning(ctx, p); err != nil {
		t.Fatal(err)
	}
	s := must("POST", base+"/synchronizations", nil, 201)
	if s["connection_id"] != ws || s["status"] != "pending" || !strings.HasPrefix(s["synchronization_id"].(string), "dsync_") {
		t.Fatalf("synchronization %v", s)
	}
	must("POST", base+"/synchronizations", nil, 409)
	if p, _ := st.DirectorySync().GetProvisioning(ctx, tn.ID, ws); p.NextSyncAt == nil || p.NextSyncAt.After(time.Now()) || p.SyncID != s["synchronization_id"] {
		t.Fatalf("not scheduled %+v", p)
	}

	// Group selection.
	g := base + "/synchronized-groups"
	if out := must("GET", g, nil, 200); len(out["groups"].([]any)) != 0 {
		t.Fatalf("groups %v", out)
	}
	must("PUT", g, map[string]any{"groups": []any{map[string]any{"id": "03abc", "name": "Engineering", "email": "eng@corp.example.com", "direct_members_count": 3}, map[string]any{"id": "04def", "name": "Sales"}}}, 204)
	must("POST", g, map[string]any{"groups": []any{map[string]any{"id": "05ghi", "name": "Support"}, map[string]any{"id": "04def", "name": "Sales EMEA"}}}, 204)
	out := must("GET", g, nil, 200)
	if gs := out["groups"].([]any); len(gs) != 3 || gs[1].(map[string]any)["name"] != "Sales EMEA" {
		t.Fatalf("after add %v", out)
	}
	if out := must("GET", g+"?q="+"name:eng*", nil, 200); len(out["groups"].([]any)) != 1 {
		t.Fatalf("q %v", out)
	}
	if code, _, _ := a.call("GET", g+"?q=title:x", admin, nil); code != 400 {
		t.Fatal("bad q accepted")
	}
	page := must("GET", g+"?take=2", nil, 200)
	if len(page["groups"].([]any)) != 2 || page["next"] == nil {
		t.Fatalf("page %v", page)
	}
	if rest := must("GET", g+"?take=2&from="+page["next"].(string), nil, 200); len(rest["groups"].([]any)) != 1 || rest["next"] != nil {
		t.Fatalf("second page %v", rest)
	}
	must("DELETE", g, map[string]any{"groups": []any{map[string]any{"id": "03abc"}}}, 204)
	if out := must("GET", g, nil, 200); len(out["groups"].([]any)) != 2 {
		t.Fatalf("after delete %v", out)
	}
	if code, _, _ := a.call("PUT", g, admin, map[string]any{"groups": []any{map[string]any{"id": "not-alnum!"}}}); code != 400 {
		t.Fatal("bad group ID accepted")
	}

	list := must("GET", "/connections-directory-provisionings", nil, 200)
	if l := list["directory_provisionings"].([]any); len(l) != 1 || l[0].(map[string]any)["connection_id"] != ws {
		t.Fatalf("list %v", list)
	}
	// The grant never appears.
	if _, _, raw := a.call("GET", base, admin, nil); strings.Contains(string(raw), "sealed") || strings.Contains(string(raw), "grant") {
		t.Fatalf("grant exposed: %s", raw)
	}
	must("DELETE", base, nil, 204)
	must("DELETE", base, nil, 404)
	must("GET", g, nil, 404)
}

// TestDirectoryProvisioningScopes is the 401/403 matrix of the Phase C routes.
func TestDirectoryProvisioningScopes(t *testing.T) {
	a, _, ws, _ := newDirSyncManagement(t)
	base := "/connections/" + ws + "/directory-provisioning"
	cases := []struct{ method, path, scope string }{
		{"GET", base, "read:directory_provisionings"}, {"POST", base, "create:directory_provisionings"},
		{"PATCH", base, "update:directory_provisionings"}, {"DELETE", base, "delete:directory_provisionings"},
		{"GET", base + "/default-mapping", "read:directory_provisionings"}, {"POST", base + "/synchronizations", "create:directory_provisionings"},
		{"GET", base + "/synchronized-groups", "read:directory_provisionings"}, {"POST", base + "/synchronized-groups", "update:directory_provisionings"},
		{"PUT", base + "/synchronized-groups", "update:directory_provisionings"}, {"DELETE", base + "/synchronized-groups", "update:directory_provisionings"},
		{"GET", "/connections-directory-provisionings", "read:directory_provisionings"},
	}
	all := append(slices.Clone(orgMgmtScopes), dirSyncMgmtScopes...)
	for _, c := range cases {
		t.Run(c.method+c.path, func(t *testing.T) {
			if code, _, raw := a.call(c.method, c.path, "", map[string]any{}); code != 401 {
				t.Fatalf("no token=%d %s", code, raw)
			}
			var others []string
			for _, s := range all {
				if s != c.scope {
					others = append(others, s)
				}
			}
			if code, out, raw := a.call(c.method, c.path, a.token(others), map[string]any{}); code != 403 || out["errorCode"] != "insufficient_scope" {
				t.Fatalf("without %s=%d %s", c.scope, code, raw)
			}
			if code, _, raw := a.call(c.method, c.path, a.token([]string{c.scope}), map[string]any{}); code == 401 || code == 403 {
				t.Fatalf("with only %s=%d %s", c.scope, code, raw)
			}
		})
	}
}

// TestDirectoryProvisioningConsentLink: an operator managing the tenant
// gets a consent link on the tenant host, and the link starts the Google
// administrator consent with offline Directory API access.
func TestDirectoryProvisioningConsentLink(t *testing.T) {
	a, st, ws, oidc := newDirSyncManagement(t)
	ctx := context.Background()
	systemURL := "https://" + mgmtSystemHost + "/api/system/tenants/"
	acmeOnly, userID := tenantOperatorToken(t, st, "dirsync-op@example.test", []string{"acme"})
	otherOnly := mintTargetOperator(t, st, userID, []string{"globex"})
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: mustSystemID(t, st), UserID: userID, Tenants: []string{"acme"}}); err != nil {
		t.Fatal(err)
	}
	path := "acme/connections/" + ws + "/directory-provisioning/consent"
	if rec, _ := sendRaw(a.h, "POST", systemURL+path, acmeOnly, nil); rec.Code != 404 {
		t.Fatalf("without a configuration = %d %s", rec.Code, rec.Body)
	}
	if code, _, raw := a.call("POST", "/connections/"+ws+"/directory-provisioning", a.admin, nil); code != 201 {
		t.Fatalf("%d %s", code, raw)
	}
	for name, tc := range map[string]struct {
		url, token string
		want       int
	}{
		"no token":       {systemURL + path, "", 401},
		"other tenant":   {systemURL + path, otherOnly, 403},
		"tenant M2M":     {systemURL + path, a.admin, 401},
		"not google":     {systemURL + "acme/connections/" + oidc + "/directory-provisioning/consent", acmeOnly, 400},
		"tenant host":    {"https://acme.example.test/api/system/tenants/" + path, acmeOnly, 404},
		"unknown tenant": {systemURL + "nope/connections/" + ws + "/directory-provisioning/consent", acmeOnly, 404},
	} {
		if rec, _ := sendRaw(a.h, "POST", tc.url, tc.token, nil); rec.Code != tc.want {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}
	rec, res := sendRaw(a.h, "POST", systemURL+path, acmeOnly, nil)
	out, _ := res.(map[string]any)
	if rec.Code != 200 {
		t.Fatalf("consent link = %d %s", rec.Code, rec.Body)
	}
	link, _ := out["url"].(string)
	if !strings.HasPrefix(link, "https://acme.example.test/directory-provisioning/consent?ticket=") || out["redirect_uri"] != "https://acme.example.test/directory-provisioning/callback" {
		t.Fatalf("link %v", out)
	}
	start, _ := sendRaw(a.h, "GET", link, "", nil)
	loc := start.Header().Get("Location")
	if start.Code != 303 || !strings.Contains(loc, "access_type=offline") || !strings.Contains(loc, "hd=corp.example.com") || !strings.Contains(loc, "admin.directory.group.readonly") {
		t.Fatalf("consent start = %d %s %s", start.Code, loc, start.Body)
	}
	// The link of one tenant does nothing on another tenant's host.
	globex := &store.Tenant{ID: "globex-id", Name: "globex", Domains: []string{"globex.example.test"}}
	if err := st.Tenants().Create(ctx, globex); err != nil {
		t.Fatal(err)
	}
	if rec, _ := sendRaw(a.h, "GET", strings.Replace(link, "acme.example.test", "globex.example.test", 1), "", nil); rec.Code != 400 {
		t.Fatalf("cross-tenant link = %d", rec.Code)
	}
}
