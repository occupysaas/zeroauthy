package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const connBase = "https://acme.example.test/api/v2/connections"

type connEnv struct {
	t      *testing.T
	h      http.Handler
	st     store.Store
	w      keys.Wrapper
	admin  string
	reader string
	tenant *store.Tenant
}

func newConnEnv(t *testing.T) *connEnv {
	t.Helper()
	h, st := newMgmtEnv(t)
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	tn, err := st.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	return &connEnv{
		t: t, h: h, st: st, w: w, tenant: tn,
		admin:  clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret"),
		reader: m2mToken(t, h, "acme.example.test", acmeMgmtAPI),
	}
}

// do sends a request as the admin and decodes an object body.
func (e *connEnv) do(method, target string, body any) (*httptest.ResponseRecorder, map[string]any) {
	e.t.Helper()
	return sendJSON(e.h, method, target, e.admin, body)
}

// doAny is do for bodies that are not objects.
func (e *connEnv) doAny(method, target string, body any) (*httptest.ResponseRecorder, any) {
	e.t.Helper()
	rec, _ := sendJSON(e.h, method, target, e.admin, body)
	var out any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func (e *connEnv) create(body map[string]any) map[string]any {
	e.t.Helper()
	rec, out := e.do("POST", connBase, body)
	if rec.Code != 201 {
		e.t.Fatalf("create %v = %d %s", body, rec.Code, rec.Body)
	}
	return out
}

func (e *connEnv) createClient(name string) string {
	e.t.Helper()
	rec, out := e.do("POST", "https://acme.example.test/api/v2/clients", map[string]any{"name": name, "app_type": "spa", "callbacks": []string{"https://app.acme.test/cb"}})
	id, _ := out["client_id"].(string)
	if rec.Code != 201 || id == "" {
		e.t.Fatalf("create client = %d %s", rec.Code, rec.Body)
	}
	return id
}

func wantError(t *testing.T, what string, rec *httptest.ResponseRecorder, body map[string]any, status int, code string) {
	t.Helper()
	got, _ := body["errorCode"].(string)
	if rec.Code != status || got != code {
		t.Errorf("%s = %d %s, want %d %q", what, rec.Code, rec.Body, status, code)
	}
}

var apiConnID = regexp.MustCompile(`^con_[A-Za-z0-9]{16}$`)

func TestCreateConnectionDefaults(t *testing.T) {
	e := newConnEnv(t)
	out := e.create(map[string]any{"name": "Customers", "strategy": "auth0"})
	id, _ := out["id"].(string)
	if !apiConnID.MatchString(id) {
		t.Errorf("id = %q", id)
	}
	if out["name"] != "Customers" || out["strategy"] != "auth0" || out["is_domain_connection"] != false {
		t.Errorf("body = %v", out)
	}
	if got, ok := out["enabled_clients"].([]any); !ok || len(got) != 0 {
		t.Errorf("enabled_clients = %v", out["enabled_clients"])
	}
	if !slices.Equal(toStrings(out["realms"]), []string{"Customers"}) {
		t.Errorf("realms = %v", out["realms"])
	}
	if a, _ := out["authentication"].(map[string]any); a["active"] != true {
		t.Errorf("authentication = %v", out["authentication"])
	}
	if a, _ := out["connected_accounts"].(map[string]any); a["active"] != false {
		t.Errorf("connected_accounts = %v", out["connected_accounts"])
	}
	if _, has := out["display_name"]; has {
		t.Errorf("display_name = %v", out["display_name"])
	}
	opts, _ := out["options"].(map[string]any)
	if opts["brute_force_protection"] != true || opts["strategy_version"] != float64(2) {
		t.Errorf("options = %v", opts)
	}
	if m, _ := opts["mfa"].(map[string]any); m["active"] != true || m["return_enroll_settings"] != true {
		t.Errorf("mfa = %v", opts["mfa"])
	}
	pw, _ := opts["password_options"].(map[string]any)
	cx, _ := pw["complexity"].(map[string]any)
	if cx["min_length"] != float64(15) || cx["character_type_rule"] != "all" || cx["max_length_exceeded"] != "error" ||
		cx["identical_characters"] != "allow" || cx["sequential_characters"] != "allow" {
		t.Errorf("complexity = %v", cx)
	}
	if h, _ := pw["history"].(map[string]any); h["active"] != false || h["size"] != float64(3) {
		t.Errorf("history = %v", pw["history"])
	}
	if d, _ := pw["dictionary"].(map[string]any); d["active"] != false || d["default"] != "en_100k" {
		t.Errorf("dictionary = %v", pw["dictionary"])
	}
	if pd, _ := pw["profile_data"].(map[string]any); pd["active"] != false || len(toStrings(pd["blocked_fields"])) != 8 {
		t.Errorf("profile_data = %v", pw["profile_data"])
	}
	if _, has := opts["configuration"]; has {
		t.Errorf("configuration = %v", opts["configuration"])
	}

	c, err := e.st.Connections().Get(context.Background(), e.tenant.ID, id)
	if err != nil || c.Origin != store.OriginAPI || len(c.EnabledClients) != 0 || !c.BruteForceProtection {
		t.Errorf("stored = %+v, %v", c, err)
	}
}

func toStrings(v any) []string {
	l, _ := v.([]any)
	out := make([]string, len(l))
	for i, e := range l {
		out[i], _ = e.(string)
	}
	return out
}

func TestCreateConnectionValidation(t *testing.T) {
	e := newConnEnv(t)
	cid := e.createClient("App")
	for name, tc := range map[string]struct {
		body map[string]any
		code string
	}{
		"no strategy":        {map[string]any{"name": "NoStrategy"}, "invalid_body"},
		"other strategy":     {map[string]any{"name": "Google", "strategy": "google-oauth2"}, "invalid_body"},
		"no name":            {map[string]any{"strategy": "auth0"}, "invalid_body"},
		"bad name":           {map[string]any{"name": "has_underscore", "strategy": "auth0"}, "invalid_body"},
		"double hyphen":      {map[string]any{"name": "a--b", "strategy": "auth0"}, "invalid_body"},
		"long name":          {map[string]any{"name": strings.Repeat("a", 129), "strategy": "auth0"}, "invalid_body"},
		"unknown property":   {map[string]any{"name": "Unknown", "strategy": "auth0", "colour": "red"}, "invalid_body"},
		"options not object": {map[string]any{"name": "Opts", "strategy": "auth0", "options": "x"}, "invalid_body"},
		"both models":        {map[string]any{"name": "Both", "strategy": "auth0", "options": map[string]any{"passwordPolicy": "good", "password_options": map[string]any{}}}, "invalid_body"},
		"min length 73":      {map[string]any{"name": "Long", "strategy": "auth0", "options": map[string]any{"password_options": map[string]any{"complexity": map[string]any{"min_length": 73}}}}, "invalid_body"},
		"unknown client":     {map[string]any{"name": "NoClient", "strategy": "auth0", "enabled_clients": []string{"nope"}}, "inexistent_client"},
		"malformed client":   {map[string]any{"name": "BadClient", "strategy": "auth0", "enabled_clients": []string{""}}, "invalid_body"},
		"client not string":  {map[string]any{"name": "NumClient", "strategy": "auth0", "enabled_clients": []any{5}}, "invalid_body"},
		"scripts w/o custom": {map[string]any{"name": "Scripts", "strategy": "auth0", "options": map[string]any{"customScripts": map[string]any{"login": "x"}}}, "invalid_body"},
		"case variant key":   {map[string]any{"name": "Variant", "strategy": "auth0", "options": map[string]any{"Configuration": map[string]any{"K": "v"}}}, "invalid_body"},
	} {
		rec, body := e.do("POST", connBase, tc.body)
		wantError(t, name, rec, body, 400, tc.code)
		if tc.body["name"] != nil && tc.body["name"] != "" {
			if _, err := e.st.Connections().GetByName(context.Background(), e.tenant.ID, tc.body["name"].(string)); err == nil {
				t.Errorf("%s: the connection was created", name)
			}
		}
	}

	// Review focus 3: a client of another tenant is as unknown as none.
	ctx := context.Background()
	if err := e.st.Tenants().Create(ctx, &store.Tenant{ID: "ten_globex", Name: "globex", Domains: []string{"globex.test"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Clients().Create(ctx, &store.Client{TenantID: "ten_globex", ClientID: "globex-app", Name: "Globex", AppType: store.AppTypeSPA}); err != nil {
		t.Fatal(err)
	}
	rec, body := e.do("POST", connBase, map[string]any{"name": "Foreign", "strategy": "auth0", "enabled_clients": []string{"globex-app"}})
	wantError(t, "foreign client on create", rec, body, 400, "inexistent_client")

	// enabled_clients on create.
	out := e.create(map[string]any{"name": "WithClients", "strategy": "auth0", "enabled_clients": []string{cid, cid}})
	if !slices.Equal(toStrings(out["enabled_clients"]), []string{cid}) {
		t.Errorf("enabled_clients = %v", out["enabled_clients"])
	}

	// Conflict, and scopes.
	rec, body = e.do("POST", connBase, map[string]any{"name": "WithClients", "strategy": "auth0"})
	wantError(t, "duplicate", rec, body, 409, "connection_conflict")
	if rec, body := sendJSON(e.h, "POST", connBase, e.reader, map[string]any{"name": "Reader", "strategy": "auth0"}); rec.Code != 403 || body["errorCode"] != "insufficient_scope" {
		t.Errorf("create with read scopes = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := sendJSON(e.h, "POST", connBase, "", map[string]any{"name": "NoToken", "strategy": "auth0"}); rec.Code != 401 {
		t.Errorf("create without a token = %d", rec.Code)
	}
}

func TestCreateConnectionOptions(t *testing.T) {
	e := newConnEnv(t)
	out := e.create(map[string]any{
		"name": "Rich", "strategy": "auth0", "display_name": "Rich DB", "is_domain_connection": true,
		"metadata": map[string]any{"team": "core"},
		"options": map[string]any{
			"requires_username": true, "disable_signup": true,
			"validation":       map[string]any{"username": map[string]any{"min": 3, "max": 20}},
			"password_options": map[string]any{"complexity": map[string]any{"min_length": 20, "character_types": []string{"number"}}},
			"my_custom_option": map[string]any{"deep": []any{1, "two"}},
		},
	})
	opts, _ := out["options"].(map[string]any)
	if out["display_name"] != "Rich DB" || out["is_domain_connection"] != true || opts["requires_username"] != true || opts["disable_signup"] != true {
		t.Errorf("body = %v", out)
	}
	if v, _ := opts["validation"].(map[string]any); v["username"].(map[string]any)["max"] != float64(20) {
		t.Errorf("validation = %v", opts["validation"])
	}
	cx := opts["password_options"].(map[string]any)["complexity"].(map[string]any)
	if cx["min_length"] != float64(20) || !slices.Equal(toStrings(cx["character_types"]), []string{"number"}) {
		t.Errorf("complexity = %v", cx)
	}
	if c, _ := opts["my_custom_option"].(map[string]any); len(c) != 1 {
		t.Errorf("unknown option key = %v", opts["my_custom_option"])
	}
	c, _ := e.st.Connections().GetByName(context.Background(), e.tenant.ID, "Rich")
	if c.UsernameMin != 3 || c.UsernameMax != 20 || !c.RequiresUsername || !c.IsDomainConnection || c.PasswordOptions.Complexity.MinLength != 20 {
		t.Errorf("stored = %+v", c)
	}
}

func TestGetConnection(t *testing.T) {
	e := newConnEnv(t)
	cid := e.createClient("App")
	made := e.create(map[string]any{"name": "Getme", "strategy": "auth0", "enabled_clients": []string{cid}})
	id := made["id"].(string)

	rec, out := e.do("GET", connBase+"/"+id, nil)
	if _, has := out["enabled_clients"]; rec.Code != 200 || has || out["name"] != "Getme" || out["id"] != id {
		t.Errorf("get = %d %s", rec.Code, rec.Body)
	}
	if rec, out := sendJSON(e.h, "GET", connBase+"/"+id, e.reader, nil); rec.Code != 403 {
		t.Errorf("get with read:clients only = %d %v", rec.Code, out)
	}
	rec, out = e.do("GET", connBase+"/"+id+"?fields=name", nil)
	if rec.Code != 200 || len(out) != 3 || out["name"] == nil || out["id"] == nil || out["is_domain_connection"] == nil {
		t.Errorf("fields=name = %d %s", rec.Code, rec.Body)
	}
	rec, out = e.do("GET", connBase+"/"+id+"?fields=options,realms&include_fields=false", nil)
	if _, has := out["options"]; rec.Code != 200 || has || out["id"] == nil || out["is_domain_connection"] == nil || out["name"] == nil {
		t.Errorf("include_fields=false = %d %s", rec.Code, rec.Body)
	}

	rec, out = e.do("GET", connBase+"/con_0000000000000000", nil)
	wantError(t, "unknown", rec, out, 404, "inexistent_connection")
	for _, bad := range []string{"nope", "con_", "con_has-dash", "con_" + strings.Repeat("a", 65), "CON_abc"} {
		rec, out = e.do("GET", connBase+"/"+bad, nil)
		wantError(t, "GET "+bad, rec, out, 400, "invalid_uri")
	}
	// A seeded ID has its own length and is still served.
	if err := e.st.Connections().Create(context.Background(), &store.Connection{TenantID: e.tenant.ID, ID: "con_" + strings.Repeat("s", 24), Name: "Seeded", Strategy: store.StrategyDatabase}); err != nil {
		t.Fatal(err)
	}
	if rec, out := e.do("GET", connBase+"/con_"+strings.Repeat("s", 24), nil); rec.Code != 200 || out["name"] != "Seeded" {
		t.Errorf("seeded ID = %d %s", rec.Code, rec.Body)
	}
}

func TestPatchConnection(t *testing.T) {
	e := newConnEnv(t)
	cid := e.createClient("App")
	made := e.create(map[string]any{
		"name": "Patchme", "strategy": "auth0", "enabled_clients": []string{cid}, "display_name": "Before",
		"options": map[string]any{
			"requires_username": true, "keep_me": "x",
			"password_options": map[string]any{"complexity": map[string]any{"min_length": 30, "character_types": []string{"number"}}, "history": map[string]any{"active": true, "size": 5}},
		},
	})
	url := connBase + "/" + made["id"].(string)

	// options is replaced whole; the other properties stay.
	rec, out := e.do("PATCH", url, map[string]any{"options": map[string]any{
		"disable_signup":   true,
		"password_options": map[string]any{"complexity": map[string]any{"min_length": 12}},
	}})
	if rec.Code != 200 {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	opts := out["options"].(map[string]any)
	pw := opts["password_options"].(map[string]any)
	cx := pw["complexity"].(map[string]any)
	if opts["disable_signup"] != true || opts["requires_username"] != false || opts["keep_me"] != nil || opts["strategy_version"] != nil || opts["mfa"] != nil {
		t.Errorf("options not replaced whole: %v", opts)
	}
	if cx["min_length"] != float64(12) || len(toStrings(cx["character_types"])) != 0 {
		t.Errorf("complexity = %v", cx)
	}
	if h := pw["history"].(map[string]any); h["active"] != false || h["size"] != float64(3) {
		t.Errorf("history did not take its default: %v", h)
	}
	if opts["brute_force_protection"] != true {
		t.Errorf("brute_force_protection = %v", opts["brute_force_protection"])
	}
	if out["display_name"] != "Before" || out["name"] != "Patchme" {
		t.Errorf("other properties changed: %v", out)
	}
	c, _ := e.st.Connections().Get(context.Background(), e.tenant.ID, made["id"].(string))
	if !slices.Equal(c.EnabledClients, []string{cid}) || c.Origin != store.OriginAPI || c.PasswordOptions.Complexity.MinLength != 12 {
		t.Errorf("stored = %+v", c)
	}

	// Without options, options stay.
	rec, out = e.do("PATCH", url, map[string]any{"display_name": "After", "is_domain_connection": true})
	if rec.Code != 200 || out["display_name"] != "After" || out["is_domain_connection"] != true || out["options"].(map[string]any)["disable_signup"] != true {
		t.Errorf("patch display_name = %d %s", rec.Code, rec.Body)
	}

	// Unknown properties.
	for name, body := range map[string]map[string]any{
		"name":            {"name": "Renamed"},
		"strategy":        {"strategy": "auth0"},
		"enabled_clients": {"enabled_clients": []string{cid}},
		"unknown":         {"colour": "red"},
		"empty":           {},
		"options null":    {"options": nil},
		"options string":  {"options": "x"},
		"bad password":    {"options": map[string]any{"password_options": map[string]any{"complexity": map[string]any{"min_length": 0}}}},
		"both models":     {"options": map[string]any{"passwordPolicy": "good", "password_options": map[string]any{}}},
	} {
		rec, out := e.do("PATCH", url, body)
		wantError(t, "patch "+name, rec, out, 400, "invalid_body")
	}
	if c2, _ := e.st.Connections().Get(context.Background(), e.tenant.ID, made["id"].(string)); c2.Name != "Patchme" {
		t.Errorf("name = %q", c2.Name)
	}

	rec, out = e.do("PATCH", connBase+"/con_0000000000000000", map[string]any{"display_name": "x"})
	wantError(t, "unknown id", rec, out, 404, "inexistent_connection")
	rec, out = e.do("PATCH", connBase+"/nope", map[string]any{"display_name": "x"})
	wantError(t, "malformed id", rec, out, 400, "invalid_uri")
	if rec, _ := sendJSON(e.h, "PATCH", url, e.reader, map[string]any{"display_name": "x"}); rec.Code != 403 {
		t.Errorf("patch with read scopes = %d", rec.Code)
	}
}

const loginScript = "function login(email, password, callback) { return callback(null, {user_id: email}); }"

// Review focus 2 (D-0042): values are strings or null and are sealed;
// responses carry opaque blobs, never plaintext. options is replaced whole,
// so a blob sent back keeps its secret and a PATCH that leaves
// configuration out drops it (this replaces the plan's keep-on-omission
// rule, which Auth0 does not follow).
func TestPatchConnectionKeepsConfiguration(t *testing.T) {
	e := newConnEnv(t)
	ctx := context.Background()
	custom := func(cfg map[string]any) map[string]any {
		o := map[string]any{"enabledDatabaseCustomization": true, "customScripts": map[string]any{"login": loginScript}}
		if cfg != nil {
			o["configuration"] = cfg
		}
		return o
	}
	unsealed := func(id string) map[string]string {
		t.Helper()
		c, err := e.st.Connections().Get(ctx, e.tenant.ID, id)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := keys.OpenConnectionConfig(e.w, e.tenant.ID, id, c.ConfigurationSealed)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	blobs := func(out map[string]any) map[string]any {
		cfg, _ := out["options"].(map[string]any)["configuration"].(map[string]any)
		return cfg
	}
	noPlaintext := func(what string, rec *httptest.ResponseRecorder, plain ...string) {
		t.Helper()
		for _, s := range plain {
			if strings.Contains(rec.Body.String(), s) {
				t.Errorf("%s: the response holds the plaintext %q: %s", what, s, rec.Body)
			}
		}
	}

	rec, made := e.do("POST", connBase, map[string]any{"name": "Legacy", "strategy": "auth0",
		"options": custom(map[string]any{"API_TOKEN": "tok-s3cret", "API_URL": "https://legacy.example", "GONE": "gone-s3cret"})})
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	noPlaintext("create", rec, "tok-s3cret", "legacy.example", "gone-s3cret")
	id := made["id"].(string)
	url := connBase + "/" + id
	got := blobs(made)
	if len(got) != 3 || got["API_TOKEN"] == "tok-s3cret" || !keys.IsConfigValueBlob(got["API_TOKEN"].(string)) {
		t.Fatalf("create returned %v", got)
	}
	if !sameConfig(unsealed(id), map[string]string{"API_TOKEN": "tok-s3cret", "API_URL": "https://legacy.example", "GONE": "gone-s3cret"}) {
		t.Fatalf("stored = %v", unsealed(id))
	}
	if c, _ := e.st.Connections().Get(ctx, e.tenant.ID, id); c.Extra != nil && strings.Contains(toJSON(c.Extra), "s3cret") {
		t.Errorf("Extra holds configuration: %v", c.Extra)
	}

	// GET returns blobs too.
	rec, read := e.do("GET", url, nil)
	noPlaintext("get", rec, "tok-s3cret", "legacy.example")
	if len(blobs(read)) != 3 {
		t.Errorf("get configuration = %v", blobs(read))
	}

	// A blob sent back keeps its secret, a new string replaces, null removes,
	// and a key left out is dropped.
	rec, out := e.do("PATCH", url, map[string]any{"options": custom(map[string]any{
		"API_TOKEN": blobs(read)["API_TOKEN"], // kept
		"API_URL":   "https://new.example",    // replaced
		"GONE":      nil,                      // removed
		"FRESH":     "fresh-s3cret",           // added
	})})
	if rec.Code != 200 {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	noPlaintext("patch", rec, "tok-s3cret", "new.example", "fresh-s3cret")
	if want := (map[string]string{"API_TOKEN": "tok-s3cret", "API_URL": "https://new.example", "FRESH": "fresh-s3cret"}); !sameConfig(unsealed(id), want) {
		t.Errorf("stored after patch = %v, want %v", unsealed(id), want)
	}
	if b := blobs(out); len(b) != 3 || b["GONE"] != nil {
		t.Errorf("patch response configuration = %v", b)
	}

	// The same plaintext sent again is stored again (a new blob), not kept
	// by accident: it is the value that matters.
	rec, _ = e.do("PATCH", url, map[string]any{"options": custom(map[string]any{"API_TOKEN": "tok-s3cret"})})
	if rec.Code != 200 || !sameConfig(unsealed(id), map[string]string{"API_TOKEN": "tok-s3cret"}) {
		t.Errorf("plaintext patch = %d %v", rec.Code, unsealed(id))
	}

	// Other properties only: options and configuration are untouched.
	rec, _ = e.do("PATCH", url, map[string]any{"display_name": "Renamed"})
	if rec.Code != 200 || len(unsealed(id)) != 1 {
		t.Errorf("patch without options = %d %v", rec.Code, unsealed(id))
	}

	// A blob that is not this key's current value is refused, never stored
	// as a secret: another key's, another connection's, a stale one, garbage.
	rec, read = e.do("GET", url, nil)
	oldBlob := blobs(read)["API_TOKEN"]
	other := e.create(map[string]any{"name": "Other", "strategy": "auth0", "options": custom(map[string]any{"API_TOKEN": "other-s3cret"})})
	rec, _ = e.do("PATCH", url, map[string]any{"options": custom(map[string]any{"API_TOKEN": "replaced-s3cret"})})
	for name, v := range map[string]any{
		"stale":            oldBlob,
		"other connection": blobs(other)["API_TOKEN"],
		"garbage":          "zcv1.garbage",
	} {
		rec, body := e.do("PATCH", url, map[string]any{"options": custom(map[string]any{"API_TOKEN": v})})
		wantError(t, "blob "+name, rec, body, 400, "invalid_body")
	}
	if !sameConfig(unsealed(id), map[string]string{"API_TOKEN": "replaced-s3cret"}) {
		t.Errorf("a refused blob changed the secret: %v", unsealed(id))
	}
	rec, body := e.do("PATCH", url, map[string]any{"options": custom(map[string]any{"A": blobs(other)["API_TOKEN"]})})
	wantError(t, "blob under another key", rec, body, 400, "invalid_body")

	// Omitting configuration drops it (Auth0 replaces options whole).
	rec, out = e.do("PATCH", url, map[string]any{"options": custom(nil)})
	if _, has := out["options"].(map[string]any)["configuration"]; rec.Code != 200 || has {
		t.Errorf("patch without configuration = %d %s", rec.Code, rec.Body)
	}
	if c, _ := e.st.Connections().Get(ctx, e.tenant.ID, id); len(c.ConfigurationSealed) != 0 {
		t.Error("the configuration survived a PATCH that left it out")
	}

	// Configuration needs a custom database; a number is not a value; a blob
	// is no way to invent a secret on create.
	rec, body = e.do("PATCH", url, map[string]any{"options": map[string]any{"configuration": map[string]any{"K": "v"}}})
	wantError(t, "configuration without customization", rec, body, 400, "invalid_body")
	rec, body = e.do("PATCH", url, map[string]any{"options": custom(map[string]any{"K": 5})})
	wantError(t, "number value", rec, body, 400, "invalid_body")
	rec, body = e.do("POST", connBase, map[string]any{"name": "Forged", "strategy": "auth0", "options": custom(map[string]any{"K": blobs(other)["API_TOKEN"]})})
	wantError(t, "blob on create", rec, body, 400, "invalid_body")
	// Case variants of typed keys never reach Extra.
	rec, body = e.do("PATCH", url, map[string]any{"options": custom(map[string]any{"K": "v"})})
	if rec.Code != 200 {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	bad := custom(nil)
	bad["CONFIGURATION"] = map[string]any{"LEAK": "leak-s3cret"}
	rec, body = e.do("PATCH", url, map[string]any{"options": bad})
	wantError(t, "configuration case variant", rec, body, 400, "invalid_body")
	noPlaintext("case variant", rec, "leak-s3cret")
}

func sameConfig(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestDeleteConnection(t *testing.T) {
	e := newConnEnv(t)
	ctx := context.Background()
	made := e.create(map[string]any{"name": "Doomed", "strategy": "auth0"})
	id := made["id"].(string)
	u := &store.User{TenantID: e.tenant.ID, UserID: "auth0|u1", Email: "u1@acme.test", CreatedAt: time.Now(),
		Identities: []store.Identity{{Connection: "Doomed", Provider: store.StrategyDatabase, UserID: "u1"}}}
	if err := e.st.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}

	before := time.Now().UTC().Add(-time.Minute)
	rec, out := e.do("DELETE", connBase+"/"+id, nil)
	at, perr := time.Parse(time.RFC3339, toStr(out["deleted_at"]))
	if rec.Code != 202 || perr != nil || at.Before(before) || at.After(time.Now().Add(time.Minute)) {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if rec, out := e.do("GET", connBase+"/"+id, nil); rec.Code != 404 || out["errorCode"] != "inexistent_connection" {
		t.Errorf("get after delete = %d %s", rec.Code, rec.Body)
	}
	if _, err := e.st.Users().Get(ctx, e.tenant.ID, "auth0|u1"); err == nil {
		t.Error("the connection's user survived")
	}
	if rec, _ := e.do("DELETE", connBase+"/"+id, nil); rec.Code != 204 {
		t.Errorf("second delete = %d", rec.Code)
	}
	if rec, _ := e.do("DELETE", connBase+"/con_0000000000000000", nil); rec.Code != 204 {
		t.Errorf("delete of a well-formed unknown ID = %d", rec.Code)
	}
	rec, out = e.do("DELETE", connBase+"/nope", nil)
	wantError(t, "malformed", rec, out, 400, "invalid_uri")
	if rec, _ := sendJSON(e.h, "DELETE", connBase+"/"+id, e.reader, nil); rec.Code != 403 {
		t.Errorf("delete with read scopes = %d", rec.Code)
	}
}

func toStr(v any) string { s, _ := v.(string); return s }

// Review focus 1: deleting the connection the tenant's default_directory
// names clears it (observed on Auth0), so the password grant never points
// at a missing connection. The only database connection may be deleted.
func TestDeleteConnectionDefaultDirectory(t *testing.T) {
	e := newConnEnv(t)
	ctx := context.Background()
	a := e.create(map[string]any{"name": "Primary", "strategy": "auth0"})
	b := e.create(map[string]any{"name": "Secondary", "strategy": "auth0"})
	setDir := func(name string) {
		t.Helper()
		tn, _ := e.st.Tenants().Get(ctx, e.tenant.ID)
		tn.DefaultDirectory = name
		if err := e.st.Tenants().Update(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	dir := func() string { tn, _ := e.st.Tenants().Get(ctx, e.tenant.ID); return tn.DefaultDirectory }

	setDir("Primary")
	if rec, _ := e.do("DELETE", connBase+"/"+b["id"].(string), nil); rec.Code != 202 {
		t.Fatalf("delete = %d", rec.Code)
	}
	if dir() != "Primary" {
		t.Errorf("deleting another connection changed default_directory to %q", dir())
	}
	if rec, _ := e.do("DELETE", connBase+"/"+a["id"].(string), nil); rec.Code != 202 {
		t.Fatalf("delete = %d", rec.Code)
	}
	if dir() != "" {
		t.Errorf("default_directory = %q after its connection was deleted", dir())
	}
	// The password grant now finds no directory instead of a missing connection.
	form := url.Values{"grant_type": {"password"}, "client_id": {"m2m"}, "client_secret": {"s3cret"}, "username": {"x@acme.test"}, "password": {"nope nope nope nope"}}
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code == 200 || rec.Code >= 500 {
		t.Errorf("password grant after the delete = %d %s", rec.Code, rec.Body)
	}
}

func TestListConnections(t *testing.T) {
	e := newConnEnv(t)
	for _, n := range []string{"beta", "Alpha", "gamma", "Delta", "alpine"} {
		e.create(map[string]any{"name": n, "strategy": "auth0"})
	}
	names := func(v any) []string {
		var out []string
		l, _ := v.([]any)
		for _, c := range l {
			out = append(out, c.(map[string]any)["name"].(string))
		}
		return out
	}
	want := []string{"Alpha", "alpine", "beta", "Delta", "gamma"}

	rec, list := e.doAny("GET", connBase, nil)
	if rec.Code != 200 || !slices.Equal(names(list), want) {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	if _, has := list.([]any)[0].(map[string]any)["enabled_clients"]; has {
		t.Error("the list carries enabled_clients")
	}
	// Totals: the key, and per_page defaults to 100.
	rec, tot := e.do("GET", connBase+"?include_totals=true", nil)
	if rec.Code != 200 || tot["total"] != float64(5) || tot["start"] != float64(0) || tot["limit"] != float64(100) || !slices.Equal(names(tot["connections"]), want) {
		t.Errorf("totals = %d %s", rec.Code, rec.Body)
	}
	rec, tot = e.do("GET", connBase+"?include_totals=true&per_page=2&page=1", nil)
	if rec.Code != 200 || tot["total"] != float64(5) || tot["start"] != float64(2) || tot["limit"] != float64(2) || !slices.Equal(names(tot["connections"]), []string{"beta", "Delta"}) {
		t.Errorf("page 1 = %d %s", rec.Code, rec.Body)
	}
	for _, q := range []string{"per_page=0", "per_page=101", "page=-1", "per_page=x", "include_totals=maybe", "take=0", "take=101", "take=x"} {
		rec, body := e.do("GET", connBase+"?"+q, nil)
		wantError(t, q, rec, body, 400, "invalid_query_string")
	}
	// Filters.
	rec, list = e.doAny("GET", connBase+"?name=beta", nil)
	if rec.Code != 200 || !slices.Equal(names(list), []string{"beta"}) {
		t.Errorf("name filter = %s", rec.Body)
	}
	if _, list = e.doAny("GET", connBase+"?name=BETA", nil); len(names(list)) != 0 {
		t.Errorf("name filter is not exact: %v", list)
	}
	if _, list = e.doAny("GET", connBase+"?strategy=auth0&strategy=google-oauth2", nil); len(names(list)) != 5 {
		t.Errorf("strategy filter = %v", list)
	}
	if _, list = e.doAny("GET", connBase+"?strategy=google-oauth2", nil); len(names(list)) != 0 {
		t.Errorf("strategy filter = %v", list)
	}
	// Fields always add id and is_domain_connection.
	_, list = e.doAny("GET", connBase+"?fields=name&name=beta", nil)
	if c := list.([]any)[0].(map[string]any); len(c) != 3 || c["id"] == nil || c["is_domain_connection"] == nil {
		t.Errorf("fields = %v", c)
	}
	_, list = e.doAny("GET", connBase+"?fields=options&include_fields=false&name=beta", nil)
	if c := list.([]any)[0].(map[string]any); c["options"] != nil || c["id"] == nil || c["is_domain_connection"] == nil || c["name"] == nil {
		t.Errorf("include_fields=false = %v", c)
	}

	// Checkpoint paging, which wins over page and include_totals.
	var seen []string
	from := ""
	for range 10 {
		target := connBase + "?take=2&page=3&include_totals=true"
		if from != "" {
			target += "&from=" + url.QueryEscape(from)
		}
		rec, page := e.do("GET", target, nil)
		if rec.Code != 200 || page["total"] != nil || page["start"] != nil {
			t.Fatalf("checkpoint page = %d %s", rec.Code, rec.Body)
		}
		seen = append(seen, names(page["connections"])...)
		next, ok := page["next"].(string)
		if !ok {
			if len(names(page["connections"])) == 0 {
				t.Error("an empty last page")
			}
			break
		}
		if len(names(page["connections"])) != 2 {
			t.Errorf("short page with a next: %s", rec.Body)
		}
		from = next
	}
	if !slices.Equal(seen, want) {
		t.Errorf("checkpoint paging saw %v, want %v", seen, want)
	}
	// A connection created or deleted between pages neither repeats nor skips.
	rec, page := e.do("GET", connBase+"?take=2", nil)
	next := page["next"].(string)
	var firstID string
	for _, c := range page["connections"].([]any) {
		if c.(map[string]any)["name"] == "alpine" {
			firstID = c.(map[string]any)["id"].(string)
		}
	}
	e.do("DELETE", connBase+"/"+firstID, nil) // the cursor's own connection
	e.create(map[string]any{"name": "aardvark", "strategy": "auth0"})
	_, page = e.do("GET", connBase+"?take=100&from="+url.QueryEscape(next), nil)
	if got := names(page["connections"]); !slices.Equal(got, []string{"beta", "Delta", "gamma"}) {
		t.Errorf("after changes: %v (%s)", got, rec.Body)
	}
	if _, has := page["next"]; has {
		t.Error("next on the last page")
	}
	for _, from := range []string{"garbage", "!!!", "djE6", "djE6Y29uXw"} {
		rec, body := e.do("GET", connBase+"?from="+from, nil)
		wantError(t, "from="+from, rec, body, 400, "invalid_query_string")
	}
}

func TestConnectionClients(t *testing.T) {
	e := newConnEnv(t)
	ctx := context.Background()
	a, b, c := e.createClient("A"), e.createClient("B"), e.createClient("C")
	conn := e.create(map[string]any{"name": "Clients", "strategy": "auth0", "enabled_clients": []string{c}})
	url := connBase + "/" + conn["id"].(string) + "/clients"
	ids := func(out map[string]any) []string {
		var r []string
		for _, x := range out["clients"].([]any) {
			r = append(r, x.(map[string]any)["client_id"].(string))
		}
		return r
	}

	rec, out := e.do("GET", url, nil)
	if rec.Code != 200 || !slices.Equal(ids(out), []string{c}) || out["next"] != nil {
		t.Fatalf("get = %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.doAny("PATCH", url, []map[string]any{{"client_id": a, "status": true}, {"client_id": b, "status": true}, {"client_id": c, "status": false}})
	if rec.Code != 204 || rec.Body.Len() != 0 {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	_, out = e.do("GET", url, nil)
	got := ids(out)
	slices.Sort(got)
	want := []string{a, b}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("enabled = %v, want %v", got, want)
	}
	// Enabling twice and disabling a client that is not enabled are fine.
	rec, _ = e.doAny("PATCH", url, []map[string]any{{"client_id": a, "status": true}, {"client_id": c, "status": false}})
	if rec.Code != 204 {
		t.Errorf("idempotent patch = %d %s", rec.Code, rec.Body)
	}
	if cc, _ := e.st.Connections().Get(ctx, e.tenant.ID, conn["id"].(string)); len(cc.EnabledClients) != 2 {
		t.Errorf("stored = %v", cc.EnabledClients)
	}

	// Review focus 3: unknown and other tenants' clients are refused, and
	// nothing changes when any entry is.
	if err := e.st.Tenants().Create(ctx, &store.Tenant{ID: "ten_globex", Name: "globex", Domains: []string{"globex.test"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Clients().Create(ctx, &store.Client{TenantID: "ten_globex", ClientID: "globex-app", Name: "Globex", AppType: store.AppTypeSPA}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"nope", "globex-app"} {
		rec, body := e.doAny("PATCH", url, []map[string]any{{"client_id": c, "status": true}, {"client_id": id, "status": true}})
		wantError(t, "patch "+id, rec, toMap(body), 400, "inexistent_client")
		rec, body = e.doAny("PATCH", url, []map[string]any{{"client_id": id, "status": false}})
		wantError(t, "disable "+id, rec, toMap(body), 400, "inexistent_client")
	}
	if cc, _ := e.st.Connections().Get(ctx, e.tenant.ID, conn["id"].(string)); len(cc.EnabledClients) != 2 {
		t.Errorf("a refused patch changed the list: %v", cc.EnabledClients)
	}
	for name, body := range map[string]any{
		"empty array":      []any{},
		"not an array":     map[string]any{"client_id": a, "status": true},
		"malformed id":     []map[string]any{{"client_id": "", "status": true}},
		"id with space":    []map[string]any{{"client_id": "a b", "status": true}},
		"no status":        []map[string]any{{"client_id": a}},
		"status string":    []map[string]any{{"client_id": a, "status": "true"}},
		"no client_id":     []map[string]any{{"status": true}},
		"unknown property": []map[string]any{{"client_id": a, "status": true, "x": 1}},
		"entry not object": []any{"x"},
	} {
		rec, out := e.doAny("PATCH", url, body)
		wantError(t, name, rec, toMap(out), 400, "invalid_body")
	}
	rec, bad := e.do("PATCH", connBase+"/nope/clients", nil)
	wantError(t, "malformed connection id", rec, bad, 400, "invalid_uri")
	rec, bad = e.do("PATCH", connBase+"/con_0000000000000000/clients", nil)
	if rec.Code != 400 && rec.Code != 404 {
		t.Errorf("unknown connection = %d", rec.Code)
	}
	rec, bad = e.do("GET", connBase+"/con_0000000000000000/clients", nil)
	wantError(t, "unknown connection", rec, bad, 404, "inexistent_connection")
	rec, bad = e.do("GET", connBase+"/nope/clients", nil)
	wantError(t, "malformed connection id", rec, bad, 400, "invalid_uri")

	// Checkpoint paging.
	many := make([]map[string]any, 0, 5)
	for i := range 5 {
		many = append(many, map[string]any{"client_id": e.createClient("N" + string(rune('a'+i))), "status": true})
	}
	if rec, _ := e.doAny("PATCH", url, many); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	var all []string
	from := ""
	for range 10 {
		target := url + "?take=3"
		if from != "" {
			target += "&from=" + from
		}
		rec, page := e.do("GET", target, nil)
		if rec.Code != 200 {
			t.Fatalf("page = %d %s", rec.Code, rec.Body)
		}
		all = append(all, ids(page)...)
		next, ok := page["next"].(string)
		if !ok {
			break
		}
		from = next
	}
	if len(all) != 7 || !slices.IsSorted(all) {
		t.Errorf("paged %v", all)
	}
	for _, from := range []string{"garbage", "!!!"} {
		rec, body := e.do("GET", url+"?from="+from, nil)
		wantError(t, "from="+from, rec, body, 400, "invalid_query_string")
	}
	rec, body := e.do("GET", url+"?take=0", nil)
	wantError(t, "take=0", rec, body, 400, "invalid_query_string")
	if rec, _ := sendJSON(e.h, "GET", url, e.reader, nil); rec.Code != 403 {
		t.Errorf("get clients with read:clients only = %d", rec.Code)
	}
	if rec, _ := sendJSON(e.h, "PATCH", url, e.reader, []map[string]any{{"client_id": a, "status": true}}); rec.Code != 403 {
		t.Errorf("patch clients with read scopes = %d", rec.Code)
	}
}

func toMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

// API-created connections carry origin api, and the seed leaves them alone.
func TestSeedSkipsAPIConnections(t *testing.T) {
	e := newConnEnv(t)
	ctx := context.Background()
	made := e.create(map[string]any{"name": "Api-Made", "strategy": "auth0", "options": map[string]any{"disable_signup": true}})
	f, err := seed.Parse([]byte(mgmtSeed + `
    connections:
      - {name: Api-Made, enabled_clients: [m2m]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.CheckManagementAPI(""); err != nil {
		t.Fatal(err)
	}
	if err := seed.Apply(ctx, e.st, f, nil, e.w); err != nil {
		t.Fatal(err)
	}
	c, err := e.st.Connections().GetByName(ctx, e.tenant.ID, "Api-Made")
	if err != nil || c.ID != made["id"] || c.Origin != store.OriginAPI || len(c.EnabledClients) != 0 || !c.DisableSignup {
		t.Errorf("the seed changed an API connection: %+v, %v", c, err)
	}
}

// An application enabled on a connection through the API logs a user in
// through hosted login; before it is enabled, it cannot.
func TestConnectionEnabledThroughAPILogsIn(t *testing.T) {
	e := newConnEnv(t)
	ctx := context.Background()
	cid := e.createClient("Hosted app")
	conn := e.create(map[string]any{"name": "Hosted-Users", "strategy": "auth0"})
	id := conn["id"].(string)

	hash, err := secrets.Hash("a long enough password 1")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.Users().Create(ctx, &store.User{
		TenantID: e.tenant.ID, UserID: "auth0|dana", Email: "dana@acme.test", EmailVerified: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		Identities: []store.Identity{{Connection: "Hosted-Users", Provider: store.StrategyDatabase, UserID: "dana", PasswordHash: hash}},
	}); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:       jar,
		Transport: handlerTransport{e.h},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	get := func(u string) (*http.Response, string) {
		t.Helper()
		resp, err := client.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp, buf.String()
	}
	authorize := "https://acme.example.test/authorize?" + url.Values{
		"client_id": {cid}, "redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"}, "scope": {"openid email"},
		"state": {"s1"}, "nonce": {"n1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "connection": {"Hosted-Users"},
	}.Encode()

	// Not enabled yet.
	resp, body := get(authorize)
	if loc, _ := resp.Location(); loc != nil && loc.Path == "/u/login" {
		t.Fatalf("authorize reached the login page before the connection was enabled: %d %s", resp.StatusCode, body)
	}

	rec, _ := e.doAny("PATCH", connBase+"/"+id+"/clients", []map[string]any{{"client_id": cid, "status": true}})
	if rec.Code != 204 {
		t.Fatalf("enable = %d %s", rec.Code, rec.Body)
	}
	resp, body = get(authorize)
	loginURL, _ := resp.Location()
	if resp.StatusCode != 302 || loginURL == nil || loginURL.Path != "/u/login" {
		t.Fatalf("authorize = %d %v %s", resp.StatusCode, loginURL, body)
	}
	_, page := get(loginURL.String())
	csrf := csrfRe.FindStringSubmatch(page)
	if csrf == nil {
		t.Fatalf("no csrf: %s", page)
	}
	form := url.Values{"state": {loginURL.Query().Get("state")}, "csrf": {csrf[1]}, "username": {"dana@acme.test"}, "password": {"a long enough password 1"}}
	req, _ := http.NewRequest("POST", "https://acme.example.test/u/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	cb, _ := resp2.Location()
	if resp2.StatusCode != 302 || cb == nil || cb.Host != "app.acme.test" || cb.Query().Get("code") == "" || cb.Query().Get("state") != "s1" {
		t.Fatalf("login = %d %v", resp2.StatusCode, cb)
	}

	// Disabling it again closes the door.
	rec, _ = e.doAny("PATCH", connBase+"/"+id+"/clients", []map[string]any{{"client_id": cid, "status": false}})
	if rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	resp, _ = get(authorize)
	if loc, _ := resp.Location(); loc != nil && loc.Path == "/u/login" {
		t.Error("authorize still reaches login after the application was disabled")
	}
}

// handlerTransport serves requests straight from a handler.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}
