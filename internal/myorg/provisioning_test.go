package myorg

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func oktaIdP(name string) map[string]any {
	return map[string]any{"name": name, "strategy": "okta", "options": map[string]any{"domain": "acme.okta.com", "client_id": "c", "client_secret": testSecret}}
}

func (e *env) provisioningEnv(t *testing.T, profile string) (string, string) {
	t.Helper()
	e.withWrites(t)
	cfg := `{"allowed_strategies":["oidc","okta"],"connection_deletion_behavior":"allow","invitation_landing_client_id":"portal"`
	if profile != "" {
		must(t, e.st.SelfService().CreateConnectionProfile(context.Background(), &store.ConnectionProfile{TenantID: e.tn.ID, ID: "cop_1", Name: "SSO", Doc: []byte(profile)}))
		cfg += `,"connection_profile_id":"cop_1"`
	}
	e.setConfig(t, cfg+`}`)
	tok := e.adminToken(t)
	return tok, e.createIdP(t, tok, oktaIdP("acme-okta"))["id"].(string)
}

func TestProvisioning(t *testing.T) {
	e := newEnv(t)
	tok, id := e.provisioningEnv(t, "")
	base := "/identity-providers/" + id + "/provisioning"
	if rec, _ := e.do(t, tok, "GET", base, nil); rec.Code != 404 {
		t.Fatalf("before create = %d", rec.Code)
	}
	rec, p := e.do(t, tok, "POST", base, nil)
	if rec.Code != 201 || p["method"] != "scim" || p["identity_provider_id"] != id || p["identity_provider_name"] != "acme-okta" || p["strategy"] != "okta" ||
		p["user_id_attribute"] == "" || len(p["attributes"].([]any)) == 0 {
		t.Fatalf("create = %d %v", rec.Code, p)
	}
	a := p["attributes"].([]any)[0].(map[string]any)
	if a["user_attribute"] == nil || a["provisioning_field"] == nil || a["is_required"] != false || a["is_extra"] != false || a["is_missing"] != false {
		t.Fatalf("attribute %v", a)
	}
	if rec, _ := e.do(t, tok, "POST", base, nil); rec.Code != 400 {
		t.Fatalf("create twice = %d", rec.Code)
	}
	if rec, g := e.do(t, tok, "PUT", base+"/update-attributes", map[string]any{}); rec.Code != 200 || len(g["attributes"].([]any)) != len(p["attributes"].([]any)) {
		t.Fatalf("refresh = %d %v", rec.Code, g)
	}
	_, tk := e.do(t, tok, "POST", base+"/scim-tokens", map[string]any{})
	if rec, _ := e.do(t, tok, "DELETE", base, nil); rec.Code != 204 {
		t.Fatalf("delete = %d", rec.Code)
	}
	if rec, _ := e.do(t, tok, "GET", base, nil); rec.Code != 404 {
		t.Fatalf("after delete = %d", rec.Code)
	}
	toks, _ := e.st.Directory().ListSCIMTokens(context.Background(), e.tn.ID, id)
	if len(toks) != 0 {
		t.Fatalf("tokens survive provisioning deletion: %v (created %v)", toks, tk)
	}
	// A profile without SCIM for the strategy refuses provisioning.
	e2 := newEnv(t)
	tok2, id2 := e2.provisioningEnv(t, `{"enabled_features":[],"strategy_overrides":{"oidc":{"enabled_features":["scim"]}}}`)
	if rec, _ := e2.do(t, tok2, "POST", "/identity-providers/"+id2+"/provisioning", nil); rec.Code != 400 {
		t.Fatalf("provisioning not in profile = %d", rec.Code)
	}
	// Provisioning writes need access level full.
	e.setAccess(t, id, "limited")
	if rec, _ := e.do(t, tok, "POST", base, nil); rec.Code != 403 {
		t.Fatalf("create at limited = %d", rec.Code)
	}
}

func TestSCIMTokens(t *testing.T) {
	e := newEnv(t)
	tok, id := e.provisioningEnv(t, `{"enabled_features":["scim"],"provisioning":{"scim":{"tokens":{"scopes":["get:users","post:users"],"default_expiry":3600,"max_allowed_expiry":7200}}}}`)
	base := "/identity-providers/" + id + "/provisioning"
	if rec, _ := e.do(t, tok, "POST", base+"/scim-tokens", map[string]any{}); rec.Code != 404 {
		t.Fatalf("token without provisioning = %d", rec.Code)
	}
	e.do(t, tok, "POST", base, nil)
	rec, t1 := e.do(t, tok, "POST", base+"/scim-tokens", map[string]any{})
	if rec.Code != 201 || t1["token"] == nil || t1["token_id"] == nil || len(t1["scopes"].([]any)) != 2 {
		t.Fatalf("default token = %d %v", rec.Code, t1)
	}
	if until, _ := time.Parse(time.RFC3339Nano, t1["valid_until"].(string)); until.Sub(e.now) != time.Hour {
		t.Fatalf("default expiry %v", t1["valid_until"])
	}
	for _, c := range []struct {
		body map[string]any
		why  string
	}{
		{map[string]any{"token_lifetime": 900}, "lifetime at the minimum"},
		{map[string]any{"token_lifetime": 7201}, "beyond the profile maximum"},
		{map[string]any{"token_lifetime": nil}, "non-expiring with a profile maximum"},
		{map[string]any{"scopes": []any{"delete:users"}}, "scope outside the profile"},
		{map[string]any{"scopes": []any{}}, "empty scopes"},
		{map[string]any{"token_lifetime": 3600, "x": 1}, "unknown member"},
	} {
		if rec, _ := e.do(t, tok, "POST", base+"/scim-tokens", c.body); rec.Code != 400 {
			t.Errorf("%s = %d %s", c.why, rec.Code, rec.Body)
		}
	}
	rec, t2 := e.do(t, tok, "POST", base+"/scim-tokens", map[string]any{"token_lifetime": 1800, "scopes": []any{"get:users"}})
	if rec.Code != 201 || len(t2["scopes"].([]any)) != 1 {
		t.Fatalf("second token = %d %v", rec.Code, t2)
	}
	if rec, _ := e.do(t, tok, "POST", base+"/scim-tokens", map[string]any{}); rec.Code != 400 {
		t.Fatalf("third active token = %d", rec.Code)
	}
	rec, l := e.do(t, tok, "GET", base+"/scim-tokens", nil)
	if rec.Code != 200 || len(l["scim_tokens"].([]any)) != 2 || strings.Contains(rec.Body.String(), `"token":`) {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	tid := t1["token_id"].(string)
	if rec, g := e.do(t, tok, "GET", base+"/scim-tokens/"+tid, nil); rec.Code != 200 || g["token_id"] != tid || g["token"] != nil {
		t.Fatalf("get = %d %v", rec.Code, g)
	}
	if rec, _ := e.do(t, tok, "DELETE", base+"/scim-tokens/"+tid, nil); rec.Code != 204 {
		t.Fatalf("delete = %d", rec.Code)
	}
	if rec, _ := e.do(t, tok, "GET", base+"/scim-tokens/"+tid, nil); rec.Code != 404 {
		t.Fatalf("after delete = %d", rec.Code)
	}
	if rec, _ := e.do(t, tok, "DELETE", base+"/scim-tokens/tok_missing", nil); rec.Code != 404 {
		t.Fatalf("delete missing = %d", rec.Code)
	}
	toks, _ := e.st.Directory().ListSCIMTokens(context.Background(), e.tn.ID, id)
	if len(toks) != 1 {
		t.Fatalf("stored tokens %d", len(toks))
	}
	// Without a profile maximum, null is a non-expiring token.
	e2 := newEnv(t)
	tok2, id2 := e2.provisioningEnv(t, "")
	e2.do(t, tok2, "POST", "/identity-providers/"+id2+"/provisioning", nil)
	if rec, nt := e2.do(t, tok2, "POST", "/identity-providers/"+id2+"/provisioning/scim-tokens", map[string]any{"token_lifetime": nil}); rec.Code != 201 || nt["valid_until"] != nil || len(nt["scopes"].([]any)) != 5 {
		t.Fatalf("non-expiring = %d %v", rec.Code, nt)
	}
	_ = http.StatusOK
}

// TestSCIMTokenOnce: the token value is in the create response only, never
// in a log.
func TestSCIMTokenOnce(t *testing.T) {
	e := newEnv(t)
	tok, id := e.provisioningEnv(t, "")
	base := "/identity-providers/" + id + "/provisioning"
	e.do(t, tok, "POST", base, nil)
	_, created := e.do(t, tok, "POST", base+"/scim-tokens", map[string]any{})
	value, _ := created["token"].(string)
	if len(value) < 32 {
		t.Fatalf("token %v", created)
	}
	rec, _ := e.do(t, tok, "GET", base+"/scim-tokens", nil)
	if strings.Contains(rec.Body.String(), value) || strings.Contains(e.logs.String(), value) {
		t.Fatal("token value exposed after creation")
	}
}
