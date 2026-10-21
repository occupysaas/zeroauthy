package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/oauth"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// operatorToken invites email as an operator and mints the access token
// the console would get for them.
func operatorToken(t *testing.T, st store.Store, email string) (token, userID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := system.CreateOperator(ctx, st, email); err != nil {
		t.Fatal(err)
	}
	sys, _ := st.Tenants().GetByName(ctx, tenant.SystemName)
	u, err := st.Users().FindByLogin(ctx, sys.ID, system.OperatorsConnection, email)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	m := &oauth.Minter{Keys: keys.NewManager(st.SigningKeys(), w)}
	raw, err := m.AccessToken(ctx, oauth.AccessTokenParams{
		TenantID: sys.ID, Issuer: "https://" + mgmtSystemHost + "/", Subject: u.UserID,
		Audience: []string{tenant.OperatorAudience}, ClientID: system.ConsoleClientID,
		Scopes: []string{"openid"}, Lifetime: time.Hour, Operator: []string{store.OperatorAllTenants},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw, u.UserID
}

func sendRaw(h http.Handler, method, target, token string, body any) (*httptest.ResponseRecorder, any) {
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func errCode(v any) string {
	m, _ := v.(map[string]any)
	s, _ := m["errorCode"].(string)
	return s
}

func TestSystemAPITenants(t *testing.T) {
	h, st := newMgmtEnv(t)
	op, _ := operatorToken(t, st, "op@example.test")
	sysAPI := "https://" + mgmtSystemHost + "/api/system/tenants"

	rec, out := sendRaw(h, "GET", sysAPI, op, nil)
	list, _ := out.([]any)
	if rec.Code != 200 || len(list) != 2 {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	acme := list[0].(map[string]any)
	if acme["name"] != "acme" || acme["host"] != "acme.example.test" || acme["management_api_identifier"] != acmeMgmtAPI ||
		acme["seeded"] != true || acme["reserved"] != false {
		t.Errorf("acme = %v", acme)
	}
	if sys := list[1].(map[string]any); sys["name"] != "system" || sys["reserved"] != true || sys["host"] != mgmtSystemHost {
		t.Errorf("system = %v", sys)
	}

	// The system API answers only on the system host, and only operators.
	if rec, _ := sendRaw(h, "GET", "https://acme.example.test/api/system/tenants", op, nil); rec.Code != 404 {
		t.Errorf("on a tenant host = %d", rec.Code)
	}
	admin := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	if rec, _ := sendRaw(h, "GET", sysAPI, admin, nil); rec.Code != 401 {
		t.Errorf("M2M token = %d %s", rec.Code, rec.Body)
	}
	// Operators also manage every tenant's applications.
	if rec, _ := sendRaw(h, "GET", "https://acme.example.test/api/v2/clients", op, nil); rec.Code != 200 {
		t.Errorf("operator on acme's clients = %d %s", rec.Code, rec.Body)
	}

	for name, tc := range map[string]struct {
		body   any
		status int
		code   string
	}{
		"bad name":         {map[string]any{"name": "Not_A_Label", "domains": []string{"x.test"}}, 400, "invalid_body"},
		"long name":        {map[string]any{"name": strings.Repeat("a", 64), "domains": []string{"x.test"}}, 400, "invalid_body"},
		"system":           {map[string]any{"name": "system", "domains": []string{"x.test"}}, 400, "invalid_body"},
		"no domain":        {map[string]any{"name": "nodomain"}, 400, "invalid_body"},
		"system host":      {map[string]any{"name": "sneaky", "domains": []string{mgmtSystemHost}}, 400, "invalid_body"},
		"not a host":       {map[string]any{"name": "path", "domains": []string{"x.test/path"}}, 400, "invalid_body"},
		"unknown property": {map[string]any{"name": "extra", "domains": []string{"x.test"}, "plan": "pro"}, 400, "invalid_body"},
		"existing name":    {map[string]any{"name": "acme", "domains": []string{"y.test"}}, 409, "conflict"},
		"taken domain":     {map[string]any{"name": "copycat", "domains": []string{"login.acme.test"}}, 409, "conflict"},
	} {
		rec, out := sendRaw(h, "POST", sysAPI, op, tc.body)
		if rec.Code != tc.status || errCode(out) != tc.code {
			t.Errorf("%s: %d %s, want %d %s", name, rec.Code, rec.Body, tc.status, tc.code)
		}
	}

	rec, out = sendRaw(h, "POST", sysAPI, op, map[string]any{"name": "globex", "friendly_name": "Globex", "domains": []string{"Login.Globex.TEST"}})
	created, _ := out.(map[string]any)
	if rec.Code != 201 || created["host"] != "login.globex.test" || created["management_api_identifier"] != "https://login.globex.test/api/v2/" || created["seeded"] != false {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	ctx := context.Background()
	tn, err := st.Tenants().GetByName(ctx, "globex")
	if err != nil || tn.Origin != store.OriginAPI || tn.DefaultDirectory != "Username-Password-Authentication" {
		t.Fatalf("stored = %+v, %v", tn, err)
	}
	if ks, _ := st.SigningKeys().List(ctx, tn.ID); len(ks) < 2 {
		t.Errorf("signing keys = %d", len(ks))
	}
	if _, err := st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication"); err != nil {
		t.Errorf("default connection: %v", err)
	}
	if rs, err := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://login.globex.test/api/v2/"); err != nil || !rs.IsSystem {
		t.Errorf("management API: %v", err)
	}
	// The new tenant answers at once.
	if rec, _ := sendRaw(h, "GET", "https://login.globex.test/api/v2/clients", op, nil); rec.Code != 200 {
		t.Errorf("new tenant's clients = %d %s", rec.Code, rec.Body)
	}

	rec, out = sendRaw(h, "PATCH", sysAPI+"/globex", op, map[string]any{"friendly_name": "Globex Corp", "domains": []string{"login.globex.test", "id.globex.test"}})
	if updated, _ := out.(map[string]any); rec.Code != 200 || updated["friendly_name"] != "Globex Corp" || len(updated["domains"].([]any)) != 2 {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	if rec, out := sendRaw(h, "PATCH", sysAPI+"/system", op, map[string]any{"friendly_name": "x"}); rec.Code != 403 || errCode(out) != "operation_not_supported" {
		t.Errorf("patch system = %d %s", rec.Code, rec.Body)
	}
	if rec, out := sendRaw(h, "PATCH", sysAPI+"/nope", op, map[string]any{"friendly_name": "x"}); rec.Code != 404 || errCode(out) != "inexistent_tenant" {
		t.Errorf("patch unknown = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := sendRaw(h, "PATCH", sysAPI+"/globex", op, map[string]any{"name": "renamed"}); rec.Code != 400 {
		t.Errorf("rename = %d %s", rec.Code, rec.Body)
	}

	if rec, out := sendRaw(h, "DELETE", sysAPI+"/globex?confirm=globe", op, nil); rec.Code != 400 || errCode(out) != "invalid_query_string" {
		t.Errorf("delete without confirmation = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := sendRaw(h, "DELETE", sysAPI+"/globex", op, nil); rec.Code != 400 {
		t.Errorf("delete without confirm = %d %s", rec.Code, rec.Body)
	}
	if rec, out := sendRaw(h, "DELETE", sysAPI+"/system?confirm=system", op, nil); rec.Code != 403 || errCode(out) != "operation_not_supported" {
		t.Errorf("delete system = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := sendRaw(h, "DELETE", sysAPI+"/globex?confirm=globex", op, nil); rec.Code != 204 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if _, err := st.Tenants().GetByName(ctx, "globex"); err != store.ErrNotFound {
		t.Errorf("tenant after delete: %v", err)
	}
	if rec, _ := sendRaw(h, "GET", "https://login.globex.test/api/v2/clients", op, nil); rec.Code == 200 {
		t.Errorf("deleted tenant still answers")
	}
}

func TestSystemAPIOperators(t *testing.T) {
	h, st := newMgmtEnv(t)
	op, opID := operatorToken(t, st, "op@example.test")
	api := "https://" + mgmtSystemHost + "/api/system/operators"

	rec, out := sendRaw(h, "POST", api, op, map[string]any{"email": "New@Example.test"})
	invite, _ := out.(map[string]any)
	link, _ := invite["setup_url"].(string)
	newID, _ := invite["user_id"].(string)
	if rec.Code != 201 || invite["email"] != "new@example.test" || !strings.HasPrefix(link, "https://"+mgmtSystemHost+"/") || newID == "" ||
		invite["tenants"].([]any)[0] != "*" {
		t.Fatalf("invite = %d %s", rec.Code, rec.Body)
	}
	if u, err := url.Parse(link); err != nil || u.Query().Get("ticket") == "" {
		t.Errorf("setup link %q", link)
	}
	for _, body := range []any{map[string]any{"email": "not an email"}, map[string]any{}, map[string]any{"email": "a@b.test", "role": "admin"}} {
		if rec, _ := sendRaw(h, "POST", api, op, body); rec.Code != 400 {
			t.Errorf("invite %v = %d", body, rec.Code)
		}
	}

	rec, out = sendRaw(h, "GET", api, op, nil)
	if list, _ := out.([]any); rec.Code != 200 || len(list) != 2 {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}

	if rec, out := sendRaw(h, "DELETE", api+"/"+url.PathEscape("auth0|nobody"), op, nil); rec.Code != 404 || errCode(out) != "inexistent_operator" {
		t.Errorf("delete unknown = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := sendRaw(h, "DELETE", api+"/"+url.PathEscape(newID), op, nil); rec.Code != 204 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if rec, out := sendRaw(h, "DELETE", api+"/"+url.PathEscape(opID), op, nil); rec.Code != 409 || errCode(out) != "last_operator" {
		t.Errorf("delete last = %d %s", rec.Code, rec.Body)
	}

	// A removed operator's token stops working at once.
	other, otherID := operatorToken(t, st, "other@example.test")
	if rec, _ := sendRaw(h, "GET", api, other, nil); rec.Code != 200 {
		t.Fatalf("other operator = %d", rec.Code)
	}
	if rec, _ := sendRaw(h, "DELETE", api+"/"+url.PathEscape(otherID), op, nil); rec.Code != 204 {
		t.Fatalf("delete other = %d", rec.Code)
	}
	if rec, _ := sendRaw(h, "GET", api, other, nil); rec.Code != 401 {
		t.Errorf("removed operator's token = %d", rec.Code)
	}
}

// The Users API on the system tenant reaches operators too: it refuses to
// delete, block or link away the last one, as DeleteOperator does.
func TestSystemTenantUsersKeepLastOperator(t *testing.T) {
	h, st := newMgmtEnv(t)
	op, opID := operatorToken(t, st, "op@example.test")
	ctx := context.Background()
	sys, _ := st.Tenants().GetByName(ctx, tenant.SystemName)
	users := "https://" + mgmtSystemHost + "/api/v2/users/"
	provider, sub, _ := strings.Cut(opID, "|")
	primary := &store.User{TenantID: sys.ID, UserID: "auth0|primary", Email: "primary@example.test",
		Identities: []store.Identity{{Connection: system.OperatorsConnection, Provider: "auth0", UserID: "primary"}}}
	if err := st.Users().Create(ctx, primary); err != nil {
		t.Fatal(err)
	}
	refused := func(name, method, target string, body any) {
		t.Helper()
		rec, out := sendRaw(h, method, target, op, body)
		if rec.Code != 409 || errCode(out) != "last_operator" {
			t.Errorf("%s = %d %s, want 409 last_operator", name, rec.Code, rec.Body)
		}
	}
	refused("delete", "DELETE", users+url.PathEscape(opID), nil)
	refused("block", "PATCH", users+url.PathEscape(opID), map[string]any{"blocked": true})
	refused("link as secondary", "POST", users+url.PathEscape(primary.UserID)+"/identities", map[string]any{"provider": provider, "user_id": sub})
	if u, err := st.Users().Get(ctx, sys.ID, opID); err != nil || u.Blocked {
		t.Fatalf("operator after the refusals = %+v, %v", u, err)
	}
	// Other changes to the last operator go through.
	if rec, _ := sendRaw(h, "PATCH", users+url.PathEscape(opID), op, map[string]any{"blocked": false, "name": "Op"}); rec.Code != 200 {
		t.Errorf("unblock and rename = %d %s", rec.Code, rec.Body)
	}
	// With a second operator, the first can be blocked.
	operatorToken(t, st, "second@example.test")
	if rec, _ := sendRaw(h, "PATCH", users+url.PathEscape(opID), op, map[string]any{"blocked": true}); rec.Code != 200 {
		t.Errorf("block with another operator = %d %s", rec.Code, rec.Body)
	}
}
