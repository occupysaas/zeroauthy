package scim

import (
	"context"
	"regexp"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

var groupIDPattern = regexp.MustCompile(`^grp_[1-9a-km-zA-HJ-NP-Z]{14,22}$`)

func memberIDs(res map[string]any) []string {
	list, _ := res["members"].([]any)
	var out []string
	for _, el := range list {
		out = append(out, el.(map[string]any)["value"].(string))
	}
	return out
}

func TestSCIMGroups(t *testing.T) {
	e := newEnv(t)
	tok := e.tokens["con_a"]
	for _, u := range []string{"e-1", "e-2", "e-3"} {
		if code, _ := e.do("POST", "con_a", "/Users", tok, `{"externalId":"`+u+`","userName":"`+u+`"}`); code != 201 {
			t.Fatalf("user %s %d", u, code)
		}
	}
	e.do("POST", "con_b", "/Users", e.tokens["con_b"], `{"externalId":"e-b","userName":"b"}`)
	code, g := e.do("POST", "con_a", "/Groups", tok, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering","externalId":"ext-eng",
		"members":[{"value":"samlp|corp-saml|e-1"},{"value":"samlp|corp-saml|e-2"}]}`)
	if code != 201 || !groupIDPattern.MatchString(g["id"].(string)) || g["displayName"] != "Engineering" || g["externalId"] != "ext-eng" || len(memberIDs(g)) != 2 {
		t.Fatalf("create %d %v", code, g)
	}
	id := g["id"].(string)
	stored, err := e.st.Directory().GetGroup(context.Background(), e.tn.ID, id)
	if err != nil || stored.ConnectionID != "con_a" || stored.Name != "Engineering" {
		t.Fatalf("stored %+v %v", stored, err)
	}
	if code, out := e.do("POST", "con_a", "/Groups", tok, `{"displayName":"Engineering"}`); code != 409 || out["scimType"] != "uniqueness" {
		t.Fatalf("duplicate name %d %v", code, out)
	}
	// Only users of the same connection can be members (Auth0: only user members).
	for name, body := range map[string]string{
		"other connection's user": `{"displayName":"X","members":[{"value":"oidc|corp-oidc|e-b"}]}`,
		"unknown user":            `{"displayName":"X","members":[{"value":"samlp|corp-saml|nobody"}]}`,
		"group member":            `{"displayName":"X","members":[{"value":"` + id + `","type":"Group"}]}`,
		"no name":                 `{"members":[]}`,
		"long name":               `{"displayName":"` + stringOf('a', 129) + `"}`,
	} {
		if code, _ := e.do("POST", "con_a", "/Groups", tok, body); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	code, list := e.do("GET", "con_a", "/Groups?filter="+urlEscape(`displayName eq "Engineering"`), tok, nil)
	if code != 200 || list["totalResults"].(float64) != 1 {
		t.Fatalf("filter %d %v", code, list)
	}
	code, list = e.do("GET", "con_a", "/Groups?excludedAttributes=members", tok, nil)
	if code != 200 || list["totalResults"].(float64) != 1 || list["Resources"].([]any)[0].(map[string]any)["members"] != nil {
		t.Fatalf("excluded members %d %v", code, list)
	}
	if code, out := e.do("GET", "con_a", "/Groups?filter="+urlEscape(`displayName co "Eng"`), tok, nil); code != 400 || out["scimType"] != "invalidFilter" {
		t.Errorf("unsupported operator %d", code)
	}
	if code, list := e.do("GET", "con_b", "/Groups", e.tokens["con_b"], nil); code != 200 || list["totalResults"].(float64) != 0 {
		t.Errorf("connection B sees A's group: %v", list)
	}
	if code, _ := e.do("GET", "con_b", "/Groups/"+id, e.tokens["con_b"], nil); code != 404 {
		t.Errorf("connection B reads A's group: %d", code)
	}
	// PATCH members (Entra and Okta shapes) and the name.
	code, p := e.do("PATCH", "con_a", "/Groups/"+id, tok, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"Add","path":"members","value":[{"value":"samlp|corp-saml|e-3"}]},
		{"op":"Remove","path":"members","value":[{"value":"samlp|corp-saml|e-1"}]},
		{"op":"replace","path":"displayName","value":"Platform"}]}`)
	if code != 200 || p["displayName"] != "Platform" || len(memberIDs(p)) != 2 {
		t.Fatalf("patch %d %v", code, p)
	}
	ms, _, _ := e.st.Directory().ListGroupMembers(context.Background(), e.tn.ID, id, store.Page{})
	if len(ms) != 2 || ms[0].UserID != "samlp|corp-saml|e-2" || ms[1].UserID != "samlp|corp-saml|e-3" {
		t.Fatalf("members after patch %+v", ms)
	}
	if code, _ := e.do("PATCH", "con_a", "/Groups/"+id, tok, `{"Operations":[{"op":"add","path":"members","value":[{"value":"oidc|corp-oidc|e-b"}]}]}`); code != 400 {
		t.Errorf("patch adding another connection's user: %d", code)
	}
	code, put := e.do("PUT", "con_a", "/Groups/"+id, tok, `{"displayName":"Platform","members":[{"value":"samlp|corp-saml|e-1"}]}`)
	if code != 200 || len(memberIDs(put)) != 1 || put["externalId"] != nil {
		t.Fatalf("put %d %v", code, put)
	}
	if code, _ := e.do("DELETE", "con_a", "/Groups/"+id, tok, nil); code != 204 {
		t.Fatalf("delete %d", code)
	}
	if _, err := e.st.Directory().GetGroup(context.Background(), e.tn.ID, id); err == nil {
		t.Fatal("group survived DELETE")
	}
}

func stringOf(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

func TestSCIMDiscovery(t *testing.T) {
	e := newEnv(t)
	tok := e.tokens["con_a"]
	code, spc := e.do("GET", "con_a", "/ServiceProviderConfig", tok, nil)
	if code != 200 || spc["patch"].(map[string]any)["supported"] != true || spc["bulk"].(map[string]any)["supported"] != false ||
		spc["filter"].(map[string]any)["maxResults"].(float64) != 100 {
		t.Fatalf("service provider config %d %v", code, spc)
	}
	code, rt := e.do("GET", "con_a", "/ResourceTypes", tok, nil)
	if code != 200 || rt["totalResults"].(float64) != 2 {
		t.Fatalf("resource types %d %v", code, rt)
	}
	code, sc := e.do("GET", "con_a", "/Schemas", tok, nil)
	if code != 200 || sc["totalResults"].(float64) != 3 {
		t.Fatalf("schemas %d %v", code, sc)
	}
	if code, _ := e.do("GET", "con_a", "/ServiceProviderConfig", "", nil); code != 401 {
		t.Fatalf("discovery without a token: %d", code)
	}
}
