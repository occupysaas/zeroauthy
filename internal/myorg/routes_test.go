package myorg

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/zeroauthy/zeroauthy/api"
)

// TestMyOrgRoutesContract: every operation of api/myorg.yaml is routed and
// checks its own scopes (a token without them is 403 insufficient_scope
// naming each), so no contract operation is left unserved.
func TestMyOrgRoutesContract(t *testing.T) {
	e := newEnv(t)
	doc, err := openapi3.NewLoader().LoadFromData(api.MyOrgYAML)
	must(t, err)
	tok := e.adminToken(t, "openid")
	param := regexp.MustCompile(`\{[a-z_]+\}`)
	sample := map[string]string{"{user_id}": "auth0|bob", "{invitation_id}": "uinv_aaaaaaaaaaaaaaaa", "{domain_id}": "ord_aaaaaaaaaaaaaaaaaaaaaa", "{idp_id}": "con_aaaaaaaaaaaaaaaa", "{domain}": "acme.test", "{idp_scim_token_id}": "tok1"}
	n := 0
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			n++
			url := param.ReplaceAllStringFunc(path, func(p string) string { return sample[p] })
			rec, body := e.do(t, tok, method, url, map[string]any{})
			if rec.Code != http.StatusForbidden || body["type"] == nil || !strings.Contains(rec.Body.String(), "insufficient_scope") {
				t.Errorf("%s %s = %d %s, want 403 insufficient_scope", method, path, rec.Code, rec.Body)
				continue
			}
			for _, s := range (*op.Security)[0]["myOrgToken"] {
				if !strings.Contains(rec.Body.String(), s) {
					t.Errorf("%s %s: problem does not name %s: %s", method, path, s, rec.Body)
				}
			}
		}
	}
	if n != 40 {
		t.Errorf("%d operations", n)
	}
}
