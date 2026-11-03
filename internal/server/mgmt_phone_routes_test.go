package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
)

// Each phone route needs its documented scope: no caller is 401, a caller
// with only an unrelated scope is 403, and the right scope reaches the handler
// (which, with no store here, is anything but 401, 403 or 501).
func TestPhoneRouteScopes(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{}})
	routes := []struct{ method, path, scope string }{
		{"GET", "/api/v2/branding/phone/providers", "read:phone_providers"},
		{"POST", "/api/v2/branding/phone/providers", "create:phone_providers"},
		{"GET", "/api/v2/branding/phone/providers/pro_1", "read:phone_providers"},
		{"PATCH", "/api/v2/branding/phone/providers/pro_1", "update:phone_providers"},
		{"DELETE", "/api/v2/branding/phone/providers/pro_1", "delete:phone_providers"},
		{"POST", "/api/v2/branding/phone/providers/pro_1/try", "create:phone_providers"},
		{"GET", "/api/v2/branding/phone/templates", "read:phone_templates"},
		{"POST", "/api/v2/branding/phone/templates", "create:phone_templates"},
		{"GET", "/api/v2/branding/phone/templates/tem_1", "read:phone_templates"},
		{"PATCH", "/api/v2/branding/phone/templates/tem_1", "update:phone_templates"},
		{"DELETE", "/api/v2/branding/phone/templates/tem_1", "delete:phone_templates"},
		{"PATCH", "/api/v2/branding/phone/templates/tem_1/reset", "update:phone_templates"},
		{"POST", "/api/v2/branding/phone/templates/tem_1/try", "create:phone_templates"},
		{"GET", "/api/v2/attack-protection/phone-provider-protection", "read:attack_protection"},
		{"PATCH", "/api/v2/attack-protection/phone-provider-protection", "update:attack_protection"},
	}
	for _, rt := range routes {
		for _, scopes := range [][]string{nil, {"read:clients"}, {rt.scope}} {
			r := httptest.NewRequest(rt.method, rt.path, strings.NewReader(`{}`))
			r.Header.Set("Content-Type", "application/json")
			want := http.StatusUnauthorized
			if scopes != nil {
				r = r.WithContext(mgmt.WithCaller(r.Context(), mgmt.Caller{Kind: mgmt.M2M, Scopes: scopes}))
				want = http.StatusForbidden
			}
			w := httptest.NewRecorder()
			func() {
				defer func() { _ = recover() }() // the scoped handler reaches a nil store
				h.ServeHTTP(w, r)
			}()
			if scopes != nil && scopes[0] == rt.scope {
				if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden || w.Code == http.StatusNotImplemented {
					t.Fatalf("%s %s with %s: %d", rt.method, rt.path, rt.scope, w.Code)
				}
				continue
			}
			if w.Code != want {
				t.Fatalf("%s %s scopes=%v: got %d want %d", rt.method, rt.path, scopes, w.Code, want)
			}
		}
	}
}
