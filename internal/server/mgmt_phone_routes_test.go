package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
)

// Each phone route refuses an unauthenticated caller; the scope and live
// grant checks of real callers are in TestPhoneRoutesGrantAndLiveRevocation.
func TestPhoneRouteScopes(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{}})
	for _, rt := range phoneRoutes {
		r := httptest.NewRequest(rt.method, rt.path, strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s: got %d want 401", rt.method, rt.path, w.Code)
		}
	}
}

var phoneRoutes = []struct{ method, path, scope string }{
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
