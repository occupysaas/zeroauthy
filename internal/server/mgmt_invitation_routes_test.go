package server

import (
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOrganizationInvitationRouteScopes(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{}})
	for _, method := range []string{"GET", "POST", "DELETE"} {
		path := "/api/v2/organizations/org_0000000000000000/invitations"
		if method == "DELETE" {
			path += "/uinv_missing"
		}
		for _, authenticated := range []bool{false, true} {
			r := httptest.NewRequest(method, path, nil)
			want := http.StatusUnauthorized
			if authenticated {
				r = r.WithContext(mgmt.WithCaller(r.Context(), mgmt.Caller{Kind: mgmt.M2M, Scopes: []string{"read:organizations"}}))
				want = http.StatusForbidden
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatalf("%s authenticated=%v got %d want %d", method, authenticated, w.Code, want)
			}
		}
	}
}
