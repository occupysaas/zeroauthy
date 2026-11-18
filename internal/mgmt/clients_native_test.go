package mgmt_test

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"net/http"
	"testing"
)

func TestClientNativeFieldsRoundTrip(t *testing.T) {
	e := newClientsEnv(t)
	native := map[string]any{"apple": map[string]any{"enabled": true}, "facebook": map[string]any{"enabled": false}, "google": map[string]any{"enabled": true}}
	mobile := map[string]any{"ios": map[string]any{"team_id": "ABCDEFGHIJ", "app_bundle_identifier": "com.example.native"}}
	r, out := e.create(t, m2mCaller(allClientScopes...), map[string]any{"name": "Native", "app_type": "native"})
	if r.Code != 201 {
		t.Fatal(r.Body)
	}
	id := out["client_id"].(string)
	r, out = e.patch(t, m2mCaller(allClientScopes...), id, map[string]any{"native_social_login": native, "mobile": mobile})
	if r.Code != 200 || !jsonEqual(out["native_social_login"], native) || !jsonEqual(out["mobile"], mobile) {
		t.Fatalf("%d %v", r.Code, out)
	}
	r, got := e.call(t, e.tn, m2mCaller(allClientScopes...), "GET", "/api/v2/clients/"+id, nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetClient(w, r, id, mgmtapi.GetClientParams{}) })
	if r.Code != 200 || !jsonEqual(got.(map[string]any)["native_social_login"], native) {
		t.Fatal(got)
	}
	c, err := e.st.Clients().Get(context.Background(), e.tn.ID, id)
	if err != nil || !c.NativeSocialLogin["apple"] {
		t.Fatalf("%+v %v", c, err)
	}
	for _, bad := range []any{nil, true, map[string]any{"apple": true}, map[string]any{"apple": map[string]any{"enabled": "true"}}, map[string]any{"apple": map[string]any{"enabled": nil}}} {
		r, _ := e.patch(t, m2mCaller(allClientScopes...), id, map[string]any{"native_social_login": bad})
		if r.Code != 400 {
			t.Fatalf("accepted %v: %d", bad, r.Code)
		}
	}
}
