package federation

import (
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"reflect"
	"strings"
	"testing"
)

func TestAttrMapTemplates(t *testing.T) {
	c, err := CompileAttrMap(&rules.AttrMap{Mode: "use_map", Attributes: map[string]string{"name": "Jane", "email": "${context.tokenset.email}", "nickname": "user|${context.tokenset.sub}", "connection_ref": "${context.connection.id}", "roles": "${context.tokenset.https://example.com/roles}"}}, "oidc", "back_channel")
	if err != nil {
		t.Fatal(err)
	}
	root, extra := c.Apply(MapContext{TokenSet: map[string]any{"email": "jane@example.com", "sub": "123", "https://example.com/roles": []any{"admin"}}, ConnectionID: "con_1"})
	if root["email"] != "jane@example.com" || root["nickname"] != "user|123" || root["name"] != "Jane" || extra["connection_ref"] != "con_1" || !reflect.DeepEqual(extra["roles"], []any{"admin"}) {
		t.Fatal(root, extra)
	}
}
func TestAttrMapMissing(t *testing.T) {
	c, e := CompileAttrMap(&rules.AttrMap{Mode: "use_map", Attributes: map[string]string{"name": "${context.tokenset.missing}", "nickname": "user|${context.tokenset.missing}"}}, "oidc", "back_channel")
	if e != nil {
		t.Fatal(e)
	}
	r, _ := c.Apply(MapContext{})
	if _, ok := r["name"]; ok || r["nickname"] != "user|" {
		t.Fatal(r)
	}
}
func TestAttrMapRestricted(t *testing.T) {
	for _, target := range []string{"user_id", "identities", "app_metadata", "blocked", "logins_count", "last_login", "password", "created_at", "email_verified_at"} {
		if _, e := CompileAttrMap(&rules.AttrMap{Mode: "use_map", Attributes: map[string]string{target: "x"}}, "oidc", "back_channel"); e == nil {
			t.Errorf("accepted %s", target)
		}
	}
}
func TestAttrMapGrammar(t *testing.T) {
	for _, v := range []string{"${context.env.X}", "${a}", "${${x}}", "${context.tokenset.email", "${context.tokenset.a b}"} {
		if _, e := CompileAttrMap(&rules.AttrMap{Mode: "use_map", Attributes: map[string]string{"name": v}}, "oidc", "back_channel"); e == nil {
			t.Errorf("accepted %s", v)
		}
	}
}
func TestAttrMapUserinfoFrontChannel(t *testing.T) {
	if _, e := CompileAttrMap(&rules.AttrMap{Mode: "use_map", Attributes: map[string]string{"name": "${context.userinfo.name}"}}, "oidc", "front_channel"); e == nil {
		t.Fatal("userinfo reference accepted")
	}
}
func TestAttrMapLimits(t *testing.T) {
	if _, e := CompileAttrMap(&rules.AttrMap{Mode: "use_map", Attributes: map[string]string{"name": strings.Repeat("x", 1025)}}, "oidc", "back_channel"); e == nil {
		t.Fatal("template too long")
	}
	a := map[string]string{}
	for i := 0; i < 101; i++ {
		a[strings.Repeat("a", i+1)] = "x"
	}
	if _, e := CompileAttrMap(&rules.AttrMap{Mode: "use_map", Attributes: a}, "oidc", "back_channel"); e == nil {
		t.Fatal("too many attributes")
	}
}
func TestAttrMapBindAll(t *testing.T) {
	c, e := CompileAttrMap(&rules.AttrMap{Mode: "bind_all"}, "oidc", "back_channel")
	if e != nil {
		t.Fatal(e)
	}
	r, x := c.Apply(MapContext{TokenSet: map[string]any{"name": "Jane", "blocked": true, "email_verified": "true", "federated_groups": []any{"staff"}, "access_token": "must-not-map", "id_token": "must-not-map"}})
	if r["name"] != "Jane" || len(r) != 1 || len(x) != 1 {
		t.Fatal(r, x)
	}
}
