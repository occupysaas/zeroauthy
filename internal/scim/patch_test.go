package scim

import (
	"encoding/json"
	"testing"
)

func resource(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func ops(t *testing.T, s string) []PatchOperation {
	t.Helper()
	var p PatchRequest
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		t.Fatal(err)
	}
	return p.Operations
}

func TestApplyPatch(t *testing.T) {
	res := resource(t, `{"userName":"jdoe","active":true,"name":{"givenName":"J"},"emails":[{"primary":true,"value":"a@x.test"}],
		"members":[{"value":"u1"},{"value":"u2"}]}`)
	err := ApplyPatch(res, ops(t, `{"Operations":[
		{"op":"Replace","path":"active","value":"False"},
		{"op":"replace","path":"name.familyName","value":"Doe"},
		{"op":"replace","path":"emails[primary eq true].value","value":"b@x.test"},
		{"op":"add","path":"emails[type eq \"work\"].value","value":"w@x.test"},
		{"op":"add","path":"members","value":[{"value":"u3"},{"value":"u1"}]},
		{"op":"remove","path":"members[value eq \"u2\"]"},
		{"op":"replace","value":{"displayName":"J Doe","name":{"givenName":"Jay"}}}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := Get(res, Path{Attr: "active"}); ActiveValue(v) != false {
		t.Errorf("active %v", res["active"])
	}
	name := res["name"].(map[string]any)
	if name["familyName"] != "Doe" || name["givenName"] != "Jay" || res["displayName"] != "J Doe" {
		t.Errorf("name %v displayName %v", name, res["displayName"])
	}
	if v, _ := Get(res, Path{Attr: "emails", Filter: &Filter{Path: "primary", Value: true}, Sub: "value"}); v != "b@x.test" {
		t.Errorf("primary email %v", v)
	}
	if v, _ := Get(res, Path{Attr: "emails", Filter: &Filter{Path: "type", Value: "work"}, Sub: "value"}); v != "w@x.test" {
		t.Errorf("work email %v", v)
	}
	if got := memberValues(res); len(got) != 2 || got[0] != "u1" || got[1] != "u3" {
		t.Errorf("members %v", got)
	}
	// Entra removes members with a value list on the plain path.
	if err := ApplyPatch(res, ops(t, `{"Operations":[{"op":"Remove","path":"members","value":[{"value":"u1"}]}]}`)); err != nil {
		t.Fatal(err)
	}
	if got := memberValues(res); len(got) != 1 || got[0] != "u3" {
		t.Errorf("members after value removal %v", got)
	}
	if err := ApplyPatch(res, ops(t, `{"Operations":[{"op":"remove","path":"members"}]}`)); err != nil || len(memberValues(res)) != 0 {
		t.Errorf("remove all members: %v %v", err, res["members"])
	}
	for name, bad := range map[string]string{
		"unknown op":        `{"Operations":[{"op":"move","path":"userName"}]}`,
		"bad path":          `{"Operations":[{"op":"replace","path":"emails[","value":"x"}]}`,
		"no path no object": `{"Operations":[{"op":"replace","value":"x"}]}`,
		"remove no path":    `{"Operations":[{"op":"remove"}]}`,
		"add no value":      `{"Operations":[{"op":"add","path":"title"}]}`,
	} {
		if err := ApplyPatch(resource(t, `{}`), ops(t, bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for v, want := range map[any]bool{true: true, false: false, "True": true, "false": false} {
		if ActiveValue(v) != want {
			t.Errorf("ActiveValue(%v)", v)
		}
	}
}
