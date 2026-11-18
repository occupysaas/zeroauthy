package mgmt_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var profileScopes = []string{"read:token_exchange_profiles", "create:token_exchange_profiles", "update:token_exchange_profiles", "delete:token_exchange_profiles", "read:actions", "delete:actions"}

var profileActionEnvs = map[*clientsEnv]*actionstest.Env{}

// profileAction stores an Action named name; deployed also deploys it. It
// returns the Action's id.
func profileAction(t *testing.T, e *clientsEnv, name, trigger string, deployed bool) string {
	t.Helper()
	if !deployed {
		a := &store.Action{TenantID: e.tn.ID, ID: "act_" + name, Name: name, Trigger: trigger, Runtime: actionsrules.Runtime, Code: "exports.onExecuteCustomTokenExchange=()=>{}"}
		if err := e.st.Actions().CreateAction(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	if profileActionEnvs[e] == nil {
		profileActionEnvs[e] = actionstest.NewOffline(t, e.st, e.w)
	}
	return profileActionEnvs[e].Deploy(t, e.tn.ID, trigger, name, "exports.onExecuteCustomTokenExchange=()=>{}").ID
}

func (e *clientsEnv) profileCall(t *testing.T, method, target string, body any, fn http.HandlerFunc) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.call(t, e.tn, m2mCaller(profileScopes...), method, target, body, fn)
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *clientsEnv) postProfile(t *testing.T, body any) (*httptest.ResponseRecorder, map[string]any) {
	return e.profileCall(t, "POST", "/api/v2/token-exchange-profiles", body, e.h.PostTokenExchangeProfile)
}

func (e *clientsEnv) patchProfile(t *testing.T, id string, body any) (*httptest.ResponseRecorder, map[string]any) {
	return e.profileCall(t, "PATCH", "/api/v2/token-exchange-profiles/"+id, body,
		func(w http.ResponseWriter, r *http.Request) { e.h.PatchTokenExchangeProfile(w, r, id) })
}

func (e *clientsEnv) listProfiles(t *testing.T, query string) (*httptest.ResponseRecorder, map[string]any) {
	return e.profileCall(t, "GET", "/api/v2/token-exchange-profiles"+query, nil,
		func(w http.ResponseWriter, r *http.Request) {
			e.h.GetTokenExchangeProfiles(w, r, mgmtapi.GetTokenExchangeProfilesParams{})
		})
}

func profileBody(action, typ string) map[string]any {
	return map[string]any{"name": "Legacy login", "subject_token_type": typ, "action_id": action, "type": "custom_authentication"}
}

const exchangeTrigger = "custom-token-exchange"

func TestProfileCreate(t *testing.T) {
	e := newClientsEnv(t)
	act := profileAction(t, e, "ok", exchangeTrigger, true)
	rec, got := e.postProfile(t, profileBody(act, "urn:acme:legacy-token"))
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	id, _ := got["id"].(string)
	if len(id) != 4+22 || !strings.HasPrefix(id, "tep_") {
		t.Errorf("id = %q", id)
	}
	if got["action_id"] != act || got["type"] != "custom_authentication" || got["subject_token_type"] != "urn:acme:legacy-token" || got["created_at"] == nil || got["updated_at"] == nil {
		t.Errorf("body = %v", got)
	}
	rec, read := e.profileCall(t, "GET", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetTokenExchangeProfile(w, r, id) })
	if rec.Code != 200 || read["id"] != id {
		t.Errorf("get = %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.profileCall(t, "GET", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetTokenExchangeProfile(w, r, "tep_missing") })
	if rec.Code != 404 {
		t.Errorf("get missing = %d", rec.Code)
	}
	rec, _ = e.profileCall(t, "DELETE", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteTokenExchangeProfile(w, r, id) })
	if rec.Code != 204 {
		t.Errorf("delete = %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.profileCall(t, "DELETE", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteTokenExchangeProfile(w, r, id) })
	if rec.Code != 404 {
		t.Errorf("second delete = %d", rec.Code)
	}
}

func TestProfileValidation(t *testing.T) {
	e := newClientsEnv(t)
	ok := profileAction(t, e, "ok", exchangeTrigger, true)
	undeployed := profileAction(t, e, "draft", exchangeTrigger, false)
	wrong := profileAction(t, e, "login", "post-login", true)
	valid := "https://acme.example/legacy"
	with := func(k string, v any) map[string]any {
		b := profileBody(ok, valid)
		b[k] = v
		return b
	}
	cases := map[string]struct {
		body    map[string]any
		message string
	}{
		"name too short":   {with("name", "ab"), ""},
		"name too long":    {with("name", strings.Repeat("n", 51)), ""},
		"type too short":   {with("subject_token_type", "urn:a:b"), ""},
		"type too long":    {with("subject_token_type", "urn:"+strings.Repeat("a", 97)), ""},
		"http scheme":      {with("subject_token_type", "http://acme.example/legacy"), ""},
		"wrong type":       {with("type", "oidc"), ""},
		"unknown property": {with("extra", 1), ""},
		"missing action":   {map[string]any{"name": "Legacy", "subject_token_type": valid, "type": "custom_authentication"}, ""},
		"undeployed":       {profileBody(undeployed, valid), "Action is not deployed"},
		"wrong trigger":    {profileBody(wrong, valid), "Action must have supported_triggers: custom-token-exchange"},
		"unknown action":   {profileBody("act_nope", valid), "Action not found"},
	}
	for _, prefix := range []string{"http://auth0.com", "https://auth0.com", "http://okta.com", "https://okta.com", "urn:ietf", "urn:auth0", "urn:okta"} {
		suffix := ""
		if strings.HasPrefix(prefix, "http") {
			suffix = "/x"
		} else {
			suffix = ":example"
		}
		cases["reserved "+prefix] = struct {
			body    map[string]any
			message string
		}{with("subject_token_type", prefix+suffix), ""}
	}
	for name, c := range cases {
		rec, out := e.postProfile(t, c.body)
		if rec.Code != 400 {
			t.Errorf("%s = %d %s, want 400", name, rec.Code, rec.Body)
			continue
		}
		if c.message != "" && !strings.Contains(fmt.Sprint(out["message"]), c.message) {
			t.Errorf("%s message = %v, want %q", name, out["message"], c.message)
		}
	}
	if rec, _ := e.listProfiles(t, ""); strings.Contains(rec.Body.String(), "tep_") {
		t.Errorf("a refused create stored a profile: %s", rec.Body)
	}
}

func TestProfileDuplicateType(t *testing.T) {
	e := newClientsEnv(t)
	act := profileAction(t, e, "ok", exchangeTrigger, true)
	if rec, _ := e.postProfile(t, profileBody(act, "urn:acme:one")); rec.Code != 201 {
		t.Fatal(rec.Body)
	}
	if rec, _ := e.postProfile(t, profileBody(act, "urn:acme:one")); rec.Code != 409 {
		t.Errorf("duplicate = %d %s, want 409", rec.Code, rec.Body)
	}
}

func TestProfileLimit(t *testing.T) {
	e := newClientsEnv(t)
	act := profileAction(t, e, "ok", exchangeTrigger, true)
	for i := 0; i < 100; i++ {
		if rec, _ := e.postProfile(t, profileBody(act, fmt.Sprintf("urn:acme:type-%03d", i))); rec.Code != 201 {
			t.Fatalf("profile %d = %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec, _ := e.postProfile(t, profileBody(act, "urn:acme:type-101")); rec.Code != 403 {
		t.Errorf("101st = %d %s, want 403", rec.Code, rec.Body)
	}
}

func TestProfilePatch(t *testing.T) {
	e := newClientsEnv(t)
	act := profileAction(t, e, "ok", exchangeTrigger, true)
	other := profileAction(t, e, "two", exchangeTrigger, true)
	_, first := e.postProfile(t, profileBody(act, "urn:acme:one"))
	_, second := e.postProfile(t, profileBody(act, "urn:acme:two"))
	id := first["id"].(string)
	rec, got := e.patchProfile(t, id, map[string]any{"name": "Renamed", "subject_token_type": "https://acme.example/new"})
	if rec.Code != 200 || got["name"] != "Renamed" || got["subject_token_type"] != "https://acme.example/new" || got["action_id"] != act {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	if got["updated_at"] == first["updated_at"] {
		t.Errorf("updated_at did not move: %v", got["updated_at"])
	}
	for name, body := range map[string]map[string]any{
		"action_id":        {"action_id": other},
		"type":             {"type": "custom_authentication"},
		"unknown":          {"nope": 1},
		"null name":        {"name": nil},
		"short name":       {"name": "ab"},
		"reserved type":    {"subject_token_type": "urn:auth0:x:y"},
		"bad type scheme":  {"subject_token_type": "http://acme.example/x"},
		"name wrong shape": {"name": 5},
	} {
		if rec, _ := e.patchProfile(t, id, body); rec.Code != 400 {
			t.Errorf("patch %s = %d %s, want 400", name, rec.Code, rec.Body)
		}
	}
	if rec, _ := e.patchProfile(t, id, map[string]any{"subject_token_type": second["subject_token_type"]}); rec.Code != 409 {
		t.Errorf("colliding type = %d %s, want 409", rec.Code, rec.Body)
	}
	if rec, _ := e.patchProfile(t, "tep_missing", map[string]any{"name": "Renamed"}); rec.Code != 404 {
		t.Errorf("patch missing = %d", rec.Code)
	}
}

func TestProfileCheckpointList(t *testing.T) {
	e := newClientsEnv(t)
	act := profileAction(t, e, "ok", exchangeTrigger, true)
	want := map[string]bool{}
	for i := 0; i < 5; i++ {
		_, p := e.postProfile(t, profileBody(act, fmt.Sprintf("urn:acme:type-%d", i)))
		want[p["id"].(string)] = true
	}
	seen := map[string]bool{}
	from, pages := "", 0
	for {
		q := "?take=2"
		if from != "" {
			q += "&from=" + from
		}
		rec, page := e.listProfiles(t, q)
		if rec.Code != 200 {
			t.Fatalf("list = %d %s", rec.Code, rec.Body)
		}
		pages++
		for _, p := range page["token_exchange_profiles"].([]any) {
			id := p.(map[string]any)["id"].(string)
			if seen[id] {
				t.Errorf("%s listed twice", id)
			}
			seen[id] = true
		}
		next, has := page["next"].(string)
		if !has {
			break
		}
		from = next
		if pages > 5 {
			t.Fatal("paging does not end")
		}
	}
	if pages != 3 || len(seen) != 5 {
		t.Errorf("pages=%d seen=%d, want 3 and 5", pages, len(seen))
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("%s never listed", id)
		}
	}
	rec, page := e.listProfiles(t, "")
	if rec.Code != 200 || len(page["token_exchange_profiles"].([]any)) != 5 || page["next"] != nil {
		t.Errorf("default list = %d %s", rec.Code, rec.Body)
	}
	for _, q := range []string{"?take=0", "?take=101", "?take=x"} {
		if rec, _ := e.listProfiles(t, q); rec.Code != 400 {
			t.Errorf("list %s = %d, want 400", q, rec.Code)
		}
	}
}

func TestActionDeleteGuard(t *testing.T) {
	e := newClientsEnv(t)
	used := profileAction(t, e, "used", exchangeTrigger, true)
	free := profileAction(t, e, "free", exchangeTrigger, true)
	_, p := e.postProfile(t, profileBody(used, "urn:acme:one"))
	del := func(id, query string) *httptest.ResponseRecorder {
		rec, _ := e.profileCall(t, "DELETE", "/api/v2/actions/actions/"+id+query, nil,
			func(w http.ResponseWriter, r *http.Request) { e.h.DeleteAction(w, r, id) })
		return rec
	}
	for _, q := range []string{"", "?force=true"} {
		rec := del(used, q)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "action is used by a token exchange profile") {
			t.Errorf("delete used%s = %d %s", q, rec.Code, rec.Body)
		}
	}
	if rec := del(free, ""); rec.Code != 204 {
		t.Errorf("delete unused = %d %s", rec.Code, rec.Body)
	}
	e.profileCall(t, "DELETE", "/x", nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.DeleteTokenExchangeProfile(w, r, p["id"].(string))
	})
	if rec := del(used, ""); rec.Code != 204 {
		t.Errorf("delete after the profile is gone = %d %s", rec.Code, rec.Body)
	}
}

func TestProfilesPluginUnavailable(t *testing.T) {
	e := newClientsEnv(t)
	act := profileAction(t, e, "ok", exchangeTrigger, true)
	e.h.Store = noCredentialStore{e.st}
	routes := map[string]*httptest.ResponseRecorder{}
	routes["list"], _ = e.listProfiles(t, "")
	routes["create"], _ = e.postProfile(t, profileBody(act, "urn:acme:one"))
	routes["get"], _ = e.profileCall(t, "GET", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetTokenExchangeProfile(w, r, "tep_x") })
	routes["patch"], _ = e.patchProfile(t, "tep_x", map[string]any{"name": "Renamed"})
	routes["delete"], _ = e.profileCall(t, "DELETE", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteTokenExchangeProfile(w, r, "tep_x") })
	for name, rec := range routes {
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s = %d %s, want 501", name, rec.Code, rec.Body)
		}
	}
	// Without the capability no profile can exist, so an Action still deletes.
	rec, _ := e.profileCall(t, "DELETE", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteAction(w, r, act) })
	if rec.Code != 204 {
		t.Errorf("delete Action without the capability = %d %s", rec.Code, rec.Body)
	}
}
