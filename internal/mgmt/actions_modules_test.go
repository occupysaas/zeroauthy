package mgmt_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestActionsModulesContract(t *testing.T) {
	e := newClientsEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	ctx := context.Background()
	call := func(method, path string, body any, fn http.HandlerFunc, want int) map[string]any {
		t.Helper()
		rec, out := e.call(t, e.tn, m2mCaller("read:actions", "create:actions", "update:actions", "delete:actions"), method, path, body, fn)
		if rec.Code != want {
			t.Fatalf("%s %s = %d %s want %d", method, path, rec.Code, rec.Body, want)
		}
		m, _ := out.(map[string]any)
		return m
	}
	create := func(body any, want int) map[string]any {
		return call("POST", "/actions/modules", body, e.h.CreateActionModule, want)
	}
	m := create(map[string]any{"name": "shared", "code": "module.exports={n:1}", "publish": true, "secrets": []any{map[string]any{"name": "KEY", "value": "hidden"}}}, 201)
	id := m["id"].(string)
	if m["latest_version_number"] != float64(1) || m["all_changes_published"] != true || m["actions_using_module_total"] != float64(0) || m["latest_version"] == nil {
		t.Fatal(m)
	}
	if strings.Contains(fmt.Sprint(m), "hidden") {
		t.Fatal("secret leaked", m)
	}
	vid := m["latest_version"].(map[string]any)["id"].(string)
	get := func(w http.ResponseWriter, r *http.Request) { e.h.GetActionModule(w, r, id) }
	patch := func(w http.ResponseWriter, r *http.Request) { e.h.UpdateActionModule(w, r, id) }
	pub := func(w http.ResponseWriter, r *http.Request) { e.h.PublishActionModule(w, r, id) }
	del := func(w http.ResponseWriter, r *http.Request) { e.h.DeleteActionModule(w, r, id) }
	rollback := func(w http.ResponseWriter, r *http.Request) { e.h.RollbackActionModule(w, r, id) }
	call("GET", "/modules/"+id, nil, get, 200)
	create(map[string]any{"name": "shared", "code": "x"}, 409)
	create(map[string]any{"name": "shared", "code": "x", "publish": true, "dependencies": []any{map[string]any{"name": "missing-duplicate-fixture", "version": "1.0.0"}}}, 409)
	call("PATCH", "/modules/"+id, map[string]any{"name": "renamed"}, patch, 400)
	call("POST", "/modules/versions", nil, pub, 409)
	call("PATCH", "/modules/"+id, map[string]any{"code": "module.exports={n:2}", "secrets": []any{}}, patch, 200)
	m = call("GET", "/modules/"+id, nil, get, 200)
	if len(m["secrets"].([]any)) != 0 || m["all_changes_published"] != false {
		t.Fatal(m)
	}
	call("POST", "/modules/rollback", map[string]any{"module_version_id": vid}, rollback, 200)
	m = call("GET", "/modules/"+id, nil, get, 200)
	if m["code"] != "module.exports={n:1}" || m["latest_version_number"] != float64(1) {
		t.Fatal(m)
	}
	call("GET", "/modules/versions", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionModuleVersions(w, r, id) }, 200)
	call("GET", "/modules/version", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionModuleVersion(w, r, id, vid) }, 200)
	for _, refs := range []any{[]any{map[string]any{"module_id": id, "module_version_id": vid}}, []any{map[string]any{"module_name": "shared", "module_version_number": 1}}} {
		a := call("POST", "/actions", map[string]any{"name": fmt.Sprintf("a%v", refs), "supported_triggers": []any{map[string]any{"id": "post-login"}}, "modules": refs, "deploy": true}, e.h.CreateAction, 201)
		rs := a["modules"].([]any)
		if len(rs) != 1 || len(rs[0].(map[string]any)) != 4 {
			t.Fatal(a)
		}
		aid := a["id"].(string)
		stored, _ := e.st.Actions().GetAction(ctx, e.tn.ID, aid)
		v, _ := e.st.Actions().GetVersion(ctx, e.tn.ID, aid, stored.DeployedVersionID)
		if len(v.Modules) != 1 || v.Modules[0].VersionID != vid {
			t.Fatal(v)
		}
		users := call("GET", "/modules/actions", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionModuleActions(w, r, id) }, 200)
		u := users["actions"].([]any)[0].(map[string]any)
		if u["action_id"] != aid || u["module_version_id"] != vid || u["action_name"] != a["name"] || u["module_version_number"] != float64(1) {
			t.Fatalf("module Action reference=%v", u)
		}
		call("DELETE", "/modules/"+id, nil, del, 412)
		call("DELETE", "/actions?force=true", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteAction(w, r, aid) }, 204)
	}
	users := call("GET", "/modules/actions", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionModuleActions(w, r, id) }, 200)
	if users["total"] != float64(0) {
		t.Fatal(users)
	}
	call("GET", "/modules", nil, e.h.GetActionModules, 200)
	for _, ref := range []any{map[string]any{"module_id": "missing", "module_version_id": vid}, map[string]any{"module_name": "shared", "module_version_number": 2}} {
		call("POST", "/actions", map[string]any{"name": "unknown", "supported_triggers": []any{map[string]any{"id": "post-login"}}, "modules": []any{ref}}, e.h.CreateAction, 400)
	}
	// An unbuilt draft is 400; limits and conflicts retain their distinct codes.
	stored, _ := e.st.Actions().GetModule(ctx, e.tn.ID, id)
	stored.DraftBuildID = "missing"
	stored.Code = "changed"
	if err := e.st.Actions().UpdateModule(ctx, stored); err != nil {
		t.Fatal(err)
	}
	call("POST", "/modules/versions", nil, pub, 400)
	// Reach the real immutable version limit through the repository.
	original, _ := e.st.Actions().GetModuleVersion(ctx, e.tn.ID, id, vid)
	stored.DraftBuildID = original.BuildID
	for n := 1; n < actionsrules.Inventory().Limits["module_versions"]; n++ {
		stored.Code = fmt.Sprintf("module.exports=%d", n)
		if err := e.st.Actions().UpdateModule(ctx, stored); err != nil {
			t.Fatal(err)
		}
		if _, err := e.st.Actions().PublishModule(ctx, e.tn.ID, id); err != nil {
			t.Fatal(err)
		}
	}
	stored.Code = "limit changed"
	if err := e.st.Actions().UpdateModule(ctx, stored); err != nil {
		t.Fatal(err)
	}
	call("POST", "/modules/versions", nil, pub, 412)
	call("DELETE", "/modules/"+id, nil, del, 204)
	call("GET", "/modules/"+id, nil, get, 404)
	for _, body := range []any{map[string]any{"name": "x"}, map[string]any{"name": "", "code": ""}, map[string]any{"name": strings.Repeat("a", 256), "code": ""}, map[string]any{"name": "x", "code": strings.Repeat("a", 65537)}, map[string]any{"name": "x", "code": "", "api_version": strings.Repeat("v", 21)}, map[string]any{"name": "x", "code": "", "secrets": []any{map[string]any{"name": "K", "value": strings.Repeat("x", 4097)}}}, map[string]any{"name": "x", "code": "", "registry_url": "https://example.test"}} {
		create(body, 400)
	}
}

func TestActionsModulesPublicVersionShapeAndTombstone(t *testing.T) {
	e := newClientsEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	caller := m2mCaller("create:actions", "read:actions", "delete:actions")
	rec, out := e.call(t, e.tn, caller, "POST", "/modules", map[string]any{"name": "pin", "code": "module.exports={}", "publish": true}, e.h.CreateActionModule)
	if rec.Code != 201 {
		t.Fatal(rec.Code, rec.Body)
	}
	m := out.(map[string]any)
	id := m["id"].(string)
	v := m["latest_version"].(map[string]any)
	vid := v["id"].(string)
	if v["version_number"] != float64(1) || v["number"] != nil {
		t.Errorf("public module version shape=%v", v)
	}
	// Retain a version through an old Action pin, while removing current use.
	ctx := context.Background()
	a := &store.Action{TenantID: e.tn.ID, ID: "pinner", Name: "pinner", Trigger: "post-login", Modules: []store.ModuleRef{{ModuleID: id, VersionID: vid}}}
	module, _ := e.st.Actions().GetModule(ctx, e.tn.ID, id)
	a.DraftBuildID = module.DraftBuildID
	if err := e.st.Actions().CreateAction(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Actions().Deploy(ctx, e.tn.ID, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	a.Modules = nil
	if err := e.st.Actions().UpdateAction(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Actions().Deploy(ctx, e.tn.ID, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Actions().DeleteModule(ctx, e.tn.ID, id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Actions().GetModuleVersion(ctx, e.tn.ID, id, vid); err != nil {
		t.Fatal("internal pinned tombstone absent", err)
	}
	rec, _ = e.call(t, e.tn, caller, "GET", "/modules/version", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionModuleVersion(w, r, id, vid) })
	if rec.Code != 404 {
		t.Fatalf("public tombstone=%d %s", rec.Code, rec.Body)
	}
}

func TestActionsManagementSevenTriggersDryRun(t *testing.T) {
	e := newClientsEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	caller := m2mCaller("create:actions", "read:actions")
	rec, out := e.call(t, e.tn, caller, "GET", "/triggers", nil, e.h.GetActionTriggers)
	if rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	triggers := out.(map[string]any)["triggers"].([]any)
	if len(triggers) != 7 {
		t.Fatal(triggers)
	}
	for _, tr := range actionsrules.Inventory().Triggers {
		t.Run(tr.ID, func(t *testing.T) {
			commands := "console.log('ran');"
			switch tr.ID {
			case "post-login":
				commands += `api.user.setAppMetadata("dry",true);api.redirect.sendUserTo("https://example.test/next");api.access.deny("dry");`
			case "credentials-exchange":
				commands += `api.access.deny("invalid_request","dry");`
			case "pre-user-registration":
				commands += `api.user.setUserMetadata("dry",true);api.access.deny("dry","dry");`
			case "password-reset-post-challenge":
				commands += `api.transaction.setResultUrl("https://example.test/result");`
			case "custom-email-provider":
				commands += `api.notification.retry("dry");api.notification.drop("dry");`
			}
			body := map[string]any{"name": tr.ID, "supported_triggers": []any{map[string]any{"id": tr.ID}}, "code": "exports." + tr.Handler + "=async(event,api)=>{" + commands + "};", "deploy": true}
			rec, out := e.call(t, e.tn, caller, "POST", "/actions", body, e.h.CreateAction)
			if rec.Code != 201 {
				t.Fatal(rec.Code, rec.Body)
			}
			a := out.(map[string]any)
			id := a["id"].(string)
			rec, out = e.call(t, e.tn, caller, "POST", "/test", map[string]any{"payload": map[string]any{}}, func(w http.ResponseWriter, r *http.Request) { e.h.TestAction(w, r, id) })
			if rec.Code != 200 {
				t.Fatal(rec.Code, rec.Body)
			}
			p := out.(map[string]any)["payload"].(map[string]any)
			if p["error"] != nil || len(p["logs"].([]any)) != 1 {
				t.Fatal(p)
			}
			if _, err := e.st.Actions().GetExecution(context.Background(), e.tn.ID, p["execution_id"].(string)); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("dry-run persisted execution", err)
			}
		})
	}
	jobs, err := e.st.Actions().ClaimJobs(context.Background(), time.Now().Add(24*time.Hour), time.Minute, 100)
	if err != nil || len(jobs) != 0 {
		t.Fatal("dry-run queued jobs", jobs, err)
	}
	rec, _ = e.call(t, e.tn, caller, "POST", "/actions", map[string]any{"name": "deferred", "supported_triggers": []any{map[string]any{"id": "send-phone-message"}}}, e.h.CreateAction)
	if rec.Code != 400 {
		t.Fatal(rec.Code, rec.Body)
	}
}

func TestActionsModulesLimitsIsolationAndFailedBuild(t *testing.T) {
	e := newClientsEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	ctx := context.Background()
	caller := m2mCaller("read:actions", "create:actions", "update:actions", "delete:actions")
	call := func(body any, want int) map[string]any {
		t.Helper()
		rec, out := e.call(t, e.tn, caller, "POST", "/modules", body, e.h.CreateActionModule)
		if rec.Code != want {
			t.Fatalf("create = %d %s want %d", rec.Code, rec.Body, want)
		}
		m, _ := out.(map[string]any)
		return m
	}
	deps := []any{}
	for i := 0; i < 51; i++ {
		deps = append(deps, map[string]any{"name": fmt.Sprintf("pkg%d", i), "version": "1.0.0"})
	}
	ss := []any{}
	for i := 0; i < 65; i++ {
		ss = append(ss, map[string]any{"name": fmt.Sprintf("K%d", i), "value": "v"})
	}
	invalid := []map[string]any{
		{"dependencies": deps}, {"secrets": ss}, {"dependencies": []any{map[string]any{"name": "x", "version": "^1.0.0"}}}, {"dependencies": []any{map[string]any{"name": "x", "registry_url": "https://example.test"}}},
		{"secrets": []any{map[string]any{"name": "bad-name", "value": "x"}}}, {"secrets": []any{map[string]any{"name": strings.Repeat("K", 129), "value": "x"}}}, {"dependencies": []any{map[string]any{"name": strings.Repeat("p", 215), "version": "1.0.0"}}}, {"secrets": []any{map[string]any{"name": "X", "value": "x"}, map[string]any{"name": "X", "value": "x"}}},
		{"secrets": []any{map[string]any{"name": "new"}}}, {"code": "bad\x00code"}, {"api_version": "v\x00"}, {"publish": "true"}, {"secrets": nil}, {"dependencies": nil},
	}
	for i, extra := range invalid {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			body := map[string]any{"name": "invalid", "code": ""}
			for k, v := range extra {
				body[k] = v
			}
			call(body, 400)
		})
	}
	// All documented character limits count Unicode characters, not UTF-8 bytes.
	m := call(map[string]any{"name": strings.Repeat("é", 255), "code": strings.Repeat("é", 65536), "api_version": strings.Repeat("é", 20), "publish": true, "secrets": []any{map[string]any{"name": "KEY", "value": "module-secret"}}}, 201)
	id := m["id"].(string)
	vid := m["latest_version"].(map[string]any)["id"].(string)
	stored, _ := e.st.Actions().GetModule(ctx, e.tn.ID, id)
	plain, err := keys.OpenModuleSecret(e.w, e.tn.ID, id, "KEY", stored.Secrets[0].Sealed)
	if err != nil || plain != "module-secret" {
		t.Fatal(plain, err)
	}
	if _, err := keys.OpenActionSecret(e.w, e.tn.ID, id, "KEY", stored.Secrets[0].Sealed); err == nil {
		t.Fatal("module secret accepted as Action secret")
	}
	if _, err := keys.OpenModuleSecret(e.w, e.sys.ID, id, "KEY", stored.Secrets[0].Sealed); err == nil {
		t.Fatal("secret not tenant-bound")
	}
	patch := func(w http.ResponseWriter, r *http.Request) { e.h.UpdateActionModule(w, r, id) }
	rec, out := e.call(t, e.tn, caller, "PATCH", "/module", map[string]any{"code": "module.exports={n:2}", "secrets": []any{map[string]any{"name": "KEY"}}}, patch)
	if rec.Code != 200 || out.(map[string]any)["all_changes_published"] != false {
		t.Fatal(rec.Code, rec.Body)
	}
	after, _ := e.st.Actions().GetModule(ctx, e.tn.ID, id)
	if !bytes.Equal(after.Secrets[0].Sealed, stored.Secrets[0].Sealed) {
		t.Fatal("omitted value changed secret")
	}
	// Every resource operation must hide a module belonging to another tenant.
	ops := []struct {
		method string
		body   any
		fn     http.HandlerFunc
	}{
		{"GET", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionModule(w, r, id) }},
		{"PATCH", map[string]any{"code": "changed"}, patch},
		{"DELETE", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteActionModule(w, r, id) }},
		{"GET", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionModuleActions(w, r, id) }},
		{"POST", map[string]any{"module_version_id": vid}, func(w http.ResponseWriter, r *http.Request) { e.h.RollbackActionModule(w, r, id) }},
		{"GET", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionModuleVersions(w, r, id) }},
		{"POST", nil, func(w http.ResponseWriter, r *http.Request) { e.h.PublishActionModule(w, r, id) }},
		{"GET", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionModuleVersion(w, r, id, vid) }},
	}
	for _, op := range ops {
		rec, _ := e.call(t, e.sys, caller, op.method, "/modules/resource", op.body, op.fn)
		if rec.Code != 404 {
			t.Errorf("cross tenant %s=%d %s", op.method, rec.Code, rec.Body)
		}
	}
	refs := []any{}
	for i := 0; i < 11; i++ {
		refs = append(refs, map[string]any{"module_name": fmt.Sprintf("m%d", i), "module_version_number": 1})
	}
	rec, _ = e.call(t, e.tn, caller, "POST", "/actions", map[string]any{"name": "too-many", "supported_triggers": []any{map[string]any{"id": "post-login"}}, "modules": refs}, e.h.CreateAction)
	if rec.Code != 400 {
		t.Fatal(rec.Code, rec.Body)
	}
	// Failed synchronous publication leaves no API-visible module to skip on restart.
	call(map[string]any{"name": "failed", "code": "module.exports={}", "dependencies": []any{map[string]any{"name": "missing-offline-fixture", "version": "1.0.0"}}, "publish": true}, 400)
	if _, err := e.st.Actions().GetModuleByName(ctx, e.tn.ID, "failed"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("failed module persisted", err)
	}
	// Omitted paging returns every module; explicit paging limits the result.
	for i := 0; i < 52; i++ {
		draft := &store.ActionModule{TenantID: e.tn.ID, ID: fmt.Sprintf("extra%d", i), Name: fmt.Sprintf("extra%d", i), DraftBuildID: stored.DraftBuildID}
		if err := e.st.Actions().CreateModule(ctx, draft); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{"", "?per_page=1", "?page=1&per_page=1"} {
		rec, out := e.call(t, e.tn, caller, "GET", "/modules"+q, nil, e.h.GetActionModules)
		if rec.Code != 200 {
			t.Fatal(rec.Code, rec.Body)
		}
		v := out.(map[string]any)
		n := 53
		if q != "" {
			n = 1
		}
		if len(v["modules"].([]any)) != n || v["total"] != float64(53) {
			t.Fatal(v)
		}
	}
	for i := 53; i < actionsrules.Inventory().Limits["modules_per_tenant"]; i++ {
		draft := &store.ActionModule{TenantID: e.tn.ID, ID: fmt.Sprintf("cap%d", i), Name: fmt.Sprintf("cap%d", i), DraftBuildID: stored.DraftBuildID}
		if err := e.st.Actions().CreateModule(ctx, draft); err != nil {
			t.Fatal(err)
		}
	}
	call(map[string]any{"name": "over-cap", "code": ""}, 412)
	for _, q := range []string{"?per_page=0", "?per_page=101", "?page=-1", "?page=1&page=2", "?unknown=1"} {
		rec, _ := e.call(t, e.tn, caller, "GET", "/modules"+q, nil, e.h.GetActionModules)
		if rec.Code != 400 {
			t.Fatal(rec.Code, rec.Body)
		}
	}
}

func TestActionsModulesPinnedVersionsAndDeployedOnlyUse(t *testing.T) {
	e := newClientsEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	caller := m2mCaller("read:actions", "create:actions", "update:actions", "delete:actions")
	call := func(method string, body any, fn http.HandlerFunc, want int) map[string]any {
		t.Helper()
		rec, out := e.call(t, e.tn, caller, method, "/resource", body, fn)
		if rec.Code != want {
			t.Fatalf("%d %s want %d", rec.Code, rec.Body, want)
		}
		m, _ := out.(map[string]any)
		return m
	}
	m := call("POST", map[string]any{"name": "shared", "code": "module.exports={n:1}", "publish": true}, e.h.CreateActionModule, 201)
	mid := m["id"].(string)
	mvid := m["latest_version"].(map[string]any)["id"].(string)
	a := call("POST", map[string]any{"name": "pinner", "supported_triggers": []any{map[string]any{"id": "post-login"}}, "modules": []any{map[string]any{"module_name": "shared", "module_version_number": 1}}, "deploy": true}, e.h.CreateAction, 201)
	aid := a["id"].(string)
	avid := a["deployed_version"].(map[string]any)["id"].(string)
	call("PATCH", map[string]any{"code": "module.exports={n:2}"}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateActionModule(w, r, mid) }, 200)
	v2 := call("POST", nil, func(w http.ResponseWriter, r *http.Request) { e.h.PublishActionModule(w, r, mid) }, 200)
	if v2["version_number"] != float64(2) {
		t.Fatal(v2)
	}
	pinned := call("GET", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionVersion(w, r, aid, avid) }, 200)
	if pinned["modules"].([]any)[0].(map[string]any)["module_version_id"] != mvid {
		t.Fatal("module publication changed Action pins", pinned)
	}
	call("POST", map[string]any{"module_version_id": mvid}, func(w http.ResponseWriter, r *http.Request) { e.h.RollbackActionModule(w, r, mid) }, 200)
	m = call("GET", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionModule(w, r, mid) }, 200)
	if m["latest_version_number"] != float64(2) || m["all_changes_published"] != false || m["latest_version"].(map[string]any)["id"] != v2["id"] {
		t.Fatal("rollback changed latest publication", m)
	}
	a = call("PATCH", map[string]any{"modules": []any{}}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateAction(w, r, aid) }, 200)
	if a["all_changes_deployed"] != false {
		t.Fatal(a)
	}
	m = call("GET", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionModule(w, r, mid) }, 200)
	if m["actions_using_module_total"] != float64(1) {
		t.Fatal(m)
	}
	users := call("GET", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionModuleActions(w, r, mid) }, 200)
	if users["total"] != float64(1) || users["actions"].([]any)[0].(map[string]any)["module_version_id"] != mvid {
		t.Fatal(users)
	}
	call("DELETE", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteActionModule(w, r, mid) }, 412)
	restored := call("POST", map[string]any{"update_draft": true}, func(w http.ResponseWriter, r *http.Request) { e.h.DeployActionVersion(w, r, aid, avid) }, 202)
	if restored["modules"].([]any)[0].(map[string]any)["module_version_id"] != mvid {
		t.Fatal(restored)
	}
	a = call("GET", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetAction(w, r, aid) }, 200)
	if a["all_changes_deployed"] != true || len(a["modules"].([]any)) != 1 {
		t.Fatal(a)
	}
}

// Redeploying an old version with update_draft must keep working after a
// module it pins was deleted: the draft takes the version's pins verbatim (M-7).
func TestActionsRollbackUpdateDraftWithTombstonedModule(t *testing.T) {
	e := newClientsEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	caller := m2mCaller("read:actions", "create:actions", "update:actions", "delete:actions")
	call := func(method string, body any, fn http.HandlerFunc, want int) map[string]any {
		t.Helper()
		rec, out := e.call(t, e.tn, caller, method, "/resource", body, fn)
		if rec.Code != want {
			t.Fatalf("%d %s want %d", rec.Code, rec.Body, want)
		}
		m, _ := out.(map[string]any)
		return m
	}
	m := call("POST", map[string]any{"name": "doomed", "code": "module.exports={n:1}", "publish": true}, e.h.CreateActionModule, 201)
	mid := m["id"].(string)
	mvid := m["latest_version"].(map[string]any)["id"].(string)
	a := call("POST", map[string]any{"name": "pinner", "supported_triggers": []any{map[string]any{"id": "post-login"}}, "modules": []any{map[string]any{"module_name": "doomed", "module_version_number": 1}}, "deploy": true}, e.h.CreateAction, 201)
	aid := a["id"].(string)
	old := a["deployed_version"].(map[string]any)["id"].(string)
	call("PATCH", map[string]any{"modules": []any{}}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateAction(w, r, aid) }, 200)
	call("POST", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeployAction(w, r, aid) }, 202)
	call("DELETE", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteActionModule(w, r, mid) }, 204)
	restored := call("POST", map[string]any{"update_draft": true}, func(w http.ResponseWriter, r *http.Request) { e.h.DeployActionVersion(w, r, aid, old) }, 202)
	if restored["modules"].([]any)[0].(map[string]any)["module_version_id"] != mvid {
		t.Fatal(restored)
	}
	a = call("GET", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetAction(w, r, aid) }, 200)
	if refs := a["modules"].([]any); len(refs) != 1 || refs[0].(map[string]any)["module_version_id"] != mvid || a["all_changes_deployed"] != true {
		t.Fatal(a)
	}
	// The restored draft stays editable and deployable on its pinned tombstone.
	call("PATCH", map[string]any{"code": "exports.onExecutePostLogin=async()=>{};"}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateAction(w, r, aid) }, 200)
	call("POST", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeployAction(w, r, aid) }, 202)
	// A deleted module still cannot be newly referenced by a draft.
	other := call("POST", map[string]any{"name": "other", "supported_triggers": []any{map[string]any{"id": "post-login"}}}, e.h.CreateAction, 201)
	call("PATCH", map[string]any{"modules": []any{map[string]any{"module_id": mid, "module_version_id": mvid}}}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateAction(w, r, other["id"].(string)) }, 400)
}
