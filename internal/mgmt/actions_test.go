package mgmt_test

import (
	"context"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/actions/build"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestActionsManagementContract(t *testing.T) {
	e := newClientsEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	call := func(method, path string, body any, fn http.HandlerFunc, want int) map[string]any {
		t.Helper()
		rec, out := e.call(t, e.tn, m2mCaller("read:actions", "create:actions", "update:actions", "delete:actions"), method, path, body, fn)
		if rec.Code != want {
			t.Fatalf("%s %s=%d %s; want %d", method, path, rec.Code, rec.Body, want)
		}
		v, _ := out.(map[string]any)
		return v
	}
	create := func(body any, want int) map[string]any {
		return call("POST", "/api/v2/actions/actions", body, e.h.CreateAction, want)
	}
	a := create(map[string]any{"name": "Login", "supported_triggers": []any{map[string]any{"id": "post-login", "version": "v3"}}, "code": `exports.onExecutePostLogin=async(event,api)=>{console.log(event.secrets.KEY);api.user.setAppMetadata("dry",true);api.access.deny("test");};`, "secrets": []any{map[string]any{"name": "KEY", "value": "hidden-value"}}}, 201)
	id := a["id"].(string)
	if a["all_changes_deployed"] != false || a["status"] == nil {
		t.Fatal(a)
	}
	assertSecrets := func(out map[string]any) {
		t.Helper()
		ss := out["secrets"].([]any)
		s := ss[0].(map[string]any)
		if len(s) != 2 || s["name"] != "KEY" || s["updated_at"] == nil {
			t.Fatalf("secret exposed or malformed: %v", s)
		}
	}
	assertSecrets(a)
	stored, err := e.st.Actions().GetAction(context.Background(), e.tn.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := keys.OpenActionSecret(e.w, e.tn.ID, id, "KEY", stored.Secrets[0].Sealed)
	if err != nil || plain != "hidden-value" {
		t.Fatalf("secret=%q %v", plain, err)
	}
	if _, err := keys.OpenActionSecret(e.w, e.sys.ID, id, "KEY", stored.Secrets[0].Sealed); err == nil {
		t.Fatal("secret not tenant bound")
	}
	if _, err := keys.OpenActionSecret(e.w, e.tn.ID, "other", "KEY", stored.Secrets[0].Sealed); err == nil {
		t.Fatal("secret not Action bound")
	}
	get := func(w http.ResponseWriter, r *http.Request) { e.h.GetAction(w, r, id) }
	deploy := func(w http.ResponseWriter, r *http.Request) { e.h.DeployAction(w, r, id) }
	patch := func(w http.ResponseWriter, r *http.Request) { e.h.UpdateAction(w, r, id) }
	// An explicitly unbuilt draft never deploys or tests, even with a usable engine.
	b, _ := e.st.Actions().GetBuild(context.Background(), e.tn.ID, stored.DraftBuildID)
	deadline := time.Now().Add(time.Minute)
	for b.Status != store.BuildBuilt && b.Status != store.BuildFailed && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		b, _ = e.st.Actions().GetBuild(context.Background(), e.tn.ID, stored.DraftBuildID)
	}
	if b.Status != store.BuildBuilt {
		t.Fatalf("build=%+v", b)
	}
	a = call("GET", "/actions/"+id, nil, get, 200)
	if a["status"] != "built" {
		t.Fatal(a)
	}
	v := call("POST", "/actions/"+id+"/deploy", nil, deploy, 202)
	assertSecrets(v)
	if v["number"] != float64(1) {
		t.Fatal(v)
	}
	vid := v["id"].(string)
	a = call("GET", "/actions/"+id, nil, get, 200)
	if a["all_changes_deployed"] != true {
		t.Fatal(a)
	}
	call("PATCH", "/actions/"+id, map[string]any{"code": "exports.onExecutePostLogin=async()=>{};"}, patch, 200)
	a = call("GET", "/actions/"+id, nil, get, 200)
	if a["all_changes_deployed"] != false {
		t.Fatal(a)
	}
	rollback := func(w http.ResponseWriter, r *http.Request) { e.h.DeployActionVersion(w, r, id, vid) }
	v = call("POST", "/actions/rollback", map[string]any{"update_draft": true}, rollback, 202)
	if v["number"] != float64(2) {
		t.Fatal(v)
	}
	a = call("GET", "/actions/"+id, nil, get, 200)
	if a["all_changes_deployed"] != true {
		t.Fatal(a)
	}
	versions := call("GET", "/actions/versions?per_page=1", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionVersions(w, r, id) }, 200)
	if versions["total"] != float64(2) || len(versions["versions"].([]any)) != 1 || versions["per_page"] != float64(1) || versions["page"] != float64(0) {
		t.Fatal(versions)
	}
	call("GET", "/actions/version", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionVersion(w, r, id, vid) }, 200)
	tested := call("POST", "/actions/test", map[string]any{"payload": map[string]any{}}, func(w http.ResponseWriter, r *http.Request) { e.h.TestAction(w, r, id) }, 200)
	payload := tested["payload"].(map[string]any)
	if len(payload["commands"].([]any)) != 2 || strings.Contains(payload["logs"].([]any)[0].(string), "hidden-value") || payload["duration_ms"] == nil {
		t.Fatal(payload)
	}
	// Test must not persist an execution or user mutation; engine conformance covers metadata.
	execID := "execution"
	if err := e.st.Actions().CreateExecution(context.Background(), &store.Execution{TenantID: e.tn.ID, ID: execID, Trigger: "post-login", Status: "success", CreatedAt: time.Now().Add(-11 * 24 * time.Hour), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	ex := func(w http.ResponseWriter, r *http.Request) { e.h.GetActionExecution(w, r, execID) }
	call("GET", "/actions/executions/"+execID, nil, ex, 200)
	if _, err := e.st.Actions().PurgeExecutions(context.Background(), time.Now().Add(-10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	call("GET", "/actions/executions/"+execID, nil, ex, 404)
	binding := func(w http.ResponseWriter, r *http.Request) { e.h.UpdateActionBindings(w, r, "post-login") }
	for _, typ := range []string{"action_id", "action_name", "binding_id"} {
		value := id
		if typ == "action_name" {
			value = "Login"
		}
		if typ == "binding_id" {
			out := call("GET", "/actions/bindings", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetActionBindings(w, r, "post-login") }, 200)
			value = out["bindings"].([]any)[0].(map[string]any)["id"].(string)
		}
		out := call("PATCH", "/actions/bindings", map[string]any{"bindings": []any{map[string]any{"ref": map[string]any{"type": typ, "value": value}, "display_name": "Login"}}}, binding, 200)
		if len(out["bindings"].([]any)) != 1 {
			t.Fatal(out)
		}
	}
	call("DELETE", "/actions/"+id, nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteAction(w, r, id) }, 400)
	call("PATCH", "/actions/bindings", map[string]any{"bindings": []any{map[string]any{"ref": map[string]any{"type": "action_id", "value": id}, "secrets": []any{}}}}, binding, 400)
	call("DELETE", "/actions/"+id+"?force=true", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteAction(w, r, id) }, 204)
	call("GET", "/actions/"+id, nil, get, 404)
	// Cross-tenant IDs stay opaque.
	other := ae.Deploy(t, e.sys.ID, "post-login", "other", "exports.onExecutePostLogin=async()=>{};")
	call("GET", "/actions/other", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetAction(w, r, other.ID) }, 404)
}

func TestActionsManagementLimits(t *testing.T) {
	e := newClientsEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	base := func() map[string]any {
		return map[string]any{"name": "Test", "supported_triggers": []any{map[string]any{"id": "post-login"}}}
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"empty name", func(m map[string]any) { m["name"] = "" }},
		{"long name", func(m map[string]any) { m["name"] = strings.Repeat("界", 129) }},
		{"code bytes", func(m map[string]any) { m["code"] = strings.Repeat("x", 100001) }},
		{"runtime", func(m map[string]any) { m["runtime"] = "node18" }},
		{"empty runtime", func(m map[string]any) { m["runtime"] = "" }},
		{"unsupported trigger", func(m map[string]any) { m["supported_triggers"] = []any{map[string]any{"id": "send-phone-message"}} }},
		{"two triggers", func(m map[string]any) {
			m["supported_triggers"] = []any{map[string]any{"id": "post-login"}, map[string]any{"id": "credentials-exchange"}}
		}},
		{"unknown", func(m map[string]any) { m["unknown"] = true }},
		{"registry", func(m map[string]any) {
			m["dependencies"] = []any{map[string]any{"name": "pkg", "version": "1.0.0", "registry_url": "https://example.invalid"}}
		}},
		{"range", func(m map[string]any) { m["dependencies"] = []any{map[string]any{"name": "pkg", "version": "^1.0.0"}} }},
		{"deps count", func(m map[string]any) {
			a := []any{}
			for i := 0; i < 51; i++ {
				a = append(a, map[string]any{"name": "pkg", "version": "1.0.0"})
			}
			m["dependencies"] = a
		}},
		{"secret value", func(m map[string]any) {
			m["secrets"] = []any{map[string]any{"name": "KEY", "value": strings.Repeat("x", 4097)}}
		}},
		{"secret name", func(m map[string]any) {
			m["secrets"] = []any{map[string]any{"name": strings.Repeat("X", 129), "value": "x"}}
		}},
		{"secret chars", func(m map[string]any) { m["secrets"] = []any{map[string]any{"name": "bad-name", "value": "x"}} }},
		{"secret count", func(m map[string]any) {
			a := []any{}
			for i := 0; i < 65; i++ {
				a = append(a, map[string]any{"name": "KEY", "value": "x"})
			}
			m["secrets"] = a
		}},
		{"null", func(m map[string]any) { m["dependencies"] = nil }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			body := base()
			tt.mutate(body)
			rec, _ := e.call(t, e.tn, m2mCaller("create:actions"), "POST", "/actions", body, e.h.CreateAction)
			if rec.Code != 400 {
				t.Fatalf("got %d %s", rec.Code, rec.Body)
			}
		})
	}
	for _, query := range []string{"?per_page=101", "?per_page=0", "?page=-1", "?page=2147483647", "?page=0&page=1", "?unknown=x", "?deployed=no", "?installed=1", "?triggerId=unsupported", "?page="} {
		rec, _ := e.call(t, e.tn, m2mCaller("read:actions"), "GET", "/actions"+query, nil, e.h.GetActions)
		if rec.Code != 400 {
			t.Errorf("%s=%d %s", query, rec.Code, rec.Body)
		}
	}
	unbuilt := &store.Action{TenantID: e.tn.ID, ID: "unbuilt", Name: "Unbuilt", Trigger: "post-login", Runtime: "node22"}
	if err := e.st.Actions().CreateAction(context.Background(), unbuilt); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		body any
		fn   http.HandlerFunc
	}{{nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeployAction(w, r, "unbuilt") }}, {map[string]any{"payload": map[string]any{}}, func(w http.ResponseWriter, r *http.Request) { e.h.TestAction(w, r, "unbuilt") }}} {
		rec, _ := e.call(t, e.tn, m2mCaller("create:actions"), "POST", "/actions", tt.body, tt.fn)
		if rec.Code != 400 {
			t.Fatalf("unbuilt=%d %s", rec.Code, rec.Body)
		}
	}
}

// Explicit nulls must not silently become omitted fields or false booleans.
func TestActionsStrictTransport(t *testing.T) {
	e := newClientsEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "local registry fixture", 404) }))
	t.Cleanup(registry.Close)
	manager, err := build.New(config.Actions{CacheDir: t.TempDir(), Registry: registry.URL}, e.st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	e.h.Actions.Builds = manager
	a := ae.Deploy(t, e.tn.ID, "post-login", "transport", "exports.onExecutePostLogin=async()=>{};")
	v, _ := e.st.Actions().GetAction(context.Background(), e.tn.ID, a.ID)
	cases := []struct {
		method, path string
		body         any
		fn           http.HandlerFunc
	}{
		{"PATCH", "/actions", `{"dependencies":[{"name":"pkg","version":null}]}`, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateAction(w, r, a.ID) }},
		{"PATCH", "/actions", `{"supported_triggers":[{"id":"post-login","version":null}]}`, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateAction(w, r, a.ID) }},
		{"POST", "/actions/rollback", `{"update_draft":null}`, func(w http.ResponseWriter, r *http.Request) { e.h.DeployActionVersion(w, r, a.ID, v.DeployedVersionID) }},
		{"POST", "/actions/deploy", `{"unknown":true}`, func(w http.ResponseWriter, r *http.Request) { e.h.DeployAction(w, r, a.ID) }},
		{"GET", "/actions", `{"unknown":true}`, func(w http.ResponseWriter, r *http.Request) { e.h.GetAction(w, r, a.ID) }},
		{"PATCH", "/bindings", `{"bindings":[{"ref":{"type":"action_id","value":"` + a.ID + `"},"display_name":null}]}`, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateActionBindings(w, r, "post-login") }},
	}
	for _, tt := range cases {
		rec, _ := e.call(t, e.tn, m2mCaller("create:actions", "update:actions", "read:actions"), tt.method, tt.path, tt.body, tt.fn)
		if rec.Code != 400 {
			t.Errorf("%s body=%v got %d %s", tt.path, tt.body, rec.Code, rec.Body)
		}
	}
}

func TestActionsRecoveryOnReadDeployTest(t *testing.T) {
	for _, status := range []store.BuildStatus{store.BuildPending, store.BuildBuilding} {
		for _, op := range []string{"GET", "deploy", "test"} {
			t.Run(string(status)+"/"+op, func(t *testing.T) {
				e := newClientsEnv(t)
				ae := actionstest.NewOffline(t, e.st, e.w)
				e.h.Actions = ae.Engine
				id := build.ID("node22", nil)
				if err := e.st.Actions().PutBuild(context.Background(), &store.Build{TenantID: e.tn.ID, ID: id, Status: status}); err != nil {
					t.Fatal(err)
				}
				a := &store.Action{TenantID: e.tn.ID, ID: "recover", Name: "recover", Trigger: "post-login", Runtime: "node22", DraftBuildID: id}
				if err := e.st.Actions().CreateAction(context.Background(), a); err != nil {
					t.Fatal(err)
				}
				var fn http.HandlerFunc
				var body any
				method := "POST"
				switch op {
				case "GET":
					method = "GET"
					fn = func(w http.ResponseWriter, r *http.Request) { e.h.GetAction(w, r, a.ID) }
				case "deploy":
					fn = func(w http.ResponseWriter, r *http.Request) { e.h.DeployAction(w, r, a.ID) }
				case "test":
					body = map[string]any{"payload": map[string]any{}}
					fn = func(w http.ResponseWriter, r *http.Request) { e.h.TestAction(w, r, a.ID) }
				}
				rec, _ := e.call(t, e.tn, m2mCaller("read:actions", "create:actions"), method, "/actions", body, fn)
				if rec.Code != 200 && rec.Code != 202 && rec.Code != 400 {
					t.Fatalf("%s=%d %s", op, rec.Code, rec.Body)
				}
				deadline := time.Now().Add(time.Minute)
				for {
					b, err := e.st.Actions().GetBuild(context.Background(), e.tn.ID, id)
					if err != nil {
						t.Fatal(err)
					}
					if b.Status == store.BuildBuilt {
						break
					}
					if b.Status == store.BuildFailed || time.Now().After(deadline) {
						t.Fatalf("abandoned build was not recovered: %+v", b)
					}
					time.Sleep(10 * time.Millisecond)
				}
			})
		}
	}
}

type failingActionReads struct {
	store.Actions
	err error
}

func (s failingActionReads) GetAction(context.Context, string, string) (*store.Action, error) {
	return nil, s.err
}

type actionsStore struct {
	store.Store
	actions store.Actions
}

func (s actionsStore) Actions() store.Actions { return s.actions }
func TestActionsResolveTimeoutStatus(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Store = actionsStore{Store: e.st, actions: failingActionReads{Actions: e.st.Actions(), err: build.ErrResolveTimeout}}
	rec, _ := e.call(t, e.tn, m2mCaller("read:actions"), "GET", "/actions", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetAction(w, r, "missing") })
	if rec.Code != 503 {
		t.Fatalf("resolver timeout=%d %s", rec.Code, rec.Body)
	}
}

func TestActionsDuplicateNameIsBadRequest(t *testing.T) {
	e := newClientsEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	ae.Deploy(t, e.tn.ID, "post-login", "taken", "exports.onExecutePostLogin=async()=>{};")
	other := ae.Deploy(t, e.tn.ID, "post-login", "free", "exports.onExecutePostLogin=async()=>{};")
	for _, tt := range []struct {
		method string
		body   any
		fn     http.HandlerFunc
	}{
		{"POST", map[string]any{"name": "taken", "supported_triggers": []any{map[string]any{"id": "post-login"}}}, e.h.CreateAction},
		{"PATCH", map[string]any{"name": "taken"}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateAction(w, r, other.ID) }},
	} {
		rec, _ := e.call(t, e.tn, m2mCaller("create:actions", "update:actions"), tt.method, "/actions", tt.body, tt.fn)
		if rec.Code != 400 {
			t.Errorf("duplicate=%d %s", rec.Code, rec.Body)
		}
	}
}

func TestActionsLimitsAndFiltersBoundary(t *testing.T) {
	e := newClientsEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	ss := []any{}
	for i := 0; i < 64; i++ {
		ss = append(ss, map[string]any{"name": fmt.Sprintf("KEY_%d", i), "value": strings.Repeat("x", 4096)})
	}
	rec, out := e.call(t, e.tn, m2mCaller("create:actions"), "POST", "/actions", map[string]any{"name": strings.Repeat("界", 128), "supported_triggers": []any{map[string]any{"id": "post-login"}}, "code": strings.Repeat("x", 100000), "secrets": ss}, e.h.CreateAction)
	if rec.Code != 201 {
		t.Fatalf("allowed boundary=%d %s", rec.Code, rec.Body)
	}
	id := out.(map[string]any)["id"].(string)
	// A valid undeployed draft cannot be bound.
	binding := func(w http.ResponseWriter, r *http.Request) { e.h.UpdateActionBindings(w, r, "post-login") }
	bind := func(bs []any, want int) {
		t.Helper()
		rec, _ := e.call(t, e.tn, m2mCaller("update:actions"), "PATCH", "/bindings", map[string]any{"bindings": bs}, binding)
		if rec.Code != want {
			t.Fatalf("bindings=%d %s", rec.Code, rec.Body)
		}
	}
	bind([]any{map[string]any{"ref": map[string]any{"type": "action_id", "value": id}}}, 400)
	a := ae.Deploy(t, e.tn.ID, "post-login", "bound", "exports.onExecutePostLogin=async()=>{};")
	bs := []any{}
	for i := 0; i < 20; i++ {
		bs = append(bs, map[string]any{"ref": map[string]any{"type": "action_id", "value": a.ID}})
	}
	bind(bs, 200)
	bind(append(bs, bs[0]), 400)
	ds := []any{}
	for i := 0; i < 50; i++ {
		ds = append(ds, map[string]any{"name": fmt.Sprintf("task10-fixture-%d", i), "version": "1.0.0"})
	}
	rec, _ = e.call(t, e.tn, m2mCaller("update:actions"), "PATCH", "/actions", map[string]any{"dependencies": ds}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateAction(w, r, id) })
	if rec.Code != 200 {
		t.Fatalf("dependency boundary=%d %s", rec.Code, rec.Body)
	}
	for _, tt := range []struct {
		query string
		total int
	}{{"?deployed=true", 1}, {"?deployed=false", 1}, {"?installed=true", 0}, {"?installed=false", 2}, {"?actionName=bound", 1}, {"?triggerId=credentials-exchange", 0}, {"?page=1&per_page=1", 2}} {
		rec, out := e.call(t, e.tn, m2mCaller("read:actions"), "GET", "/actions"+tt.query, nil, e.h.GetActions)
		if rec.Code != 200 || out.(map[string]any)["total"] != float64(tt.total) {
			t.Errorf("%s=%d %v", tt.query, rec.Code, out)
		}
	}
	// Test is a dry run even for a real tenant user; writes are counted at the
	// store boundary and the persisted metadata is checked independently.
	u := &store.User{TenantID: e.tn.ID, UserID: "auth0|dry", AppMetadata: map[string]any{"kept": true}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := e.st.Users().Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	draft, _ := e.st.Actions().GetAction(context.Background(), e.tn.ID, a.ID)
	draft.Code = `exports.onExecutePostLogin=async(event,api)=>{api.user.setAppMetadata("changed",true);api.redirect.sendUserTo("https://example.invalid/dry");};`
	if err := e.st.Actions().UpdateAction(context.Background(), draft); err != nil {
		t.Fatal(err)
	}
	counts := &actionstest.Counts{}
	e.h.Actions.Store = actionstest.CountingStore{Store: e.st, Counts: counts}
	rec, _ = e.call(t, e.tn, m2mCaller("create:actions"), "POST", "/actions/test", map[string]any{"payload": map[string]any{"user": map[string]any{"user_id": u.UserID}}}, func(w http.ResponseWriter, r *http.Request) { e.h.TestAction(w, r, a.ID) })
	if rec.Code != 200 {
		t.Fatalf("dry-run=%d %s", rec.Code, rec.Body)
	}
	after, _ := e.st.Users().Get(context.Background(), e.tn.ID, u.UserID)
	if after.AppMetadata["changed"] != nil || after.AppMetadata["kept"] != true || counts.Snapshot()["Actions.CreateExecution"] != 0 {
		t.Fatalf("dry run wrote state: user=%v counts=%v", after, counts.Snapshot())
	}
}

func TestActionsBindingReferenceUpdatesTimestamp(t *testing.T) {
	e := newClientsEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	a := ae.Deploy(t, e.tn.ID, "post-login", "timestamp", "exports.onExecutePostLogin=async()=>{};")
	ae.Bind(t, e.tn.ID, "post-login", a)
	before, err := e.st.Actions().Bindings(context.Background(), e.tn.ID, "post-login")
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := e.call(t, e.tn, m2mCaller("update:actions"), "PATCH", "/bindings", map[string]any{"bindings": []any{map[string]any{"ref": map[string]any{"type": "binding_id", "value": before[0].ID}, "display_name": "changed"}}}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateActionBindings(w, r, "post-login") })
	if rec.Code != 200 {
		t.Fatalf("binding=%d %s", rec.Code, rec.Body)
	}
	after, err := e.st.Actions().Bindings(context.Background(), e.tn.ID, "post-login")
	if err != nil {
		t.Fatal(err)
	}
	if after[0].UpdatedAt.Equal(before[0].UpdatedAt) || after[0].ID != before[0].ID || !after[0].CreatedAt.Equal(before[0].CreatedAt) {
		t.Fatalf("binding update timestamps before=%+v after=%+v", before, after)
	}
}
