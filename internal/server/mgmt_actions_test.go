package server

import (
	"context"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
)

func TestActionsManagementRoutes(t *testing.T) {
	text := strings.Replace(mgmtSeed, `"read:connections", "create:connections"`, `"read:actions", "create:actions", "update:actions", "delete:actions", "read:connections", "create:connections"`, 1)
	h, _ := newMgmtEnvSeed(t, text, nil)
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	limited := m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
	scopedTokens := map[string]string{}
	for _, scope := range []string{"read:actions", "create:actions", "update:actions", "delete:actions"} {
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"admin"}, "client_secret": {"admin-s3cret"}, "audience": {acmeMgmtAPI}, "scope": {scope}}
		req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != 200 {
			t.Fatalf("token %s=%d %s", scope, rec.Code, rec.Body)
		}
		scopedTokens[scope] = out["access_token"].(string)
	}
	for _, op := range actionsrules.Inventory().Operations {
		path := strings.NewReplacer("{id}", "missing", "{versionId}", "missing", "{triggerId}", "post-login").Replace(op.Path)
		required := op.RequiredScopes[0]
		for scope, scopedToken := range scopedTokens {
			rec, _ := sendJSON(h, op.Method, "https://acme.example.test"+path, scopedToken, nil)
			if scope == required {
				if rec.Code == 401 || rec.Code == 403 || rec.Code >= 500 {
					t.Errorf("exact scope %s %s %s=%d %s", scope, op.Method, path, rec.Code, rec.Body)
				}
			} else if rec.Code != 403 {
				t.Errorf("wrong scope %s %s %s=%d %s", scope, op.Method, path, rec.Code, rec.Body)
			}
		}
		for _, auth := range []struct {
			token string
			want  int
		}{{"", 401}, {limited, 403}} {
			rec, _ := sendJSON(h, op.Method, "https://acme.example.test"+path, auth.token, nil)
			if rec.Code != auth.want {
				t.Errorf("%s %s scope=%s got %d %s; want %d", op.Method, path, auth.token, rec.Code, rec.Body, auth.want)
			}
		}
	}
	rec, out := sendJSON(h, "GET", "https://acme.example.test/api/v2/actions/triggers", token, nil)
	if rec.Code != 200 {
		t.Fatalf("triggers=%d %s", rec.Code, rec.Body)
	}
	if len(out["triggers"].([]any)) != 2 {
		t.Fatal(out)
	}
}

func TestActionsManagementResponseSchemas(t *testing.T) {
	text := strings.Replace(mgmtSeed, `"read:connections", "create:connections"`, `"read:actions", "create:actions", "update:actions", "delete:actions", "read:connections", "create:connections"`, 1)
	var ae *actionstest.Env
	h, st := newMgmtEnvSeed(t, text, func(d *Deps) { ae = actionstest.NewOffline(t, d.Store, d.Wrapper); d.Actions = ae.Engine })
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	c := newMgmtContract(t)
	base := "https://acme.example.test/api/v2/actions"
	call := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		status, b := c.do(h, method, base+path, token, body)
		if status != want {
			t.Fatalf("%s %s=%d %s", method, path, status, b)
		}
		var out map[string]any
		_ = json.Unmarshal(b, &out)
		return out
	}
	a := call("POST", "/actions", map[string]any{"name": "router", "supported_triggers": []any{map[string]any{"id": "post-login"}}, "deploy": true, "code": `exports.onExecutePostLogin=async(event,api)=>{api.access.deny("dry");};`}, 201)
	id := a["id"].(string)
	call("GET", "/actions", nil, 200)
	call("GET", "/actions/"+id, nil, 200)
	call("PATCH", "/actions/"+id, map[string]any{"name": "renamed"}, 200)
	v := call("POST", "/actions/"+id+"/deploy", nil, 202)
	vid := v["id"].(string)
	call("GET", "/actions/"+id+"/versions", nil, 200)
	call("GET", "/actions/"+id+"/versions/"+vid, nil, 200)
	call("POST", "/actions/"+id+"/versions/"+vid+"/deploy", map[string]any{}, 202)
	call("POST", "/actions/"+id+"/test", map[string]any{"payload": map[string]any{}}, 200)
	call("PATCH", "/actions/"+id, map[string]any{"code": `exports.onExecutePostLogin=async()=>{throw new Error("contract throw");};`}, 200)
	thrown := call("POST", "/actions/"+id+"/test", map[string]any{"payload": map[string]any{}}, 200)
	payload := thrown["payload"].(map[string]any)
	actionError, ok := payload["error"].(map[string]any)
	if !ok || actionError["id"] == nil || actionError["message"] == nil {
		t.Fatalf("throwing Action error=%v", payload)
	}
	call("GET", "/triggers", nil, 200)
	call("PATCH", "/triggers/post-login/bindings", map[string]any{"bindings": []any{map[string]any{"ref": map[string]any{"type": "action_id", "value": id}}}}, 200)
	call("GET", "/triggers/post-login/bindings", nil, 200)
	call("PATCH", "/triggers/post-login/bindings", map[string]any{"bindings": []any{}}, 200)
	seeded, err := seed.Parse([]byte("tenants:\n- name: acme\n  domains: [acme.example.test, login.acme.test]\n  triggers:\n    post-login:\n      bindings: [{ref: {type: action_name, value: renamed}}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	seeded.Mode = seed.ModeCreateOnly
	if err := seed.ApplyWithActions(context.Background(), st, seeded, nil, ae.Engine.Secrets, ae.Engine); err != nil {
		t.Fatal(err)
	}
	preserved := call("GET", "/triggers/post-login/bindings", nil, 200)
	if preserved["total"] != float64(0) {
		t.Fatalf("seed restart undid management clear: %v", preserved)
	}

	tn, _ := st.Tenants().GetByName(context.Background(), "acme")
	if err := st.Actions().CreateExecution(context.Background(), &store.Execution{TenantID: tn.ID, ID: "record", Trigger: "post-login", Status: "success", Results: []store.ExecutionResult{{ActionName: "renamed", ErrorID: "test_error", ErrorMsg: "failed", StartedAt: time.Now(), EndedAt: time.Now()}}, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	call("GET", "/executions/record", nil, 200)
	call("DELETE", "/actions/"+id+"?force=true", nil, 204)
}
