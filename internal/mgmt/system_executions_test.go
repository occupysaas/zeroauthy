package mgmt_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func TestSystemExecutionsList(t *testing.T) {
	e, raw := operatorEnv(t)
	h := &mgmt.Handlers{Store: e.st, Now: func() time.Time { return now }}
	routes := http.NewServeMux()
	routes.HandleFunc("GET /api/system/tenants/{tenant}/actions/executions", func(w http.ResponseWriter, r *http.Request) {
		h.GetTenantActionExecutions(w, r, r.PathValue("tenant"), mgmtapi.GetTenantActionExecutionsParams{})
	})
	routes.HandleFunc("GET /api/system/tenants/{tenant}/actions/executions/{id}", func(w http.ResponseWriter, r *http.Request) {
		h.GetTenantActionExecution(w, r, r.PathValue("tenant"), r.PathValue("id"))
	})
	auth := mgmt.Auth(mgmt.Config{Store: e.st, Keys: e.km, BaseDomain: base, SystemHost: systemHost, Now: func() time.Time { return now }})
	e.handler = tenant.NewResolver(e.st.Tenants(), base, false).Middleware(auth(mgmt.RequireOperator(routes)))
	ctx := context.Background()
	for _, id := range []string{"a", "b", "c"} {
		if err := e.st.Actions().CreateExecution(ctx, &store.Execution{TenantID: e.ids["acme"], ID: id, Trigger: "post-login", Status: "final", CreatedAt: now, UpdatedAt: now, Results: []store.ExecutionResult{{ActionID: "immutable-id", ActionName: "renamed", Logs: []string{"safe"}, DenialReason: "Blocked [REDACTED]"}}}); err != nil {
			t.Fatal(err)
		}
	}
	path := "/api/system/tenants/acme/actions/executions"
	for _, tc := range []struct {
		query string
		want  []string
	}{{"?take=2", []string{"c", "b"}}, {"?after=a&take=2", []string{"b", "c"}}, {"?action=immutable-id&trigger=post-login", []string{"c", "b", "a"}}, {"?action=renamed", []string{}}, {"?trigger=missing", []string{}}} {
		rec := operatorRequest(e, "GET", path+tc.query, raw, nil)
		var out []struct {
			ID string `json:"id"`
		}
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("list %s: %d %s", tc.query, rec.Code, rec.Body)
		}
		ids := []string{}
		for _, ex := range out {
			ids = append(ids, ex.ID)
		}
		if !reflect.DeepEqual(ids, tc.want) {
			t.Fatalf("%s ids=%v", tc.query, ids)
		}
	}
	for _, tc := range []struct {
		path string
		code int
	}{{path + "/a", 200}, {"/api/system/tenants/globex/actions/executions/a", 404}, {"/api/system/tenants/globex/actions/executions?after=a", 404}, {path + "?take=no", 400}} {
		rec := operatorRequest(e, "GET", tc.path, raw, nil)
		if rec.Code != tc.code {
			t.Fatalf("GET %s: %d %s", tc.path, rec.Code, rec.Body)
		}
	}
	recDetail := operatorRequest(e, "GET", path+"/a", raw, nil)
	var detail struct {
		Results []map[string]any `json:"results"`
	}
	if json.Unmarshal(recDetail.Body.Bytes(), &detail) != nil || len(detail.Results) != 1 || detail.Results[0]["denial_reason"] != "Blocked [REDACTED]" || detail.Results[0]["action_id"] != "immutable-id" || detail.Results[0]["error"] != nil {
		t.Fatalf("operator denial projection: %s", recDetail.Body)
	}
	limited := e.mint(t, operator("https://"+systemHost+"/", []string{"globex"}))
	if rec := operatorRequest(e, "GET", path, limited, nil); rec.Code != 403 {
		t.Fatalf("tenant grant=%d", rec.Code)
	}
	for i := 0; i < 110; i++ {
		if err := e.st.Actions().CreateExecution(ctx, &store.Execution{TenantID: e.ids["acme"], ID: fmt.Sprintf("bulk-%03d", i), CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	rec := operatorRequest(e, "GET", path+"?take=999", raw, nil)
	var capped []map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &capped) != nil || len(capped) != 100 {
		t.Fatalf("cap=%d %s", rec.Code, rec.Body)
	}
}
func TestPublicExecutionShapeUnchanged(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := &mgmt.Handlers{Store: e.st}
	ex := &store.Execution{TenantID: e.ids["acme"], ID: "private-console", Trigger: "post-login", Status: "final", CreatedAt: now, UpdatedAt: now, Results: []store.ExecutionResult{{ActionID: "secret-id", ActionName: "named", Logs: []string{"private console"}, DenialReason: "private reason", JobID: "job", JobAttempt: 2, StartedAt: now, EndedAt: now}}}
	if err := e.st.Actions().CreateExecution(ctx, ex); err != nil {
		t.Fatal(err)
	}
	routes := http.NewServeMux()
	routes.HandleFunc("GET /api/v2/actions/executions/{id}", func(w http.ResponseWriter, r *http.Request) { h.GetActionExecution(w, r, r.PathValue("id")) })
	e.handler = tenant.NewResolver(e.st.Tenants(), base, false).Middleware(routes)
	req := httptest.NewRequest("GET", "https://acme."+base+"/api/v2/actions/executions/private-console", nil)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	var got map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	expected := map[string]any{"id": "private-console", "trigger_id": "post-login", "status": "final", "created_at": now.Format(time.RFC3339Nano), "updated_at": now.Format(time.RFC3339Nano), "results": []any{map[string]any{"action_name": "named", "started_at": now.Format(time.RFC3339Nano), "ended_at": now.Format(time.RFC3339Nano)}}}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("public shape=%s", rec.Body)
	}
}

type executionWithoutLogs struct{ store.Store }

func (executionWithoutLogs) CheckLogsSupport(context.Context) error { return store.ErrLogsUnavailable }
func (executionWithoutLogs) LogsSupported() bool                    { return false }

type executionWithoutActions struct{ store.Store }

func (executionWithoutActions) Actions() store.Actions { return store.UnimplementedActions{} }
func TestSystemExecutionsUnavailable(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.st.Actions().CreateExecution(ctx, &store.Execution{TenantID: e.ids["acme"], ID: "existing"}); err != nil {
		t.Fatal(err)
	}
	for name, st := range map[string]store.Store{"missing-logs": executionWithoutLogs{e.st}, "missing-list": executionWithoutActions{e.st}} {
		t.Run(name, func(t *testing.T) {
			h := &mgmt.Handlers{Store: st}
			for _, run := range []func(http.ResponseWriter, *http.Request){func(w http.ResponseWriter, r *http.Request) {
				h.GetTenantActionExecutions(w, r, "acme", mgmtapi.GetTenantActionExecutionsParams{})
			}, func(w http.ResponseWriter, r *http.Request) { h.GetTenantActionExecution(w, r, "acme", "existing") }} {
				rec := httptest.NewRecorder()
				run(rec, httptest.NewRequest("GET", "https://"+systemHost+"/api/system/tenants/acme/actions/executions", nil))
				var doc map[string]any
				_ = json.Unmarshal(rec.Body.Bytes(), &doc)
				if rec.Code != 501 || doc["errorCode"] != "logs_unavailable" {
					t.Fatalf("capability=%d %s", rec.Code, rec.Body)
				}
			}
		})
	}
}
