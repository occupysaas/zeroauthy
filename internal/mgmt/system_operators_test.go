package mgmt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func operatorRequest(e *env, method, path, raw string, body any) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(method, "https://"+systemHost+path, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func operatorEnv(t *testing.T) (*env, string) {
	t.Helper()
	e := newEnv(t)
	h := &mgmt.Handlers{Store: e.st, BaseDomain: base, SystemHost: systemHost, Now: func() time.Time { return now }}
	routes := http.NewServeMux()
	routes.HandleFunc("PATCH /api/system/operators/{id}", func(w http.ResponseWriter, r *http.Request) {
		h.UpdateOperator(w, r, r.PathValue("id"))
	})
	routes.HandleFunc("DELETE /api/system/operators/{id}", func(w http.ResponseWriter, r *http.Request) { h.DeleteOperator(w, r, r.PathValue("id")) })
	routes.HandleFunc("GET /api/system/tenants", h.GetTenants)
	routes.HandleFunc("GET /api/v2/clients", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	routes.HandleFunc("GET /api/console/tenants", func(w http.ResponseWriter, r *http.Request) {
		h.GetConsoleTenants(w, r)
	})
	auth := mgmt.Auth(mgmt.Config{Store: e.st, Keys: e.km, BaseDomain: base, SystemHost: systemHost, Now: func() time.Time { return now }})
	e.handler = tenant.NewResolver(e.st.Tenants(), base, false).Middleware(auth(mgmt.RequireOperator(routes)))
	return e, e.mint(t, operator("https://"+systemHost+"/", []string{"*"}))
}

func TestOperatorTenants(t *testing.T) {
	t.Run("round trip and old token", func(t *testing.T) {
		e, raw := operatorEnv(t)
		ctx := context.Background()
		if err := e.st.Users().Create(ctx, &store.User{TenantID: e.ids["system"], UserID: "auth0|backup"}); err != nil {
			t.Fatal(err)
		}
		if err := e.st.Operators().Upsert(ctx, &store.Operator{TenantID: e.ids["system"], UserID: "auth0|backup", Tenants: []string{"system"}}); err != nil {
			t.Fatal(err)
		}
		rec := operatorRequest(e, "PATCH", "/api/system/operators/auth0%7Cop", raw, map[string]any{"tenants": []string{"acme"}})
		if rec.Code != 200 {
			t.Fatalf("PATCH = %d %s", rec.Code, rec.Body)
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if !reflect.DeepEqual(out["tenants"], []any{"acme"}) || out["user_id"] != "auth0|op" {
			t.Fatalf("operator = %v", out)
		}
		rec = operatorRequest(e, "GET", "/api/system/tenants", raw, nil)
		if rec.Code != 403 {
			t.Fatalf("old token system API = %d", rec.Code)
		}
		for _, host := range []string{"acme.example.com", "globex.example.com"} {
			req := httptest.NewRequest("GET", "https://"+host+"/api/v2/clients", nil)
			req.Header.Set("Authorization", "Bearer "+raw)
			rec = httptest.NewRecorder()
			e.handler.ServeHTTP(rec, req)
			want := 200
			if host == "globex.example.com" {
				want = 403
			}
			if rec.Code != want {
				t.Fatalf("old token on %s = %d, want %d", host, rec.Code, want)
			}
		}
	})
	t.Run("stored lists round trip", func(t *testing.T) {
		e, raw := operatorEnv(t)
		ctx := context.Background()
		before, err := e.st.Operators().Get(ctx, e.ids["system"], "auth0|acme-op")
		if err != nil {
			t.Fatal(err)
		}
		for _, names := range [][]string{{"acme", "globex"}, {"*"}, {"system"}, {}} {
			rec := operatorRequest(e, "PATCH", "/api/system/operators/auth0%7Cacme-op", raw, map[string]any{"tenants": names})
			var got struct {
				Tenants []string `json:"tenants"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &got)
			if rec.Code != 200 || !reflect.DeepEqual(got.Tenants, names) {
				t.Fatalf("PATCH %v = %d %s", names, rec.Code, rec.Body)
			}
			stored, err := e.st.Operators().Get(ctx, e.ids["system"], "auth0|acme-op")
			if err != nil || !reflect.DeepEqual(stored.Tenants, names) || !stored.CreatedAt.Equal(before.CreatedAt) || !stored.UpdatedAt.Equal(now) {
				t.Fatalf("stored operator = %+v, %v", stored, err)
			}
		}
	})
	t.Run("validation", func(t *testing.T) {
		e, raw := operatorEnv(t)
		for _, body := range []any{map[string]any{"tenants": []string{"missing"}}, map[string]any{"tenants": []string{"*", "acme"}}, map[string]any{}, map[string]any{"tenants": nil}, map[string]any{"tenants": "acme"}, map[string]any{"tenants": []string{"acme"}, "extra": true}} {
			rec := operatorRequest(e, "PATCH", "/api/system/operators/auth0%7Cacme-op", raw, body)
			if rec.Code != 400 {
				t.Errorf("%v = %d %s", body, rec.Code, rec.Body)
			}
		}
		rec := operatorRequest(e, "PATCH", "/api/system/operators/missing", raw, map[string]any{"tenants": []string{"acme"}})
		if rec.Code != 404 {
			t.Errorf("missing = %d", rec.Code)
		}
		scoped := operator("https://"+systemHost+"/", []string{"acme"})
		scoped.sub = "auth0|acme-op"
		rec = operatorRequest(e, "PATCH", "/api/system/operators/auth0%7Cop", e.mint(t, scoped), map[string]any{"tenants": []string{"*"}})
		if rec.Code != 403 {
			t.Errorf("tenant-only caller = %d", rec.Code)
		}
	})
	t.Run("last system admin", func(t *testing.T) {
		e, raw := operatorEnv(t)
		for _, method := range []string{"PATCH", "DELETE"} {
			rec := operatorRequest(e, method, "/api/system/operators/auth0%7Cop", raw, map[string]any{"tenants": []string{"acme"}})
			if rec.Code != 409 {
				t.Errorf("%s = %d %s", method, rec.Code, rec.Body)
			}
		}
		rec := operatorRequest(e, "PATCH", "/api/system/operators/auth0%7Cacme-op", raw, map[string]any{"tenants": []string{}})
		if rec.Code != 200 {
			t.Errorf("empty list = %d", rec.Code)
		}
	})
	t.Run("concurrent changes retain system admin", func(t *testing.T) {
		for _, methods := range [][]string{{"PATCH", "PATCH"}, {"DELETE", "DELETE"}, {"PATCH", "DELETE"}} {
			e, raw := operatorEnv(t)
			if err := e.st.Users().Create(context.Background(), &store.User{TenantID: e.ids["system"], UserID: "auth0|second"}); err != nil {
				t.Fatal(err)
			}
			if err := e.st.Operators().Upsert(context.Background(), &store.Operator{TenantID: e.ids["system"], UserID: "auth0|second", Tenants: []string{"system"}}); err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			codes := make(chan int, 2)
			var wg sync.WaitGroup
			for i, id := range []string{"auth0%7Cop", "auth0%7Csecond"} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					codes <- operatorRequest(e, methods[i], "/api/system/operators/"+id, raw, map[string]any{"tenants": []string{"acme"}}).Code
				}()
			}
			close(start)
			wg.Wait()
			close(codes)
			success, refused := 0, 0
			for code := range codes {
				if code == 200 || code == 204 {
					success++
				}
				if code == 409 || code == 403 || code == 401 {
					refused++
				}
			}
			if success != 1 || refused != 1 {
				t.Errorf("%v: success=%d refused=%d", methods, success, refused)
			}
			ops, err := e.st.Operators().List(context.Background(), e.ids["system"])
			if err != nil {
				t.Fatal(err)
			}
			admins := 0
			for _, op := range ops {
				for _, name := range op.Tenants {
					if name == "*" || name == "system" {
						admins++
						break
					}
				}
			}
			if admins != 1 {
				t.Fatalf("admins=%d", admins)
			}
		}
	})
}

func TestOperatorTenantsDiscovery(t *testing.T) {
	e, _ := operatorEnv(t)
	scoped := operator("https://"+systemHost+"/", []string{"acme"})
	scoped.sub = "auth0|acme-op"
	raw := e.mint(t, scoped)
	rec := operatorRequest(e, "GET", "/api/console/tenants", raw, nil)
	if rec.Code != 200 {
		t.Fatalf("discovery = %d %s", rec.Code, rec.Body)
	}
	var out []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out) != 1 || out[0]["name"] != "acme" {
		t.Fatalf("allowed = %v", out)
	}
	// Expanding stored grants cannot expand the old token's authority.
	op, _ := e.st.Operators().Get(context.Background(), e.ids["system"], "auth0|acme-op")
	op.Tenants = []string{"*"}
	if err := e.st.Operators().Upsert(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	rec = operatorRequest(e, "GET", "/api/console/tenants", raw, nil)
	out = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || len(out) != 1 || out[0]["name"] != "acme" {
		t.Fatalf("token intersection = %d %s", rec.Code, rec.Body)
	}
	op.Tenants = []string{}
	if err := e.st.Operators().Upsert(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	rec = operatorRequest(e, "GET", "/api/console/tenants", raw, nil)
	out = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || len(out) != 0 {
		t.Fatalf("shrunk discovery = %d %s", rec.Code, rec.Body)
	}
}
