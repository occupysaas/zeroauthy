package mgmt_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func capturedContext(t *testing.T, st store.Store, tid, typ string) map[string]any {
	t.Helper()
	rows, err := st.Events().EventsAfter(context.Background(), tid, 0, []string{typ}, 100, time.Now().Add(time.Hour))
	if err != nil || len(rows) != 1 {
		t.Fatalf("events %s: count=%d err=%v", typ, len(rows), err)
	}
	var body map[string]any
	if err := json.Unmarshal(rows[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	return body["data"].(map[string]any)["context"].(map[string]any)
}

func TestManagementEventContext(t *testing.T) {
	for _, kind := range []mgmt.Kind{mgmt.M2M, mgmt.Operator} {
		t.Run(map[mgmt.Kind]string{mgmt.M2M: "M2M", mgmt.Operator: "operator"}[kind], func(t *testing.T) {
			e := newUsersEnv(t)
			ctx := context.Background()
			caller := &store.Client{TenantID: e.tn.ID, ClientID: "m2m", Name: "Authenticated caller"}
			if err := e.st.Clients().Create(ctx, caller); err != nil {
				t.Fatal(err)
			}
			st := events.Wrap(e.st, events.Config{})
			e.h.Store = st
			req := httptest.NewRequest("POST", "https://untrusted-host.invalid/api/v2/users?client_id=spoofed", strings.NewReader(`{"connection":"`+dbConn+`","email":"event@example.test","password":"private-password-123"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "event-context-test")
			req.Header.Set("Authorization", "Bearer private-token")
			req.Header.Set("X-Forwarded-For", "192.0.2.199")
			ctx = tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: e.tn, Host: "custom.acme.test"})
			ctx = httpx.WithClientIP(ctx, netip.MustParseAddr("198.51.100.8"))
			ctx = mgmt.WithCaller(ctx, mgmt.Caller{Kind: kind, ClientID: "m2m", UserID: "operator", Scopes: allUserScopes})
			rec := httptest.NewRecorder()
			e.h.LogMiddleware(http.HandlerFunc(e.h.CreateUser)).ServeHTTP(rec, req.WithContext(ctx))
			if rec.Code != http.StatusCreated {
				t.Fatalf("create=%d %s", rec.Code, rec.Body)
			}
			c := capturedContext(t, st, e.tn.ID, "user.created")
			if c["request"] == nil || c["connection"] == nil || c["tenant"].(map[string]any)["id"] != e.tn.ID {
				t.Fatal(c)
			}
			r := c["request"].(map[string]any)
			if r["ip"] != "198.51.100.8" || r["hostname"] != "custom.acme.test" || r["custom_domain"] != "custom.acme.test" || r["method"] != "POST" || r["user_agent"] != "event-context-test" || len(r["geo"].(map[string]any)) != 0 {
				t.Fatal(c)
			}
			if kind == mgmt.M2M {
				if c["client"] == nil {
					t.Fatal(c)
				}
				cl := c["client"].(map[string]any)
				if cl["id"] != "m2m" || cl["name"] != caller.Name || len(cl["metadata"].(map[string]any)) != 0 {
					t.Fatal(c)
				}
			} else if c["client"] != nil {
				t.Fatalf("operator acquired an M2M client: %v", c)
			}
			rows, err := st.Events().EventsAfter(ctx, e.tn.ID, 0, nil, 100, time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				for _, secret := range []string{"private-password-123", "private-token", "spoofed", "password_hash", "access_token"} {
					if strings.Contains(string(row.Body), secret) {
						t.Fatalf("event leaked %q: %s", secret, row.Body)
					}
				}
			}
		})
	}
}

func TestManagementUserMutationEventContext(t *testing.T) {
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			e := newUsersEnv(t)
			ctx := context.Background()
			caller := &store.Client{TenantID: e.tn.ID, ClientID: "calling-app", Name: "Calling automation"}
			if err := e.st.Clients().Create(ctx, caller); err != nil {
				t.Fatal(err)
			}
			created := e.mustCreate(t, map[string]any{
				"email": "profile@example.test", "name": "Original name", "given_name": "Ada", "family_name": "Lovelace",
				"nickname": "original", "user_metadata": map[string]any{"marker": "retained"}, "app_metadata": map[string]any{"tier": "pro"},
			})
			id := created["user_id"].(string)
			st := events.Wrap(e.st, events.Config{})
			e.h.Store = st
			body := ""
			if method == http.MethodPatch {
				body = `{"name":"Changed name","password":"replacement password 123","user_metadata":{"new":"added"}}`
			}
			req := httptest.NewRequest(method, "https://untrusted.invalid/api/v2/users/"+id, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "mutation-context-test")
			req.Header.Set("X-Forwarded-For", "192.0.2.199")
			ctx = tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: e.tn, Host: "custom.acme.test"})
			ctx = httpx.WithClientIP(ctx, netip.MustParseAddr("198.51.100.8"))
			ctx = mgmt.WithCaller(ctx, mgmt.Caller{Kind: mgmt.M2M, ClientID: caller.ClientID, Scopes: allUserScopes})
			rec := httptest.NewRecorder()
			handler := func(w http.ResponseWriter, r *http.Request) { e.h.UpdateUser(w, r, id) }
			typ, status := "user.updated", http.StatusOK
			if method == http.MethodDelete {
				handler = func(w http.ResponseWriter, r *http.Request) { e.h.DeleteUser(w, r, id) }
				typ, status = "user.deleted", http.StatusNoContent
			}
			e.h.LogMiddleware(http.HandlerFunc(handler)).ServeHTTP(rec, req.WithContext(ctx))
			if rec.Code != status {
				t.Fatalf("%s = %d %s", method, rec.Code, rec.Body)
			}
			rows, err := st.Events().EventsAfter(ctx, e.tn.ID, 0, []string{typ}, 100, time.Now().Add(time.Hour))
			if err != nil || len(rows) != 1 {
				t.Fatalf("events=%d err=%v", len(rows), err)
			}
			var event map[string]any
			if err := json.Unmarshal(rows[0].Body, &event); err != nil {
				t.Fatal(err)
			}
			data := event["data"].(map[string]any)
			attribution := data["context"].(map[string]any)
			if attribution["connection"] == nil {
				t.Fatalf("resolved connection missing: %v", attribution)
			}
			connection := attribution["connection"].(map[string]any)
			if connection["id"] != e.conn.ID || connection["name"] != e.conn.Name || connection["strategy"] != e.conn.Strategy {
				t.Fatal(attribution)
			}
			client := attribution["client"].(map[string]any)
			request := attribution["request"].(map[string]any)
			if client["id"] != caller.ClientID || client["name"] != caller.Name || len(client["metadata"].(map[string]any)) != 0 || attribution["tenant"].(map[string]any)["id"] != e.tn.ID {
				t.Fatal(attribution)
			}
			if request["ip"] != "198.51.100.8" || request["hostname"] != "custom.acme.test" || request["custom_domain"] != "custom.acme.test" || request["method"] != method || request["user_agent"] != "mutation-context-test" {
				t.Fatal(attribution)
			}
			object := data["object"].(map[string]any)
			assertProfile := func(profile map[string]any, name string) {
				t.Helper()
				if profile["user_id"] != id || profile["email"] != "profile@example.test" || profile["name"] != name || profile["given_name"] != "Ada" || profile["family_name"] != "Lovelace" || profile["nickname"] != "original" || profile["created_at"] != created["created_at"] || profile["picture"] != created["picture"] {
					t.Fatalf("incomplete profile: %v", profile)
				}
				if profile["user_metadata"].(map[string]any)["marker"] != "retained" || profile["app_metadata"].(map[string]any)["tier"] != "pro" || len(profile["identities"].([]any)) != 1 {
					t.Fatalf("incomplete profile metadata/identities: %v", profile)
				}
			}
			if method == http.MethodPatch {
				assertProfile(object, "Changed name")
				assertProfile(data["previous_object"].(map[string]any), "Original name")
				if object["user_metadata"].(map[string]any)["new"] != "added" || data["previous_object"].(map[string]any)["user_metadata"].(map[string]any)["new"] != nil {
					t.Fatal(data)
				}
			} else {
				assertProfile(object, "Original name")
				if object["deleted_at"] == nil || data["previous_object"] != nil {
					t.Fatal(data)
				}
			}
			for _, secret := range []string{"replacement password 123", "password_hash", "imported_hash"} {
				if strings.Contains(string(rows[0].Body), secret) {
					t.Fatalf("event leaked %q", secret)
				}
			}
		})
	}
}
