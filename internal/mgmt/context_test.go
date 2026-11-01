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
