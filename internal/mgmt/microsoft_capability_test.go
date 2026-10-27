package mgmt_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type oldMicrosoftStore struct{ store.Store }

func (s oldMicrosoftStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(oldMicrosoftStore{tx}) })
}
func TestMicrosoftManagementCapability(t *testing.T) {
	ctx := context.Background()
	for _, op := range []string{"create", "update connection", "enable", "update user", "delete user", "link", "unlink"} {
		t.Run(op, func(t *testing.T) {
			e := newUsersEnv(t)
			c := &store.Connection{TenantID: e.tn.ID, ID: "con_ms", Name: "ms", Strategy: "windowslive", Extra: map[string]any{"client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}
			_ = e.st.Connections().Create(ctx, c)
			u := &store.User{TenantID: e.tn.ID, UserID: "windowslive|MS", Identities: []store.Identity{{Connection: "ms", Provider: "windowslive", UserID: "MS"}}}
			if err := e.st.Users().Create(ctx, u); err != nil {
				t.Fatal(err)
			}
			p := e.mustCreate(t, map[string]any{"email": "primary@x.test", "password": "primary pass 1"})["user_id"].(string)
			if op == "unlink" {
				if rec, _ := e.link(t, p, map[string]any{"provider": "windowslive", "user_id": "MS"}); rec.Code != 201 {
					t.Fatal(rec.Body.String())
				}
			}
			_ = e.st.Clients().Create(ctx, &store.Client{TenantID: e.tn.ID, ClientID: "app"})
			e.h.Store = oldMicrosoftStore{e.st}
			var status int
			var body string
			switch op {
			case "create":
				rec, _ := e.do(t, m2mCaller("create:connections"), "POST", "/api/v2/connections", map[string]any{"name": "new-ms", "strategy": "windowslive", "options": map[string]any{"client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "client_secret": "PRIVATE"}}, e.h.CreateConnection)
				status, body = rec.Code, rec.Body.String()
			case "update connection":
				rec, _ := e.do(t, m2mCaller("update:connections"), "PATCH", "/api/v2/connections/con_ms", map[string]any{"display_name": "new"}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateConnection(w, r, "con_ms") })
				status, body = rec.Code, rec.Body.String()
			case "enable":
				rec, _ := e.do(t, m2mCaller("update:connections"), "PATCH", "/api/v2/connections/con_ms/clients", []map[string]any{{"client_id": "app", "status": true}}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateConnectionClients(w, r, "con_ms") })
				status, body = rec.Code, rec.Body.String()
			case "update user":
				rec, _ := e.patch(t, u.UserID, map[string]any{"blocked": true})
				status, body = rec.Code, rec.Body.String()
			case "delete user":
				rec := e.del(t, u.UserID)
				status, body = rec.Code, rec.Body.String()
			case "link":
				rec, _ := e.link(t, p, map[string]any{"provider": "windowslive", "user_id": "MS"})
				status, body = rec.Code, rec.Body.String()
			case "unlink":
				rec, _ := e.unlink(t, p, "windowslive", "MS")
				status, body = rec.Code, rec.Body.String()
			}
			if status != 500 {
				t.Fatalf("%s unsupported = %d %s", op, status, body)
			}
			if strings.Contains(body, "PRIVATE") {
				t.Fatal("secret in response")
			}
		})
	}
}
