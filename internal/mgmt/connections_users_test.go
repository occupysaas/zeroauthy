package mgmt_test

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"testing"
)

func TestDeleteConnectionUserByEmail(t *testing.T) {
	e := newUsersEnv(t)
	u := &store.User{TenantID: e.tn.ID, UserID: "auth0|delete-email", Email: "a@example.com", Identities: []store.Identity{{Connection: e.conn.Name, Provider: "auth0", UserID: "delete-email"}}}
	ctx := context.Background()
	if err := e.st.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Sessions().Create(ctx, &store.LoginSession{TenantID: e.tn.ID, ID: "session", UserID: u.UserID}); err != nil {
		t.Fatal(err)
	}
	recorder := logs.NewRecorder(e.st, logs.Config{}, nil)
	e.h.Recorder = recorder
	r, v := e.call(t, e.tn, m2mCaller("delete:users"), "DELETE", "/users?email=a@example.com", nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.DeleteConnectionUsersByEmail(w, r, e.conn.ID, mgmtapi.DeleteConnectionUsersByEmailParams{Email: "a@example.com"})
	})
	if r.Code != 204 {
		t.Fatal(r.Code, v)
	}
	if _, err := e.st.Users().Get(ctx, e.tn.ID, u.UserID); err != store.ErrNotFound {
		t.Fatal(err)
	}
	if _, err := e.st.Sessions().Get(ctx, e.tn.ID, "session"); err != store.ErrNotFound {
		t.Fatal("session retained", err)
	}
	if err := recorder.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	events, _, err := e.st.Logs().SearchLogs(ctx, e.tn.ID, nil, store.LogPage{PerPage: 100})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Type == "sdu" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing deletion log")
	}
}
func TestDeleteByEmailMultipleUsers(t *testing.T) {
	e := newUsersEnv(t)
	e.conn.RequiresUsername = true
	if err := e.st.Connections().Update(context.Background(), e.conn); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, id := range []string{"one", "two"} {
		u := &store.User{TenantID: e.tn.ID, UserID: "auth0|" + id, Username: id, Email: "same@example.com", Identities: []store.Identity{{Connection: e.conn.Name, Provider: "auth0", UserID: id, ProfileData: map[string]any{"email": id + "@linked.example"}}}}
		if err := e.st.Users().Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		r, v := e.call(t, e.tn, m2mCaller(), "DELETE", "/users?email=same@example.com", nil, func(w http.ResponseWriter, r *http.Request) {
			e.h.DeleteConnectionUsersByEmail(w, r, e.conn.ID, mgmtapi.DeleteConnectionUsersByEmailParams{Email: "same@example.com"})
		})
		if r.Code != 204 {
			t.Fatal(r.Code, v)
		}
	}
	for _, id := range []string{"one", "two"} {
		if _, err := e.st.Users().Get(ctx, e.tn.ID, "auth0|"+id); err != store.ErrNotFound {
			t.Fatal(id, err)
		}
	}
}
func TestDeleteConnectionEmailValidation(t *testing.T) {
	e := newUsersEnv(t)
	for _, tc := range []struct {
		id, email string
		status    int
	}{{e.conn.ID, "", 400}, {"con_unknown", "a@example.com", 404}, {e.conn.ID, "unknown@example.com", 204}} {
		r, _ := e.call(t, e.tn, m2mCaller(), "DELETE", "/users", nil, func(w http.ResponseWriter, r *http.Request) {
			e.h.DeleteConnectionUsersByEmail(w, r, tc.id, mgmtapi.DeleteConnectionUsersByEmailParams{Email: tc.email})
		})
		if r.Code != tc.status {
			t.Fatal(tc, r.Code)
		}
	}
}
func TestConnectionStatus(t *testing.T) {
	e := keysEnv(t)
	for _, id := range []string{"con_enterprise", "con_missing"} {
		r, v := e.call(t, e.tn, m2mCaller(), "GET", "/status", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetConnectionStatus(w, r, id) })
		if r.Code != 404 || v.(map[string]any)["statusCode"] != float64(404) {
			t.Fatal(r.Code, v)
		}
	}
}
