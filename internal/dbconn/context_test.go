package dbconn

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/store"
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

func TestSignupEventContext(t *testing.T) {
	e := newEnv(t)
	st := events.Wrap(e.st, events.Config{})
	e.h.Store, e.h.Database.Store = st, st
	status, body, _ := e.post(t, "/dbconnections/signup", "application/json", `{"client_id":"app","connection":"Username-Password-Authentication","email":"context@example.test","password":"long enough pw"}`)
	if status != 200 {
		t.Fatalf("signup=%d %v", status, body)
	}
	c := capturedContext(t, st, e.tenantID, "user.created")
	if c["client"] == nil || c["connection"] == nil || c["request"] == nil {
		t.Fatal(c)
	}
	if c["client"].(map[string]any)["id"] != "app" || c["connection"].(map[string]any)["strategy"] != "auth0" || c["request"].(map[string]any)["method"] != "POST" {
		t.Fatal(c)
	}
}
