package oauth

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/events"
)

func TestOAuthActionEventContext(t *testing.T) {
	f := newActionsFixture(t)
	status, body := f.token(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "scope", "openid offline_access"))
	if status != 200 {
		t.Fatalf("initial=%d %v", status, body)
	}
	refresh := body["refresh_token"].(string)
	f.actions.PostLogin(t, f.tid, "context", `exports.onExecutePostLogin=async(event,api)=>{api.user.setAppMetadata("event_context","applied");};`)
	st := events.Wrap(f.st, events.Config{})
	f.st, f.h.Store, f.h.Database.Store, f.h.Actions.Store = st, st, st, st
	status, body = f.token(t, refreshForm("ropg", refresh, "client_secret", "ropg-secret"))
	if status != 200 {
		t.Fatalf("refresh=%d %v", status, body)
	}
	rows, err := st.Events().EventsAfter(context.Background(), f.tid, 0, []string{"user.updated"}, 100, time.Now().Add(time.Hour))
	if err != nil || len(rows) != 1 {
		t.Fatalf("events=%d %v", len(rows), err)
	}
	var event map[string]any
	if err := json.Unmarshal(rows[0].Body, &event); err != nil {
		t.Fatal(err)
	}
	data := event["data"].(map[string]any)
	c := data["context"].(map[string]any)
	if c["client"] == nil || c["request"] == nil || c["connection"] == nil {
		t.Fatal(c)
	}
	if c["client"].(map[string]any)["id"] != "ropg" || c["connection"].(map[string]any)["name"] != "Username-Password-Authentication" || c["request"].(map[string]any)["method"] != "POST" {
		t.Fatal(c)
	}
	if data["object"].(map[string]any)["app_metadata"].(map[string]any)["event_context"] != "applied" {
		t.Fatal(data)
	}
}
