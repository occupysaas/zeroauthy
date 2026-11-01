package login

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
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
	st := events.Wrap(memory.New(), events.Config{})
	e := newEnvWithStore(t, st)
	tn := mustTenant(t, e, "acme")
	if err := st.Events().DeleteTenantEvents(context.Background(), tn.ID); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "screen_hint", "signup")
	rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"context@acme.test"}, "password": {"long enough pw"}})
	if rec.Code != 302 {
		t.Fatalf("signup = %d %s", rec.Code, rec.Body)
	}
	c := capturedContext(t, st, tn.ID, "user.created")
	if c["client"] == nil || c["connection"] == nil || c["request"] == nil {
		t.Fatalf("context=%v", c)
	}
	if c["client"].(map[string]any)["id"] != "spa" || c["connection"].(map[string]any)["name"] != "Username-Password-Authentication" || c["request"].(map[string]any)["method"] != "POST" {
		t.Fatal(c)
	}
}
func TestSocialFirstLoginEmitsUserCreated(t *testing.T) {
	e := newSocialEnv(t)
	st := events.Wrap(e.st, events.Config{})
	e.h.Store, e.h.Federation.Store, e.h.Database.Store = st, st, st
	b := e.browser("acme.example.test")
	rec := e.explicitLogin(t, b, e.google, "google-oauth2", "context-user")
	if rec.Code != 302 {
		t.Fatalf("social=%d %s", rec.Code, rec.Body)
	}
	c := capturedContext(t, st, e.tenant.ID, "user.created")
	if c["client"] == nil || c["connection"] == nil || c["request"] == nil {
		t.Fatal(c)
	}
	if c["connection"].(map[string]any)["id"] != "con_google" {
		t.Fatal(c)
	}
}
