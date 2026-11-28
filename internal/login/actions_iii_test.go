package login

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
)

// TestFreshLoginSessionEffects: api.session calls on a fresh password login
// shape the session before it is stored and its cookie set (Plan 40).
func TestFreshLoginSessionEffects(t *testing.T) {
	f := newMFAFixture(t)
	a := actionstest.NewOffline(t, f.st, f.h.Authz.Wrapper)
	a.PostLogin(t, f.tn.ID, "fresh", `exports.onExecutePostLogin = async (event, api) => {
	  api.session.setCookieMode("non-persistent");
	  api.session.setExpiresAt(Date.parse(event.session.created_at) + 60 * 60 * 1000);
	  api.session.setMetadata("device", "kiosk");
	  api.user.setAppMetadata("seen_created_at", event.session.created_at);
	};`)
	f.h.Authz.Actions = a.Engine
	u, _ := f.st.Users().Get(context.Background(), f.tn.ID, f.uid)
	_, state, csrf := f.b.begin(t)
	rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {u.Email}, "password": {"alice password 1"}})
	appCode(t, rec)
	var token string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "za_session" && c.Value != "" {
			token = c.Value
			if !c.Expires.IsZero() {
				t.Fatalf("non-persistent cookie has Expires %v", c.Expires)
			}
		}
	}
	if token == "" {
		t.Fatalf("no session cookie: %v", rec.Header().Values("Set-Cookie"))
	}
	sess, err := f.st.Sessions().GetByTokenHash(context.Background(), f.tn.ID, secrets.HashToken(token))
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := f.st.Users().Get(context.Background(), f.tn.ID, f.uid)
	seen, err := time.Parse(time.RFC3339, saved.AppMetadata["seen_created_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if sess.CookieMode != "non-persistent" || sess.Metadata["device"] != "kiosk" || !sess.ExpiresAt.Equal(seen.Add(time.Hour)) || sess.IdleExpiresAt.After(sess.ExpiresAt) {
		t.Fatalf("session %+v", sess)
	}
}
